#!/usr/bin/env node

/**
 * Servidor local de desarrollo para CentinelaIA.
 * Sirve el frontend estático y expone los handlers de Lambda como una API HTTP
 * en el mismo origen (sin CORS), SIN Docker y SIN desplegar a AWS.
 *
 * Modo: AI_ENGINE_MODE=fallback, DynamoDB apuntando a un endpoint muerto
 * (persistencia fail-open) y autenticación deshabilitada (sin API_SHARED_SECRET).
 * El escaneo, el análisis, la correlación y el enriquecimiento CVE funcionan;
 * el historial no persiste (no hay DynamoDB local).
 *
 * Uso: npm run local   (por defecto en el puerto 3000)
 */

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';

// ─── Configuración de entorno para ejecución local (antes de importar handlers) ─
process.env['AI_ENGINE_MODE'] ??= 'fallback';
process.env['AWS_REGION'] ??= 'us-east-1';
process.env['AWS_ACCESS_KEY_ID'] ??= 'local';
process.env['AWS_SECRET_ACCESS_KEY'] ??= 'local';
process.env['AWS_EC2_METADATA_DISABLED'] = 'true';
process.env['AWS_ENDPOINT_URL_DYNAMODB'] ??= 'http://127.0.0.1:9';
// Sin API_SHARED_SECRET → autenticación deshabilitada en local.

const PORT = Number(process.env['PORT'] ?? 3000);
const FRONTEND_DIR = path.resolve(fileURLToPath(new URL('../../../frontend', import.meta.url)));

type Handler = (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult>;

const MIME_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

/** Config local inyectada: API en el mismo origen, sin API key. */
const LOCAL_CONFIG_JS =
  "export const API_BASE_URL = '';\nexport const API_KEY = '';\n";

async function main(): Promise<void> {
  // Import tardío: garantiza que el entorno esté configurado antes de crear los handlers.
  const [{ handler: scanHandler }, { handler: analyzeHandler }, { handler: translateLogHandler }] =
    await Promise.all([
      import('../handlers/scan-handler.js'),
      import('../handlers/analyze-handler.js'),
      import('../handlers/translate-log-handler.js'),
    ]);

  const server = http.createServer((req, res) => {
    void handleRequest(req, res, { scanHandler, analyzeHandler, translateLogHandler });
  });

  server.listen(PORT, () => {
    console.log(`\n  CentinelaIA local → http://localhost:${PORT}`);
    console.log(`  Modo IA: ${process.env['AI_ENGINE_MODE']} · Auth: deshabilitada · DynamoDB: no (historial no persiste)\n`);
  });
}

async function handleRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  handlers: { scanHandler: Handler; analyzeHandler: Handler; translateLogHandler: Handler },
): Promise<void> {
  const url = new URL(req.url ?? '/', `http://localhost:${PORT}`);
  const pathname = url.pathname;
  const method = (req.method ?? 'GET').toUpperCase();

  // Rutas de API → delegar al handler correspondiente
  const apiHandler = routeApi(pathname, handlers);
  if (apiHandler) {
    const body = await readBody(req);
    const event = buildEvent(method, pathname, url.searchParams, req.headers, body);
    try {
      const result = await apiHandler(event);
      res.writeHead(result.statusCode, {
        'Content-Type': 'application/json',
        ...(result.headers as Record<string, string> | undefined),
      });
      res.end(result.body);
    } catch (error: unknown) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Local server error', detail: String(error) }));
    }
    return;
  }

  // Resto → servir archivos estáticos del frontend
  await serveStatic(pathname, res);
}

/** Determina qué handler atiende una ruta de API, o null si es estática. */
function routeApi(
  pathname: string,
  handlers: { scanHandler: Handler; analyzeHandler: Handler; translateLogHandler: Handler },
): Handler | null {
  if (/^\/scan(\/.*)?$/.test(pathname)) return handlers.scanHandler;
  if (/^\/analyze(\/.*)?$/.test(pathname)) return handlers.analyzeHandler;
  if (pathname === '/translate-log') return handlers.translateLogHandler;
  return null;
}

/** Construye un APIGatewayProxyEvent mínimo compatible con los handlers (v1 y v2). */
function buildEvent(
  method: string,
  pathname: string,
  searchParams: URLSearchParams,
  headers: http.IncomingHttpHeaders,
  body: string | null,
): APIGatewayProxyEvent {
  const query = Object.fromEntries(searchParams.entries());
  return {
    body,
    headers: headers as Record<string, string>,
    httpMethod: method,
    path: pathname,
    pathParameters: null,
    queryStringParameters: Object.keys(query).length > 0 ? query : null,
    multiValueHeaders: {},
    multiValueQueryStringParameters: null,
    isBase64Encoded: false,
    requestContext: { http: { method, path: pathname } },
    resource: pathname,
    stageVariables: null,
  } as unknown as APIGatewayProxyEvent;
}

/** Lee el cuerpo de la petición como string. */
function readBody(req: http.IncomingMessage): Promise<string | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk) => chunks.push(chunk as Buffer));
    req.on('end', () => resolve(chunks.length > 0 ? Buffer.concat(chunks).toString('utf8') : null));
    req.on('error', () => resolve(null));
  });
}

/** Sirve archivos estáticos del frontend; inyecta un config.js local. */
async function serveStatic(pathname: string, res: http.ServerResponse): Promise<void> {
  // config.js sintético: API en el mismo origen, sin API key (auth local deshabilitada).
  if (pathname === '/config.js') {
    res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8' });
    res.end(LOCAL_CONFIG_JS);
    return;
  }

  const relative = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const filePath = path.join(FRONTEND_DIR, relative);

  // Evitar path traversal fuera de FRONTEND_DIR
  if (!filePath.startsWith(FRONTEND_DIR)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  try {
    const content = await readFile(filePath);
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] ?? 'application/octet-stream' });
    res.end(content);
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
  }
}

main().catch((error: unknown) => {
  console.error(`Error al iniciar el servidor local: ${(error as Error).message}`);
  process.exitCode = 1;
});
