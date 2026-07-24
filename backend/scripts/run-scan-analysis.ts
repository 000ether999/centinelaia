#!/usr/bin/env node

/**
 * Script mínimo de integración para encadenar POST /scan y POST /analyze.
 * Por defecto invoca handlers locales; --base-url usa los endpoints HTTP reales.
 */

import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import type { ScanResult } from '../models/scan.js';
import type { AnalysisResult } from '../services/ai-engine/types.js';

type Options = { target: string; sessionId: string; baseUrl?: string };
type Handler = (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult>;
type PostJson = (path: '/scan' | '/analyze', body: unknown) => Promise<unknown>;

function parseOptions(args: string[]): Options {
  const options: Options = { target: 'https://example.com', sessionId: 'phase3-demo' };
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index];
    if (flag === '--help') {
      console.error('Uso: npm run demo:phase3 -- [--target URL] [--session-id ID] [--base-url URL]');
      process.exit(0);
    }
    if (!['--target', '--session-id', '--base-url'].includes(flag ?? '')) {
      throw new Error(`Argumento desconocido: ${flag ?? ''}. Usa --help para ver las opciones.`);
    }
    const value = args[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`Falta un valor para ${flag}.`);
    if (flag === '--target') options.target = value;
    if (flag === '--session-id') options.sessionId = value;
    if (flag === '--base-url') options.baseUrl = normalizeBaseUrl(value);
    index += 1;
  }
  return options;
}

function normalizeBaseUrl(value: string): string {
  const url = new URL(value);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('--base-url debe usar http:// o https://.');
  }
  return value.replace(/\/+$/, '');
}

function createEvent(path: string, body: unknown): APIGatewayProxyEvent {
  return {
    body: JSON.stringify(body),
    headers: { 'content-type': 'application/json' },
    httpMethod: 'POST',
    isBase64Encoded: false,
    multiValueHeaders: {},
    multiValueQueryStringParameters: null,
    path,
    pathParameters: null,
    queryStringParameters: null,
    requestContext: { http: { method: 'POST', path } },
    resource: path,
    stageVariables: null,
  } as unknown as APIGatewayProxyEvent;
}

function parseResponseBody(path: string, response: APIGatewayProxyResult): unknown {
  let payload: unknown;
  try {
    payload = JSON.parse(response.body);
  } catch {
    throw new Error(`POST ${path} devolvió una respuesta que no es JSON.`);
  }
  if (response.statusCode < 200 || response.statusCode >= 300) {
    const detail = getErrorDetail(payload);
    throw new Error(`POST ${path} falló con HTTP ${response.statusCode}: ${detail}`);
  }
  return payload;
}

function getErrorDetail(payload: unknown): string {
  if (isRecord(payload) && typeof payload.error === 'string') return payload.error;
  return JSON.stringify(payload);
}

async function createLocalPost(): Promise<PostJson> {
  process.env['AI_ENGINE_MODE'] = 'fallback';
  process.env['AWS_REGION'] ??= 'us-east-1';
  process.env['AWS_ACCESS_KEY_ID'] ??= 'local';
  process.env['AWS_SECRET_ACCESS_KEY'] ??= 'local';
  process.env['AWS_EC2_METADATA_DISABLED'] = 'true';
  process.env['AWS_ENDPOINT_URL_DYNAMODB'] ??= 'http://127.0.0.1:9';

  // Los imports tardíos garantizan que fallback se configure antes de crear los handlers.
  const [{ handler: scanHandler }, { handler: analyzeHandler }] = await Promise.all([
    import('../handlers/scan-handler.js'),
    import('../handlers/analyze-handler.js'),
  ]);
  const handlers: Record<'/scan' | '/analyze', Handler> = {
    '/scan': scanHandler,
    '/analyze': analyzeHandler,
  };
  return async (path, body) => parseResponseBody(path, await handlers[path](createEvent(path, body)));
}

function createRemotePost(baseUrl: string): PostJson {
  return async (path, body) => {
    let response: Response;
    try {
      response = await fetch(`${baseUrl}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
    } catch (error: unknown) {
      throw new Error(`No se pudo conectar con POST ${path} en ${baseUrl}: ${(error as Error).message}`);
    }
    return parseResponseBody(path, {
      statusCode: response.status,
      body: await response.text(),
    });
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function requireScanResult(value: unknown): ScanResult {
  if (!isRecord(value) || !Array.isArray(value.findings)) {
    throw new Error('POST /scan no devolvió un ScanResult válido con findings.');
  }
  return value as unknown as ScanResult;
}

function requireAnalysisResult(value: unknown): AnalysisResult {
  if (
    !isRecord(value) ||
    typeof value.riskScore !== 'number' ||
    typeof value.riskLevel !== 'string' ||
    !Array.isArray(value.explanations) ||
    !Array.isArray(value.recommendations) ||
    !isRecord(value.metadata) ||
    typeof value.metadata.executionMode !== 'string'
  ) {
    throw new Error('POST /analyze no devolvió un AnalysisResult completo con metadata.executionMode.');
  }
  return value as unknown as AnalysisResult;
}

async function main(): Promise<void> {
  const options = parseOptions(process.argv.slice(2));
  const post = options.baseUrl ? createRemotePost(options.baseUrl) : await createLocalPost();

  const scanResult = requireScanResult(await post('/scan', {
    target: options.target,
    authorizationConfirmed: true,
    sessionId: options.sessionId,
  }));
  const analysisResult = requireAnalysisResult(await post('/analyze', {
    findings: scanResult.findings,
    sessionId: options.sessionId,
    sourceContext: `Escaneo web de ${options.target}`,
  }));

  console.log(JSON.stringify(analysisResult, null, 2));
}

main().catch((error: unknown) => {
  console.error(`Error en el flujo scan→analyze: ${(error as Error).message}`);
  process.exitCode = 1;
});
