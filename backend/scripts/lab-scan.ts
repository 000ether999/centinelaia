#!/usr/bin/env node

/**
 * CLI de laboratorio para CentinelaIA.
 *
 * Permite escanear activos propios o de laboratorio (localhost, IPs privadas)
 * activando el modo laboratorio en el proceso local. Diseñado para pentesters
 * y estudiantes que necesitan auditar infraestructura propia.
 *
 * Uso:
 *   npm run lab -- --target http://127.0.0.1:8081 --authorize
 *   npm run lab -- --target localhost:3000 --authorize --out resultado.json
 */

// ─── Activar modo laboratorio ANTES de importar los módulos del scanner ──────
process.env['CENTINELAIA_ALLOW_PRIVATE_TARGETS'] = 'true';
process.env['AI_ENGINE_MODE'] ??= 'fallback';
process.env['AWS_REGION'] ??= 'us-east-1';
process.env['AWS_ACCESS_KEY_ID'] ??= 'local';
process.env['AWS_SECRET_ACCESS_KEY'] ??= 'local';
process.env['AWS_EC2_METADATA_DISABLED'] = 'true';
process.env['AWS_ENDPOINT_URL_DYNAMODB'] ??= 'http://127.0.0.1:9';

import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import type { ScanResult } from '../models/scan.js';
import type { AnalysisResult } from '../services/ai-engine/types.js';
import { writeFileSync } from 'node:fs';

// ─── Tipos y parsing de argumentos ──────────────────────────────────────────

interface LabOptions {
  target: string;
  sessionId: string;
  authorize: boolean;
  baseUrl?: string;
  out?: string;
}

const HELP_TEXT = `
CentinelaIA — CLI de laboratorio

Uso:
  npm run lab -- --target <url|host[:port]> --authorize [opciones]

Opciones obligatorias:
  --target <url|host[:port]>   Target a escanear (URL, dominio, IP, host:port)
  --authorize                   Confirma que tienes autorización para escanear el target

Opciones opcionales:
  --session-id <id>            Identificador de sesión (default: lab-<timestamp>)
  --base-url <url>             Enviar findings a un despliegue remoto en vez de analizar localmente
  --out <ruta>                 Guardar resultado JSON completo en un archivo
  --help                       Muestra este mensaje

Ejemplos:
  npm run lab -- --target http://127.0.0.1:8081 --authorize
  npm run lab -- --target localhost:3000 --authorize --out scan.json
  npm run lab -- --target 192.168.1.50 --authorize --session-id mi-lab

IMPORTANTE: Este CLI solo debe usarse contra activos PROPIOS o de laboratorio.
El flag --authorize es el equivalente a la casilla de autorización del frontend.
`.trim();

function parseArgs(args: string[]): LabOptions {
  const options: LabOptions = {
    target: '',
    sessionId: `lab-${Date.now()}`,
    authorize: false,
  };

  for (let i = 0; i < args.length; i++) {
    const flag = args[i];

    if (flag === '--help') {
      console.log(HELP_TEXT);
      process.exit(0);
    }

    if (flag === '--authorize') {
      options.authorize = true;
      continue;
    }

    if (flag === '--target') {
      const value = args[++i];
      if (!value || value.startsWith('--')) {
        console.error('Error: --target requiere un valor.');
        process.exit(1);
      }
      options.target = value;
      continue;
    }

    if (flag === '--session-id') {
      const value = args[++i];
      if (!value || value.startsWith('--')) {
        console.error('Error: --session-id requiere un valor.');
        process.exit(1);
      }
      options.sessionId = value;
      continue;
    }

    if (flag === '--base-url') {
      const value = args[++i];
      if (!value || value.startsWith('--')) {
        console.error('Error: --base-url requiere un valor.');
        process.exit(1);
      }
      options.baseUrl = value.replace(/\/+$/, '');
      continue;
    }

    if (flag === '--out') {
      const value = args[++i];
      if (!value || value.startsWith('--')) {
        console.error('Error: --out requiere un valor.');
        process.exit(1);
      }
      options.out = value;
      continue;
    }

    console.error(`Error: argumento desconocido "${flag}". Usa --help para ver opciones.`);
    process.exit(1);
  }

  return options;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

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

type Handler = (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult>;
type PostJson = (path: '/scan' | '/analyze', body: unknown) => Promise<unknown>;

function parseResponseBody(path: string, response: { statusCode: number; body: string }): unknown {
  let payload: unknown;
  try {
    payload = JSON.parse(response.body);
  } catch {
    throw new Error(`POST ${path} devolvió una respuesta no JSON.`);
  }
  if (response.statusCode < 200 || response.statusCode >= 300) {
    const detail = typeof payload === 'object' && payload !== null && 'error' in payload
      ? (payload as { error: string }).error
      : JSON.stringify(payload);
    throw new Error(`POST ${path} falló con HTTP ${response.statusCode}: ${detail}`);
  }
  return payload;
}

async function createLocalPost(): Promise<PostJson> {
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
      throw new Error(`No se pudo conectar a ${baseUrl}${path}: ${(error as Error).message}`);
    }
    return parseResponseBody(path, { statusCode: response.status, body: await response.text() });
  };
}

// ─── Ejecución principal ─────────────────────────────────────────────────────

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));

  // Validar consentimiento explícito
  if (!options.authorize) {
    console.error(
      '\n❌ El flag --authorize es obligatorio.\n\n' +
      'Este CLI de laboratorio solo debe usarse contra activos PROPIOS\n' +
      'o entornos de práctica autorizados. El flag --authorize confirma\n' +
      'que tienes permiso para escanear el target indicado.\n\n' +
      'Uso: npm run lab -- --target <target> --authorize\n',
    );
    process.exit(1);
  }

  if (!options.target) {
    console.error('Error: --target es obligatorio. Usa --help para más información.');
    process.exit(1);
  }

  console.log(`\n🔬 CentinelaIA — Modo Laboratorio`);
  console.log(`   Target: ${options.target}`);
  console.log(`   Session: ${options.sessionId}\n`);

  const post = options.baseUrl ? createRemotePost(options.baseUrl) : await createLocalPost();

  // Ejecutar escaneo
  let scanResult: ScanResult;
  try {
    const raw = await post('/scan', {
      target: options.target,
      authorizationConfirmed: true,
      sessionId: options.sessionId,
    });
    scanResult = raw as ScanResult;
  } catch (error: unknown) {
    console.error(`\n❌ Error en el escaneo: ${(error as Error).message}`);
    process.exit(1);
  }

  // Si unreachable, reportar y salir con código de error
  if (scanResult.status === 'unreachable') {
    console.error(`\n⚠️  Estado: UNREACHABLE — el target no respondió a ningún módulo.`);
    console.error(`   Verifica que el servicio está activo en ${options.target}\n`);
    process.exit(2);
  }

  // Enviar a /analyze
  let analysisResult: AnalysisResult;
  try {
    const raw = await post('/analyze', {
      findings: scanResult.findings,
      sessionId: options.sessionId,
      sourceContext: `Lab scan de ${options.target}`.slice(0, 200),
    });
    analysisResult = raw as AnalysisResult;
  } catch (error: unknown) {
    console.error(`\n⚠️  Escaneo completado pero el análisis falló: ${(error as Error).message}`);
    console.error('   Mostrando solo el resumen del escaneo.\n');
    printScanSummary(options.target, scanResult, null);
    if (options.out) {
      writeFileSync(options.out, JSON.stringify(scanResult, null, 2), 'utf-8');
      console.log(`\n💾 Resultado guardado en: ${options.out}`);
    }
    process.exit(0);
  }

  // Imprimir resumen
  printScanSummary(options.target, scanResult, analysisResult);

  // Guardar JSON si se pidió
  if (options.out) {
    const output = { scan: scanResult, analysis: analysisResult };
    writeFileSync(options.out, JSON.stringify(output, null, 2), 'utf-8');
    console.log(`\n💾 Resultado completo guardado en: ${options.out}`);
  }
}

function printScanSummary(
  target: string,
  scan: ScanResult,
  analysis: AnalysisResult | null,
): void {
  // Conteo por severidad
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of scan.findings) {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  }

  console.log(`\n═══════════════════════════════════════════════════════`);
  console.log(`  RESULTADO — ${target}`);
  console.log(`═══════════════════════════════════════════════════════`);
  console.log(`  Estado: ${scan.status} | Duración: ${scan.durationMs}ms`);
  console.log(`  Findings: ${scan.totalFindings} total`);
  console.log(`    Critical: ${counts['critical']}  High: ${counts['high']}  Medium: ${counts['medium']}  Low: ${counts['low']}  Info: ${counts['info']}`);

  if (analysis) {
    console.log(`\n  Score: ${analysis.riskScore}/100 | Grado: ${analysis.riskLevel}`);
    if (analysis.hygieneScore !== undefined) console.log(`  Hygiene Score: ${analysis.hygieneScore}`);
    if (analysis.exposureScore !== undefined) console.log(`  Exposure Score: ${analysis.exposureScore}`);
    if (analysis.analysisId) {
      console.log(`  Analysis ID: ${analysis.analysisId}`);
    }
  }

  console.log(`  Authorization: confirmed (--authorize)`);
  console.log(`═══════════════════════════════════════════════════════\n`);
}

main().catch((error: unknown) => {
  console.error(`\nError fatal: ${(error as Error).message}`);
  process.exit(1);
});
