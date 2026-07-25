/**
 * Handler Lambda para el endpoint /scan.
 * Parsea el evento de API Gateway, rutea según método y path,
 * orquesta el escaneo y persiste resultados en DynamoDB.
 */

import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { isAuthorized, unauthorizedResponse } from './auth.js';
import { validateScanRequest } from '../services/scanner/validator.js';
import { executeScan } from '../services/scanner/orchestrator.js';
import type { OrchestratorConfig } from '../services/scanner/orchestrator.js';
import { createDynamoStore } from '../services/scanner/store.js';
import { createHeaderAnalyzer } from '../services/scanner/modules/header-analyzer.js';
import { createTlsChecker } from '../services/scanner/modules/tls-checker.js';
import { createCookieInspector } from '../services/scanner/modules/cookie-inspector.js';
import { createDnsChecker } from '../services/scanner/modules/dns-checker.js';
import { createFingerprinter } from '../services/scanner/modules/fingerprinter.js';
import { createCorsChecker } from '../services/scanner/modules/cors-checker.js';
import { createHttpMethodsChecker } from '../services/scanner/modules/http-methods-checker.js';
import { createSecurityTxtChecker } from '../services/scanner/modules/security-txt-checker.js';
import { createRedirectChecker } from '../services/scanner/modules/redirect-checker.js';
import { createSecurityExposureChecker } from '../services/scanner/modules/security-exposure-checker.js';
import type { ScanResult, ConsentEvidence } from '../models/scan.js';
import type { ScanModuleInput } from '../services/scanner/modules/types.js';
import { enrichWithCves } from '../services/cve-enricher/index.js';

// ─── Inicialización fuera del handler (reutilizada entre invocaciones) ───────

const TABLE_NAME = process.env['SCANS_TABLE'] || 'centinelaia-scans';
const store = createDynamoStore(TABLE_NAME);

/** Headers CORS comunes para todas las respuestas */
const CORS_HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
} as const;

// ─── Helpers de respuesta ────────────────────────────────────────────────────

function jsonResponse(statusCode: number, body: unknown): APIGatewayProxyResult {
  return {
    statusCode,
    headers: CORS_HEADERS,
    body: JSON.stringify(body),
  };
}

// ─── Detección de método y path (soporta API Gateway v1 y v2) ────────────────

function getMethod(event: APIGatewayProxyEvent): string {
  // v2 HTTP API
  const httpContext = (event.requestContext as unknown as Record<string, unknown>)['http'] as
    | { method?: string }
    | undefined;
  if (httpContext?.method) return httpContext.method.toUpperCase();
  // v1 REST API
  return event.httpMethod.toUpperCase();
}

function getPath(event: APIGatewayProxyEvent): string {
  // v2 HTTP API
  const httpContext = (event.requestContext as unknown as Record<string, unknown>)['http'] as
    | { path?: string }
    | undefined;
  if (httpContext?.path) return httpContext.path;
  // v1 REST API
  return event.path;
}

// ─── Handler principal ───────────────────────────────────────────────────────

export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  try {
    if (!isAuthorized(event)) return unauthorizedResponse();

    const method = getMethod(event);
    const path = getPath(event);

    // POST /scan — ejecutar escaneo
    if (method === 'POST' && /^\/scan\/?$/.test(path)) {
      return await handlePostScan(event);
    }

    // GET /scan/{scanId} — obtener un resultado por ID
    const scanIdMatch = path.match(/^\/scan\/([^/]+)\/?$/);
    if (method === 'GET' && scanIdMatch) {
      const scanId = event.pathParameters?.['scanId'] ?? scanIdMatch[1]!;
      return await handleGetScan(scanId);
    }

    // GET /scan?sessionId=X — listar por sesión
    if (method === 'GET' && /^\/scan\/?$/.test(path)) {
      return await handleListScans(event);
    }

    return jsonResponse(404, { error: 'Not found' });
  } catch (error: unknown) {
    console.error('Unhandled error in scan-handler:', error);
    return jsonResponse(500, { error: 'Internal server error' });
  }
}

// ─── Handlers de ruta ────────────────────────────────────────────────────────

async function handlePostScan(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  // Parsear body JSON
  let body: unknown;
  try {
    body = JSON.parse(event.body ?? '');
  } catch {
    return jsonResponse(400, { error: 'Request body must be valid JSON' });
  }

  // Validar request
  const validation = await validateScanRequest(body);
  if (!validation.valid) {
    const { code, message } = validation.error!;
    return jsonResponse(code, { error: message });
  }

  const { targetUrl, targetDomain, isIpAddress } = validation.normalized!;
  const { sessionId } = body as { sessionId: string };

  // Construir input para los módulos
  const moduleInput: ScanModuleInput = {
    targetUrl,
    targetDomain,
    isIpAddress,
    timeoutMs: 5000,
  };

  // Configurar orquestador con los 10 módulos registrados
  const config: OrchestratorConfig = {
    moduleTimeoutMs: 5000,
    globalTimeoutMs: 25000,
    modules: [
      createHeaderAnalyzer(),
      createTlsChecker(),
      createCookieInspector(),
      createDnsChecker(),
      createFingerprinter(),
      createCorsChecker(),
      createHttpMethodsChecker(),
      createSecurityTxtChecker(),
      createRedirectChecker(),
      createSecurityExposureChecker(),
    ],
  };

  // Ejecutar escaneo
  const orchestratorResult = await executeScan(moduleInput, config);

  // Enriquecer con CVEs (fail-open: si falla, continuar con findings originales)
  let enrichedFindings = orchestratorResult.findings;
  try {
    enrichedFindings = await enrichWithCves(orchestratorResult.findings);
  } catch (error: unknown) {
    console.warn(
      '[scan-handler] CVE enrichment failed, proceeding without CVEs:',
      error instanceof Error ? error.message : error,
    );
  }

  // Construir evidencia de consentimiento
  const consent: ConsentEvidence = {
    authorizationConfirmed: true,
    target: (body as { target: string }).target,
    confirmedAt: new Date().toISOString(),
  };

  // Construir resultado completo
  const fullResult: ScanResult = {
    ...orchestratorResult,
    findings: enrichedFindings,
    sessionId,
    consent,
    persisted: true,
  };

  // Persistir en DynamoDB
  const { persisted } = await store.put(fullResult);
  fullResult.persisted = persisted;

  return jsonResponse(200, fullResult);
}

async function handleGetScan(scanId: string): Promise<APIGatewayProxyResult> {
  const result = await store.get(scanId);

  if (!result) {
    return jsonResponse(404, { error: 'Scan not found' });
  }

  return jsonResponse(200, result);
}

async function handleListScans(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const sessionId = event.queryStringParameters?.['sessionId'];

  if (!sessionId) {
    return jsonResponse(400, { error: "Query parameter 'sessionId' is required" });
  }

  const results = await store.listBySession(sessionId);
  return jsonResponse(200, results);
}
