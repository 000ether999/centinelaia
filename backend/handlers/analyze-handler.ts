/**
 * Handler Lambda para el endpoint /analyze del AI Engine.
 * Parsea el evento de API Gateway, rutea según método y path,
 * delega al orchestrator o al persistence client según la ruta.
 * Handler liviano: solo parsea y delega, sin lógica de negocio.
 */

import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { analyzeFindings } from '../services/ai-engine/index.js';
import { createPersistenceClient } from '../services/ai-engine/persistence-client.js';

// ─── Inicialización fuera del handler (reutilizada entre invocaciones) ───────

const persistence = createPersistenceClient();

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
  const httpContext = (event.requestContext as unknown as Record<string, unknown>)['http'] as
    | { method?: string }
    | undefined;
  if (httpContext?.method) return httpContext.method.toUpperCase();
  return event.httpMethod.toUpperCase();
}

function getPath(event: APIGatewayProxyEvent): string {
  const httpContext = (event.requestContext as unknown as Record<string, unknown>)['http'] as
    | { path?: string }
    | undefined;
  if (httpContext?.path) return httpContext.path;
  return event.path;
}

// ─── Handler principal ───────────────────────────────────────────────────────

export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  try {
    const method = getMethod(event);
    const path = getPath(event);

    // POST /analyze — ejecutar análisis
    if (method === 'POST' && /^\/analyze\/?$/.test(path)) {
      return await handlePostAnalyze(event);
    }

    // GET /analyze/{analysisId} — obtener un resultado por ID
    const analysisIdMatch = path.match(/^\/analyze\/([^/]+)\/?$/);
    if (method === 'GET' && analysisIdMatch) {
      const analysisId = event.pathParameters?.['analysisId'] ?? analysisIdMatch[1]!;
      return await handleGetAnalysis(analysisId);
    }

    // GET /analyze?sessionId=X — listar por sesión
    if (method === 'GET' && /^\/analyze\/?$/.test(path)) {
      return await handleListAnalyses(event);
    }

    return jsonResponse(404, { error: 'Not found' });
  } catch (error: unknown) {
    console.error('Unhandled error in analyze-handler:', error);
    return jsonResponse(500, { error: 'Internal server error' });
  }
}

// ─── Handlers de ruta ────────────────────────────────────────────────────────

async function handlePostAnalyze(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  // Parsear body JSON
  let body: unknown;
  try {
    body = JSON.parse(event.body ?? '');
  } catch {
    return jsonResponse(400, { error: 'Request body must be valid JSON' });
  }

  // Invocar orchestrator
  const result = await analyzeFindings(body);

  // Verificar si el resultado es un error de validación
  if ('error' in result && !('analysisId' in result)) {
    return jsonResponse(400, result);
  }

  return jsonResponse(200, result);
}

async function handleGetAnalysis(analysisId: string): Promise<APIGatewayProxyResult> {
  const result = await persistence.getById(analysisId);

  if (!result) {
    return jsonResponse(404, { error: 'Analysis not found' });
  }

  return jsonResponse(200, result);
}

async function handleListAnalyses(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const sessionId = event.queryStringParameters?.['sessionId'];

  if (!sessionId) {
    return jsonResponse(400, { error: "Query parameter 'sessionId' is required" });
  }

  const results = await persistence.listBySession(sessionId);
  return jsonResponse(200, results);
}
