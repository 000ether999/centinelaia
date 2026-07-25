/**
 * Handler Lambda para el endpoint /analyze del AI Engine.
 * Parsea el evento de API Gateway, rutea según método y path,
 * delega al orchestrator o al persistence client según la ruta.
 * Handler liviano: solo parsea y delega, sin lógica de negocio.
 */

import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { isAuthorized, unauthorizedResponse } from './auth.js';
import { jsonResponse, getMethod, getPath } from './http.js';
import { analyzeFindings } from '../services/ai-engine/index.js';
import { createPersistenceClient } from '../services/ai-engine/persistence-client.js';
import { mergeFindings } from '../services/log-translator/merge-findings.js';
import { correlateFindings } from '../services/log-translator/correlate-findings.js';
import { enrichWithCves } from '../services/cve-enricher/index.js';

// ─── Inicialización fuera del handler (reutilizada entre invocaciones) ───────

const persistence = createPersistenceClient();

// ─── Handler principal ───────────────────────────────────────────────────────

type AnalyzeExecutor = typeof analyzeFindings;
type AnalysisPersistence = Pick<
  ReturnType<typeof createPersistenceClient>,
  'getById' | 'listBySession'
>;

export interface AnalyzeHandlerDependencies {
  executeAnalysis?: AnalyzeExecutor;
  persistence?: AnalysisPersistence;
}

/** Punto de entrada Lambda con las dependencias de producción. */
export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  return handleAnalyzeRequest(event);
}

/** Permite ejecutar el mismo handler con dependencias locales en checkpoints y pruebas. */
export async function handleAnalyzeRequest(
  event: APIGatewayProxyEvent,
  dependencies: AnalyzeHandlerDependencies = {}
): Promise<APIGatewayProxyResult> {
  try {
    if (!isAuthorized(event)) return unauthorizedResponse();

    const method = getMethod(event);
    const path = getPath(event);
    const executeAnalysis = dependencies.executeAnalysis ?? analyzeFindings;
    const persistenceClient = dependencies.persistence ?? persistence;

    // POST /analyze — ejecutar análisis
    if (method === 'POST' && /^\/analyze\/?$/.test(path)) {
      return await handlePostAnalyze(event, executeAnalysis);
    }

    // GET /analyze/{analysisId} — obtener un resultado por ID
    const analysisIdMatch = path.match(/^\/analyze\/([^/]+)\/?$/);
    if (method === 'GET' && analysisIdMatch) {
      const analysisId = event.pathParameters?.['analysisId'] ?? analysisIdMatch[1]!;
      return await handleGetAnalysis(analysisId, persistenceClient);
    }

    // GET /analyze?sessionId=X — listar por sesión
    if (method === 'GET' && /^\/analyze\/?$/.test(path)) {
      return await handleListAnalyses(event, persistenceClient);
    }

    return jsonResponse(404, { error: 'Not found' });
  } catch (error: unknown) {
    console.error('Unhandled error in analyze-handler:', error);
    return jsonResponse(500, { error: 'Internal server error' });
  }
}

// ─── Handlers de ruta ────────────────────────────────────────────────────────

async function handlePostAnalyze(
  event: APIGatewayProxyEvent,
  executeAnalysis: AnalyzeExecutor
): Promise<APIGatewayProxyResult> {
  // Parsear body JSON
  let body: unknown;
  try {
    body = JSON.parse(event.body ?? '');
  } catch {
    return jsonResponse(400, { error: 'Request body must be valid JSON' });
  }

  // Si viene nmapOutput, nmapXml o authLog, fusionar findings antes de invocar el análisis
  if (body && typeof body === 'object') {
    const raw = body as Record<string, unknown>;
    const hasNmap = typeof raw['nmapOutput'] === 'string' && (raw['nmapOutput'] as string).trim();
    const hasNmapXml = typeof raw['nmapXml'] === 'string' && (raw['nmapXml'] as string).trim();
    const hasAuth = typeof raw['authLog'] === 'string' && (raw['authLog'] as string).trim();

    if (hasNmap || hasNmapXml || hasAuth) {
      const { mergedFindings, mergedSourceContext } = mergeFindings({
        findings: Array.isArray(raw['findings']) ? (raw['findings'] as any[]) : [],
        nmapOutput: typeof raw['nmapOutput'] === 'string' ? raw['nmapOutput'] as string : undefined,
        nmapXml: typeof raw['nmapXml'] === 'string' ? raw['nmapXml'] as string : undefined,
        authLog: typeof raw['authLog'] === 'string' ? raw['authLog'] as string : undefined,
        sourceContext: typeof raw['sourceContext'] === 'string' ? raw['sourceContext'] : undefined,
      });

      // Enriquecer con CVEs conocidos (fail-open: si falla, continuar sin CVEs).
      // Cierra el gap: hoy solo scan-handler invoca enrichWithCves, por lo que
      // versiones de software detectadas en un log de Nmap subido a /analyze
      // nunca se cruzaban con el NVD.
      let enrichedFindings = mergedFindings;
      try {
        enrichedFindings = await enrichWithCves(mergedFindings);
      } catch (error: unknown) {
        console.warn(
          '[analyze-handler] CVE enrichment failed, proceeding without CVEs:',
          error instanceof Error ? error.message : error,
        );
      }

      // Correlación determinista (sin IA) por puerto/servicio y versión+CVE
      // entre los findings de las distintas fuentes fusionadas. Defensivo:
      // si no hay coincidencias, no agrega nada y nunca rompe el flujo.
      const correlationFindings = correlateFindings(enrichedFindings);

      // Reemplazar findings y sourceContext con la versión fusionada + enriquecida
      raw['findings'] = [...enrichedFindings, ...correlationFindings];
      if (mergedSourceContext !== undefined) {
        raw['sourceContext'] = mergedSourceContext;
      }
      // Eliminar campos de log para que el validator no los vea como campos extra
      delete raw['nmapOutput'];
      delete raw['nmapXml'];
      delete raw['authLog'];
    }
  }

  // Invocar orchestrator
  const result = await executeAnalysis(body);

  // Verificar si el resultado es un error de validación
  if ('error' in result && !('analysisId' in result)) {
    return jsonResponse(400, result);
  }

  return jsonResponse(200, result);
}

async function handleGetAnalysis(
  analysisId: string,
  persistenceClient: AnalysisPersistence
): Promise<APIGatewayProxyResult> {
  const result = await persistenceClient.getById(analysisId);

  if (!result) {
    return jsonResponse(404, { error: 'Analysis not found' });
  }

  return jsonResponse(200, result);
}

async function handleListAnalyses(
  event: APIGatewayProxyEvent,
  persistenceClient: AnalysisPersistence
): Promise<APIGatewayProxyResult> {
  const sessionId = event.queryStringParameters?.['sessionId'];

  if (!sessionId) {
    return jsonResponse(400, { error: "Query parameter 'sessionId' is required" });
  }

  const results = await persistenceClient.listBySession(sessionId);
  return jsonResponse(200, results);
}
