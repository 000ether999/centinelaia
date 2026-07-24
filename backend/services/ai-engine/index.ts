/**
 * Orquestador principal del AI Engine (punto de entrada del módulo).
 * Coordina el flujo completo de análisis: validar → hash → caché →
 * prompt → Bedrock → parsear → priorizar → score → ensamblar → persistir.
 * Implementa timeout global de 25s con AbortController.
 */

import type { AnalysisRequest, AnalysisResult, AnalysisMetadata, Explanation, Recommendation } from './types.js';
import type { Finding } from '../scanner/modules/types.js';
import { validateAnalysisRequest } from './validator.js';
import { calculateRiskScore } from './risk-score.js';
import { buildAnalysisPrompt } from './prompt-builder.js';
import { parseBedrockResponse } from './response-parser.js';
import { generateFallbackExplanations, generateFallbackRecommendations } from './fallback-generator.js';
import { prioritizeRecommendations } from './recommendation-prioritizer.js';
import { createBedrockClient } from './bedrock-client.js';
import type { BedrockClient } from './bedrock-client.js';
import { createCacheClient, calculateFindingsHash } from './cache-client.js';
import type { CacheClient } from './cache-client.js';
import { createPersistenceClient } from './persistence-client.js';
import type { PersistenceClient } from './persistence-client.js';

/** Timeout global del orchestrator (configurable via env, leído en cada invocación) */
function getOrchestratorTimeoutMs(): number {
  return parseInt(process.env['ORCHESTRATOR_TIMEOUT_MS'] || '25000', 10);
}

/** Dependencias inyectables para testing */
export interface OrchestratorDeps {
  bedrockClient?: BedrockClient;
  cacheClient?: CacheClient;
  persistenceClient?: PersistenceClient;
}

/**
 * Función principal del módulo AI Engine.
 * Analiza un conjunto de findings y retorna un AnalysisResult completo.
 * Acepta dependencias opcionales para testing (dependency injection).
 */
export async function analyzeFindings(
  request: unknown,
  deps?: OrchestratorDeps
): Promise<AnalysisResult | { error: string; details?: unknown }> {
  const startTime = Date.now();

  // Iniciar timer global con AbortController
  const abortController = new AbortController();
  const globalTimer = setTimeout(() => {
    abortController.abort();
  }, getOrchestratorTimeoutMs());

  try {
    // Paso 1: Validar entrada
    const validation = validateAnalysisRequest(request);
    if (!validation.valid) {
      clearTimeout(globalTimer);
      return { error: validation.error!.message, details: validation.error };
    }

    const { sanitizedInput } = validation;
    const { findings, sessionId, sourceContext } = sanitizedInput!;

    // Caso especial: findings vacío — retornar score 0 sin invocar Bedrock
    if (findings.length === 0) {
      clearTimeout(globalTimer);
      return buildEmptyResult(sessionId, startTime);
    }

    // Inicializar clientes (inyectados o reales)
    const bedrock = deps?.bedrockClient ?? createBedrockClient();
    const cache = deps?.cacheClient ?? createCacheClient();
    const persistence = deps?.persistenceClient ?? createPersistenceClient();

    // Paso 2: Calcular hash de findings
    const findingsHash = calculateFindingsHash(findings);

    // Paso 3: Buscar en caché
    const cacheResult = await cache.get(findingsHash);
    if (cacheResult.hit && cacheResult.result) {
      clearTimeout(globalTimer);
      const cached = { ...cacheResult.result, cached: true };
      cached.metadata = { ...cached.metadata, cached: true };
      return cached;
    }

    // Paso 4: Construir prompt e invocar Bedrock
    let explanations: Explanation[];
    let recommendations: Recommendation[];
    let status: 'complete' | 'degraded' | 'partial' = 'complete';
    let modelId = bedrock.config.modelId;

    try {
      const prompt = buildAnalysisPrompt(findings, sourceContext);
      const rawResponse = await bedrock.invoke(prompt, abortController.signal);

      // Paso 5: Parsear respuesta
      const parsed = parseBedrockResponse(rawResponse, findings);
      explanations = parsed.explanations;
      recommendations = parsed.recommendations;

      if (parsed.partial) {
        status = 'partial';
      }
    } catch (error: unknown) {
      // Si timeout global o Bedrock falla — modo degradado
      console.warn(
        '[Orchestrator] Bedrock falló, activando modo degradado:',
        (error as Error).message || 'unknown'
      );
      explanations = generateFallbackExplanations(findings);
      recommendations = generateFallbackRecommendations(findings);
      status = 'degraded';
      modelId = 'none';
    }

    // Paso 6: Priorizar recomendaciones (siempre, independiente del origen)
    const prioritizedRecommendations = prioritizeRecommendations(recommendations, findings);

    // Paso 7: Calcular Risk Score (siempre determinista)
    const { riskScore, riskLevel } = calculateRiskScore(findings);

    // Paso 8: Ensamblar resultado
    const latencyMs = Date.now() - startTime;
    const metadata: AnalysisMetadata = {
      timestamp: new Date().toISOString(),
      modelId,
      latencyMs,
      cached: false,
      status,
    };

    const result: AnalysisResult = {
      analysisId: '', // se asigna al persistir
      riskScore,
      riskLevel,
      explanations,
      recommendations: prioritizedRecommendations,
      metadata,
      cached: false,
      degraded: status === 'degraded',
      partial: status === 'partial',
      truncated: validation.truncated,
      truncatedCount: validation.truncatedCount,
    };

    // Paso 9: Escribir en caché (await con timeout 2s, fail-open)
    await cache.put(findingsHash, result);

    // Paso 10: Persistir en DynamoDB (await, fail-open)
    const { analysisId, persisted, storageTruncated } = await persistence.save(
      result,
      sessionId,
      findingsHash
    );

    result.analysisId = analysisId;
    result.persisted = persisted;
    result.storageTruncated = storageTruncated;

    clearTimeout(globalTimer);
    return result;
  } catch (error: unknown) {
    clearTimeout(globalTimer);
    console.error('[Orchestrator] Error no capturado:', error);
    return { error: 'Error interno del servidor' };
  }
}

/**
 * Construye un resultado vacío para el caso de findings vacío.
 */
function buildEmptyResult(sessionId: string, startTime: number): AnalysisResult {
  return {
    analysisId: '',
    riskScore: 0,
    riskLevel: 'minimal',
    explanations: [],
    recommendations: [],
    metadata: {
      timestamp: new Date().toISOString(),
      modelId: 'none',
      latencyMs: Date.now() - startTime,
      cached: false,
      status: 'complete',
    },
    cached: false,
    degraded: false,
    partial: false,
  };
}

// Re-exportar tipos y funciones útiles para consumidores del módulo
export type { AnalysisRequest, AnalysisResult } from './types.js';
export { calculateFindingsHash } from './cache-client.js';
