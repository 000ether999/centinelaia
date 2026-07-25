/**
 * Orquestador principal del AI Engine (punto de entrada del módulo).
 * Coordina el flujo completo de análisis: validar → hash → caché →
 * prompt → Bedrock → parsear → priorizar → score → ensamblar → persistir.
 * Implementa timeout global de 25s con AbortController.
 */

import type {
  AiExecutionMode,
  AiTextClient,
  AnalysisRequest,
  AnalysisResult,
  AnalysisMetadata,
  Explanation,
  Recommendation,
} from './types.js';
import { normalizeAnalysisResultExecutionMode } from './types.js';
import { validateAnalysisRequest } from './validator.js';
import { calculateRiskScore } from './risk-score.js';
import { buildAnalysisPrompt } from './prompt-builder.js';
import { parseBedrockResponse } from './response-parser.js';
import { generateFallbackExplanations, generateFallbackRecommendations } from './fallback-generator.js';
import { prioritizeRecommendations } from './recommendation-prioritizer.js';
import { createAiClientSelection, resolveAiEngineMode } from './ai-client-factory.js';
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
  aiTextClient?: AiTextClient;
  /** Alias conservado para no romper consumidores existentes. */
  bedrockClient?: BedrockClient;
  executionMode?: AiExecutionMode;
  cacheClient?: CacheClient;
  persistenceClient?: PersistenceClient;
}

function getExecutionMode(deps?: OrchestratorDeps): AiExecutionMode {
  if (deps?.executionMode) return deps.executionMode;

  // Una inyección previa sin variable configurada conserva el comportamiento de tests existentes.
  if (process.env['AI_ENGINE_MODE'] === undefined && (deps?.aiTextClient || deps?.bedrockClient)) {
    return 'bedrock';
  }

  return resolveAiEngineMode();
}

/**
 * Función principal del módulo AI Engine.
 * Analiza un conjunto de findings y retorna un AnalysisResult completo.
 */
export async function analyzeFindings(
  request: unknown,
  deps?: OrchestratorDeps
): Promise<AnalysisResult | { error: string; details?: unknown }> {
  const startTime = Date.now();
  const abortController = new AbortController();
  const globalTimer = setTimeout(() => abortController.abort(), getOrchestratorTimeoutMs());

  try {
    const validation = validateAnalysisRequest(request);
    if (!validation.valid) {
      clearTimeout(globalTimer);
      return { error: validation.error!.message, details: validation.error };
    }

    const { findings, sessionId, sourceContext } = validation.sanitizedInput!;
    const executionMode = getExecutionMode(deps);

    // Un análisis vacío informa el modo configurado, pero no crea ningún cliente AI.
    if (findings.length === 0) {
      clearTimeout(globalTimer);
      return buildEmptyResult(startTime, executionMode);
    }

    const cache = deps?.cacheClient ?? createCacheClient();
    const persistence = deps?.persistenceClient ?? createPersistenceClient();
    const findingsHash = calculateFindingsHash(findings);

    const cacheResult = await cache.get(findingsHash);
    if (cacheResult.hit && cacheResult.result) {
      const cachedResult = normalizeAnalysisResultExecutionMode(cacheResult.result);
      if (cachedResult.metadata.executionMode === executionMode) {
        const result: AnalysisResult = {
          ...cachedResult,
          cached: true,
          metadata: { ...cachedResult.metadata, cached: true },
        };
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
      }

      console.info(
        `[Orchestrator] Caché ignorada: modo almacenado ${cachedResult.metadata.executionMode}, ` +
        `modo solicitado ${executionMode}.`
      );
    }

    const injectedClient = deps?.aiTextClient ?? deps?.bedrockClient;
    const aiSelection = createAiClientSelection(executionMode, injectedClient);
    let explanations: Explanation[];
    let recommendations: Recommendation[];
    let status: 'complete' | 'degraded' | 'partial' = 'complete';
    let modelId = aiSelection.modelId;
    let actualExecutionMode: AiExecutionMode = aiSelection.executionMode;

    if (aiSelection.client === null) {
      console.info('[Orchestrator] AI Engine en modo fallback; no se crea ni invoca un cliente AI.');
      explanations = generateFallbackExplanations(findings);
      recommendations = generateFallbackRecommendations(findings);
      status = 'degraded';
    } else {
      if (aiSelection.executionMode === 'mock') {
        console.info(`[Orchestrator] AI Engine en modo mock (${aiSelection.modelId}).`);
      }

      try {
        const prompt = buildAnalysisPrompt(findings, sourceContext);
        const rawResponse = await aiSelection.client.invoke(prompt, abortController.signal);
        const parsed = parseBedrockResponse(rawResponse, findings);
        explanations = parsed.explanations;
        recommendations = parsed.recommendations;
        if (parsed.partial) status = 'partial';
      } catch (error: unknown) {
        console.warn(
          `[Orchestrator] Cliente AI (${aiSelection.executionMode}) falló, activando modo degradado:`,
          (error as Error).message || 'unknown'
        );
        explanations = generateFallbackExplanations(findings);
        recommendations = generateFallbackRecommendations(findings);
        status = 'degraded';
        modelId = 'none';
        actualExecutionMode = 'fallback';
      }
    }

    const prioritizedRecommendations = prioritizeRecommendations(recommendations, findings);
    const { riskScore, riskLevel, grade, hygieneScore, exposureScore } = calculateRiskScore(findings);
    const metadata: AnalysisMetadata = {
      timestamp: new Date().toISOString(),
      modelId,
      latencyMs: Date.now() - startTime,
      cached: false,
      status,
      executionMode: actualExecutionMode,
    };

    const result: AnalysisResult = {
      analysisId: '',
      riskScore,
      riskLevel,
      grade,
      explanations,
      recommendations: prioritizedRecommendations,
      metadata,
      cached: false,
      degraded: status === 'degraded',
      partial: status === 'partial',
      truncated: validation.truncated,
      truncatedCount: validation.truncatedCount,
      // Incluir los findings sanitizados para que findingIndex los indexe correctamente
      findings,
      hygieneScore,
      exposureScore,
    };

    // cache.put se llama DESPUÉS de asignar result.findings,
    // así un cache-hit posterior ya incluye el arreglo completo
    await cache.put(findingsHash, result);
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

/** Construye un resultado vacío sin crear ni invocar clientes AI. */
function buildEmptyResult(startTime: number, executionMode: AiExecutionMode): AnalysisResult {
  return {
    analysisId: '',
    riskScore: 0,
    riskLevel: 'minimal',
    grade: 'A',
    explanations: [],
    recommendations: [],
    // findings vacío: coherente con la alineación de índices (no hay nada que indexar)
    findings: [],
    metadata: {
      timestamp: new Date().toISOString(),
      modelId: 'none',
      latencyMs: Date.now() - startTime,
      cached: false,
      status: 'complete',
      executionMode,
    },
    cached: false,
    degraded: false,
    partial: false,
  };
}

export type { AnalysisRequest, AnalysisResult } from './types.js';
export { calculateFindingsHash } from './cache-client.js';
