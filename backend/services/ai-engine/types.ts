/**
 * Tipos e interfaces del módulo AI Engine.
 * Define el contrato de entrada/salida del motor de análisis por IA,
 * incluyendo solicitudes, resultados, metadatos y estructuras auxiliares.
 */

import type { Finding, FindingCategory, FindingSeverity } from '../scanner/modules/types.js';

// Re-exportar tipos del scanner para consumo externo del módulo
export type { Finding, FindingCategory, FindingSeverity };

/** Contrato común para clientes de generación de texto del AI Engine */
export interface AiTextClient {
  invoke(prompt: string, signal?: AbortSignal): Promise<string>;
  config: { modelId: string };
}

// ─── Tipos de entrada ────────────────────────────────────────────────────────

/** Solicitud de análisis al AI Engine */
export interface AnalysisRequest {
  findings: Finding[];
  sessionId: string;
  sourceContext?: string; // máximo 200 caracteres
}

// ─── Tipos de salida ─────────────────────────────────────────────────────────

/** Resultado completo del análisis */
export interface AnalysisResult {
  analysisId: string;           // UUID v4
  riskScore: number;            // 0-100, entero
  riskLevel: RiskLevel;
  grade: RiskGrade;             // Grado compuesto A–F
  explanations: Explanation[];
  recommendations: Recommendation[];
  metadata: AnalysisMetadata;
  // Campos opcionales
  cached?: boolean;
  degraded?: boolean;
  partial?: boolean;
  truncated?: boolean;
  truncatedCount?: number;
  persisted?: boolean;
  storageTruncated?: boolean;
}

/** Niveles de riesgo derivados del score */
export type RiskLevel = 'critical' | 'high' | 'moderate' | 'low' | 'minimal';

/** Grado compuesto tipo SSL Labs (A = mínimo riesgo, F = crítico) */
export type RiskGrade = 'A' | 'B' | 'C' | 'D' | 'F';

/** Explicación en lenguaje natural de un hallazgo */
export interface Explanation {
  findingIndex: number;       // índice en el arreglo de entrada
  text: string;               // 50-500 caracteres, español
  fallback: boolean;          // true si generada sin IA
}

/** Recomendación de remediación priorizada */
export interface Recommendation {
  priority: number;           // 1 a N (1 = máxima prioridad)
  title: string;              // máximo 100 caracteres
  description: string;        // 50-300 caracteres
  effort: EffortLevel;
  relatedFindings: number[];  // índices de findings relacionados
}

/** Niveles de esfuerzo para implementar una corrección */
export type EffortLevel = 'quick-win' | 'moderate' | 'complex';

/** Modos disponibles para ejecutar el enriquecimiento del análisis */
export type AiExecutionMode = 'bedrock' | 'mock' | 'fallback';

/** Metadatos del análisis */
export interface AnalysisMetadata {
  timestamp: string;          // ISO 8601
  modelId: string;            // ID del modelo o "none" si degradado
  latencyMs: number;
  cached: boolean;
  status: AnalysisStatus;
  executionMode: AiExecutionMode;
}

/** Estados posibles del resultado de análisis */
export type AnalysisStatus = 'complete' | 'degraded' | 'partial';

/**
 * Completa metadata antigua sin modo usando el modelId persistido.
 * Evita exponer resultados cacheados con procedencia ambigua.
 */
export function normalizeAnalysisResultExecutionMode(result: AnalysisResult): AnalysisResult {
  const metadata = result.metadata as AnalysisMetadata & { executionMode?: AiExecutionMode };
  if (metadata.executionMode) return result;

  const normalizedModelId = metadata.modelId.toLowerCase();
  const executionMode: AiExecutionMode = normalizedModelId.includes('mock')
    ? 'mock'
    : normalizedModelId === 'none'
      ? 'fallback'
      : 'bedrock';

  return { ...result, metadata: { ...metadata, executionMode } };
}

// ─── Tipos de validación ─────────────────────────────────────────────────────

/** Resultado de la validación de entrada */
export interface ValidationResult {
  valid: boolean;
  error?: { message: string; index?: number };
  sanitizedInput?: AnalysisRequest;
  truncated?: boolean;
  truncatedCount?: number;
}

// ─── Tipos de respuesta de Bedrock ───────────────────────────────────────────

/** Estructura JSON que el prompt instruye a Bedrock a retornar */
export interface BedrockExpectedResponse {
  explanations: Array<{
    findingIndex: number;
    text: string;
  }>;
  recommendations: Array<{
    title: string;
    description: string;
    effort: EffortLevel;
    relatedFindings: number[];
  }>;
}

// ─── Tipos de error ──────────────────────────────────────────────────────────

/** Respuesta de error de la API */
export interface ErrorResponse {
  error: string;
  details?: {
    index?: number;
    field?: string;
    reason?: string;
  };
}
