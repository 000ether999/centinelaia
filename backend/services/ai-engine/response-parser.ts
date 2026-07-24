/**
 * Parser de respuestas de Bedrock para el AI Engine.
 * Extrae y valida el JSON retornado por el modelo, descarta campos
 * no declarados en el esquema (protección anti-injection), y genera
 * fallbacks para campos faltantes o incompletos.
 */

import type { BedrockExpectedResponse, Explanation, Recommendation, EffortLevel } from './types.js';
import type { Finding } from '../scanner/modules/types.js';
import { generateFallbackExplanations, generateFallbackRecommendations } from './fallback-generator.js';

/** Resultado del parseo de la respuesta de Bedrock */
export interface ParsedResponse {
  explanations: Explanation[];
  recommendations: Recommendation[];
  partial: boolean;
}

/** Valores válidos para el campo effort */
const VALID_EFFORTS: ReadonlySet<string> = new Set<EffortLevel>([
  'quick-win',
  'moderate',
  'complex',
]);

/**
 * Extrae el JSON de la respuesta de texto de Bedrock.
 * Busca el primer bloque JSON válido dentro del texto.
 */
function extractJson(rawText: string): unknown | null {
  // Intentar parsear el texto completo primero
  try {
    return JSON.parse(rawText);
  } catch {
    // Buscar un bloque JSON dentro del texto (puede estar rodeado de texto)
  }

  // Buscar delimitadores de JSON: primer '{' y último '}'
  const start = rawText.indexOf('{');
  const end = rawText.lastIndexOf('}');

  if (start === -1 || end === -1 || end <= start) {
    return null;
  }

  try {
    return JSON.parse(rawText.slice(start, end + 1));
  } catch {
    return null;
  }
}

/**
 * Valida y extrae las explanations de la respuesta de Bedrock.
 * Descarta entradas con estructura inválida.
 */
function parseExplanations(
  raw: unknown[],
  findingsCount: number
): Explanation[] {
  const explanations: Explanation[] = [];

  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;

    const entry = item as Record<string, unknown>;
    const findingIndex = entry['findingIndex'];
    const text = entry['text'];

    // Validar tipos y rangos
    if (typeof findingIndex !== 'number' || findingIndex < 0 || findingIndex >= findingsCount) continue;
    if (typeof text !== 'string' || text.length < 10) continue;

    // Truncar texto si excede 500 caracteres
    const trimmedText = text.length > 500 ? text.slice(0, 497) + '...' : text;

    explanations.push({
      findingIndex: Math.floor(findingIndex),
      text: trimmedText,
      fallback: false,
    });
  }

  return explanations;
}

/**
 * Valida y extrae las recommendations de la respuesta de Bedrock.
 * Descarta entradas con estructura inválida, no asigna prioridad
 * (eso lo hace el recommendation-prioritizer).
 */
function parseRecommendations(raw: unknown[]): Recommendation[] {
  const recommendations: Recommendation[] = [];

  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;

    const entry = item as Record<string, unknown>;
    const title = entry['title'];
    const description = entry['description'];
    const effort = entry['effort'];
    const relatedFindings = entry['relatedFindings'];

    // Validar campos obligatorios
    if (typeof title !== 'string' || title.length === 0) continue;
    if (typeof description !== 'string' || description.length < 10) continue;
    if (typeof effort !== 'string' || !VALID_EFFORTS.has(effort)) continue;
    if (!Array.isArray(relatedFindings)) continue;

    // Filtrar relatedFindings a solo números válidos
    const validFindings = relatedFindings
      .filter((f): f is number => typeof f === 'number' && f >= 0)
      .map((f) => Math.floor(f));

    if (validFindings.length === 0) continue;

    // Truncar campos si exceden límites
    const trimmedTitle = title.length > 100 ? title.slice(0, 97) + '...' : title;
    const trimmedDesc = description.length > 300 ? description.slice(0, 297) + '...' : description;

    recommendations.push({
      priority: 0, // se asigna después por el priorizador
      title: trimmedTitle,
      description: trimmedDesc,
      effort: effort as EffortLevel,
      relatedFindings: validFindings,
    });
  }

  return recommendations;
}

/**
 * Parsea la respuesta completa de Bedrock.
 * Extrae JSON, valida campos esperados, descarta campos no declarados,
 * y genera fallbacks para campos faltantes.
 */
export function parseBedrockResponse(rawText: string, findings: Finding[]): ParsedResponse {
  // Extraer JSON de la respuesta de texto
  const parsed = extractJson(rawText);

  // Si no se puede parsear JSON, retornar fallback completo
  if (!parsed || typeof parsed !== 'object') {
    return {
      explanations: generateFallbackExplanations(findings),
      recommendations: generateFallbackRecommendations(findings),
      partial: true,
    };
  }

  const response = parsed as Record<string, unknown>;
  let partial = false;

  // Parsear explanations (si existen)
  let explanations: Explanation[];
  if (Array.isArray(response['explanations'])) {
    explanations = parseExplanations(response['explanations'], findings.length);

    // Generar fallbacks para findings sin explicación
    const explainedIndices = new Set(explanations.map((e) => e.findingIndex));
    const missingExplanations = generateFallbackExplanations(findings)
      .filter((e) => !explainedIndices.has(e.findingIndex));

    if (missingExplanations.length > 0) {
      explanations = [...explanations, ...missingExplanations];
      partial = true;
    }
  } else {
    // Campo ausente — usar fallback completo
    explanations = generateFallbackExplanations(findings);
    partial = true;
  }

  // Parsear recommendations (si existen)
  let recommendations: Recommendation[];
  if (Array.isArray(response['recommendations'])) {
    recommendations = parseRecommendations(response['recommendations']);

    // Si no se obtuvo ninguna recomendación válida, usar fallback
    if (recommendations.length === 0) {
      recommendations = generateFallbackRecommendations(findings);
      partial = true;
    }
  } else {
    // Campo ausente — usar fallback completo
    recommendations = generateFallbackRecommendations(findings);
    partial = true;
  }

  return { explanations, recommendations, partial };
}
