/**
 * Helper de fusión de hallazgos de múltiples fuentes.
 * Combina findings directos del scanner con findings derivados de una salida
 * de Nmap, y genera un sourceContext apropiado para el AI Engine.
 */

import type { Finding } from '../scanner/modules/types.js';
import { translateNmapOutput } from './nmap-parser.js';

/** Límite impuesto por el validator del AI Engine para sourceContext. */
const MAX_SOURCE_CONTEXT_LENGTH = 200;

export interface MergeInput {
  /** Findings directos (del scanner o enviados por el cliente). */
  findings: Finding[];
  /** Salida cruda de Nmap (opcional). Si viene, se traduce y fusiona. */
  nmapOutput?: string;
  /** sourceContext original del cliente (opcional). */
  sourceContext?: string;
}

export interface MergeResult {
  /** Findings combinados (directos + derivados de Nmap). */
  mergedFindings: Finding[];
  /** sourceContext enriquecido que indica las fuentes presentes. */
  mergedSourceContext: string | undefined;
}

/**
 * Fusiona findings directos con findings derivados de nmapOutput.
 * Si no hay nmapOutput, retorna los findings originales sin cambios.
 */
export function mergeFindings(input: MergeInput): MergeResult {
  const { findings, nmapOutput, sourceContext } = input;

  // Si no hay salida de Nmap, retornar sin cambios
  if (!nmapOutput || !nmapOutput.trim()) {
    return {
      mergedFindings: findings,
      mergedSourceContext: sourceContext,
    };
  }

  // Traducir la salida de Nmap a findings estructurados
  const nmapFindings = translateNmapOutput(nmapOutput);

  // Fusionar: findings directos primero, luego findings de Nmap
  const mergedFindings = [...findings, ...nmapFindings];

  // Construir sourceContext enriquecido respetando el límite de 200 chars
  const mergedSourceContext = buildMergedSourceContext(
    sourceContext,
    findings.length,
    nmapFindings.length,
  );

  return { mergedFindings, mergedSourceContext };
}

/**
 * Construye un sourceContext que indica las fuentes presentes, truncado
 * al máximo permitido por el validator del AI Engine (200 caracteres).
 */
function buildMergedSourceContext(
  originalContext: string | undefined,
  directCount: number,
  nmapCount: number,
): string {
  // Si solo hay findings de Nmap (sin directos del scanner)
  if (directCount === 0 && nmapCount > 0) {
    const ctx = `Análisis de ${nmapCount} hallazgos de log Nmap.`;
    return ctx.slice(0, MAX_SOURCE_CONTEXT_LENGTH);
  }

  // Hay ambas fuentes — correlación real
  const base = originalContext
    ? `${originalContext} + log Nmap (${nmapCount} hallazgos).`
    : `Correlación: ${directCount} hallazgos del scanner + ${nmapCount} de log Nmap.`;

  // Si hay dos fuentes, indicarlo explícitamente para el prompt
  const multiSource = base.length <= MAX_SOURCE_CONTEXT_LENGTH
    ? base
    : `Scanner (${directCount}) + Nmap (${nmapCount}). Correlacionar hallazgos entre fuentes.`;

  return multiSource.slice(0, MAX_SOURCE_CONTEXT_LENGTH);
}
