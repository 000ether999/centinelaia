/**
 * Helper de fusión de hallazgos de múltiples fuentes.
 * Combina findings directos del scanner con findings derivados de una salida
 * de Nmap, y genera un sourceContext apropiado para el AI Engine.
 */

import type { Finding } from '../scanner/modules/types.js';
import { translateNmapOutput } from './nmap-parser.js';
import { translateAuthLog } from './authlog-parser.js';

/** Límite impuesto por el validator del AI Engine para sourceContext. */
const MAX_SOURCE_CONTEXT_LENGTH = 200;

export interface MergeInput {
  /** Findings directos (del scanner o enviados por el cliente). */
  findings: Finding[];
  /** Salida cruda de Nmap (opcional). Si viene, se traduce y fusiona. */
  nmapOutput?: string;
  /** Texto de log de autenticación (opcional). Si viene, se traduce y fusiona. */
  authLog?: string;
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
 * Fusiona findings directos con findings derivados de nmapOutput y/o authLog.
 * Si no hay logs externos, retorna los findings originales sin cambios.
 */
export function mergeFindings(input: MergeInput): MergeResult {
  const { findings, nmapOutput, authLog, sourceContext } = input;

  // Si no hay salida de Nmap ni authLog, retornar sin cambios
  if ((!nmapOutput || !nmapOutput.trim()) && (!authLog || !authLog.trim())) {
    return {
      mergedFindings: findings,
      mergedSourceContext: sourceContext,
    };
  }

  // Traducir fuentes externas
  const nmapFindings = nmapOutput?.trim() ? translateNmapOutput(nmapOutput) : [];
  const authFindings = authLog?.trim() ? translateAuthLog(authLog) : [];

  // Fusionar: findings directos primero, luego Nmap, luego auth.log
  const mergedFindings = [...findings, ...nmapFindings, ...authFindings];

  // Construir sourceContext enriquecido respetando el límite de 200 chars
  const mergedSourceContext = buildMergedSourceContext(
    sourceContext,
    findings.length,
    nmapFindings.length,
    authFindings.length,
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
  authCount: number = 0,
): string {
  const sources: string[] = [];
  if (directCount > 0) sources.push(`scanner (${directCount})`);
  if (nmapCount > 0) sources.push(`Nmap (${nmapCount})`);
  if (authCount > 0) sources.push(`auth.log (${authCount})`);

  // Caso simple: una sola fuente externa sin findings directos
  if (sources.length === 1 && directCount === 0) {
    const ctx = `Análisis de ${nmapCount + authCount} hallazgos de ${nmapCount > 0 ? 'log Nmap' : 'auth.log'}.`;
    return ctx.slice(0, MAX_SOURCE_CONTEXT_LENGTH);
  }

  // Múltiples fuentes — correlación
  const base = originalContext
    ? `${originalContext} + ${sources.filter((s) => !s.startsWith('scanner')).join(' + ')}.`
    : `Correlación: ${sources.join(' + ')}.`;

  // Fallback si es demasiado largo
  const multiSource = base.length <= MAX_SOURCE_CONTEXT_LENGTH
    ? base
    : `${sources.join(' + ')}. Correlacionar hallazgos entre fuentes.`;

  return multiSource.slice(0, MAX_SOURCE_CONTEXT_LENGTH);
}
