/**
 * Helper de fusión de hallazgos de múltiples fuentes.
 * Combina findings directos del scanner con findings derivados de una salida
 * de Nmap (texto o XML), y genera un sourceContext apropiado para el AI Engine.
 */

import type { Finding } from '../scanner/modules/types.js';
import { translateNmapOutput } from './nmap-parser.js';
import { translateAuthLog } from './authlog-parser.js';
import { parseNmapXml } from './nmap-xml-parser.js';

/** Límite impuesto por el validator del AI Engine para sourceContext. */
const MAX_SOURCE_CONTEXT_LENGTH = 200;

/**
 * Detecta si un texto es XML de Nmap (empieza por <?xml o <nmaprun tras espacios).
 */
function looksLikeNmapXml(text: string): boolean {
  const trimmed = text.trimStart();
  return trimmed.startsWith('<?xml') || trimmed.startsWith('<nmaprun');
}

export interface MergeInput {
  /** Findings directos (del scanner o enviados por el cliente). */
  findings: Finding[];
  /** Salida cruda de Nmap texto (opcional). Si viene, se traduce y fusiona. */
  nmapOutput?: string;
  /** Salida XML de Nmap (opcional). Si viene, se parsea y fusiona. */
  nmapXml?: string;
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
 * Fusiona findings directos con findings derivados de nmapOutput, nmapXml y/o authLog.
 * Si no hay logs externos, retorna los findings originales sin cambios.
 *
 * Detección automática: si nmapOutput contiene XML (empieza por <?xml o <nmaprun),
 * lo procesa con el parser XML en vez del parser de texto. Esto permite que un
 * usuario pegue XML en el campo de texto y funcione correctamente.
 */
export function mergeFindings(input: MergeInput): MergeResult {
  const { findings, nmapOutput, nmapXml, authLog, sourceContext } = input;

  // Si no hay salida de Nmap, XML ni authLog, retornar sin cambios
  const hasNmapText = nmapOutput?.trim();
  const hasNmapXmlField = nmapXml?.trim();
  const hasAuthLog = authLog?.trim();

  if (!hasNmapText && !hasNmapXmlField && !hasAuthLog) {
    return {
      mergedFindings: findings,
      mergedSourceContext: sourceContext,
    };
  }

  // Traducir fuentes externas
  let nmapFindings: Finding[] = [];
  if (hasNmapText) {
    // Detección automática de formato: si parece XML, usar parser XML
    nmapFindings = looksLikeNmapXml(nmapOutput!)
      ? parseNmapXml(nmapOutput!)
      : translateNmapOutput(nmapOutput!);
  }

  let xmlFindings: Finding[] = [];
  if (hasNmapXmlField) {
    xmlFindings = parseNmapXml(nmapXml!);
  }

  const authFindings = hasAuthLog ? translateAuthLog(authLog!) : [];

  // Fusionar: findings directos primero, luego Nmap texto, luego XML, luego auth.log
  const allExternalFindings = [...nmapFindings, ...xmlFindings, ...authFindings];
  const mergedFindings = [...findings, ...allExternalFindings];

  // Construir sourceContext enriquecido respetando el límite de 200 chars
  const mergedSourceContext = buildMergedSourceContext(
    sourceContext,
    findings.length,
    nmapFindings.length + xmlFindings.length,
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
