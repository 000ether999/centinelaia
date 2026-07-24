/**
 * Priorizador de recomendaciones del AI Engine.
 * Ordena las recomendaciones aplicando criterios de severidad, cobertura
 * de findings y esfuerzo. Agrupa las de menor prioridad si exceden 10.
 */

import type { Finding, FindingSeverity } from '../scanner/modules/types.js';
import type { Recommendation, EffortLevel } from './types.js';

/** Orden de severidad para priorización (menor = más grave) */
const SEVERITY_PRIORITY: Record<FindingSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** Orden de esfuerzo para desempate (menor = más rápido) */
const EFFORT_PRIORITY: Record<EffortLevel, number> = {
  'quick-win': 0,
  'moderate': 1,
  'complex': 2,
};

/** Máximo de recomendaciones individuales antes de agrupar */
const MAX_RECOMMENDATIONS = 10;

/**
 * Prioriza y ordena un arreglo de recomendaciones según los criterios del Requisito 4.2:
 * 1. Severidad del finding más grave asociado a cada recomendación (descendente)
 * 2. Cantidad de findings que resuelve (descendente)
 * 3. Esfuerzo como desempate (quick-win < moderate < complex)
 *
 * Si hay más de 10 recomendaciones, agrupa las posiciones 11+ en una final.
 * Si todos los findings son "info", retorna una única recomendación indicando
 * que no se requieren acciones correctivas.
 */
export function prioritizeRecommendations(
  recommendations: Recommendation[],
  findings: Finding[]
): Recommendation[] {
  // Caso especial: todos los findings son severidad "info"
  const allInfo = findings.length > 0 && findings.every((f) => f.severity === 'info');
  if (allInfo) {
    return [
      {
        priority: 1,
        title: 'Configuración aceptable',
        description: 'No se requieren acciones correctivas inmediatas. Los hallazgos detectados son informativos y la configuración actual es aceptable.',
        effort: 'quick-win',
        relatedFindings: findings.map((_, i) => i),
      },
    ];
  }

  // Caso vacío
  if (recommendations.length === 0) {
    return [];
  }

  // Calcular la severidad máxima asociada a cada recomendación
  const withMetrics = recommendations.map((rec) => {
    const maxSeverity = getMaxSeverityForRecommendation(rec, findings);
    return { rec, maxSeverity };
  });

  // Ordenar por criterios del Requisito 4.2
  withMetrics.sort((a, b) => {
    // Criterio 1: severidad del finding más grave (descendente)
    const sevDiff = SEVERITY_PRIORITY[a.maxSeverity] - SEVERITY_PRIORITY[b.maxSeverity];
    if (sevDiff !== 0) return sevDiff;

    // Criterio 2: cantidad de findings que resuelve (descendente — más findings primero)
    const countDiff = b.rec.relatedFindings.length - a.rec.relatedFindings.length;
    if (countDiff !== 0) return countDiff;

    // Criterio 3: esfuerzo como desempate (quick-win primero)
    return EFFORT_PRIORITY[a.rec.effort] - EFFORT_PRIORITY[b.rec.effort];
  });

  // Extraer recomendaciones ordenadas
  let sorted = withMetrics.map((item) => item.rec);

  // Agrupar posiciones 11+ si hay más de 10
  if (sorted.length > MAX_RECOMMENDATIONS) {
    const top10 = sorted.slice(0, MAX_RECOMMENDATIONS);
    const overflow = sorted.slice(MAX_RECOMMENDATIONS);

    // Concatenar relatedFindings de todas las agrupadas
    const groupedFindings = overflow.flatMap((r) => r.relatedFindings);
    // Eliminar duplicados y ordenar
    const uniqueFindings = [...new Set(groupedFindings)].sort((a, b) => a - b);

    const groupedRecommendation: Recommendation = {
      priority: MAX_RECOMMENDATIONS + 1,
      title: 'Otras mejoras menores',
      description: 'Agrupa mejoras adicionales de menor prioridad que pueden abordarse cuando las correcciones principales estén completas.',
      effort: 'moderate',
      relatedFindings: uniqueFindings,
    };

    sorted = [...top10, groupedRecommendation];
  }

  // Asignar prioridad secuencial 1..N
  sorted.forEach((rec, idx) => {
    rec.priority = idx + 1;
  });

  return sorted;
}

/**
 * Determina la severidad más alta entre los findings relacionados
 * a una recomendación.
 */
function getMaxSeverityForRecommendation(
  recommendation: Recommendation,
  findings: Finding[]
): FindingSeverity {
  let maxSeverity: FindingSeverity = 'info';

  for (const findingIndex of recommendation.relatedFindings) {
    const finding = findings[findingIndex];
    if (finding && SEVERITY_PRIORITY[finding.severity] < SEVERITY_PRIORITY[maxSeverity]) {
      maxSeverity = finding.severity;
    }
  }

  return maxSeverity;
}
