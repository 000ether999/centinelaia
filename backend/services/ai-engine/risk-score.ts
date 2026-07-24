/**
 * Calculadora determinista del Risk Score.
 * Calcula un score de riesgo compuesto (0-100) basado en la severidad
 * y diversidad de categorías de los hallazgos. El resultado es independiente
 * del orden de entrada — garantiza determinismo.
 */

import type { Finding, FindingSeverity, FindingCategory } from '../scanner/modules/types.js';
import type { RiskLevel } from './types.js';

/** Pesos de severidad para el cálculo del score base */
const SEVERITY_WEIGHTS: Record<FindingSeverity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 0,
};

/** Umbral mínimo de severidad para que una categoría cuente en diversidad */
const DIVERSITY_THRESHOLD_SEVERITIES: ReadonlySet<FindingSeverity> = new Set([
  'critical',
  'high',
  'medium',
]);

/** Incremento por cada categoría distinta con findings medium+ */
const DIVERSITY_INCREMENT_PERCENT = 0.10;

/** Máximo incremento por diversidad (50% = 5 categorías) */
const MAX_DIVERSITY_PERCENT = 0.50;

/** Rangos para clasificar el riskLevel */
const RISK_LEVEL_THRESHOLDS: Array<{ min: number; max: number; level: RiskLevel }> = [
  { min: 81, max: 100, level: 'critical' },
  { min: 61, max: 80, level: 'high' },
  { min: 41, max: 60, level: 'moderate' },
  { min: 21, max: 40, level: 'low' },
  { min: 0, max: 20, level: 'minimal' },
];

/** Resultado del cálculo de Risk Score */
export interface RiskScoreResult {
  riskScore: number;
  riskLevel: RiskLevel;
}

/**
 * Calcula el Risk Score determinista para un conjunto de findings.
 * El score es independiente del orden del arreglo de entrada.
 */
export function calculateRiskScore(findings: Finding[]): RiskScoreResult {
  // Caso base: sin findings
  if (findings.length === 0) {
    return { riskScore: 0, riskLevel: 'minimal' };
  }

  // Paso 1: Calcular score base (suma de pesos por severidad, tope 100)
  const baseScore = calculateBaseScore(findings);

  // Paso 2: Calcular factor de diversidad
  const diversityFactor = calculateDiversityFactor(findings);

  // Paso 3: Aplicar diversidad al score base y limitar a 100
  const finalScore = Math.min(
    Math.round(baseScore * (1 + diversityFactor)),
    100
  );

  // Paso 4: Determinar nivel de riesgo
  const riskLevel = determineRiskLevel(finalScore);

  return { riskScore: finalScore, riskLevel };
}

/**
 * Calcula el score base: MIN(suma(peso × cantidad por severidad), 100).
 */
function calculateBaseScore(findings: Finding[]): number {
  let sum = 0;
  for (const finding of findings) {
    sum += SEVERITY_WEIGHTS[finding.severity];
  }
  return Math.min(sum, 100);
}

/**
 * Calcula el factor de diversidad: +10% por categoría distinta
 * que contenga al menos un finding de severidad medium o superior.
 * Máximo incremento: 50% (5 categorías).
 */
function calculateDiversityFactor(findings: Finding[]): number {
  // Recopilar categorías con al menos un finding medium+
  const categoriesWithSignificantFindings = new Set<FindingCategory>();

  for (const finding of findings) {
    if (DIVERSITY_THRESHOLD_SEVERITIES.has(finding.severity)) {
      categoriesWithSignificantFindings.add(finding.category);
    }
  }

  const categoryCount = categoriesWithSignificantFindings.size;
  const factor = categoryCount * DIVERSITY_INCREMENT_PERCENT;

  return Math.min(factor, MAX_DIVERSITY_PERCENT);
}

/**
 * Determina el nivel de riesgo basado en los umbrales definidos.
 */
function determineRiskLevel(score: number): RiskLevel {
  for (const { min, max, level } of RISK_LEVEL_THRESHOLDS) {
    if (score >= min && score <= max) {
      return level;
    }
  }
  // Fallback defensivo (no debería alcanzarse con input válido)
  return 'minimal';
}
