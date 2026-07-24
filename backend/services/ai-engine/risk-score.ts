/**
 * Calculadora determinista del Risk Score.
 * Calcula un score de riesgo compuesto (0-100) basado en la severidad
 * y diversidad de categorías de los hallazgos. El resultado es independiente
 * del orden de entrada — garantiza determinismo.
 */

import type { Finding, FindingSeverity, FindingCategory } from '../scanner/modules/types.js';
import type { RiskGrade, RiskLevel } from './types.js';

/** Pesos de severidad para el cálculo del score base */
const SEVERITY_WEIGHTS: Record<FindingSeverity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 0,
};

// ─── Multiplicadores por categoría para evitar doble conteo e inflación ──────

/**
 * Multiplicador 0 para correlaciones: estos findings se crean al cruzar un CVE
 * con un hallazgo de Nmap. Si contaran en el score base, el mismo problema se
 * contaría dos veces (una por el CVE original y otra por la correlación).
 */
const MULTIPLIER_CORRELATION = 0;

/**
 * Multiplicador 0.5 para vulnerabilidades conocidas (CVE): provienen de una
 * búsqueda aproximada por palabras clave en NVD, sin verificación de versión
 * exacta. Contarlas a peso completo inflaría el score con falsos positivos.
 */
const MULTIPLIER_KNOWN_VULNERABILITIES = 0.5;

/**
 * Multiplicador 1.0 para todas las demás categorías: hallazgos verificados
 * directamente por los módulos de escaneo propios.
 */
const MULTIPLIER_DEFAULT = 1.0;

/** Retorna el multiplicador de score base según la categoría del finding */
function getCategoryMultiplier(category: FindingCategory): number {
  switch (category) {
    case 'correlation':
      return MULTIPLIER_CORRELATION;
    case 'known-vulnerabilities':
      return MULTIPLIER_KNOWN_VULNERABILITIES;
    default:
      return MULTIPLIER_DEFAULT;
  }
}

/**
 * Categorías excluidas del cálculo de diversidad porque no representan una
 * fuente de riesgo independiente (correlation es derivada de otro hallazgo).
 */
const DIVERSITY_EXCLUDED_CATEGORIES: ReadonlySet<FindingCategory> = new Set([
  'correlation',
]);

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

/** Mapeo de riskScore a grado tipo SSL Labs (inverso de las bandas de nivel) */
const GRADE_THRESHOLDS: Array<{ min: number; max: number; grade: RiskGrade }> = [
  { min: 81, max: 100, grade: 'F' },
  { min: 61, max: 80, grade: 'D' },
  { min: 41, max: 60, grade: 'C' },
  { min: 21, max: 40, grade: 'B' },
  { min: 0, max: 20, grade: 'A' },
];

/** Resultado del cálculo de Risk Score */
export interface RiskScoreResult {
  riskScore: number;
  riskLevel: RiskLevel;
  grade: RiskGrade;
}

/**
 * Calcula el Risk Score determinista para un conjunto de findings.
 * El score es independiente del orden del arreglo de entrada.
 */
export function calculateRiskScore(findings: Finding[]): RiskScoreResult {
  // Caso base: sin findings
  if (findings.length === 0) {
    return { riskScore: 0, riskLevel: 'minimal', grade: 'A' };
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

  // Paso 5: Determinar grado compuesto (A–F)
  const grade = determineGrade(finalScore);

  return { riskScore: finalScore, riskLevel, grade };
}

/**
 * Calcula el score base: MIN(suma(peso × multiplicador_categoría), 100).
 * El multiplicador por categoría reduce o elimina el aporte de findings
 * que no representan riesgo verificado de forma independiente.
 */
function calculateBaseScore(findings: Finding[]): number {
  let sum = 0;
  for (const finding of findings) {
    sum += SEVERITY_WEIGHTS[finding.severity] * getCategoryMultiplier(finding.category);
  }
  return Math.min(sum, 100);
}

/**
 * Calcula el factor de diversidad: +10% por categoría distinta
 * que contenga al menos un finding de severidad medium o superior.
 * Se excluyen categorías derivadas (correlation) que no representan
 * una fuente de riesgo independiente.
 * Máximo incremento: 50% (5 categorías).
 */
function calculateDiversityFactor(findings: Finding[]): number {
  // Recopilar categorías con al menos un finding medium+
  const categoriesWithSignificantFindings = new Set<FindingCategory>();

  for (const finding of findings) {
    if (DIVERSITY_THRESHOLD_SEVERITIES.has(finding.severity)
        && !DIVERSITY_EXCLUDED_CATEGORIES.has(finding.category)) {
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

/**
 * Determina el grado compuesto (A–F) basado en el riskScore.
 * Mapeo inverso de las bandas: menor riesgo = mejor grado.
 */
function determineGrade(score: number): RiskGrade {
  for (const { min, max, grade } of GRADE_THRESHOLDS) {
    if (score >= min && score <= max) {
      return grade;
    }
  }
  // Fallback defensivo
  return 'A';
}
