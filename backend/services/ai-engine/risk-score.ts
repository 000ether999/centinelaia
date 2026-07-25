/**
 * Calculadora determinista del Risk Score.
 * Calcula un score de riesgo compuesto (0-100) basado en la severidad
 * y diversidad de categorías de los hallazgos. El resultado es independiente
 * del orden de entrada — garantiza determinismo.
 *
 * Ola 11: acumulación con retorno decreciente, suelo por severidad verificada
 * (modelo SSL Labs) y separación higiene/exposición.
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
 * Multiplicador 0 para correlaciones NO emergentes: estos findings se crean al
 * cruzar dos hallazgos que ya puntúan por separado. Contarlos duplicaría el peso.
 */
const MULTIPLIER_CORRELATION_NON_EMERGENT = 0;

/**
 * Multiplicador 1.0 para correlaciones EMERGENTES: expresan un riesgo combinado
 * que ninguna de sus partes captura por separado (ej. fuerza bruta SSH + puerto
 * abierto = riesgo de compromiso de credenciales).
 */
const MULTIPLIER_CORRELATION_EMERGENT = 1.0;

/**
 * Multiplicador 0.5 para CVEs sin confirmación KEV: provienen de una búsqueda
 * aproximada por palabras clave en NVD, sin verificación de versión exacta.
 * Contarlas a peso completo inflaría el score con falsos positivos.
 */
const MULTIPLIER_CVE_APPROXIMATE = 0.5;

/**
 * Multiplicador 1.0 para CVEs confirmados por el catálogo CISA KEV: explotación
 * activa verificada, el riesgo es real y no una coincidencia aproximada.
 */
const MULTIPLIER_CVE_KEV = 1.0;

/**
 * Multiplicador 1.0 para todas las demás categorías: hallazgos verificados
 * directamente por los módulos de escaneo propios.
 */
const MULTIPLIER_DEFAULT = 1.0;

// ─── Ola 11: Decaimiento geométrico ─────────────────────────────────────────

/**
 * Factor de decaimiento geométrico para la acumulación de pesos.
 * Cada hallazgo adicional aporta DECAY^i de su peso efectivo (i = posición
 * en el arreglo ordenado de mayor a menor). Así el hallazgo más grave aporta
 * su peso completo, el segundo el 60%, el tercero el 36%, etc.
 * Esto evita que acumular ruido supere hallazgos graves aislados.
 */
const ACCUMULATION_DECAY = 0.6;

// ─── Ola 11: Suelo por severidad verificada (modelo SSL Labs) ────────────────

/**
 * Suelos de score por severidad efectiva.
 * La presencia de un hallazgo grave verificado garantiza una banda mínima,
 * análogo al mecanismo de SSL Labs donde el peor hallazgo pone techo a la nota.
 * - critical (verificado): banda F (≥81)
 * - high (verificado): banda C (≥41)
 * - medium (verificado): banda B (≥21)
 * - low/info: sin suelo
 */
const SEVERITY_SCORE_FLOOR: Record<FindingSeverity, number> = {
  critical: 81,
  high: 41,
  medium: 21,
  low: 0,
  info: 0,
};

// ─── Ola 11: Separación higiene vs exposición ────────────────────────────────

/**
 * Categorías de higiene: mala configuración, no explotable directamente.
 * Representan deuda técnica o configuración subóptima, no riesgo inmediato.
 */
const HYGIENE_CATEGORIES: ReadonlySet<FindingCategory> = new Set([
  'http-headers',
  'security-txt',
  'server-fingerprint',
  'dns-security',
]);

// Todo lo demás (tls-ssl, cookies, cors, http-methods, security-exposure,
// known-vulnerabilities, port-service, log-analysis, correlation) cuenta como
// exposición (riesgo explotable).

/** Retorna el multiplicador de score base según el finding (categoría + metadatos) */
function getFindingMultiplier(finding: Finding): number {
  if (finding.category === 'correlation') {
    // Correlaciones emergentes cuentan a peso completo
    if (finding.correlationInfo?.emergent === true) {
      return MULTIPLIER_CORRELATION_EMERGENT;
    }
    // Correlaciones no emergentes o sin correlationInfo → 0 (evita doble conteo)
    return MULTIPLIER_CORRELATION_NON_EMERGENT;
  }

  if (finding.category === 'known-vulnerabilities') {
    // CVE confirmado por CISA KEV → peso completo
    if (finding.vulnInfo?.kevKnownExploited === true) {
      return MULTIPLIER_CVE_KEV;
    }
    // CVE aproximado o sin vulnInfo → medio peso
    return MULTIPLIER_CVE_APPROXIMATE;
  }

  return MULTIPLIER_DEFAULT;
}

/**
 * Categorías excluidas del cálculo de diversidad porque no representan una
 * fuente de riesgo independiente. Las correlaciones no emergentes están
 * excluidas; las emergentes SÍ cuentan para diversidad.
 */
function isDiversityExcluded(finding: Finding): boolean {
  if (finding.category === 'correlation') {
    // Solo las emergentes cuentan para diversidad
    return finding.correlationInfo?.emergent !== true;
  }
  return false;
}

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
  /** Score parcial solo de categorías de higiene (Ola 11) */
  hygieneScore: number;
  /** Score parcial solo de categorías de exposición/riesgo explotable (Ola 11) */
  exposureScore: number;
}

/**
 * Calcula el Risk Score determinista para un conjunto de findings.
 * El score es independiente del orden del arreglo de entrada.
 */
export function calculateRiskScore(findings: Finding[]): RiskScoreResult {
  // Caso base: sin findings
  if (findings.length === 0) {
    return { riskScore: 0, riskLevel: 'minimal', grade: 'A', hygieneScore: 0, exposureScore: 0 };
  }

  // Score global (todos los findings)
  const globalScore = computeScoreForSubset(findings);

  // Scores parciales: higiene y exposición (Ola 11, Tarea 3)
  const hygieneFindings = findings.filter(f => HYGIENE_CATEGORIES.has(f.category));
  const exposureFindings = findings.filter(f => !HYGIENE_CATEGORIES.has(f.category));
  const hygieneScore = computeScoreForSubset(hygieneFindings);
  const exposureScore = computeScoreForSubset(exposureFindings);

  // Determinar nivel de riesgo y grado a partir del score global
  const riskLevel = determineRiskLevel(globalScore);
  const grade = determineGrade(globalScore);

  return { riskScore: globalScore, riskLevel, grade, hygieneScore, exposureScore };
}

/**
 * Calcula el score final para un subconjunto de findings aplicando:
 * 1. Acumulación con decaimiento geométrico (Ola 11, Tarea 1)
 * 2. Factor de diversidad
 * 3. Suelo por severidad verificada (Ola 11, Tarea 2)
 */
function computeScoreForSubset(findings: Finding[]): number {
  if (findings.length === 0) return 0;

  // Paso 1: Calcular score base con decaimiento geométrico
  const baseScore = calculateBaseScore(findings);

  // Paso 2: Calcular factor de diversidad
  const diversityFactor = calculateDiversityFactor(findings);

  // Paso 3: Aplicar diversidad al score base
  const calculatedScore = Math.min(
    Math.round(baseScore * (1 + diversityFactor)),
    100
  );

  // Paso 4: Suelo por severidad verificada (Ola 11, Tarea 2)
  const floor = calculateFloor(findings);

  // El score final es el mayor entre el calculado y el suelo
  return Math.min(100, Math.max(calculatedScore, floor));
}

/**
 * Calcula el score base con acumulación de decaimiento geométrico (Ola 11).
 * 1. Calcula el peso efectivo de cada finding: SEVERITY_WEIGHTS[severity] × getFindingMultiplier(finding)
 * 2. Descarta pesos efectivos iguales a 0.
 * 3. Ordena de mayor a menor (garantiza determinismo).
 * 4. Acumula: sum += peso[i] × DECAY^i
 */
function calculateBaseScore(findings: Finding[]): number {
  // Calcular pesos efectivos y descartar los que son 0
  const weights: number[] = [];
  for (const finding of findings) {
    const w = SEVERITY_WEIGHTS[finding.severity] * getFindingMultiplier(finding);
    if (w > 0) {
      weights.push(w);
    }
  }

  // Ordenar de mayor a menor para determinismo y para que el más grave aporte completo
  weights.sort((a, b) => b - a);

  // Acumular con decaimiento geométrico
  let sum = 0;
  for (let i = 0; i < weights.length; i++) {
    sum += weights[i]! * Math.pow(ACCUMULATION_DECAY, i);
  }

  return sum;
}

/**
 * Calcula el suelo de score basado en la severidad efectiva de los findings.
 *
 * La severidad efectiva para el suelo depende del multiplicador:
 * - multiplicador >= 1.0 (verificado: módulos scanner, CVE KEV, correlación emergente)
 *   → su severidad tal cual.
 * - multiplicador > 0 y < 1.0 (CVE aproximado NVD, sin verificar)
 *   → degrada dos escalones (critical→medium, high→low, medium→info, low→info).
 * - multiplicador === 0 (correlación no emergente, duplicado)
 *   → excluido del suelo.
 */
function calculateFloor(findings: Finding[]): number {
  let maxFloor = 0;

  for (const finding of findings) {
    const multiplier = getFindingMultiplier(finding);

    if (multiplier === 0) {
      // Excluido del suelo
      continue;
    }

    let effectiveSeverity: FindingSeverity;

    if (multiplier >= 1.0) {
      // Verificado: su severidad tal cual
      effectiveSeverity = finding.severity;
    } else {
      // No verificado (multiplicador > 0 y < 1.0): degradar dos escalones
      effectiveSeverity = degradeTwoSteps(finding.severity);
    }

    const floor = SEVERITY_SCORE_FLOOR[effectiveSeverity];
    if (floor > maxFloor) {
      maxFloor = floor;
    }
  }

  return maxFloor;
}

/**
 * Degrada una severidad dos escalones.
 * critical → medium, high → low, medium → info, low → info, info → info
 */
function degradeTwoSteps(severity: FindingSeverity): FindingSeverity {
  switch (severity) {
    case 'critical': return 'medium';
    case 'high': return 'low';
    case 'medium': return 'info';
    case 'low': return 'info';
    case 'info': return 'info';
  }
}

/**
 * Calcula el factor de diversidad: +10% por categoría distinta
 * que contenga al menos un finding de severidad medium o superior.
 * Se excluyen findings que no representan una fuente de riesgo independiente
 * (correlaciones no emergentes).
 * Máximo incremento: 50% (5 categorías).
 */
function calculateDiversityFactor(findings: Finding[]): number {
  // Recopilar categorías con al menos un finding medium+
  const categoriesWithSignificantFindings = new Set<FindingCategory>();

  for (const finding of findings) {
    if (DIVERSITY_THRESHOLD_SEVERITIES.has(finding.severity)
        && !isDiversityExcluded(finding)) {
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
