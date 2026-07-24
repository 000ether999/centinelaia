/**
 * Tests del cálculo determinista del Risk Score.
 * Verifica el score base por severidad, el factor de diversidad por categoría
 * (+10% por categoría distinta con findings medium+, tope +50%), el tope de 100
 * y el determinismo (independiente del orden de entrada).
 *
 * NOTA: el factor de diversidad incluye la PRIMERA categoría. Por eso 3 findings
 * "high" en una sola categoría dan 50 (no 45): base 45 × 1.10 = 49.5 → 50.
 */

import { describe, it, expect } from 'vitest';
import { calculateRiskScore } from '../../services/ai-engine/risk-score.js';
import type { Finding, FindingCategory, FindingSeverity } from '../../services/scanner/modules/types.js';

/** Construye un Finding mínimo válido para el cálculo (solo importan category y severity). */
function finding(category: FindingCategory, severity: FindingSeverity): Finding {
  return {
    category,
    severity,
    rawValue: null,
    description: `Hallazgo de prueba de categoría ${category} y severidad ${severity}.`,
  };
}

describe('calculateRiskScore', () => {
  it('retorna 0 / minimal para un arreglo vacío', () => {
    expect(calculateRiskScore([])).toEqual({ riskScore: 0, riskLevel: 'minimal' });
  });

  it('aplica +10% de diversidad incluso con una sola categoría (3 high → 50)', () => {
    const findings = [
      finding('http-headers', 'high'),
      finding('http-headers', 'high'),
      finding('http-headers', 'high'),
    ];
    // base 45 × (1 + 0.10) = 49.5 → round → 50
    expect(calculateRiskScore(findings)).toEqual({ riskScore: 50, riskLevel: 'moderate' });
  });

  it('suma diversidad por 5 categorías distintas hasta el tope de +50% (5 medium → 60)', () => {
    const findings = [
      finding('http-headers', 'medium'),
      finding('tls-ssl', 'medium'),
      finding('cookies', 'medium'),
      finding('dns-security', 'medium'),
      finding('server-fingerprint', 'medium'),
    ];
    // base 40 × (1 + 0.50) = 60
    expect(calculateRiskScore(findings)).toEqual({ riskScore: 60, riskLevel: 'moderate' });
  });

  it('limita el score final a 100 (4 critical → 100 / critical)', () => {
    const findings = [
      finding('tls-ssl', 'critical'),
      finding('tls-ssl', 'critical'),
      finding('tls-ssl', 'critical'),
      finding('tls-ssl', 'critical'),
    ];
    // base min(100,100)=100 × 1.10 = 110 → tope 100
    expect(calculateRiskScore(findings)).toEqual({ riskScore: 100, riskLevel: 'critical' });
  });

  it('es determinista: el orden de entrada no cambia el resultado', () => {
    const base = [
      finding('http-headers', 'medium'),
      finding('tls-ssl', 'medium'),
      finding('cookies', 'medium'),
      finding('dns-security', 'medium'),
      finding('server-fingerprint', 'medium'),
    ];
    const reordered = [base[4]!, base[1]!, base[3]!, base[0]!, base[2]!];
    expect(calculateRiskScore(reordered)).toEqual(calculateRiskScore(base));
  });

  it('ignora la severidad "info" en el score base (no aporta peso)', () => {
    const findings = [finding('http-headers', 'info'), finding('cookies', 'info')];
    // base 0 → 0, y sin categorías medium+ no hay diversidad
    expect(calculateRiskScore(findings)).toEqual({ riskScore: 0, riskLevel: 'minimal' });
  });
});
