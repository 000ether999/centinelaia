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
  it('retorna 0 / minimal / grade A para un arreglo vacío', () => {
    expect(calculateRiskScore([])).toEqual({ riskScore: 0, riskLevel: 'minimal', grade: 'A' });
  });

  it('aplica +10% de diversidad incluso con una sola categoría (3 high → 50)', () => {
    const findings = [
      finding('http-headers', 'high'),
      finding('http-headers', 'high'),
      finding('http-headers', 'high'),
    ];
    // base 45 × (1 + 0.10) = 49.5 → round → 50
    expect(calculateRiskScore(findings)).toEqual({ riskScore: 50, riskLevel: 'moderate', grade: 'C' });
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
    expect(calculateRiskScore(findings)).toEqual({ riskScore: 60, riskLevel: 'moderate', grade: 'C' });
  });

  it('limita el score final a 100 (4 critical → 100 / critical / grade F)', () => {
    const findings = [
      finding('tls-ssl', 'critical'),
      finding('tls-ssl', 'critical'),
      finding('tls-ssl', 'critical'),
      finding('tls-ssl', 'critical'),
    ];
    // base min(100,100)=100 × 1.10 = 110 → tope 100
    expect(calculateRiskScore(findings)).toEqual({ riskScore: 100, riskLevel: 'critical', grade: 'F' });
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
    expect(calculateRiskScore(findings)).toEqual({ riskScore: 0, riskLevel: 'minimal', grade: 'A' });
  });

  describe('grado compuesto A–F (mapeo inverso por bandas)', () => {
    it('score 0–20 → grado A (minimal)', () => {
      // 1 low = base 3, sin categoría medium+ → diversidad 0 → score 3
      const findings = [finding('http-headers', 'low')];
      const result = calculateRiskScore(findings);
      expect(result.grade).toBe('A');
      expect(result.riskLevel).toBe('minimal');
    });

    it('score 21–40 → grado B (low)', () => {
      // 2 high en misma categoría = base 30 × 1.10 = 33
      const findings = [finding('tls-ssl', 'high'), finding('tls-ssl', 'high')];
      const result = calculateRiskScore(findings);
      expect(result.grade).toBe('B');
      expect(result.riskLevel).toBe('low');
    });

    it('score 41–60 → grado C (moderate)', () => {
      // 3 high en misma categoría = base 45 × 1.10 = 49.5 → 50
      const findings = [
        finding('cookies', 'high'),
        finding('cookies', 'high'),
        finding('cookies', 'high'),
      ];
      const result = calculateRiskScore(findings);
      expect(result.grade).toBe('C');
      expect(result.riskLevel).toBe('moderate');
    });

    it('score 61–80 → grado D (high)', () => {
      // 1 critical + 2 high en 2 categorías = base 55 × 1.20 = 66
      const findings = [
        finding('http-headers', 'critical'),
        finding('tls-ssl', 'high'),
        finding('tls-ssl', 'high'),
      ];
      const result = calculateRiskScore(findings);
      expect(result.grade).toBe('D');
      expect(result.riskLevel).toBe('high');
    });

    it('score 81–100 → grado F (critical)', () => {
      // 4 critical = base 100 × 1.10 = tope 100
      const findings = [
        finding('tls-ssl', 'critical'),
        finding('tls-ssl', 'critical'),
        finding('tls-ssl', 'critical'),
        finding('tls-ssl', 'critical'),
      ];
      const result = calculateRiskScore(findings);
      expect(result.grade).toBe('F');
      expect(result.riskLevel).toBe('critical');
    });
  });
});
