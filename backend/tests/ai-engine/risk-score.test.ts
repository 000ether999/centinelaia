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

describe('calculateRiskScore — corrección de doble conteo y sobre-peso CVE', () => {
  it('sin doble conteo: correlation no aporta al score base', () => {
    const findings = [
      finding('known-vulnerabilities', 'critical'),
      finding('correlation', 'critical'),
    ];
    const result = calculateRiskScore(findings);
    // base = 25×0.5 + 25×0 = 12.5
    // diversidad: correlation excluida, known-vulnerabilities cuenta → 1 categoría → 0.10
    // final = round(12.5 × 1.10) = round(13.75) = 14
    expect(result.riskScore).toBe(14);
    // Debe ser estrictamente menor al cálculo antiguo (que daría 60)
    expect(result.riskScore).toBeLessThan(60);
  });

  it('CVE con medio peso: un solo CVE crítico aproximado no fuerza grado F', () => {
    const findings = [finding('known-vulnerabilities', 'critical')];
    const result = calculateRiskScore(findings);
    // base = 25×0.5 = 12.5, diversidad = 1 categoría → 0.10
    // final = round(12.5 × 1.10) = round(13.75) = 14
    expect(result.riskScore).toBe(14);
    expect(result.grade).not.toBe('F');
    expect(result.grade).toBe('A');
  });

  it('correlación no cuenta en diversidad: agregar correlation no cambia el score', () => {
    const base = [
      finding('http-headers', 'medium'),
      finding('known-vulnerabilities', 'high'),
    ];
    const withCorrelation = [
      ...base,
      finding('correlation', 'medium'),
    ];
    // Correlation aporta 0 al base y no cuenta para diversidad
    expect(calculateRiskScore(withCorrelation)).toEqual(calculateRiskScore(base));
  });

  it('determinismo con known-vulnerabilities y correlation: el orden no importa', () => {
    const findings = [
      finding('http-headers', 'high'),
      finding('known-vulnerabilities', 'critical'),
      finding('correlation', 'high'),
      finding('tls-ssl', 'medium'),
    ];
    const shuffled = [findings[2]!, findings[0]!, findings[3]!, findings[1]!];
    expect(calculateRiskScore(shuffled)).toEqual(calculateRiskScore(findings));
  });
});


describe('calculateRiskScore — Ola 9: recalibración KEV y correlaciones emergentes', () => {
  /** Helper que crea un finding con vulnInfo */
  function cveFinding(
    severity: FindingSeverity,
    kevKnownExploited: boolean,
    cveId = 'CVE-2024-0001',
    cvssScore = 9.8,
  ): Finding {
    return {
      category: 'known-vulnerabilities',
      severity,
      rawValue: kevKnownExploited ? `${cveId} (CVSS ${cvssScore}) [KEV]` : `${cveId} (CVSS ${cvssScore})`,
      description: `[${kevKnownExploited ? 'KEV - explotación activa' : 'coincidencia aproximada'}] product 1.0: vuln description padding text.`,
      vulnInfo: { cveId, cvssScore, kevKnownExploited },
    };
  }

  /** Helper que crea un finding de correlación con correlationInfo */
  function correlationFinding(
    severity: FindingSeverity,
    rule: string,
    emergent: boolean,
  ): Finding {
    return {
      category: 'correlation',
      severity,
      rawValue: `rule:${rule}`,
      description: `Correlación generada por regla ${rule} para testing del score.`,
      correlationInfo: { rule, emergent },
    };
  }

  // ─── KEV tests ──────────────────────────────────────────────────────────────

  it('CVE KEV critical (vulnInfo.kevKnownExploited: true) → cuenta a peso completo (25)', () => {
    const findings = [cveFinding('critical', true)];
    const result = calculateRiskScore(findings);
    // base = 25 × 1.0 = 25, diversidad = 1 categoría → 0.10
    // final = round(25 × 1.10) = round(27.5) = 28
    expect(result.riskScore).toBe(28);
    expect(result.grade).toBe('B');
  });

  it('CVE no-KEV critical → sigue contando 12.5 (no regresión de la Ola 2)', () => {
    const findings = [cveFinding('critical', false)];
    const result = calculateRiskScore(findings);
    // base = 25 × 0.5 = 12.5, diversidad = 1 categoría → 0.10
    // final = round(12.5 × 1.10) = round(13.75) = 14
    expect(result.riskScore).toBe(14);
    expect(result.grade).toBe('A');
  });

  it('CVE critical SIN vulnInfo → 12.5 (retrocompatible con findings antiguos)', () => {
    const findings: Finding[] = [{
      category: 'known-vulnerabilities',
      severity: 'critical',
      rawValue: 'CVE-OLD (CVSS 9.0)',
      description: 'Finding antiguo sin vulnInfo — debe comportarse como CVE aproximado.',
    }];
    const result = calculateRiskScore(findings);
    expect(result.riskScore).toBe(14); // same as no-KEV
  });

  // ─── Correlaciones emergentes tests ─────────────────────────────────────────

  it('Correlación con correlationInfo.emergent: true → cuenta a peso completo y suma diversidad', () => {
    const findings = [correlationFinding('high', 'authlog-ssh-exposure', true)];
    const result = calculateRiskScore(findings);
    // base = 15 × 1.0 = 15, diversidad = 1 categoría (correlation emergente cuenta) → 0.10
    // final = round(15 × 1.10) = round(16.5) = 17
    expect(result.riskScore).toBe(17);
  });

  it('Correlación con emergent: false → cuenta 0 y NO suma diversidad (no regresión)', () => {
    const findings = [correlationFinding('high', 'port-with-tls', false)];
    const result = calculateRiskScore(findings);
    // base = 15 × 0 = 0, diversidad = 0 (excluida)
    expect(result.riskScore).toBe(0);
    expect(result.grade).toBe('A');
  });

  it('Correlación sin correlationInfo → cuenta 0 (retrocompatible)', () => {
    const findings: Finding[] = [{
      category: 'correlation',
      severity: 'high',
      rawValue: 'old-correlation',
      description: 'Finding de correlación antiguo sin correlationInfo.',
    }];
    const result = calculateRiskScore(findings);
    expect(result.riskScore).toBe(0);
  });

  // ─── Escenario integrado: KEV + correlación SSH emergente ───────────────────

  it('Escenario integrado: CVE KEV critical + correlación SSH emergente high → grado NO es A', () => {
    const kev = cveFinding('critical', true);
    const ssh = correlationFinding('high', 'authlog-ssh-exposure', true);
    const result = calculateRiskScore([kev, ssh]);
    // base = 25×1.0 + 15×1.0 = 40
    // diversidad = 2 categorías (known-vulnerabilities + correlation emergente) → 0.20
    // final = round(40 × 1.20) = 48
    expect(result.riskScore).toBe(48);
    expect(result.grade).toBe('C');
    expect(result.grade).not.toBe('A');
  });

  // ─── No regresión: findings del scanner siguen pesando 1.0 ──────────────────

  it('findings del scanner siguen pesando 1.0 (no regresión)', () => {
    const findings = [finding('http-headers', 'high')];
    const result = calculateRiskScore(findings);
    // base = 15 × 1.0 = 15, diversidad = 1 → 0.10
    // final = round(15 × 1.10) = round(16.5) = 17
    expect(result.riskScore).toBe(17);
  });

  // ─── Determinismo preservado ────────────────────────────────────────────────

  it('determinismo preservado: barajar el orden no cambia el score', () => {
    const items = [
      cveFinding('critical', true),
      correlationFinding('high', 'authlog-ssh-exposure', true),
      finding('http-headers', 'medium'),
    ];
    const shuffled = [items[2]!, items[0]!, items[1]!];
    expect(calculateRiskScore(shuffled)).toEqual(calculateRiskScore(items));
  });

  // ─── Baseline comparación ───────────────────────────────────────────────────

  it('baseline scanner (2 headers high + 1 TLS high) puntúa coherentemente', () => {
    const findings = [
      finding('http-headers', 'high'),
      finding('http-headers', 'high'),
      finding('tls-ssl', 'high'),
    ];
    const result = calculateRiskScore(findings);
    // base = 15+15+15 = 45, diversidad = 2 categorías → 0.20
    // final = round(45 × 1.20) = 54
    expect(result.riskScore).toBe(54);
    expect(result.grade).toBe('C');
  });
});
