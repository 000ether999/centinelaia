/**
 * Tests del fallback-generator (funciones puras, sin mocks).
 *
 * Verifica:
 * - generateFallbackExplanations: una explicación por finding, con fallback:true y longitud válida.
 * - generateFallbackRecommendations: agrupa por categoría, ordena por severidad,
 *   caso especial "solo findings info" → recomendación de configuración aceptable.
 */

import { describe, it, expect } from 'vitest';
import type { Finding } from '../../services/scanner/modules/types.js';
import {
  generateFallbackExplanations,
  generateFallbackRecommendations,
} from '../../services/ai-engine/fallback-generator.js';

// ─── Fixtures ────────────────────────────────────────────────────────────────

const mixedFindings: Finding[] = [
  {
    category: 'http-headers',
    severity: 'high',
    rawValue: null,
    description: 'Security header missing: Strict-Transport-Security',
  },
  {
    category: 'http-headers',
    severity: 'medium',
    rawValue: "default-src 'self' 'unsafe-inline'",
    description: 'Security header present with insecure value: Content-Security-Policy',
  },
  {
    category: 'tls-ssl',
    severity: 'critical',
    rawValue: 'TLS 1.0',
    description: 'Server supports obsolete protocol TLS 1.0',
  },
  {
    category: 'cookies',
    severity: 'medium',
    rawValue: 'session_id',
    description: 'Cookie "session_id" is missing the Secure flag',
  },
];

const infoOnlyFindings: Finding[] = [
  {
    category: 'http-headers',
    severity: 'info',
    rawValue: 'max-age=31536000; includeSubDomains',
    description: 'Security header correctly configured: Strict-Transport-Security',
  },
  {
    category: 'tls-ssl',
    severity: 'info',
    rawValue: 'TLS 1.3',
    description: 'Server supports modern protocol TLS 1.3',
  },
  {
    category: 'cookies',
    severity: 'info',
    rawValue: null,
    description: 'No cookies detected in any HTTP response from the target',
  },
];

// ─── Tests: generateFallbackExplanations ─────────────────────────────────────

describe('generateFallbackExplanations', () => {
  it('generates one explanation per finding', () => {
    const explanations = generateFallbackExplanations(mixedFindings);
    expect(explanations).toHaveLength(mixedFindings.length);
  });

  it('every explanation has fallback:true', () => {
    const explanations = generateFallbackExplanations(mixedFindings);
    expect(explanations.every(e => e.fallback === true)).toBe(true);
  });

  it('every explanation has findingIndex matching its position', () => {
    const explanations = generateFallbackExplanations(mixedFindings);
    explanations.forEach((e, idx) => {
      expect(e.findingIndex).toBe(idx);
    });
  });

  it('every explanation text is between 50 and 500 characters', () => {
    const explanations = generateFallbackExplanations(mixedFindings);
    explanations.forEach(e => {
      expect(e.text.length).toBeGreaterThanOrEqual(50);
      expect(e.text.length).toBeLessThanOrEqual(500);
    });
  });

  it('handles empty findings array', () => {
    const explanations = generateFallbackExplanations([]);
    expect(explanations).toHaveLength(0);
  });
});

// ─── Tests: generateFallbackRecommendations ──────────────────────────────────

describe('generateFallbackRecommendations', () => {
  it('groups findings of the same category into one recommendation', () => {
    const recs = generateFallbackRecommendations(mixedFindings);

    // mixedFindings tiene 3 categorías: http-headers (2), tls-ssl (1), cookies (1)
    expect(recs).toHaveLength(3);

    // La recomendación de http-headers debe referenciar ambos findings (index 0 y 1)
    const httpHeadersRec = recs.find(r => r.relatedFindings.includes(0));
    expect(httpHeadersRec).toBeDefined();
    expect(httpHeadersRec!.relatedFindings).toContain(0);
    expect(httpHeadersRec!.relatedFindings).toContain(1);
  });

  it('orders recommendations by severity (most severe first)', () => {
    const recs = generateFallbackRecommendations(mixedFindings);

    // tls-ssl tiene severity 'critical' → priority 1
    // http-headers tiene max severity 'high' → priority 2
    // cookies tiene severity 'medium' → priority 3
    expect(recs[0]!.priority).toBe(1);
    expect(recs[0]!.relatedFindings).toContain(2); // index del finding tls-ssl

    expect(recs[1]!.priority).toBe(2);
    expect(recs[1]!.relatedFindings).toContain(0); // index del finding http-headers high

    expect(recs[2]!.priority).toBe(3);
    expect(recs[2]!.relatedFindings).toContain(3); // index del finding cookies
  });

  it('returns "configuración aceptable" recommendation when all findings are info', () => {
    const recs = generateFallbackRecommendations(infoOnlyFindings);

    expect(recs).toHaveLength(1);
    expect(recs[0]!.priority).toBe(1);
    expect(recs[0]!.title).toContain('aceptable');
    expect(recs[0]!.effort).toBe('quick-win');
    // Debe referenciar todos los findings
    expect(recs[0]!.relatedFindings).toHaveLength(infoOnlyFindings.length);
  });

  it('handles empty findings array', () => {
    const recs = generateFallbackRecommendations([]);
    // Solo findings info (vacío) → "configuración aceptable"
    expect(recs).toHaveLength(1);
    expect(recs[0]!.title).toContain('aceptable');
  });
});
