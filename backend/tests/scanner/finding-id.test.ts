/**
 * Tests para la generación de findingId estable.
 * Verifica determinismo, normalización e inmutabilidad.
 */

import { describe, it, expect } from 'vitest';
import { computeFindingId, attachFindingIds } from '../../services/scanner/finding-id.js';
import type { Finding } from '../../services/scanner/modules/types.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    category: 'http-headers',
    severity: 'high',
    description: 'Security header missing: HSTS is not configured',
    rawValue: null,
    ...overrides,
  };
}

describe('computeFindingId', () => {
  it('produce el mismo id para el mismo finding en dos invocaciones', () => {
    const finding = makeFinding();
    const id1 = computeFindingId(finding);
    const id2 = computeFindingId(finding);
    expect(id1).toBe(id2);
  });

  it('descripciones que solo difieren en dígitos producen el mismo id', () => {
    const a = makeFinding({ description: 'El certificado expira en 12 dias' });
    const b = makeFinding({ description: 'El certificado expira en 11 dias' });
    expect(computeFindingId(a)).toBe(computeFindingId(b));
  });

  it('cambiar category produce id distinto', () => {
    const a = makeFinding({ category: 'http-headers' });
    const b = makeFinding({ category: 'tls-ssl' });
    expect(computeFindingId(a)).not.toBe(computeFindingId(b));
  });

  it('cambiar rawValue produce id distinto', () => {
    const a = makeFinding({ rawValue: 'value-a' });
    const b = makeFinding({ rawValue: 'value-b' });
    expect(computeFindingId(a)).not.toBe(computeFindingId(b));
  });

  it('texto no numérico distinto en description produce id distinto', () => {
    const a = makeFinding({ description: 'Security header missing: HSTS is not configured' });
    const b = makeFinding({ description: 'Security header missing: CSP is not configured' });
    expect(computeFindingId(a)).not.toBe(computeFindingId(b));
  });

  it('diferencias de mayúsculas producen el mismo id', () => {
    const a = makeFinding({ description: 'Security Header MISSING' });
    const b = makeFinding({ description: 'security header missing' });
    expect(computeFindingId(a)).toBe(computeFindingId(b));
  });

  it('múltiples espacios se colapsan y producen el mismo id', () => {
    const a = makeFinding({ description: 'security  header   missing here' });
    const b = makeFinding({ description: 'security header missing here' });
    expect(computeFindingId(a)).toBe(computeFindingId(b));
  });

  it('rawValue: null vs rawValue: "" — comportamiento documentado: producen el MISMO id', () => {
    // Ambos se normalizan a cadena vacía internamente.
    // null → '' y '' → ''.toLowerCase().replace(...) = ''
    const a = makeFinding({ rawValue: null });
    const b = makeFinding({ rawValue: '' });
    expect(computeFindingId(a)).toBe(computeFindingId(b));
  });

  it('el id tiene exactamente 16 caracteres hexadecimales', () => {
    const id = computeFindingId(makeFinding());
    expect(id).toHaveLength(16);
    expect(id).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe('attachFindingIds', () => {
  it('no muta la entrada', () => {
    const original: Finding[] = [makeFinding()];
    const originalCopy = JSON.parse(JSON.stringify(original));
    attachFindingIds(original);
    expect(original).toEqual(originalCopy);
    expect(original[0].findingId).toBeUndefined();
  });

  it('devuelve copias con findingId poblado', () => {
    const findings: Finding[] = [makeFinding(), makeFinding({ category: 'tls-ssl' })];
    const result = attachFindingIds(findings);
    expect(result).toHaveLength(2);
    expect(result[0].findingId).toBeDefined();
    expect(result[1].findingId).toBeDefined();
    expect(result[0].findingId).not.toBe(result[1].findingId);
  });
});
