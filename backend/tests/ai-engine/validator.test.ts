/**
 * Tests del módulo validator (AI Engine).
 *
 * Verifica que validateAnalysisRequest:
 * - Acepta inputs válidos y retorna sanitizedInput correcto
 * - Rechaza inputs no-objeto, sin sessionId, con findings inválidos
 * - Sanitiza caracteres de control en description
 * - Preserva serviceInfo para findings 'port-service'
 * - Trunca a 50 findings preservando los de mayor severidad
 */

import { describe, it, expect } from 'vitest';
import { validateAnalysisRequest } from '../../services/ai-engine/validator.js';

// ─── Fixture base ──────────────────────────────────────────────────────────────

/** Finding mínimo válido */
const validFinding = {
  category: 'http-headers' as const,
  severity: 'medium' as const,
  rawValue: null,
  description: 'Valid description here long enough',
};

// ─── Caso 1: Input válido mínimo ───────────────────────────────────────────────

describe('validateAnalysisRequest — input válido mínimo', () => {
  it('retorna valid:true, sanitizedInput presente y truncated:false', () => {
    const result = validateAnalysisRequest({
      findings: [{ ...validFinding }],
      sessionId: 'test-session',
    });

    expect(result.valid).toBe(true);
    expect(result.sanitizedInput).toBeDefined();
    expect(result.truncated).toBe(false);
    // sanitizedInput debe tener el finding y el sessionId
    expect(result.sanitizedInput!.findings).toHaveLength(1);
    expect(result.sanitizedInput!.sessionId).toBe('test-session');
  });
});

// ─── Caso 2: Input no-objeto ───────────────────────────────────────────────────

describe('validateAnalysisRequest — input no-objeto', () => {
  it('retorna valid:false para null', () => {
    const result = validateAnalysisRequest(null);
    expect(result.valid).toBe(false);
  });

  it('retorna valid:false para número', () => {
    const result = validateAnalysisRequest(42);
    expect(result.valid).toBe(false);
  });

  it('retorna valid:false para string', () => {
    const result = validateAnalysisRequest('hola');
    expect(result.valid).toBe(false);
  });
});

// ─── Caso 3: sessionId ausente ─────────────────────────────────────────────────

describe('validateAnalysisRequest — sessionId ausente', () => {
  it('retorna valid:false y error.message menciona sessionId', () => {
    const result = validateAnalysisRequest({
      findings: [{ ...validFinding }],
      // sessionId ausente
    });

    expect(result.valid).toBe(false);
    expect(result.error?.message.toLowerCase()).toContain('sessionid');
  });
});

// ─── Caso 4: sessionId vacío ───────────────────────────────────────────────────

describe('validateAnalysisRequest — sessionId vacío', () => {
  it('retorna valid:false cuando sessionId es string vacío', () => {
    const result = validateAnalysisRequest({
      findings: [{ ...validFinding }],
      sessionId: '',
    });

    expect(result.valid).toBe(false);
  });

  it('retorna valid:false cuando sessionId es solo espacios', () => {
    const result = validateAnalysisRequest({
      findings: [{ ...validFinding }],
      sessionId: '   ',
    });

    expect(result.valid).toBe(false);
  });
});

// ─── Caso 5: findings no-array ─────────────────────────────────────────────────

describe('validateAnalysisRequest — findings no-array', () => {
  it('retorna valid:false cuando findings es un objeto', () => {
    const result = validateAnalysisRequest({
      findings: { category: 'http-headers' },
      sessionId: 'test-session',
    });

    expect(result.valid).toBe(false);
  });

  it('retorna valid:false cuando findings es null', () => {
    const result = validateAnalysisRequest({
      findings: null,
      sessionId: 'test-session',
    });

    expect(result.valid).toBe(false);
  });
});

// ─── Caso 6: Finding con category inválida ─────────────────────────────────────

describe('validateAnalysisRequest — category inválida', () => {
  it('retorna valid:false y error.index === 0', () => {
    const result = validateAnalysisRequest({
      findings: [{ ...validFinding, category: 'sql-injection' }],
      sessionId: 'test-session',
    });

    expect(result.valid).toBe(false);
    expect(result.error?.index).toBe(0);
  });
});

// ─── Caso 7: Finding con severity inválida ─────────────────────────────────────

describe('validateAnalysisRequest — severity inválida', () => {
  it('retorna valid:false', () => {
    const result = validateAnalysisRequest({
      findings: [{ ...validFinding, severity: 'blocker' }],
      sessionId: 'test-session',
    });

    expect(result.valid).toBe(false);
  });
});

// ─── Caso 8: Finding con description < 10 chars ────────────────────────────────

describe('validateAnalysisRequest — description demasiado corta', () => {
  it('retorna valid:false', () => {
    const result = validateAnalysisRequest({
      findings: [{ ...validFinding, description: 'Corta' }],
      sessionId: 'test-session',
    });

    expect(result.valid).toBe(false);
  });
});

// ─── Caso 9: Finding con description > 500 chars ──────────────────────────────

describe('validateAnalysisRequest — description demasiado larga', () => {
  it('retorna valid:false', () => {
    const result = validateAnalysisRequest({
      findings: [{ ...validFinding, description: 'A'.repeat(501) }],
      sessionId: 'test-session',
    });

    expect(result.valid).toBe(false);
  });
});

// ─── Caso 10: rawValue tipo number ─────────────────────────────────────────────

describe('validateAnalysisRequest — rawValue tipo number', () => {
  it('retorna valid:false porque rawValue debe ser string o null', () => {
    const result = validateAnalysisRequest({
      findings: [{ ...validFinding, rawValue: 42 }],
      sessionId: 'test-session',
    });

    expect(result.valid).toBe(false);
  });
});

// ─── Caso 11: sourceContext > 200 chars ───────────────────────────────────────

describe('validateAnalysisRequest — sourceContext demasiado largo', () => {
  it('retorna valid:false', () => {
    const result = validateAnalysisRequest({
      findings: [{ ...validFinding }],
      sessionId: 'test-session',
      sourceContext: 'X'.repeat(201),
    });

    expect(result.valid).toBe(false);
  });
});

// ─── Caso 12: Caracteres de control en description ────────────────────────────

describe('validateAnalysisRequest — sanitización de caracteres de control', () => {
  it('retorna valid:true y sanitizedInput.findings[0].description sin caracteres de control', () => {
    // \x01 (SOH) y \x07 (BEL) son caracteres de control que deben eliminarse
    const result = validateAnalysisRequest({
      findings: [{ ...validFinding, description: 'Valid description \x01 with control \x07 chars here' }],
      sessionId: 'test-session',
    });

    expect(result.valid).toBe(true);
    expect(result.sanitizedInput).toBeDefined();

    const sanitizedDesc = result.sanitizedInput!.findings[0]!.description;
    // Los caracteres de control deben haber sido eliminados
    expect(sanitizedDesc).not.toContain('\x01');
    expect(sanitizedDesc).not.toContain('\x07');
    // El texto legible sí debe estar
    expect(sanitizedDesc).toContain('Valid description');
  });
});

// ─── Caso 13: category port-service con serviceInfo ───────────────────────────

describe('validateAnalysisRequest — port-service con serviceInfo', () => {
  it('retorna valid:true y serviceInfo preservado en sanitizedInput', () => {
    const serviceInfo = {
      port: 22,
      protocol: 'tcp',
      state: 'open',
      service: 'ssh',
      version: 'OpenSSH 8.9',
    };

    const result = validateAnalysisRequest({
      findings: [
        {
          category: 'port-service',
          severity: 'medium',
          rawValue: null,
          description: 'Port 22 is open and running SSH service on this host',
          serviceInfo,
        },
      ],
      sessionId: 'test-session',
    });

    expect(result.valid).toBe(true);
    expect(result.sanitizedInput).toBeDefined();
    // serviceInfo debe estar presente en el finding sanitizado
    expect(result.sanitizedInput!.findings[0]!.serviceInfo).toBeDefined();
    expect(result.sanitizedInput!.findings[0]!.serviceInfo).toEqual(serviceInfo);
  });
});

// ─── Caso 14: Truncado a 50 findings ──────────────────────────────────────────

describe('validateAnalysisRequest — truncado a 50 findings por severidad', () => {
  it('con 51 findings: valid:true, truncated:true, truncatedCount:1, 50 findings, de mayor severidad', () => {
    // Crear 51 findings: 1 'info' y 50 'medium' — el 'info' debe descartarse al truncar
    const findings = [
      // El finding 'info' debería ser descartado (es el de menor severidad)
      {
        category: 'http-headers' as const,
        severity: 'info' as const,
        rawValue: null,
        description: 'Informational finding that should be dropped on truncation here',
      },
      // 50 findings 'medium' que deben mantenerse
      ...Array.from({ length: 50 }, (_, i) => ({
        category: 'http-headers' as const,
        severity: 'medium' as const,
        rawValue: null,
        description: `Medium severity finding number ${i + 1} here for testing purposes`,
      })),
    ];

    const result = validateAnalysisRequest({ findings, sessionId: 'test-session' });

    expect(result.valid).toBe(true);
    expect(result.truncated).toBe(true);
    expect(result.truncatedCount).toBe(1);
    expect(result.sanitizedInput!.findings).toHaveLength(50);

    // Todos los 50 findings resultantes deben ser 'medium', no 'info'
    const severities = result.sanitizedInput!.findings.map((f) => f.severity);
    expect(severities.every((s) => s === 'medium')).toBe(true);
  });
});

// ─── Caso 15: findings array vacío ────────────────────────────────────────────

describe('validateAnalysisRequest — findings array vacío', () => {
  it('retorna valid:true con sanitizedInput.findings vacío', () => {
    const result = validateAnalysisRequest({
      findings: [],
      sessionId: 'test-session',
    });

    expect(result.valid).toBe(true);
    expect(result.sanitizedInput).toBeDefined();
    expect(result.sanitizedInput!.findings).toHaveLength(0);
  });
});
