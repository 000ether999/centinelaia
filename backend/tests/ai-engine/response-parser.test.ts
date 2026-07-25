/**
 * Tests del módulo response-parser.
 *
 * Verifica el comportamiento de parseBedrockResponse ante:
 * - JSON válido completo e incompleto
 * - JSON rodeado de texto libre
 * - Entradas malformadas o vacías
 * - Campos ausentes, fuera de rango e inválidos
 * - Paso de caracteres de control (la sanitización es responsabilidad del validator)
 * - Múltiples findings con cobertura completa
 */

import { describe, it, expect } from 'vitest';
import { parseBedrockResponse } from '../../services/ai-engine/response-parser.js';
import type { Finding } from '../../services/scanner/modules/types.js';

// ─── Fixtures ─────────────────────────────────────────────────────────────────

/** Finding base usado en la mayoría de los tests */
const baseFinding: Finding = {
  category: 'http-headers',
  severity: 'medium',
  rawValue: null,
  description: 'Test finding description here',
};

/** Genera N findings basados en el fixture base */
function makeFindings(n: number): Finding[] {
  return Array.from({ length: n }, () => ({ ...baseFinding }));
}

/** JSON válido para 1 finding (explanation + recommendation correctos) */
const validJson1 = JSON.stringify({
  explanations: [
    { findingIndex: 0, text: 'Explanation text here valid 50+ chars - seguridad importante' },
  ],
  recommendations: [
    {
      title: 'Fix it',
      description: 'Description here at least 10 chars',
      effort: 'quick-win',
      relatedFindings: [0],
    },
  ],
});

// ─── Caso 1: JSON completo válido ─────────────────────────────────────────────

describe('parseBedrockResponse — JSON completo válido', () => {
  it('retorna partial:false con 1 explanation sin fallback y 1 recommendation', () => {
    const findings = makeFindings(1);
    const result = parseBedrockResponse(validJson1, findings);

    // No es parcial: todos los campos están bien
    expect(result.partial).toBe(false);

    // Exactamente 1 explanation, no fallback
    expect(result.explanations).toHaveLength(1);
    expect(result.explanations[0]!.fallback).toBe(false);
    expect(result.explanations[0]!.findingIndex).toBe(0);

    // Exactamente 1 recommendation
    expect(result.recommendations).toHaveLength(1);
    expect(result.recommendations[0]!.title).toBe('Fix it');
    expect(result.recommendations[0]!.effort).toBe('quick-win');
  });
});

// ─── Caso 2: JSON rodeado de texto ────────────────────────────────────────────

describe('parseBedrockResponse — JSON rodeado de texto libre', () => {
  it('extrae el JSON igualmente y retorna partial:false', () => {
    const findings = makeFindings(1);
    // El LLM puede devolver texto antes y después del JSON
    const rawText = `Aquí va el análisis: ${validJson1} y más texto final.`;
    const result = parseBedrockResponse(rawText, findings);

    expect(result.partial).toBe(false);
    expect(result.explanations).toHaveLength(1);
    expect(result.explanations[0]!.fallback).toBe(false);
    expect(result.recommendations).toHaveLength(1);
  });
});

// ─── Caso 3: JSON malformado ──────────────────────────────────────────────────

describe('parseBedrockResponse — JSON malformado', () => {
  it('retorna partial:true con explanations en fallback y recommendations no vacías', () => {
    const findings = makeFindings(2);
    const result = parseBedrockResponse('{esto no es json válido {{{}', findings);

    expect(result.partial).toBe(true);

    // Todas las explanations son fallback
    expect(result.explanations.length).toBeGreaterThan(0);
    expect(result.explanations.every((e) => e.fallback === true)).toBe(true);

    // Hay al menos una recommendation
    expect(result.recommendations.length).toBeGreaterThan(0);
  });
});

// ─── Caso 4: String vacío ─────────────────────────────────────────────────────

describe('parseBedrockResponse — string vacío', () => {
  it('retorna fallback completo con partial:true', () => {
    const findings = makeFindings(2);
    const result = parseBedrockResponse('', findings);

    expect(result.partial).toBe(true);
    // Una explanation por finding, todas fallback
    expect(result.explanations).toHaveLength(findings.length);
    expect(result.explanations.every((e) => e.fallback === true)).toBe(true);
    expect(result.recommendations.length).toBeGreaterThan(0);
  });
});

// ─── Caso 5: Campo explanations ausente ──────────────────────────────────────

describe('parseBedrockResponse — campo explanations ausente', () => {
  it('retorna partial:true pero recommendations presentes', () => {
    const findings = makeFindings(1);
    const json = JSON.stringify({
      // explanations ausente intencionalmente
      recommendations: [
        {
          title: 'Fix it now',
          description: 'Description here at least 10 chars for the fix',
          effort: 'moderate',
          relatedFindings: [0],
        },
      ],
    });

    const result = parseBedrockResponse(json, findings);

    expect(result.partial).toBe(true);
    // Explanations son fallback porque el campo faltaba
    expect(result.explanations.every((e) => e.fallback === true)).toBe(true);
    // Recommendations sí están presentes (vienen del JSON)
    expect(result.recommendations.length).toBeGreaterThan(0);
  });
});

// ─── Caso 6: Campo recommendations ausente ───────────────────────────────────

describe('parseBedrockResponse — campo recommendations ausente', () => {
  it('retorna partial:true pero explanations presentes', () => {
    const findings = makeFindings(1);
    const json = JSON.stringify({
      explanations: [
        { findingIndex: 0, text: 'Explanation text here valid 50+ chars - seguridad importante' },
      ],
      // recommendations ausente intencionalmente
    });

    const result = parseBedrockResponse(json, findings);

    expect(result.partial).toBe(true);
    // La explanation del índice 0 es válida (no fallback)
    expect(result.explanations.some((e) => !e.fallback)).toBe(true);
    // Recommendations vienen del fallback pero no están vacías
    expect(result.recommendations.length).toBeGreaterThan(0);
  });
});

// ─── Caso 7: findingIndex fuera de rango ──────────────────────────────────────

describe('parseBedrockResponse — findingIndex fuera de rango', () => {
  it('descarta la explanation inválida y genera fallback para el finding sin cobertura', () => {
    const findings = makeFindings(1); // solo índice 0 es válido
    const json = JSON.stringify({
      explanations: [
        // Índice 99 no existe → debe descartarse
        { findingIndex: 99, text: 'Explanation text here valid 50+ chars - seguridad importante' },
      ],
      recommendations: [
        {
          title: 'Fix it',
          description: 'Description here at least 10 chars',
          effort: 'quick-win',
          relatedFindings: [0],
        },
      ],
    });

    const result = parseBedrockResponse(json, findings);

    // El finding 0 no tiene explanation real → se genera fallback → partial:true
    expect(result.partial).toBe(true);
    // La explanation generada para el finding 0 debe ser fallback
    const exp0 = result.explanations.find((e) => e.findingIndex === 0);
    expect(exp0).toBeDefined();
    expect(exp0!.fallback).toBe(true);
  });
});

// ─── Caso 8: Texto < 10 chars en explanation ──────────────────────────────────

describe('parseBedrockResponse — texto demasiado corto en explanation', () => {
  it('descarta la explanation corta y genera fallback para ese finding', () => {
    const findings = makeFindings(1);
    const json = JSON.stringify({
      explanations: [
        // Texto solo 5 chars → debe descartarse
        { findingIndex: 0, text: 'corto' },
      ],
      recommendations: [
        {
          title: 'Fix it',
          description: 'Description here at least 10 chars',
          effort: 'quick-win',
          relatedFindings: [0],
        },
      ],
    });

    const result = parseBedrockResponse(json, findings);

    expect(result.partial).toBe(true);
    // La explanation para el finding 0 debe ser fallback
    const exp0 = result.explanations.find((e) => e.findingIndex === 0);
    expect(exp0).toBeDefined();
    expect(exp0!.fallback).toBe(true);
  });
});

// ─── Caso 9: Inyección de caracteres de control en texto de explanation ────────

describe('parseBedrockResponse — caracteres de control en texto de explanation', () => {
  it('acepta la explanation con caracteres de control (sanitización es del validator)', () => {
    const findings = makeFindings(1);
    // Texto con caracteres de control: el parser NO los filtra, eso es del validator
    const textWithControl = 'Explanation with control char \x01 and bell \x07 here for testing purposes';
    const json = JSON.stringify({
      explanations: [
        { findingIndex: 0, text: textWithControl },
      ],
      recommendations: [
        {
          title: 'Fix it',
          description: 'Description here at least 10 chars',
          effort: 'quick-win',
          relatedFindings: [0],
        },
      ],
    });

    const result = parseBedrockResponse(json, findings);

    // El parser acepta la explanation: fallback:false porque el índice es válido y el texto tiene >= 10 chars
    const exp0 = result.explanations.find((e) => e.findingIndex === 0);
    expect(exp0).toBeDefined();
    expect(exp0!.fallback).toBe(false);
  });
});

// ─── Caso 10: Recommendations con effort inválido ────────────────────────────

describe('parseBedrockResponse — recommendations con effort inválido', () => {
  it('descarta esas recommendations; con 0 válidas usa fallback', () => {
    const findings = makeFindings(1);
    const json = JSON.stringify({
      explanations: [
        { findingIndex: 0, text: 'Explanation text here valid 50+ chars - seguridad importante' },
      ],
      recommendations: [
        {
          title: 'Bad rec',
          description: 'Description here at least 10 chars for the rec',
          effort: 'super-fast', // valor inválido, no está en EffortLevel
          relatedFindings: [0],
        },
      ],
    });

    const result = parseBedrockResponse(json, findings);

    // Se descartó la rec inválida → se usa fallback → partial:true
    expect(result.partial).toBe(true);
    // Recommendations no vacías (provienen del fallback)
    expect(result.recommendations.length).toBeGreaterThan(0);
  });
});

// ─── Caso 11: N findings con explanations para todos ─────────────────────────

describe('parseBedrockResponse — N findings con cobertura completa', () => {
  it('retorna partial:false, explanations.length === N, todas fallback:false', () => {
    const N = 5;
    const findings = makeFindings(N);

    // Generar N explanations válidas + N relatedFindings en 1 recommendation
    const explanations = Array.from({ length: N }, (_, i) => ({
      findingIndex: i,
      text: `Explanation for finding ${i} — texto válido con 50+ caracteres aquí seguridad`,
    }));

    const json = JSON.stringify({
      explanations,
      recommendations: [
        {
          title: 'Fix all findings',
          description: 'Description here at least 10 chars for all findings',
          effort: 'moderate',
          relatedFindings: Array.from({ length: N }, (_, i) => i),
        },
      ],
    });

    const result = parseBedrockResponse(json, findings);

    expect(result.partial).toBe(false);
    expect(result.explanations).toHaveLength(N);
    expect(result.explanations.every((e) => e.fallback === false)).toBe(true);
    // findingIndex cubre todos 0..N-1
    const indices = result.explanations.map((e) => e.findingIndex).sort((a, b) => a - b);
    expect(indices).toEqual(Array.from({ length: N }, (_, i) => i));
  });
});
