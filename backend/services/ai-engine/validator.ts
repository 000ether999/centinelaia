/**
 * Validador de entrada del AI Engine.
 * Verifica campos obligatorios, valida estructura de cada Finding,
 * sanitiza valores de texto y trunca el arreglo si excede el límite.
 */

import type { Finding, FindingCategory, FindingSeverity } from '../scanner/modules/types.js';
import type { AnalysisRequest, ValidationResult } from './types.js';

// Conjuntos válidos para validación rápida
const VALID_CATEGORIES: ReadonlySet<string> = new Set<FindingCategory>([
  'http-headers',
  'tls-ssl',
  'cookies',
  'dns-security',
  'server-fingerprint',
]);

const VALID_SEVERITIES: ReadonlySet<string> = new Set<FindingSeverity>([
  'critical',
  'high',
  'medium',
  'low',
  'info',
]);

/** Orden de severidad para truncamiento (descendente: la más grave primero) */
const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** Límite máximo de findings por solicitud */
const MAX_FINDINGS = 50;

/** Longitudes válidas para el campo description */
const MIN_DESCRIPTION_LENGTH = 10;
const MAX_DESCRIPTION_LENGTH = 500;

/** Longitud máxima del campo sourceContext */
const MAX_SOURCE_CONTEXT_LENGTH = 200;

/**
 * Elimina caracteres de control ASCII 0-31 excepto \n (10) y \t (9).
 * Protege contra inyección de caracteres no imprimibles en el prompt.
 */
function sanitizeText(value: string): string {
  // Reemplazar caracteres de control (0-31) excepto \t (9) y \n (10)
  return value.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');
}

/**
 * Valida y sanitiza la solicitud de análisis.
 * Retorna un ValidationResult con el input sanitizado o un error descriptivo.
 */
export function validateAnalysisRequest(input: unknown): ValidationResult {
  // Verificar que el input sea un objeto
  if (!input || typeof input !== 'object') {
    return {
      valid: false,
      error: { message: 'La solicitud debe ser un objeto JSON válido' },
    };
  }

  const request = input as Record<string, unknown>;

  // Validar sessionId obligatorio
  if (!request.sessionId || typeof request.sessionId !== 'string' || request.sessionId.trim() === '') {
    return {
      valid: false,
      error: { message: 'El campo sessionId es obligatorio y no puede estar vacío' },
    };
  }

  // Validar que findings sea un arreglo
  if (!Array.isArray(request.findings)) {
    return {
      valid: false,
      error: { message: 'El campo findings es obligatorio y debe ser un arreglo' },
    };
  }

  // Validar cada finding individualmente
  const findings = request.findings as unknown[];
  for (let i = 0; i < findings.length; i++) {
    const finding = findings[i];

    if (!finding || typeof finding !== 'object') {
      return {
        valid: false,
        error: { message: `Finding en índice ${i}: debe ser un objeto válido`, index: i },
      };
    }

    const f = finding as Record<string, unknown>;

    // Validar category
    if (!f.category || !VALID_CATEGORIES.has(f.category as string)) {
      return {
        valid: false,
        error: {
          message: `Finding en índice ${i}: category inválida o ausente. Valores válidos: ${[...VALID_CATEGORIES].join(', ')}`,
          index: i,
        },
      };
    }

    // Validar severity
    if (!f.severity || !VALID_SEVERITIES.has(f.severity as string)) {
      return {
        valid: false,
        error: {
          message: `Finding en índice ${i}: severity inválida o ausente. Valores válidos: ${[...VALID_SEVERITIES].join(', ')}`,
          index: i,
        },
      };
    }

    // Validar description (obligatorio, string, 10-500 caracteres)
    if (typeof f.description !== 'string') {
      return {
        valid: false,
        error: { message: `Finding en índice ${i}: description es obligatorio y debe ser un string`, index: i },
      };
    }

    if (f.description.length < MIN_DESCRIPTION_LENGTH || f.description.length > MAX_DESCRIPTION_LENGTH) {
      return {
        valid: false,
        error: {
          message: `Finding en índice ${i}: description debe tener entre ${MIN_DESCRIPTION_LENGTH} y ${MAX_DESCRIPTION_LENGTH} caracteres (tiene ${f.description.length})`,
          index: i,
        },
      };
    }

    // Validar rawValue (puede ser string | null)
    if (f.rawValue !== null && typeof f.rawValue !== 'string') {
      return {
        valid: false,
        error: { message: `Finding en índice ${i}: rawValue debe ser string o null`, index: i },
      };
    }
  }

  // Validar sourceContext opcional
  let sourceContext: string | undefined;
  if (request.sourceContext !== undefined) {
    if (typeof request.sourceContext !== 'string') {
      return {
        valid: false,
        error: { message: 'El campo sourceContext debe ser un string' },
      };
    }
    if (request.sourceContext.length > MAX_SOURCE_CONTEXT_LENGTH) {
      return {
        valid: false,
        error: { message: `sourceContext excede el máximo de ${MAX_SOURCE_CONTEXT_LENGTH} caracteres` },
      };
    }
    sourceContext = request.sourceContext;
  }

  // Sanitizar findings (remover caracteres de control)
  let sanitizedFindings: Finding[] = findings.map((f) => {
    const finding = f as Record<string, unknown>;
    return {
      category: finding.category as FindingCategory,
      severity: finding.severity as FindingSeverity,
      rawValue: finding.rawValue !== null ? sanitizeText(finding.rawValue as string) : null,
      description: sanitizeText(finding.description as string),
    };
  });

  // Truncar a 50 findings si excede, priorizando por severidad descendente
  let truncated = false;
  let truncatedCount = 0;

  if (sanitizedFindings.length > MAX_FINDINGS) {
    truncatedCount = sanitizedFindings.length - MAX_FINDINGS;
    truncated = true;

    // Ordenar por severidad descendente (critical primero) y tomar los primeros 50
    sanitizedFindings = sanitizedFindings
      .slice() // copia para no mutar
      .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
      .slice(0, MAX_FINDINGS);
  }

  const sanitizedInput: AnalysisRequest = {
    findings: sanitizedFindings,
    sessionId: request.sessionId as string,
    ...(sourceContext !== undefined && { sourceContext }),
  };

  return {
    valid: true,
    sanitizedInput,
    truncated,
    truncatedCount,
  };
}
