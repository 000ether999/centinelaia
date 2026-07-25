/**
 * Generación de IDs estables para findings.
 * Permite emparejar hallazgos entre escaneos sucesivos sin depender
 * del orden, timestamp u otros campos volátiles.
 *
 * 16 hex = 64 bits de entropía — suficiente para el volumen esperado de findings
 * por escaneo (decenas a cientos), muy lejos de probabilidad de colisión significativa.
 */

import { createHash } from 'node:crypto';
import type { Finding } from './modules/types.js';

/**
 * Normaliza la descripción para el cálculo del ID:
 * - Minúsculas
 * - Espacios múltiples colapsados a uno
 * - Secuencias de dígitos reemplazadas por '#' (para que "expira en 12 días"
 *   y "expira en 11 días" generen el mismo id)
 */
function normalizeDescription(description: string): string {
  return description
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .replace(/\d+/g, '#');
}

/**
 * Normaliza rawValue para el cálculo del ID:
 * - Si es null, se usa cadena vacía
 * - Si no es null: minúsculas y espacios colapsados
 */
function normalizeRawValue(rawValue: string | null): string {
  if (rawValue === null) return '';
  return rawValue.toLowerCase().replace(/\s+/g, ' ');
}

/**
 * Calcula un ID estable y determinista para un finding.
 * Basado en SHA-256 de (category + rawValue normalizado + description normalizada),
 * separados por \u0000. Retorna los primeros 16 caracteres hex.
 */
export function computeFindingId(finding: Finding): string {
  const category = finding.category;
  const rawValue = normalizeRawValue(finding.rawValue);
  const description = normalizeDescription(finding.description);

  const input = [category, rawValue, description].join('\u0000');
  const hash = createHash('sha256').update(input).digest('hex');
  return hash.slice(0, 16);
}

/**
 * Devuelve copias de los findings con findingId poblado.
 * No muta la entrada.
 */
export function attachFindingIds(findings: Finding[]): Finding[] {
  return findings.map((f) => ({
    ...f,
    findingId: computeFindingId(f),
  }));
}
