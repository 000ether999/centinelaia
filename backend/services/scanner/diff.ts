/**
 * Diff entre dos escaneos sucesivos.
 * Empareja findings por findingId (calculado al vuelo si no existe) y
 * clasifica cada hallazgo como resuelto, nuevo, sin cambios o con severidad modificada.
 * Opera en modo fail-open: nunca lanza un error por targets distintos, solo avisa.
 */

import type { Finding, FindingSeverity } from './modules/types.js';
import type { ScanResult } from '../../models/scan.js';
import { computeFindingId } from './finding-id.js';

export interface ScanDiff {
  fromScanId: string;
  toScanId: string;
  target: string;
  fromTimestamp: string;
  toTimestamp: string;
  resolved: Finding[];
  added: Finding[];
  unchanged: Finding[];
  severityChanged: Array<{ finding: Finding; from: FindingSeverity; to: FindingSeverity }>;
  warning?: string;
  summary: {
    resolvedCount: number;
    addedCount: number;
    unchangedCount: number;
    severityChangedCount: number;
  };
}

/**
 * Obtiene el findingId de un finding, calculándolo al vuelo si no existe.
 */
function getFindingId(finding: Finding): string {
  return finding.findingId ?? computeFindingId(finding);
}

/**
 * Calcula el diff entre dos resultados de escaneo.
 * - Hallazgo en `from` y ausente en `to` → resolved
 * - Ausente en `from` y presente en `to` → added
 * - Presente en ambos con misma severidad → unchanged
 * - Presente en ambos con severidad distinta → severityChanged Y unchanged (sigue abierto)
 * - Si targets son distintos, incluye warning sin lanzar error
 */
export function diffScans(from: ScanResult, to: ScanResult): ScanDiff {
  const warning = from.target !== to.target
    ? `Los targets difieren: '${from.target}' vs '${to.target}'. El diff puede no ser significativo.`
    : undefined;

  // Indexar findings del from por findingId
  const fromMap = new Map<string, Finding>();
  for (const f of from.findings) {
    fromMap.set(getFindingId(f), f);
  }

  // Indexar findings del to por findingId
  const toMap = new Map<string, Finding>();
  for (const f of to.findings) {
    toMap.set(getFindingId(f), f);
  }

  const resolved: Finding[] = [];
  const added: Finding[] = [];
  const unchanged: Finding[] = [];
  const severityChanged: Array<{ finding: Finding; from: FindingSeverity; to: FindingSeverity }> = [];

  // Findings que estaban en from pero no en to → resolved
  for (const [id, finding] of fromMap) {
    if (!toMap.has(id)) {
      resolved.push(finding);
    }
  }

  // Findings en to: comparar con from
  for (const [id, toFinding] of toMap) {
    const fromFinding = fromMap.get(id);
    if (!fromFinding) {
      // Nuevo hallazgo
      added.push(toFinding);
    } else {
      // Presente en ambos — va a unchanged
      unchanged.push(toFinding);
      // Si la severidad cambió, también registrarlo en severityChanged
      if (fromFinding.severity !== toFinding.severity) {
        severityChanged.push({
          finding: toFinding,
          from: fromFinding.severity,
          to: toFinding.severity,
        });
      }
    }
  }

  const result: ScanDiff = {
    fromScanId: from.scanId,
    toScanId: to.scanId,
    target: to.target,
    fromTimestamp: from.timestamp,
    toTimestamp: to.timestamp,
    resolved,
    added,
    unchanged,
    severityChanged,
    summary: {
      resolvedCount: resolved.length,
      addedCount: added.length,
      unchangedCount: unchanged.length,
      severityChangedCount: severityChanged.length,
    },
  };

  if (warning) {
    result.warning = warning;
  }

  return result;
}
