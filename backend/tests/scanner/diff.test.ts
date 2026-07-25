/**
 * Tests para el diff entre escaneos.
 * Verifica clasificación de hallazgos como resueltos, añadidos,
 * sin cambios y con cambio de severidad.
 */

import { describe, it, expect } from 'vitest';
import { diffScans } from '../../services/scanner/diff.js';
import type { Finding } from '../../services/scanner/modules/types.js';
import type { ScanResult } from '../../models/scan.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    category: 'http-headers',
    severity: 'high',
    description: 'Security header missing: HSTS is not configured properly',
    rawValue: null,
    ...overrides,
  };
}

function makeScan(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    scanId: 'scan-1',
    target: 'https://example.com',
    timestamp: '2026-01-01T00:00:00Z',
    durationMs: 1000,
    totalFindings: 0,
    status: 'complete',
    sessionId: 'session-1',
    consent: { authorizationConfirmed: true, target: 'https://example.com', confirmedAt: '2026-01-01T00:00:00Z' },
    findings: [],
    persisted: true,
    ...overrides,
  };
}

describe('diffScans', () => {
  it('hallazgo en from y ausente en to → resolved', () => {
    const finding = makeFinding({ description: 'Cookie sin flag Secure detectada' });
    const from = makeScan({ findings: [finding] });
    const to = makeScan({ scanId: 'scan-2', findings: [] });

    const diff = diffScans(from, to);
    expect(diff.resolved).toHaveLength(1);
    expect(diff.resolved[0].description).toBe(finding.description);
    expect(diff.added).toHaveLength(0);
  });

  it('ausente en from y presente en to → added', () => {
    const finding = makeFinding({ description: 'Nuevo hallazgo encontrado aqui' });
    const from = makeScan({ findings: [] });
    const to = makeScan({ scanId: 'scan-2', findings: [finding] });

    const diff = diffScans(from, to);
    expect(diff.added).toHaveLength(1);
    expect(diff.added[0].description).toBe(finding.description);
    expect(diff.resolved).toHaveLength(0);
  });

  it('presente en ambos con misma severidad → unchanged', () => {
    const finding = makeFinding({ description: 'Hallazgo persistente en ambos escaneos' });
    const from = makeScan({ findings: [finding] });
    const to = makeScan({ scanId: 'scan-2', findings: [finding] });

    const diff = diffScans(from, to);
    expect(diff.unchanged).toHaveLength(1);
    expect(diff.added).toHaveLength(0);
    expect(diff.resolved).toHaveLength(0);
    expect(diff.severityChanged).toHaveLength(0);
  });

  it('severidad distinta → severityChanged Y unchanged, no added', () => {
    const fromFinding = makeFinding({ severity: 'medium', description: 'Cipher debil detectado en la conexion' });
    const toFinding = makeFinding({ severity: 'high', description: 'Cipher debil detectado en la conexion' });
    const from = makeScan({ findings: [fromFinding] });
    const to = makeScan({ scanId: 'scan-2', findings: [toFinding] });

    const diff = diffScans(from, to);
    expect(diff.severityChanged).toHaveLength(1);
    expect(diff.severityChanged[0].from).toBe('medium');
    expect(diff.severityChanged[0].to).toBe('high');
    expect(diff.unchanged).toHaveLength(1);
    expect(diff.added).toHaveLength(0);
  });

  it('findings sin findingId se emparejan igualmente', () => {
    const finding = makeFinding({ description: 'Finding sin id explicito asignado' });
    // Asegurar que no tiene findingId
    delete finding.findingId;
    const from = makeScan({ findings: [finding] });
    const to = makeScan({ scanId: 'scan-2', findings: [{ ...finding }] });

    const diff = diffScans(from, to);
    expect(diff.unchanged).toHaveLength(1);
    expect(diff.added).toHaveLength(0);
    expect(diff.resolved).toHaveLength(0);
  });

  it('targets distintos → warning presente, sin lanzar error', () => {
    const from = makeScan({ target: 'https://a.com' });
    const to = makeScan({ scanId: 'scan-2', target: 'https://b.com' });

    const diff = diffScans(from, to);
    expect(diff.warning).toBeDefined();
    expect(diff.warning).toContain('a.com');
    expect(diff.warning).toContain('b.com');
  });

  it('from vacío → todo en added', () => {
    const f1 = makeFinding({ description: 'Hallazgo uno para test de from vacio' });
    const f2 = makeFinding({ category: 'tls-ssl', description: 'Hallazgo dos para test de from vacio' });
    const from = makeScan({ findings: [] });
    const to = makeScan({ scanId: 'scan-2', findings: [f1, f2] });

    const diff = diffScans(from, to);
    expect(diff.added).toHaveLength(2);
    expect(diff.resolved).toHaveLength(0);
  });

  it('to vacío → todo en resolved', () => {
    const f1 = makeFinding({ description: 'Hallazgo uno para test de to vacio es' });
    const f2 = makeFinding({ category: 'cookies', description: 'Hallazgo dos para test de to vacio es' });
    const from = makeScan({ findings: [f1, f2] });
    const to = makeScan({ scanId: 'scan-2', findings: [] });

    const diff = diffScans(from, to);
    expect(diff.resolved).toHaveLength(2);
    expect(diff.added).toHaveLength(0);
  });

  it('summary coincide con longitudes de arreglos', () => {
    const resolved = makeFinding({ description: 'Hallazgo que sera resuelto en scan dos' });
    const unchanged = makeFinding({ category: 'tls-ssl', description: 'Hallazgo que persiste entre escaneos' });
    const added = makeFinding({ category: 'cookies', description: 'Hallazgo nuevo que aparece en scan dos' });
    const sevFrom = makeFinding({ category: 'cors', severity: 'low', description: 'Hallazgo que cambia de sev en scan' });
    const sevTo = makeFinding({ category: 'cors', severity: 'high', description: 'Hallazgo que cambia de sev en scan' });

    const from = makeScan({ findings: [resolved, unchanged, sevFrom] });
    const to = makeScan({ scanId: 'scan-2', findings: [unchanged, added, sevTo] });

    const diff = diffScans(from, to);
    expect(diff.summary.resolvedCount).toBe(diff.resolved.length);
    expect(diff.summary.addedCount).toBe(diff.added.length);
    expect(diff.summary.unchangedCount).toBe(diff.unchanged.length);
    expect(diff.summary.severityChangedCount).toBe(diff.severityChanged.length);
  });
});
