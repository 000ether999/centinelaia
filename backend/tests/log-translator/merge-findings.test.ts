/**
 * Tests del helper de fusión de hallazgos (mergeFindings).
 * Verifica la combinación de findings directos + findings de Nmap
 * y la generación correcta de sourceContext.
 */

import { describe, it, expect } from 'vitest';
import { mergeFindings } from '../../services/log-translator/merge-findings.js';
import type { Finding } from '../../services/scanner/modules/types.js';

const sampleScannerFinding: Finding = {
  category: 'http-headers',
  severity: 'medium',
  description: 'El header Strict-Transport-Security no está presente en la respuesta.',
  rawValue: null,
};

const sampleNmapOutput = `
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9
443/tcp  open  https    nginx 1.18.0
80/tcp   open  http     Apache httpd 2.4.52
`.trim();

describe('mergeFindings — helper de fusión', () => {
  it('should return findings unchanged when no nmapOutput is provided', () => {
    const result = mergeFindings({
      findings: [sampleScannerFinding],
      sourceContext: 'Escaneo web de example.com',
    });

    expect(result.mergedFindings).toEqual([sampleScannerFinding]);
    expect(result.mergedSourceContext).toBe('Escaneo web de example.com');
  });

  it('should return findings unchanged when nmapOutput is empty string', () => {
    const result = mergeFindings({
      findings: [sampleScannerFinding],
      nmapOutput: '   ',
      sourceContext: 'test',
    });

    expect(result.mergedFindings).toEqual([sampleScannerFinding]);
    expect(result.mergedSourceContext).toBe('test');
  });

  it('should merge scanner findings + nmap findings in correct order', () => {
    const result = mergeFindings({
      findings: [sampleScannerFinding],
      nmapOutput: sampleNmapOutput,
      sourceContext: 'Escaneo web de example.com',
    });

    // Scanner finding first, then 3 nmap findings
    expect(result.mergedFindings).toHaveLength(4);
    expect(result.mergedFindings[0]).toEqual(sampleScannerFinding);
    // Nmap findings should be server-fingerprint category
    expect(result.mergedFindings[1]!.category).toBe('server-fingerprint');
    expect(result.mergedFindings[2]!.category).toBe('server-fingerprint');
    expect(result.mergedFindings[3]!.category).toBe('server-fingerprint');
  });

  it('should build merged sourceContext indicating both sources', () => {
    const result = mergeFindings({
      findings: [sampleScannerFinding],
      nmapOutput: sampleNmapOutput,
      sourceContext: 'Escaneo web de example.com',
    });

    expect(result.mergedSourceContext).toContain('Nmap');
    expect(result.mergedSourceContext).toContain('3');
    expect(result.mergedSourceContext!.length).toBeLessThanOrEqual(200);
  });

  it('should handle nmap-only (no direct scanner findings)', () => {
    const result = mergeFindings({
      findings: [],
      nmapOutput: sampleNmapOutput,
    });

    expect(result.mergedFindings).toHaveLength(3);
    expect(result.mergedSourceContext).toContain('Nmap');
    expect(result.mergedSourceContext!.length).toBeLessThanOrEqual(200);
  });

  it('should never exceed 200 characters in sourceContext', () => {
    const longContext = 'A'.repeat(190);
    const result = mergeFindings({
      findings: [sampleScannerFinding],
      nmapOutput: sampleNmapOutput,
      sourceContext: longContext,
    });

    expect(result.mergedSourceContext!.length).toBeLessThanOrEqual(200);
  });
});
