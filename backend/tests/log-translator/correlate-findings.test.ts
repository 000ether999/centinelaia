/**
 * Tests unitarios de correlateFindings (correlación determinista sin IA).
 * Cubre:
 *  - Regla 1: puerto/servicio HTTPS (Nmap) ↔ hallazgo TLS/SSL (scanner).
 *  - Regla 2: versión (Nmap) ↔ CVE (cve-enricher) para el mismo servicio.
 *  - Caso defensivo: sin coincidencias entre fuentes → no emite nada.
 */

import { describe, it, expect } from 'vitest';
import { correlateFindings } from '../../services/log-translator/correlate-findings.js';
import type { Finding } from '../../services/scanner/modules/types.js';
import { convertNmapServiceRowToFinding, type NmapServiceRow } from '../../services/log-translator/nmap-parser.js';

function nmapFinding(row: NmapServiceRow): Finding {
  return convertNmapServiceRowToFinding(row);
}

describe('correlateFindings — correlación determinista por reglas', () => {
  it('emits a correlation finding when an https Nmap service matches a scanner TLS finding', () => {
    const tlsFinding: Finding = {
      category: 'tls-ssl',
      severity: 'high',
      rawValue: 'TLSv1.0',
      description: 'El servidor acepta TLS 1.0 que es un protocolo obsoleto e inseguro.',
    };

    const nmapHttpsFinding = nmapFinding({
      port: 443,
      protocol: 'tcp',
      state: 'open',
      service: 'https',
      version: 'nginx 1.18.0',
    });

    const correlations = correlateFindings([tlsFinding, nmapHttpsFinding]);

    expect(correlations.length).toBeGreaterThanOrEqual(1);
    const portCorrelation = correlations.find((c) => c.rawValue?.includes('port:443'));
    expect(portCorrelation).toBeDefined();
    expect(portCorrelation!.category).toBe('correlation');
    expect(portCorrelation!.severity).toBe('high');
    expect(portCorrelation!.description).toContain('443');
    expect(portCorrelation!.description.length).toBeGreaterThanOrEqual(10);
    expect(portCorrelation!.description.length).toBeLessThanOrEqual(500);
  });

  it('emits a correlation finding when a versioned Nmap service matches a known-vulnerabilities CVE', () => {
    const nmapHttpsFinding = nmapFinding({
      port: 443,
      protocol: 'tcp',
      state: 'open',
      service: 'https',
      version: 'nginx 1.18.0',
    });

    const cveFinding: Finding = {
      category: 'known-vulnerabilities',
      severity: 'critical',
      rawValue: 'CVE-2021-23017 (CVSS 9.4)',
      description: 'https nginx 1.18.0: nginx resolver off-by-one heap write vulnerability',
    };

    const correlations = correlateFindings([nmapHttpsFinding, cveFinding]);

    const versionCorrelation = correlations.find((c) => c.rawValue?.includes('CVE-2021-23017'));
    expect(versionCorrelation).toBeDefined();
    expect(versionCorrelation!.category).toBe('correlation');
    expect(versionCorrelation!.severity).toBe('critical');
    expect(versionCorrelation!.description).toContain('CVE-2021-23017');
    expect(versionCorrelation!.description).toContain('443');
  });

  it('returns an empty array when there are no cross-source matches (defensive, no-op)', () => {
    // Solo findings del scanner, sin ningún finding derivado de Nmap
    const onlyScannerFindings: Finding[] = [
      {
        category: 'http-headers',
        severity: 'medium',
        rawValue: null,
        description: 'El header Strict-Transport-Security no está presente en la respuesta.',
      },
      {
        category: 'tls-ssl',
        severity: 'high',
        rawValue: 'TLSv1.0',
        description: 'El servidor acepta TLS 1.0 que es un protocolo obsoleto e inseguro.',
      },
    ];

    expect(correlateFindings(onlyScannerFindings)).toEqual([]);
    expect(correlateFindings([])).toEqual([]);
  });

  it('returns an empty array when Nmap services do not overlap with any scanner/CVE finding', () => {
    // Servicio SSH de Nmap sin ningún hallazgo TLS ni CVE relacionado
    const sshFinding = nmapFinding({
      port: 22,
      protocol: 'tcp',
      state: 'open',
      service: 'ssh',
      version: 'OpenSSH 8.9',
    });

    const unrelatedFinding: Finding = {
      category: 'cookies',
      severity: 'low',
      rawValue: null,
      description: 'La cookie de sesión no tiene el atributo Secure configurado.',
    };

    expect(correlateFindings([sshFinding, unrelatedFinding])).toEqual([]);
  });
});
