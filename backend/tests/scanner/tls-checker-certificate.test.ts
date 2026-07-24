/**
 * Tests unitarios para analyzeCertificate del tls-checker.
 *
 * Verifica que el veredicto nativo de OpenSSL (authorized/authorizationError)
 * se usa como fuente primaria para la validación de cadena de confianza.
 * Sin conexiones de red — pruebas puras de la función exportada.
 */

import { describe, it, expect } from 'vitest';
import type tls from 'node:tls';
import { analyzeCertificate } from '../../services/scanner/modules/tls-checker.js';

// ─── Helpers para crear certificados de prueba ───────────────────────────────

function createMockCert(overrides: Partial<tls.DetailedPeerCertificate> = {}): tls.DetailedPeerCertificate {
  const baseCert: tls.DetailedPeerCertificate = {
    subject: { CN: 'example.com', O: 'Example Inc', C: 'US' } as any,
    issuer: { CN: 'Let\'s Encrypt Authority X3', O: 'Let\'s Encrypt', C: 'US' } as any,
    valid_from: '2025-01-01T00:00:00.000Z',
    valid_to: '2027-12-31T23:59:59.000Z',
    subjectaltname: 'DNS:example.com, DNS:www.example.com',
    serialNumber: 'ABC123',
    fingerprint: 'AA:BB:CC',
    fingerprint256: 'AA:BB:CC:DD',
    raw: Buffer.from(''),
    issuerCertificate: { subject: { CN: 'Let\'s Encrypt Authority X3' } } as any,
    ...overrides,
  } as any;
  return baseCert;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('tls-checker — analyzeCertificate with OpenSSL verdict', () => {
  it('authorized=true should NOT generate untrusted chain finding', () => {
    const cert = createMockCert();
    const findings = analyzeCertificate(cert, 'example.com', true, undefined);

    // No debe haber findings de cadena no confiable
    const chainFinding = findings.find(
      f => f.description.includes('not trusted') ||
           f.description.includes('self-signed') ||
           f.description.includes('incomplete'),
    );
    expect(chainFinding).toBeUndefined();

    // Debe haber un finding info confirmando que la cadena es válida
    const validFinding = findings.find(
      f => f.severity === 'info' && f.description.includes('valid and trusted'),
    );
    expect(validFinding).toBeDefined();
  });

  it('authorized=false with DEPTH_ZERO_SELF_SIGNED_CERT should generate self-signed finding', () => {
    const cert = createMockCert({
      issuer: { CN: 'example.com', O: 'Example Inc', C: 'US' } as any,
      issuerCertificate: undefined as any,
    });
    const findings = analyzeCertificate(
      cert,
      'example.com',
      false,
      'DEPTH_ZERO_SELF_SIGNED_CERT',
    );

    const selfSignedFinding = findings.find(
      f => f.severity === 'high' && f.description.includes('self-signed'),
    );
    expect(selfSignedFinding).toBeDefined();
    expect(selfSignedFinding!.rawValue).toContain('DEPTH_ZERO_SELF_SIGNED_CERT');
  });

  it('authorized=false with CERT_HAS_EXPIRED should generate expired finding', () => {
    const cert = createMockCert({
      valid_to: '2020-01-01T00:00:00.000Z',
    });
    const findings = analyzeCertificate(
      cert,
      'example.com',
      false,
      'CERT_HAS_EXPIRED',
    );

    const expiredFinding = findings.find(
      f => f.severity === 'critical' && f.description.includes('expired'),
    );
    expect(expiredFinding).toBeDefined();
  });

  it('authorized=false with UNABLE_TO_VERIFY_LEAF_SIGNATURE should generate untrusted finding', () => {
    const cert = createMockCert();
    const findings = analyzeCertificate(
      cert,
      'example.com',
      false,
      'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
    );

    const untrustedFinding = findings.find(
      f => f.severity === 'high' && f.description.includes('not trusted'),
    );
    expect(untrustedFinding).toBeDefined();
    expect(untrustedFinding!.rawValue).toContain('UNABLE_TO_VERIFY_LEAF_SIGNATURE');
  });

  it('authorized=false with ERR_TLS_CERT_ALTNAME_INVALID should generate hostname mismatch finding', () => {
    const cert = createMockCert();
    const findings = analyzeCertificate(
      cert,
      'other.com',
      false,
      'Hostname/IP does not match certificate\'s altnames',
    );

    const mismatchFinding = findings.find(
      f => f.severity === 'high' && f.description.includes('hostname mismatch'),
    );
    expect(mismatchFinding).toBeDefined();
  });
});
