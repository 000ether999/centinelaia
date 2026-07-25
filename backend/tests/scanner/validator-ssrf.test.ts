/**
 * Tests de cierre SSRF en validateScanRequest y resolveAndCheckIp.
 *
 * Verifica que literales IPv6 (incluyendo formas expandidas y mapped)
 * sean bloqueados correctamente, y que el fail-closed en
 * resolveAndCheckIp(null, null) funcione.
 *
 * Mockea `node:dns/promises` para evitar conexiones reales.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Mock de node:dns/promises ───────────────────────────────────────────────

vi.mock('node:dns/promises', () => ({
  resolve4: vi.fn(),
  resolve6: vi.fn(),
}));

import { resolve4, resolve6 } from 'node:dns/promises';
const mockedResolve4 = vi.mocked(resolve4);
const mockedResolve6 = vi.mocked(resolve6);

import { validateScanRequest, resolveAndCheckIp } from '../../services/scanner/validator.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeRequest(target: string) {
  return {
    target,
    sessionId: 'test-session',
    authorizationConfirmed: true,
  };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('SSRF closure — validateScanRequest blocks private/reserved IPs', () => {
  beforeEach(() => {
    mockedResolve4.mockReset();
    mockedResolve6.mockReset();
    // Por defecto, DNS no resuelve (para targets que son IPs directas)
    mockedResolve4.mockRejectedValue(new Error('no A'));
    mockedResolve6.mockRejectedValue(new Error('no AAAA'));
  });

  it('should block ::1 (IPv6 loopback)', async () => {
    const result = await validateScanRequest(makeRequest('::1'));
    expect(result.valid).toBe(false);
  });

  it('should block fd00::1 (unique local)', async () => {
    const result = await validateScanRequest(makeRequest('fd00::1'));
    expect(result.valid).toBe(false);
  });

  it('should block [::ffff:169.254.169.254] (IPv4-mapped IMDS in brackets)', async () => {
    const result = await validateScanRequest(makeRequest('[::ffff:169.254.169.254]'));
    expect(result.valid).toBe(false);
  });

  it('should block 0:0:0:0:0:ffff:127.0.0.1 (expanded mapped loopback)', async () => {
    const result = await validateScanRequest(makeRequest('0:0:0:0:0:ffff:127.0.0.1'));
    expect(result.valid).toBe(false);
  });

  it('should block 127.0.0.1 (no regression)', async () => {
    const result = await validateScanRequest(makeRequest('127.0.0.1'));
    expect(result.valid).toBe(false);
  });

  it('should block 169.254.169.254 (no regression)', async () => {
    const result = await validateScanRequest(makeRequest('169.254.169.254'));
    expect(result.valid).toBe(false);
  });

  it('should allow 8.8.8.8 (public IPv4)', async () => {
    const result = await validateScanRequest(makeRequest('8.8.8.8'));
    expect(result.valid).toBe(true);
  });

  it('should allow example.com resolving to public IP', async () => {
    mockedResolve4.mockResolvedValue(['93.184.216.34']);
    mockedResolve6.mockRejectedValue(new Error('no AAAA'));

    const result = await validateScanRequest(makeRequest('example.com'));
    expect(result.valid).toBe(true);
  });
});

describe('SSRF closure — resolveAndCheckIp fail-closed', () => {
  it('should return allowed: false when both targetDomain and targetIp are null', async () => {
    const result = await resolveAndCheckIp(null, null);
    expect(result.allowed).toBe(false);
    expect(result.error).toBeDefined();
  });
});
