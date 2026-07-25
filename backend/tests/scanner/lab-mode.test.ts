/**
 * Tests del modo laboratorio (Ola 13a).
 *
 * Verifica que isLabModeEnabled() respeta el candado anti-Lambda,
 * que validateScanRequest acepta targets privados en modo laboratorio,
 * y que el comportamiento normal no se altera sin el flag.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ─── Mock de node:dns/promises ───────────────────────────────────────────────

vi.mock('node:dns/promises', () => ({
  resolve4: vi.fn(),
  resolve6: vi.fn(),
}));

import { resolve4, resolve6 } from 'node:dns/promises';
const mockedResolve4 = vi.mocked(resolve4);
const mockedResolve6 = vi.mocked(resolve6);

import { isLabModeEnabled } from '../../services/scanner/safe-agent.js';
import { validateScanRequest, resolveAndCheckIp } from '../../services/scanner/validator.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Guarda las variables de entorno originales para restaurarlas. */
const originalEnv: Record<string, string | undefined> = {};
const LAB_VARS = ['CENTINELAIA_ALLOW_PRIVATE_TARGETS', 'AWS_LAMBDA_FUNCTION_NAME'];

function saveEnv() {
  for (const key of LAB_VARS) {
    originalEnv[key] = process.env[key];
  }
}

function restoreEnv() {
  for (const key of LAB_VARS) {
    if (originalEnv[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = originalEnv[key];
    }
  }
}

function makeRequest(target: string) {
  return {
    target,
    sessionId: 'lab-test',
    authorizationConfirmed: true,
  };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('isLabModeEnabled()', () => {
  beforeEach(() => {
    saveEnv();
    mockedResolve4.mockReset();
    mockedResolve6.mockReset();
  });

  afterEach(() => {
    restoreEnv();
  });

  it('returns false without the environment variable', () => {
    delete process.env['CENTINELAIA_ALLOW_PRIVATE_TARGETS'];
    delete process.env['AWS_LAMBDA_FUNCTION_NAME'];
    expect(isLabModeEnabled()).toBe(false);
  });

  it('returns true with CENTINELAIA_ALLOW_PRIVATE_TARGETS=true and NO Lambda', () => {
    process.env['CENTINELAIA_ALLOW_PRIVATE_TARGETS'] = 'true';
    delete process.env['AWS_LAMBDA_FUNCTION_NAME'];
    expect(isLabModeEnabled()).toBe(true);
  });

  it('CANDADO ANTI-LAMBDA: returns false when flag is true BUT running in Lambda', () => {
    process.env['CENTINELAIA_ALLOW_PRIVATE_TARGETS'] = 'true';
    process.env['AWS_LAMBDA_FUNCTION_NAME'] = 'centinelaia-scan';
    expect(isLabModeEnabled()).toBe(false);
  });

  it('returns false when flag is not exactly "true"', () => {
    process.env['CENTINELAIA_ALLOW_PRIVATE_TARGETS'] = 'yes';
    delete process.env['AWS_LAMBDA_FUNCTION_NAME'];
    expect(isLabModeEnabled()).toBe(false);
  });

  it('returns false with empty Lambda function name (treated as absent)', () => {
    process.env['CENTINELAIA_ALLOW_PRIVATE_TARGETS'] = 'true';
    process.env['AWS_LAMBDA_FUNCTION_NAME'] = '';
    expect(isLabModeEnabled()).toBe(true);
  });
});

describe('validateScanRequest — lab mode ACTIVE', () => {
  beforeEach(() => {
    saveEnv();
    process.env['CENTINELAIA_ALLOW_PRIVATE_TARGETS'] = 'true';
    delete process.env['AWS_LAMBDA_FUNCTION_NAME'];
    mockedResolve4.mockReset();
    mockedResolve6.mockReset();
    // En modo lab, los targets privados resuelven a sí mismos
    mockedResolve4.mockResolvedValue(['127.0.0.1']);
    mockedResolve6.mockRejectedValue(new Error('no AAAA'));
  });

  afterEach(() => {
    restoreEnv();
  });

  it('accepts localhost:8081', async () => {
    const result = await validateScanRequest(makeRequest('localhost:8081'));
    expect(result.valid).toBe(true);
    expect(result.normalized?.targetUrl).toBe('http://localhost:8081');
  });

  it('accepts 127.0.0.1:8081', async () => {
    const result = await validateScanRequest(makeRequest('127.0.0.1:8081'));
    expect(result.valid).toBe(true);
    expect(result.normalized?.targetUrl).toBe('http://127.0.0.1:8081');
  });

  it('accepts http://192.168.1.50:3000', async () => {
    mockedResolve4.mockRejectedValue(new Error('no A'));
    const result = await validateScanRequest(makeRequest('http://192.168.1.50:3000'));
    expect(result.valid).toBe(true);
    expect(result.normalized?.targetUrl).toBe('http://192.168.1.50:3000');
  });

  it('accepts http://localhost:8081', async () => {
    const result = await validateScanRequest(makeRequest('http://localhost:8081'));
    expect(result.valid).toBe(true);
  });

  it('accepts bare localhost without port', async () => {
    const result = await validateScanRequest(makeRequest('localhost'));
    expect(result.valid).toBe(true);
    expect(result.normalized?.targetUrl).toBe('http://localhost');
  });

  it('accepts lab-style host (target-a)', async () => {
    const result = await validateScanRequest(makeRequest('target-a'));
    expect(result.valid).toBe(true);
  });
});

describe('validateScanRequest — lab mode INACTIVE (no regression)', () => {
  beforeEach(() => {
    saveEnv();
    delete process.env['CENTINELAIA_ALLOW_PRIVATE_TARGETS'];
    delete process.env['AWS_LAMBDA_FUNCTION_NAME'];
    mockedResolve4.mockReset();
    mockedResolve6.mockReset();
    mockedResolve4.mockRejectedValue(new Error('no A'));
    mockedResolve6.mockRejectedValue(new Error('no AAAA'));
  });

  afterEach(() => {
    restoreEnv();
  });

  it('rejects localhost:8081', async () => {
    const result = await validateScanRequest(makeRequest('localhost:8081'));
    expect(result.valid).toBe(false);
  });

  it('rejects 127.0.0.1:8081', async () => {
    const result = await validateScanRequest(makeRequest('127.0.0.1:8081'));
    expect(result.valid).toBe(false);
  });

  it('rejects http://192.168.1.50:3000', async () => {
    const result = await validateScanRequest(makeRequest('http://192.168.1.50:3000'));
    expect(result.valid).toBe(false);
  });

  it('rejects localhost (no TLD)', async () => {
    const result = await validateScanRequest(makeRequest('localhost'));
    expect(result.valid).toBe(false);
  });

  it('still allows 8.8.8.8 (public IP)', async () => {
    const result = await validateScanRequest(makeRequest('8.8.8.8'));
    expect(result.valid).toBe(true);
  });

  it('still allows example.com resolving to public IP', async () => {
    mockedResolve4.mockResolvedValue(['93.184.216.34']);
    const result = await validateScanRequest(makeRequest('example.com'));
    expect(result.valid).toBe(true);
  });
});

describe('resolveAndCheckIp — fail-closed invariant', () => {
  beforeEach(() => {
    saveEnv();
  });

  afterEach(() => {
    restoreEnv();
  });

  it('returns allowed: false when both domain and IP are null (lab mode OFF)', async () => {
    delete process.env['CENTINELAIA_ALLOW_PRIVATE_TARGETS'];
    const result = await resolveAndCheckIp(null, null);
    expect(result.allowed).toBe(false);
  });

  it('returns allowed: false when both domain and IP are null (lab mode ON)', async () => {
    process.env['CENTINELAIA_ALLOW_PRIVATE_TARGETS'] = 'true';
    delete process.env['AWS_LAMBDA_FUNCTION_NAME'];
    const result = await resolveAndCheckIp(null, null);
    expect(result.allowed).toBe(false);
  });
});

describe('resolveAndCheckIp — improved error messages', () => {
  beforeEach(() => {
    saveEnv();
    delete process.env['CENTINELAIA_ALLOW_PRIVATE_TARGETS'];
    delete process.env['AWS_LAMBDA_FUNCTION_NAME'];
    mockedResolve4.mockReset();
    mockedResolve6.mockReset();
  });

  afterEach(() => {
    restoreEnv();
  });

  it('differentiates private IP error from DNS failure', async () => {
    // Private IP error
    const privateResult = await resolveAndCheckIp(null, '192.168.1.1');
    expect(privateResult.allowed).toBe(false);
    expect(privateResult.error).toContain('private or reserved IP range');
    expect(privateResult.error).toContain('lab mode');

    // DNS failure
    mockedResolve4.mockRejectedValue(new Error('NXDOMAIN'));
    mockedResolve6.mockRejectedValue(new Error('NXDOMAIN'));
    const dnsResult = await resolveAndCheckIp('nonexistent.example.invalid', null);
    expect(dnsResult.allowed).toBe(false);
    expect(dnsResult.error).toContain('could not be resolved');
  });
});
