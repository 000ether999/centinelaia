/**
 * Tests del módulo http-methods-checker.
 *
 * Mockea global.fetch para verificar cada rama de decisión de severidad
 * sin realizar peticiones HTTP reales.
 *
 * Validates: Requirements 2.1, 2.2, 2.3, 2.4, 4.2
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Mock de safe-agent ──────────────────────────────────────────────────────

vi.mock('../../services/scanner/safe-agent.js', () => ({
  getSafeAgent: () => ({}),
}));

// ─── Mock de fetch global ────────────────────────────────────────────────────

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

import { createHttpMethodsChecker } from '../../services/scanner/modules/http-methods-checker.js';
import type { ScanModuleInput } from '../../services/scanner/modules/types.js';

// ─── Fixture ─────────────────────────────────────────────────────────────────

const input: ScanModuleInput = {
  targetUrl: 'https://example.com',
  targetDomain: 'example.com',
  isIpAddress: false,
  timeoutMs: 5000,
};

function mockResponse(headers: Record<string, string>): Response {
  return {
    status: 200,
    headers: new Headers(headers),
  } as unknown as Response;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('http-methods-checker', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('should return severity "medium" for TRACE (XST risk)', async () => {
    mockFetch.mockResolvedValue(mockResponse({
      allow: 'GET, HEAD, TRACE',
    }));

    const checker = createHttpMethodsChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('medium');
    expect(findings[0]!.description).toContain('TRACE');
    expect(findings[0]!.description).toContain('XST');
  });

  it('should return one "medium" finding per dangerous method (PUT, DELETE)', async () => {
    mockFetch.mockResolvedValue(mockResponse({
      allow: 'GET, PUT, DELETE',
    }));

    const checker = createHttpMethodsChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(2);
    expect(findings.every(f => f.severity === 'medium')).toBe(true);
    expect(findings.some(f => f.description.includes('PUT'))).toBe(true);
    expect(findings.some(f => f.description.includes('DELETE'))).toBe(true);
  });

  it('should return severity "info" when only safe methods are present', async () => {
    mockFetch.mockResolvedValue(mockResponse({
      allow: 'GET, HEAD, POST, OPTIONS',
    }));

    const checker = createHttpMethodsChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('info');
    expect(findings[0]!.description).toContain('safe');
  });

  it('should return severity "info" when no Allow header is present', async () => {
    mockFetch.mockResolvedValue(mockResponse({}));

    const checker = createHttpMethodsChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('info');
    expect(findings[0]!.description).toContain('No Allow header');
  });

  it('should read Access-Control-Allow-Methods as fallback', async () => {
    mockFetch.mockResolvedValue(mockResponse({
      'access-control-allow-methods': 'GET, CONNECT',
    }));

    const checker = createHttpMethodsChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('medium');
    expect(findings[0]!.description).toContain('CONNECT');
  });

  it('should return severity "info" on network error without throwing', async () => {
    mockFetch.mockRejectedValue(new TypeError('fetch failed'));

    const checker = createHttpMethodsChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('info');
    expect(findings[0]!.description).toContain('HTTP methods check failed');
  });
});
