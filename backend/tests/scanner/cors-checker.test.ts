/**
 * Tests del módulo cors-checker.
 *
 * Mockea global.fetch para verificar cada rama de decisión de severidad
 * sin realizar peticiones HTTP reales.
 *
 * Validates: Requirements 1.1, 1.2, 1.3, 4.2
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Mock de safe-agent ──────────────────────────────────────────────────────

vi.mock('../../services/scanner/safe-agent.js', () => ({
  getSafeAgent: () => ({}),
}));

// ─── Mock de fetch global ────────────────────────────────────────────────────

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

import { createCorsChecker } from '../../services/scanner/modules/cors-checker.js';
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

describe('cors-checker', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('should return severity "high" when origin is reflected with credentials', async () => {
    mockFetch.mockResolvedValue(mockResponse({
      'access-control-allow-origin': 'https://evil.example.com',
      'access-control-allow-credentials': 'true',
    }));

    const checker = createCorsChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('high');
    expect(findings[0]!.category).toBe('cors');
  });

  it('should return severity "medium" when ACAO is wildcard without credentials', async () => {
    mockFetch.mockResolvedValue(mockResponse({
      'access-control-allow-origin': '*',
    }));

    const checker = createCorsChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('medium');
  });

  it('should return severity "medium" when origin reflected without credentials', async () => {
    mockFetch.mockResolvedValue(mockResponse({
      'access-control-allow-origin': 'https://evil.example.com',
    }));

    const checker = createCorsChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('medium');
  });

  it('should return severity "info" when CORS is restrictive', async () => {
    mockFetch.mockResolvedValue(mockResponse({
      'access-control-allow-origin': 'https://mysite.com',
    }));

    const checker = createCorsChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('info');
  });

  it('should return severity "info" when no ACAO header present', async () => {
    mockFetch.mockResolvedValue(mockResponse({}));

    const checker = createCorsChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('info');
  });

  it('should return severity "info" on network error without throwing', async () => {
    mockFetch.mockRejectedValue(new TypeError('fetch failed'));

    const checker = createCorsChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('info');
    expect(findings[0]!.description).toContain('CORS check failed');
    // No debe exponer el mensaje de error interno
    expect(findings[0]!.description).not.toContain('fetch failed');
  });
});
