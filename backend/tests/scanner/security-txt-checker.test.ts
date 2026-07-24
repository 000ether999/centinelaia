/**
 * Tests del módulo security-txt-checker.
 *
 * Mockea global.fetch para verificar cada rama de decisión de severidad
 * sin realizar peticiones HTTP reales.
 *
 * Validates: Requirements 3.1, 3.2, 3.3, 4.2
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Mock de safe-agent ──────────────────────────────────────────────────────

vi.mock('../../services/scanner/safe-agent.js', () => ({
  getSafeAgent: () => ({}),
}));

// ─── Mock de fetch global ────────────────────────────────────────────────────

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

import { createSecurityTxtChecker } from '../../services/scanner/modules/security-txt-checker.js';
import type { ScanModuleInput } from '../../services/scanner/modules/types.js';

// ─── Fixture ─────────────────────────────────────────────────────────────────

const input: ScanModuleInput = {
  targetUrl: 'https://example.com/path',
  targetDomain: 'example.com',
  isIpAddress: false,
  timeoutMs: 5000,
};

function mockResponseWithStatus(status: number): Response {
  return {
    status,
    headers: new Headers(),
  } as unknown as Response;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('security-txt-checker', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('should return severity "info" when /.well-known/security.txt returns 200', async () => {
    mockFetch.mockResolvedValue(mockResponseWithStatus(200));

    const checker = createSecurityTxtChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('info');
    expect(findings[0]!.description).toContain('/.well-known/security.txt');
    // Solo debe hacer un fetch (el primero retornó 200)
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('should return severity "info" when fallback /security.txt returns 200', async () => {
    mockFetch
      .mockResolvedValueOnce(mockResponseWithStatus(404)) // /.well-known/ → 404
      .mockResolvedValueOnce(mockResponseWithStatus(200)); // /security.txt → 200

    const checker = createSecurityTxtChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('info');
    expect(findings[0]!.description).toContain('/security.txt');
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('should return severity "low" when both paths return non-200', async () => {
    mockFetch
      .mockResolvedValueOnce(mockResponseWithStatus(404))
      .mockResolvedValueOnce(mockResponseWithStatus(403));

    const checker = createSecurityTxtChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('low');
    expect(findings[0]!.description).toContain('not found');
  });

  it('should return severity "info" on network error without throwing', async () => {
    mockFetch.mockRejectedValue(new TypeError('fetch failed'));

    const checker = createSecurityTxtChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('info');
    expect(findings[0]!.description).toContain('security.txt check failed');
  });

  it('should use the origin (not full URL with path) for requests', async () => {
    mockFetch.mockResolvedValue(mockResponseWithStatus(200));

    const checker = createSecurityTxtChecker();
    await checker.run(input);

    // Debe hacer fetch a https://example.com/.well-known/security.txt (sin /path)
    expect(mockFetch).toHaveBeenCalledWith(
      'https://example.com/.well-known/security.txt',
      expect.any(Object),
    );
  });
});
