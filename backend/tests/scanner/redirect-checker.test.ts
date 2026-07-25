/**
 * Tests del módulo redirect-checker.
 *
 * Mockea global.fetch para verificar cada rama de decisión sin
 * realizar peticiones HTTP reales.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Mock de safe-agent ──────────────────────────────────────────────────────

vi.mock('../../services/scanner/safe-agent.js', () => ({
  getSafeAgent: () => ({}),
}));

// ─── Mock de fetch global ────────────────────────────────────────────────────

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

import { createRedirectChecker } from '../../services/scanner/modules/redirect-checker.js';
import type { ScanModuleInput } from '../../services/scanner/modules/types.js';

// ─── Fixture ─────────────────────────────────────────────────────────────────

const input: ScanModuleInput = {
  targetUrl: 'https://example.com',
  targetDomain: 'example.com',
  isIpAddress: false,
  timeoutMs: 5000,
};

function redirectResponse(status: number, location: string): Response {
  return {
    status,
    headers: new Headers({ location }),
  } as unknown as Response;
}

function okResponse(): Response {
  return {
    status: 200,
    headers: new Headers({}),
  } as unknown as Response;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('redirect-checker', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('should return severity "info" when HTTP redirects 301 to HTTPS', async () => {
    // Primer fetch (http://): 301 → https://example.com
    mockFetch.mockResolvedValueOnce(
      redirectResponse(301, 'https://example.com'),
    );

    const checker = createRedirectChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('info');
    expect(findings[0]!.description).toContain('HTTP to HTTPS redirect correctly configured');
    expect(findings[0]!.category).toBe('http-headers');
  });

  it('should return severity "info" when HTTP redirects 302 to HTTPS', async () => {
    mockFetch.mockResolvedValueOnce(
      redirectResponse(302, 'https://example.com'),
    );

    const checker = createRedirectChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('info');
  });

  it('should return severity "medium" when HTTP responds 200 without redirect', async () => {
    mockFetch.mockResolvedValueOnce(okResponse());

    const checker = createRedirectChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('medium');
    expect(findings[0]!.description).toContain('No HTTP to HTTPS redirect detected');
  });

  it('should return severity "info" on network error (fail-open)', async () => {
    mockFetch.mockRejectedValue(new TypeError('fetch failed'));

    const checker = createRedirectChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('info');
    expect(findings[0]!.description).toContain('Redirect check failed');
  });

  // ─── Tests A-05: cadena multi-hop y forceHttp ────────────────────────────────

  it('should return info when chain http→http→https (A-05 false positive fix)', async () => {
    // hop 0: http://example.com → 301 → http://www.example.com
    mockFetch.mockResolvedValueOnce(
      redirectResponse(301, 'http://www.example.com'),
    );
    // hop 1: http://www.example.com → 301 → https://www.example.com
    mockFetch.mockResolvedValueOnce(
      redirectResponse(301, 'https://www.example.com'),
    );

    const checker = createRedirectChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('info');
    expect(findings[0]!.description).toContain('HTTP to HTTPS redirect correctly configured');
  });

  it('should return medium when chain of 3+ hops never reaches HTTPS', async () => {
    // hop 0: → http://www.example.com
    mockFetch.mockResolvedValueOnce(
      redirectResponse(301, 'http://www.example.com'),
    );
    // hop 1: → http://www2.example.com
    mockFetch.mockResolvedValueOnce(
      redirectResponse(301, 'http://www2.example.com'),
    );
    // hop 2: → http://www3.example.com
    mockFetch.mockResolvedValueOnce(
      redirectResponse(301, 'http://www3.example.com'),
    );

    const checker = createRedirectChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('medium');
    expect(findings[0]!.description).toContain('does not upgrade to HTTPS');
  });

  it('should return medium when first redirect goes to HTTP and never upgrades', async () => {
    // hop 0: → http://www.example.com
    mockFetch.mockResolvedValueOnce(
      redirectResponse(301, 'http://www.example.com'),
    );
    // hop 1: non-redirect response (200)
    mockFetch.mockResolvedValueOnce(okResponse());

    const checker = createRedirectChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('medium');
    expect(findings[0]!.description).toContain('does not upgrade to HTTPS');
  });
});

// ─── Tests de forceHttp ──────────────────────────────────────────────────────

describe('redirect-checker — forceHttp port handling', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('should call fetch with http:// and no port for https://example.com:8443', async () => {
    // Verificar que forceHttp produce http://example.com (sin :8443)
    mockFetch.mockResolvedValueOnce(
      redirectResponse(301, 'https://example.com'),
    );

    const inputWith8443: ScanModuleInput = {
      targetUrl: 'https://example.com:8443',
      targetDomain: 'example.com',
      isIpAddress: false,
      timeoutMs: 5000,
    };

    const checker = createRedirectChecker();
    await checker.run(inputWith8443);

    // El primer fetch debe ser a http://example.com/ (sin puerto 8443)
    const calledUrl = mockFetch.mock.calls[0]![0] as string;
    expect(calledUrl).toBe('http://example.com/');
    expect(calledUrl).not.toContain('8443');
  });
});
