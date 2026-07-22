/**
 * Tests de protección anti-SSRF en redirecciones (Req 2.5).
 * Verifica que Header Analyzer, Cookie Inspector y Fingerprinter bloquean
 * redirecciones a IPs privadas/reservadas y generan el Finding correcto.
 *
 * Estos tests mockean `fetch` y `resolveAndCheckIp` para simular
 * redirecciones a IPs internas sin conexiones reales de red.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ScanModuleInput } from '../../services/scanner/modules/types.js';

// ─── Mock de resolveAndCheckIp ───────────────────────────────────────────────

vi.mock('../../services/scanner/validator.js', () => ({
  resolveAndCheckIp: vi.fn(),
}));

import { resolveAndCheckIp } from '../../services/scanner/validator.js';
const mockedResolveAndCheckIp = vi.mocked(resolveAndCheckIp);

// ─── Input base para todos los tests ─────────────────────────────────────────

const baseInput: ScanModuleInput = {
  targetUrl: 'https://example.com',
  targetDomain: 'example.com',
  isIpAddress: false,
  timeoutMs: 5000,
};

// ─── Helper para crear Response mocks ────────────────────────────────────────

function createRedirectResponse(location: string, cookies: string[] = []): Response {
  const headers = new Headers();
  headers.set('location', location);
  for (const cookie of cookies) {
    headers.append('set-cookie', cookie);
  }
  return new Response(null, { status: 302, headers });
}

function createOkResponse(extraHeaders: Record<string, string> = {}): Response {
  const headers = new Headers();
  headers.set('content-type', 'text/html');
  for (const [key, value] of Object.entries(extraHeaders)) {
    headers.set(key, value);
  }
  return new Response('<html></html>', { status: 200, headers });
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('SSRF Redirect Protection (Req 2.5)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    // Re-mock resolveAndCheckIp after restore
    vi.mocked(resolveAndCheckIp).mockReset();
  });

  describe('Header Analyzer — redirect to private IP blocked', () => {
    it('should block redirect to 169.254.169.254 and generate Finding severity "medium" category "http-headers"', async () => {
      // Arrange: primer fetch retorna 302 hacia IP de metadata AWS
      const { createHeaderAnalyzer } = await import('../../services/scanner/modules/header-analyzer.js');

      // Mock fetch: primera llamada = redirect, segunda no debería ocurrir
      const fetchMock = vi.fn()
        .mockResolvedValueOnce(createRedirectResponse('http://169.254.169.254/latest/meta-data/'))
        // Si se intenta un segundo fetch (no debería), retorna OK
        .mockResolvedValueOnce(createOkResponse());

      vi.stubGlobal('fetch', fetchMock);

      // resolveAndCheckIp: bloquear la IP del redirect
      mockedResolveAndCheckIp.mockResolvedValueOnce({
        allowed: false,
        error: 'Target resolves to a non-routable or private IP address',
      });

      // Act
      const analyzer = createHeaderAnalyzer();
      const findings = await analyzer.run(baseInput);

      // Assert
      // Debe haber un Finding de SSRF blocked
      const ssrfFinding = findings.find(f =>
        f.severity === 'medium' && f.description.toLowerCase().includes('ssrf')
      );
      expect(ssrfFinding).toBeDefined();
      expect(ssrfFinding!.category).toBe('http-headers');
      expect(ssrfFinding!.severity).toBe('medium');

      // resolveAndCheckIp fue llamado con el hostname del Location
      expect(mockedResolveAndCheckIp).toHaveBeenCalledWith('169.254.169.254', null);

      // Fetch solo se llamó una vez (no siguió el redirect)
      expect(fetchMock).toHaveBeenCalledTimes(1);

      // El módulo no crasheó — produjo findings adicionales (los headers del 302)
      expect(findings.length).toBeGreaterThan(1);

      vi.unstubAllGlobals();
    });
  });

  describe('Cookie Inspector — redirect to private IP blocked', () => {
    it('should block redirect to 192.168.1.1 and generate Finding severity "medium" category "cookies"', async () => {
      // Arrange
      const { createCookieInspector } = await import('../../services/scanner/modules/cookie-inspector.js');

      // Mock fetch: primera respuesta tiene una cookie + redirect a IP privada
      const redirectResponse = createRedirectResponse('http://192.168.1.1/internal');
      // Simular getSetCookie() method
      const originalHeaders = redirectResponse.headers;
      vi.spyOn(originalHeaders, 'getSetCookie').mockReturnValue([
        'session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict',
      ]);

      const fetchMock = vi.fn().mockResolvedValueOnce(redirectResponse);
      vi.stubGlobal('fetch', fetchMock);

      // resolveAndCheckIp: bloquear la IP del redirect
      mockedResolveAndCheckIp.mockResolvedValueOnce({
        allowed: false,
        error: 'Target resolves to a non-routable or private IP address',
      });

      // Act
      const inspector = createCookieInspector();
      const findings = await inspector.run(baseInput);

      // Assert
      const ssrfFinding = findings.find(f =>
        f.severity === 'medium' && f.description.toLowerCase().includes('ssrf')
      );
      expect(ssrfFinding).toBeDefined();
      expect(ssrfFinding!.category).toBe('cookies');
      expect(ssrfFinding!.severity).toBe('medium');

      // resolveAndCheckIp fue llamado con la IP directamente
      expect(mockedResolveAndCheckIp).toHaveBeenCalledWith(null, '192.168.1.1');

      // Fetch solo se llamó una vez (no siguió el redirect)
      expect(fetchMock).toHaveBeenCalledTimes(1);

      // El módulo no crasheó
      expect(findings.length).toBeGreaterThanOrEqual(1);

      vi.unstubAllGlobals();
    });
  });

  describe('Fingerprinter — redirect to private IP blocked', () => {
    it('should block redirect to 10.0.0.1 and generate Finding severity "medium" category "server-fingerprint"', async () => {
      // Arrange
      const { createFingerprinter } = await import('../../services/scanner/modules/fingerprinter.js');

      // Mock fetch: redirect hacia IP privada 10.x
      const fetchMock = vi.fn()
        .mockResolvedValueOnce(createRedirectResponse('http://10.0.0.1/admin'))
        .mockResolvedValueOnce(createOkResponse({ 'server': 'nginx/1.18' }));

      vi.stubGlobal('fetch', fetchMock);

      // resolveAndCheckIp: bloquear la IP del redirect
      mockedResolveAndCheckIp.mockResolvedValueOnce({
        allowed: false,
        error: 'Target resolves to a non-routable or private IP address',
      });

      // Act
      const fingerprinter = createFingerprinter();
      const findings = await fingerprinter.run(baseInput);

      // Assert
      const ssrfFinding = findings.find(f =>
        f.severity === 'medium' && f.description.toLowerCase().includes('ssrf')
      );
      expect(ssrfFinding).toBeDefined();
      expect(ssrfFinding!.category).toBe('server-fingerprint');
      expect(ssrfFinding!.severity).toBe('medium');

      // resolveAndCheckIp fue llamado con la IP directamente
      expect(mockedResolveAndCheckIp).toHaveBeenCalledWith(null, '10.0.0.1');

      // Fetch solo se llamó una vez (no siguió el redirect)
      expect(fetchMock).toHaveBeenCalledTimes(1);

      // El módulo no crasheó — sigue analizando headers de la respuesta 302
      expect(findings.length).toBeGreaterThanOrEqual(1);

      vi.unstubAllGlobals();
    });
  });
});
