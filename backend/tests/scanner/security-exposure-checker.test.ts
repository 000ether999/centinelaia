/**
 * Tests del módulo security-exposure-checker.
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

import { createSecurityExposureChecker } from '../../services/scanner/modules/security-exposure-checker.js';
import { validateAnalysisRequest } from '../../services/ai-engine/validator.js';
import type { ScanModuleInput } from '../../services/scanner/modules/types.js';

// ─── Fixture ─────────────────────────────────────────────────────────────────

const input: ScanModuleInput = {
  targetUrl: 'https://example.com',
  targetDomain: 'example.com',
  isIpAddress: false,
  timeoutMs: 5000,
};

function mockTextResponse(status: number, body: string): Response {
  return {
    status,
    headers: new Headers({}),
    text: () => Promise.resolve(body),
  } as unknown as Response;
}

function notFoundResponse(): Response {
  return {
    status: 404,
    headers: new Headers({}),
    text: () => Promise.resolve(''),
  } as unknown as Response;
}

/**
 * Configura mockFetch para que cada URL (basada en su path) devuelva
 * la respuesta indicada, respondiendo 404 a las demás.
 */
function setupMockByPath(map: Record<string, Response>): void {
  mockFetch.mockImplementation((url: string) => {
    for (const [path, response] of Object.entries(map)) {
      if (url.includes(path)) return Promise.resolve(response);
    }
    return Promise.resolve(notFoundResponse());
  });
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('security-exposure-checker', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('should return severity "high" when /.git/HEAD responds 200 with ref: content', async () => {
    setupMockByPath({
      '/.git/HEAD': mockTextResponse(200, 'ref: refs/heads/main\n'),
    });

    const checker = createSecurityExposureChecker();
    const findings = await checker.run(input);

    const gitFinding = findings.find(f => f.rawValue === '/.git/HEAD');
    expect(gitFinding).toBeDefined();
    expect(gitFinding!.severity).toBe('high');
    expect(gitFinding!.category).toBe('security-exposure');
  });

  it('should return severity "high" when /.env responds 200 with key=value content', async () => {
    setupMockByPath({
      '/.env': mockTextResponse(200, 'DB_PASSWORD=secret\nAPI_KEY=abc123\n'),
    });

    const checker = createSecurityExposureChecker();
    const findings = await checker.run(input);

    const envFinding = findings.find(f => f.rawValue === '/.env');
    expect(envFinding).toBeDefined();
    expect(envFinding!.severity).toBe('high');
  });

  it('should return severity "high" when /phpinfo.php responds 200 with PHP Version', async () => {
    // phpinfo() en formato texto (no HTML) — el filtro HTML descarta respuestas
    // que inician con < para eliminar falsos positivos de SPAs
    setupMockByPath({
      '/phpinfo.php': mockTextResponse(200, 'PHP Version 8.2.0\nSystem: Linux...'),
    });

    const checker = createSecurityExposureChecker();
    const findings = await checker.run(input);

    const phpFinding = findings.find(f => f.rawValue === '/phpinfo.php');
    expect(phpFinding).toBeDefined();
    expect(phpFinding!.severity).toBe('high');
  });

  it('should return no finding when /.git/HEAD responds 404', async () => {
    // All paths return 404
    mockFetch.mockResolvedValue(notFoundResponse());

    const checker = createSecurityExposureChecker();
    const findings = await checker.run(input);

    const gitFinding = findings.find(f => f.rawValue === '/.git/HEAD');
    expect(gitFinding).toBeUndefined();
  });

  it('should return severity "info" when /.git/HEAD responds 200 but body has no ref:/HEAD', async () => {
    setupMockByPath({
      '/.git/HEAD': mockTextResponse(200, 'some unrelated content here'),
    });

    const checker = createSecurityExposureChecker();
    const findings = await checker.run(input);

    const gitFinding = findings.find(f => f.rawValue === '/.git/HEAD');
    expect(gitFinding).toBeDefined();
    expect(gitFinding!.severity).toBe('info');
    expect(gitFinding!.description).toContain('no sensitive content detected');
  });

  it('should return 0 findings when all paths respond 404', async () => {
    mockFetch.mockResolvedValue(notFoundResponse());

    const checker = createSecurityExposureChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(0);
  });

  it('should return 0 findings when all paths throw network errors (fail-open)', async () => {
    mockFetch.mockRejectedValue(new TypeError('fetch failed'));

    const checker = createSecurityExposureChecker();
    const findings = await checker.run(input);

    expect(findings).toHaveLength(0);
  });

  it('should return severity "info" when path responds 403 (access denied)', async () => {
    setupMockByPath({
      '/.git/HEAD': mockTextResponse(403, 'Forbidden'),
    });

    const checker = createSecurityExposureChecker();
    const findings = await checker.run(input);

    const gitFinding = findings.find(f => f.rawValue === '/.git/HEAD');
    expect(gitFinding).toBeDefined();
    expect(gitFinding!.severity).toBe('info');
    expect(gitFinding!.description).toContain('access denied');
  });

  // ─── Tests A-04: eliminación de falsos positivos por HTML ────────────────────

  it('should NOT generate high when /.env responds 200 with HTML (A-04 false positive)', async () => {
    // SPA que devuelve index.html para rutas desconocidas — contiene "=" en atributos
    setupMockByPath({
      '/.env': mockTextResponse(200, '<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"></head><body><div id="app"></div></body></html>'),
    });

    const checker = createSecurityExposureChecker();
    const findings = await checker.run(input);

    const envFinding = findings.find(f => f.rawValue === '/.env');
    expect(envFinding).toBeDefined();
    expect(envFinding!.severity).toBe('info');
  });

  it('should generate high when /.env responds 200 with real dotenv content', async () => {
    setupMockByPath({
      '/.env': mockTextResponse(200, 'DB_PASSWORD=secret\nAPI_KEY=abc'),
    });

    const checker = createSecurityExposureChecker();
    const findings = await checker.run(input);

    const envFinding = findings.find(f => f.rawValue === '/.env');
    expect(envFinding).toBeDefined();
    expect(envFinding!.severity).toBe('high');
  });

  it('should generate high when /.git/HEAD responds 200 with real ref format', async () => {
    setupMockByPath({
      '/.git/HEAD': mockTextResponse(200, 'ref: refs/heads/main\n'),
    });

    const checker = createSecurityExposureChecker();
    const findings = await checker.run(input);

    const gitFinding = findings.find(f => f.rawValue === '/.git/HEAD');
    expect(gitFinding).toBeDefined();
    expect(gitFinding!.severity).toBe('high');
  });

  it('should NOT generate high when /.git/HEAD responds 200 with HTML containing HEAD', async () => {
    setupMockByPath({
      '/.git/HEAD': mockTextResponse(200, '<html><head><title>HEAD</title></head><body>Not found</body></html>'),
    });

    const checker = createSecurityExposureChecker();
    const findings = await checker.run(input);

    const gitFinding = findings.find(f => f.rawValue === '/.git/HEAD');
    expect(gitFinding).toBeDefined();
    expect(gitFinding!.severity).toBe('info');
  });
});

// ─── Test de triple-consistencia (validator acepta category 'security-exposure') ───

describe('security-exposure triple-consistency', () => {
  it('validator should accept a finding with category security-exposure', () => {
    const request = {
      sessionId: 'test-session-123',
      findings: [
        {
          category: 'security-exposure',
          severity: 'high',
          rawValue: '/.git/HEAD',
          description: 'Repositorio Git expuesto públicamente',
        },
      ],
    };

    const result = validateAnalysisRequest(request);
    expect(result.valid).toBe(true);
  });
});
