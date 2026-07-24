/**
 * Tests del módulo header-analyzer.
 *
 * Mockea global.fetch, safe-agent y validator para verificar:
 * - Header de seguridad ausente → severidad correcta según SECURITY_HEADERS_CONFIG
 * - Header presente con valor seguro → 'info'
 * - Header presente con valor inseguro → 'medium'
 * - Redirección 3xx a IP privada → finding de bloqueo SSRF 'medium'
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Mocks ───────────────────────────────────────────────────────────────────

vi.mock('../../services/scanner/safe-agent.js', () => ({
  getSafeAgent: () => ({}),
}));

const mockResolveAndCheckIp = vi.fn();
vi.mock('../../services/scanner/validator.js', () => ({
  resolveAndCheckIp: (...args: unknown[]) => mockResolveAndCheckIp(...args),
}));

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

import { createHeaderAnalyzer } from '../../services/scanner/modules/header-analyzer.js';
import type { ScanModuleInput } from '../../services/scanner/modules/types.js';

// ─── Fixture ─────────────────────────────────────────────────────────────────

const input: ScanModuleInput = {
  targetUrl: 'https://example.com',
  targetDomain: 'example.com',
  isIpAddress: false,
  timeoutMs: 5000,
};

function mockResponse(status: number, headers: Record<string, string>): Response {
  return {
    status,
    headers: new Headers(headers),
  } as unknown as Response;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('header-analyzer', () => {
  beforeEach(() => {
    mockFetch.mockReset();
    mockResolveAndCheckIp.mockReset();
  });

  it('reports absent security header with correct severity (HSTS → high)', async () => {
    // Respuesta sin headers de seguridad
    mockFetch.mockResolvedValue(mockResponse(200, {}));

    const analyzer = createHeaderAnalyzer();
    const findings = await analyzer.run(input);

    // Debe generar findings para todos los 7 headers ausentes
    expect(findings.length).toBe(7);

    // HSTS ausente → high
    const hsts = findings.find(f => f.description.includes('Strict-Transport-Security'));
    expect(hsts).toBeDefined();
    expect(hsts!.severity).toBe('high');

    // CSP ausente → high
    const csp = findings.find(f => f.description.includes('Content-Security-Policy'));
    expect(csp).toBeDefined();
    expect(csp!.severity).toBe('high');

    // X-Frame-Options ausente → medium
    const xfo = findings.find(f => f.description.includes('X-Frame-Options'));
    expect(xfo).toBeDefined();
    expect(xfo!.severity).toBe('medium');

    // Referrer-Policy ausente → low
    const rp = findings.find(f => f.description.includes('Referrer-Policy'));
    expect(rp).toBeDefined();
    expect(rp!.severity).toBe('low');
  });

  it('reports header present with secure value as info', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Content-Security-Policy': "default-src 'self'",
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Permissions-Policy': 'camera=()',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'X-XSS-Protection': '1; mode=block',
    }));

    const analyzer = createHeaderAnalyzer();
    const findings = await analyzer.run(input);

    // Todos los 7 headers presentes con valor seguro → severity info
    expect(findings.length).toBe(7);
    expect(findings.every(f => f.severity === 'info')).toBe(true);
    expect(findings.every(f => f.description.includes('correctly configured'))).toBe(true);
  });

  it('reports CSP with unsafe-inline as insecure (medium)', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      'Content-Security-Policy': "default-src 'self' 'unsafe-inline'",
      'Strict-Transport-Security': 'max-age=31536000',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Permissions-Policy': 'camera=()',
      'Referrer-Policy': 'no-referrer',
      'X-XSS-Protection': '1; mode=block',
    }));

    const analyzer = createHeaderAnalyzer();
    const findings = await analyzer.run(input);

    const csp = findings.find(f => f.description.includes('Content-Security-Policy'));
    expect(csp).toBeDefined();
    expect(csp!.severity).toBe('medium');
    expect(csp!.description).toContain('insecure value');
  });

  it('reports HSTS with low max-age as insecure (medium)', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      'Content-Security-Policy': "default-src 'self'",
      'Strict-Transport-Security': 'max-age=3600',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Permissions-Policy': 'camera=()',
      'Referrer-Policy': 'no-referrer',
      'X-XSS-Protection': '1; mode=block',
    }));

    const analyzer = createHeaderAnalyzer();
    const findings = await analyzer.run(input);

    const hsts = findings.find(f => f.description.includes('Strict-Transport-Security'));
    expect(hsts).toBeDefined();
    expect(hsts!.severity).toBe('medium');
    expect(hsts!.description).toContain('insecure value');
  });

  it('generates SSRF finding when redirect targets private IP', async () => {
    // Primera respuesta: redirección 302 con Location a IP privada
    const redirectResponse = {
      status: 302,
      headers: new Headers({ location: 'http://192.168.1.1/admin' }),
    } as unknown as Response;

    mockFetch.mockResolvedValue(redirectResponse);

    // resolveAndCheckIp bloquea la IP privada
    mockResolveAndCheckIp.mockResolvedValue({ allowed: false });

    const analyzer = createHeaderAnalyzer();
    const findings = await analyzer.run(input);

    // Debe haber un finding de SSRF con severity medium
    const ssrfFinding = findings.find(f =>
      f.description.toLowerCase().includes('ssrf') ||
      f.description.toLowerCase().includes('private') ||
      f.description.toLowerCase().includes('blocked'),
    );
    expect(ssrfFinding).toBeDefined();
    expect(ssrfFinding!.severity).toBe('medium');
    expect(ssrfFinding!.category).toBe('http-headers');
  });
});
