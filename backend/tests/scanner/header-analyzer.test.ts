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

    // Debe generar findings para los 6 headers no-deprecados ausentes
    // X-XSS-Protection ya no se penaliza por ausencia (deprecado)
    expect(findings.length).toBe(6);

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

    // X-XSS-Protection NO debe estar presente como hallazgo ausente
    const xss = findings.find(f => f.description.includes('X-XSS-Protection'));
    expect(xss).toBeUndefined();
  });

  it('reports header present with secure value as info', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Content-Security-Policy': "default-src 'self'",
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Permissions-Policy': 'camera=()',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'X-XSS-Protection': '0',
    }));

    const analyzer = createHeaderAnalyzer();
    const findings = await analyzer.run(input);

    // 6 headers estándar + 1 deprecated header (X-XSS-Protection con valor "0") = 7
    expect(findings.length).toBe(7);
    expect(findings.every(f => f.severity === 'info')).toBe(true);
    expect(findings.every(f => f.description.includes('correctly configured'))).toBe(true);
  });

  it('reports CSP with unsafe-inline as insecure (medium)', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      'Content-Security-Policy': "default-src 'self' 'unsafe-inline'",
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Permissions-Policy': 'camera=()',
      'Referrer-Policy': 'no-referrer',
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
    }));

    const analyzer = createHeaderAnalyzer();
    const findings = await analyzer.run(input);

    const hsts = findings.find(f => f.description.includes('Strict-Transport-Security'));
    expect(hsts).toBeDefined();
    expect(hsts!.severity).toBe('medium');
    expect(hsts!.description).toContain('insecure value');
  });

  it('reports HSTS with max-age=86400 as insecure (below 1-year threshold)', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      'Content-Security-Policy': "default-src 'self'",
      'Strict-Transport-Security': 'max-age=86400; includeSubDomains',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Permissions-Policy': 'camera=()',
      'Referrer-Policy': 'no-referrer',
    }));

    const analyzer = createHeaderAnalyzer();
    const findings = await analyzer.run(input);

    const hsts = findings.find(f => f.description.includes('Strict-Transport-Security'));
    expect(hsts).toBeDefined();
    expect(hsts!.severity).toBe('medium');
    expect(hsts!.description).toContain('insecure value');
  });

  it('reports HSTS with max-age=31536000 and includeSubDomains as secure', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      'Content-Security-Policy': "default-src 'self'",
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Permissions-Policy': 'camera=()',
      'Referrer-Policy': 'no-referrer',
    }));

    const analyzer = createHeaderAnalyzer();
    const findings = await analyzer.run(input);

    const hsts = findings.find(f => f.description.includes('Strict-Transport-Security'));
    expect(hsts).toBeDefined();
    expect(hsts!.severity).toBe('info');
    expect(hsts!.description).toContain('correctly configured');
  });

  it('reports X-Content-Type-Options with invalid value as insecure', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      'Content-Security-Policy': "default-src 'self'",
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'foo',
      'Permissions-Policy': 'camera=()',
      'Referrer-Policy': 'no-referrer',
    }));

    const analyzer = createHeaderAnalyzer();
    const findings = await analyzer.run(input);

    const xcto = findings.find(f => f.description.includes('X-Content-Type-Options'));
    expect(xcto).toBeDefined();
    expect(xcto!.severity).toBe('medium');
    expect(xcto!.description).toContain('insecure value');
  });

  it('reports X-Content-Type-Options with nosniff as secure', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      'Content-Security-Policy': "default-src 'self'",
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Permissions-Policy': 'camera=()',
      'Referrer-Policy': 'no-referrer',
    }));

    const analyzer = createHeaderAnalyzer();
    const findings = await analyzer.run(input);

    const xcto = findings.find(f => f.description.includes('X-Content-Type-Options'));
    expect(xcto).toBeDefined();
    expect(xcto!.severity).toBe('info');
    expect(xcto!.description).toContain('correctly configured');
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


// ─── Tests Ola 10: X-Content-Type-Options con espacios internos (B-04) ───────

describe('header-analyzer — X-Content-Type-Options edge cases (B-04)', () => {
  beforeEach(() => {
    mockFetch.mockReset();
    mockResolveAndCheckIp.mockReset();
  });

  it('"no sniff" (con espacio interno) → inseguro', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      'Content-Security-Policy': "default-src 'self'",
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'no sniff',
      'Permissions-Policy': 'camera=()',
      'Referrer-Policy': 'no-referrer',
    }));

    const analyzer = createHeaderAnalyzer();
    const findings = await analyzer.run(input);

    const xcto = findings.find(f => f.description.includes('X-Content-Type-Options'));
    expect(xcto).toBeDefined();
    expect(xcto!.severity).toBe('medium');
    expect(xcto!.description).toContain('insecure value');
  });

  it('" nosniff " (con espacios en los extremos) → seguro', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      'Content-Security-Policy': "default-src 'self'",
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': ' nosniff ',
      'Permissions-Policy': 'camera=()',
      'Referrer-Policy': 'no-referrer',
    }));

    const analyzer = createHeaderAnalyzer();
    const findings = await analyzer.run(input);

    const xcto = findings.find(f => f.description.includes('X-Content-Type-Options'));
    expect(xcto).toBeDefined();
    expect(xcto!.severity).toBe('info');
    expect(xcto!.description).toContain('correctly configured');
  });

  it('"NOSNIFF" (uppercase) → seguro', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      'Content-Security-Policy': "default-src 'self'",
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'NOSNIFF',
      'Permissions-Policy': 'camera=()',
      'Referrer-Policy': 'no-referrer',
    }));

    const analyzer = createHeaderAnalyzer();
    const findings = await analyzer.run(input);

    const xcto = findings.find(f => f.description.includes('X-Content-Type-Options'));
    expect(xcto).toBeDefined();
    expect(xcto!.severity).toBe('info');
    expect(xcto!.description).toContain('correctly configured');
  });
});
