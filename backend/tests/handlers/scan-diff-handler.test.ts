/**
 * Tests para la ruta GET /scan/diff del scan-handler.
 * Verifica routing correcto, parámetros obligatorios y no-colisión con /scan/{scanId}.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { APIGatewayProxyEvent } from 'aws-lambda';

// ─── Mocks ───────────────────────────────────────────────────────────────────

const mockPut = vi.fn().mockResolvedValue({ persisted: true });
const mockGet = vi.fn();
const mockListBySession = vi.fn().mockResolvedValue([]);

vi.mock('../../services/scanner/store.js', () => ({
  createDynamoStore: vi.fn().mockReturnValue({
    put: (...args: unknown[]) => mockPut(...args),
    get: (...args: unknown[]) => mockGet(...args),
    listBySession: (...args: unknown[]) => mockListBySession(...args),
  }),
}));

vi.mock('../../handlers/auth.js', () => ({
  isAuthorized: vi.fn().mockReturnValue(true),
  unauthorizedResponse: vi.fn().mockReturnValue({
    statusCode: 401,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ error: 'Unauthorized' }),
  }),
}));

vi.mock('../../services/scanner/validator.js', () => ({
  validateScanRequest: vi.fn().mockResolvedValue({ valid: true, normalized: { targetUrl: 'https://example.com', targetDomain: 'example.com', isIpAddress: false } }),
}));

vi.mock('../../services/scanner/orchestrator.js', () => ({
  executeScan: vi.fn().mockResolvedValue({
    scanId: 'test-id', target: 'https://example.com', timestamp: '2024-01-01T00:00:00.000Z',
    durationMs: 100, totalFindings: 0, status: 'complete', findings: [],
  }),
}));

vi.mock('../../services/cve-enricher/index.js', () => ({
  enrichWithCves: vi.fn().mockImplementation((findings) => Promise.resolve(findings)),
}));

// Mock scanner modules
vi.mock('../../services/scanner/modules/header-analyzer.js', () => ({ createHeaderAnalyzer: vi.fn().mockReturnValue({ name: 'h', category: 'http-headers', run: vi.fn() }) }));
vi.mock('../../services/scanner/modules/tls-checker.js', () => ({ createTlsChecker: vi.fn().mockReturnValue({ name: 't', category: 'tls-ssl', run: vi.fn() }) }));
vi.mock('../../services/scanner/modules/cookie-inspector.js', () => ({ createCookieInspector: vi.fn().mockReturnValue({ name: 'c', category: 'cookies', run: vi.fn() }) }));
vi.mock('../../services/scanner/modules/dns-checker.js', () => ({ createDnsChecker: vi.fn().mockReturnValue({ name: 'd', category: 'dns-security', run: vi.fn() }) }));
vi.mock('../../services/scanner/modules/fingerprinter.js', () => ({ createFingerprinter: vi.fn().mockReturnValue({ name: 'f', category: 'server-fingerprint', run: vi.fn() }) }));
vi.mock('../../services/scanner/modules/cors-checker.js', () => ({ createCorsChecker: vi.fn().mockReturnValue({ name: 'co', category: 'cors', run: vi.fn() }) }));
vi.mock('../../services/scanner/modules/http-methods-checker.js', () => ({ createHttpMethodsChecker: vi.fn().mockReturnValue({ name: 'hm', category: 'http-methods', run: vi.fn() }) }));
vi.mock('../../services/scanner/modules/security-txt-checker.js', () => ({ createSecurityTxtChecker: vi.fn().mockReturnValue({ name: 'st', category: 'security-txt', run: vi.fn() }) }));
vi.mock('../../services/scanner/modules/redirect-checker.js', () => ({ createRedirectChecker: vi.fn().mockReturnValue({ name: 'r', category: 'http-headers', run: vi.fn() }) }));
vi.mock('../../services/scanner/modules/security-exposure-checker.js', () => ({ createSecurityExposureChecker: vi.fn().mockReturnValue({ name: 'se', category: 'security-exposure', run: vi.fn() }) }));

// ─── Import handler after mocks ──────────────────────────────────────────────

import { handler } from '../../handlers/scan-handler.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function createEvent(method: string, path: string, query?: Record<string, string>): APIGatewayProxyEvent {
  return {
    httpMethod: method,
    path,
    headers: { 'Content-Type': 'application/json' },
    body: null,
    queryStringParameters: query ?? null,
    pathParameters: null,
    requestContext: {} as never,
    resource: '',
    multiValueHeaders: {},
    multiValueQueryStringParameters: null,
    stageVariables: null,
    isBase64Encoded: false,
  } as APIGatewayProxyEvent;
}

const scanA = {
  scanId: 'scan-A',
  target: 'https://example.com',
  timestamp: '2026-01-01T00:00:00Z',
  durationMs: 1000,
  totalFindings: 1,
  status: 'complete',
  sessionId: 'ses-1',
  consent: { authorizationConfirmed: true, target: 'https://example.com', confirmedAt: '2026-01-01T00:00:00Z' },
  findings: [{ category: 'http-headers', severity: 'high', rawValue: null, description: 'Finding A que persiste en ambos escaneos' }],
  persisted: true,
};

const scanB = {
  scanId: 'scan-B',
  target: 'https://example.com',
  timestamp: '2026-02-01T00:00:00Z',
  durationMs: 800,
  totalFindings: 1,
  status: 'complete',
  sessionId: 'ses-1',
  consent: { authorizationConfirmed: true, target: 'https://example.com', confirmedAt: '2026-02-01T00:00:00Z' },
  findings: [{ category: 'http-headers', severity: 'high', rawValue: null, description: 'Finding A que persiste en ambos escaneos' }],
  persisted: true,
};

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('GET /scan/diff', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('devuelve 200 con diff cuando ambos escaneos existen', async () => {
    mockGet.mockImplementation((id: string) => {
      if (id === 'scan-A') return Promise.resolve(scanA);
      if (id === 'scan-B') return Promise.resolve(scanB);
      return Promise.resolve(null);
    });

    const event = createEvent('GET', '/scan/diff', { from: 'scan-A', to: 'scan-B' });
    const response = await handler(event);

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.fromScanId).toBe('scan-A');
    expect(body.toScanId).toBe('scan-B');
    expect(body.summary).toBeDefined();
  });

  it('NO se interpreta como GET /scan/{scanId="diff"} — test de colisión', async () => {
    // Si /scan/diff fuera capturado por el regex /scan/{scanId}, buscaría un scan con id "diff"
    mockGet.mockImplementation((id: string) => {
      if (id === 'diff') return Promise.resolve(null);
      if (id === 'scan-A') return Promise.resolve(scanA);
      if (id === 'scan-B') return Promise.resolve(scanB);
      return Promise.resolve(null);
    });

    const event = createEvent('GET', '/scan/diff', { from: 'scan-A', to: 'scan-B' });
    const response = await handler(event);

    // Debe ser 200 (diff route), no 404 (scan not found con id "diff")
    expect(response.statusCode).toBe(200);
    // El mock de get no debería haber sido llamado con "diff" como scanId
    const getCallArgs = mockGet.mock.calls.map((c: unknown[]) => c[0]);
    expect(getCallArgs).not.toContain('diff');
  });

  it('devuelve 400 si falta from', async () => {
    const event = createEvent('GET', '/scan/diff', { to: 'scan-B' });
    const response = await handler(event);
    expect(response.statusCode).toBe(400);
  });

  it('devuelve 400 si falta to', async () => {
    const event = createEvent('GET', '/scan/diff', { from: 'scan-A' });
    const response = await handler(event);
    expect(response.statusCode).toBe(400);
  });

  it('devuelve 404 si el escaneo from no existe', async () => {
    mockGet.mockResolvedValue(null);
    const event = createEvent('GET', '/scan/diff', { from: 'nonexistent', to: 'scan-B' });
    const response = await handler(event);
    expect(response.statusCode).toBe(404);
  });

  it('devuelve 404 si el escaneo to no existe', async () => {
    mockGet.mockImplementation((id: string) => {
      if (id === 'scan-A') return Promise.resolve(scanA);
      return Promise.resolve(null);
    });
    const event = createEvent('GET', '/scan/diff', { from: 'scan-A', to: 'nonexistent' });
    const response = await handler(event);
    expect(response.statusCode).toBe(404);
  });

  it('GET /scan/{id} normal sigue funcionando', async () => {
    mockGet.mockResolvedValue(scanA);
    const event = createEvent('GET', '/scan/scan-A', undefined);
    event.pathParameters = { scanId: 'scan-A' };
    const response = await handler(event);
    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.scanId).toBe('scan-A');
  });
});
