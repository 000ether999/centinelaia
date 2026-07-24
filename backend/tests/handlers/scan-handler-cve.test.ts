/**
 * Test de integración: scan-handler con fallo en CVE enrichment.
 * Valida Requirement 6.5: si enrichWithCves rechaza su Promise,
 * el handler persiste el ScanResult con los findings originales
 * (sin enriquecimiento de CVEs) y responde 200 OK.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { APIGatewayProxyEvent } from 'aws-lambda';

// ─── Mocks ───────────────────────────────────────────────────────────────────

vi.mock('../../services/cve-enricher/index.js', () => ({
  enrichWithCves: vi.fn().mockRejectedValue(new Error('NVD connection failed')),
}));

vi.mock('../../services/scanner/orchestrator.js', () => ({
  executeScan: vi.fn().mockResolvedValue({
    scanId: 'test-scan-id',
    target: 'https://example.com',
    timestamp: '2024-01-01T00:00:00.000Z',
    durationMs: 1000,
    totalFindings: 1,
    status: 'complete',
    findings: [
      {
        category: 'http-headers',
        severity: 'medium',
        rawValue: 'missing CSP',
        description: 'Content-Security-Policy header is missing',
      },
    ],
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
  validateScanRequest: vi.fn().mockResolvedValue({
    valid: true,
    normalized: {
      targetUrl: 'https://example.com',
      targetDomain: 'example.com',
      isIpAddress: false,
    },
  }),
}));

const mockPut = vi.fn().mockResolvedValue({ persisted: true });
const mockGet = vi.fn().mockResolvedValue(null);
const mockListBySession = vi.fn().mockResolvedValue([]);

vi.mock('../../services/scanner/store.js', () => ({
  createDynamoStore: vi.fn().mockReturnValue({
    put: (...args: unknown[]) => mockPut(...args),
    get: (...args: unknown[]) => mockGet(...args),
    listBySession: (...args: unknown[]) => mockListBySession(...args),
  }),
}));

// Mock all scanner modules to avoid importing real implementations
vi.mock('../../services/scanner/modules/header-analyzer.js', () => ({
  createHeaderAnalyzer: vi.fn().mockReturnValue({ name: 'header-analyzer', category: 'http-headers', run: vi.fn() }),
}));
vi.mock('../../services/scanner/modules/tls-checker.js', () => ({
  createTlsChecker: vi.fn().mockReturnValue({ name: 'tls-checker', category: 'tls', run: vi.fn() }),
}));
vi.mock('../../services/scanner/modules/cookie-inspector.js', () => ({
  createCookieInspector: vi.fn().mockReturnValue({ name: 'cookie-inspector', category: 'cookies', run: vi.fn() }),
}));
vi.mock('../../services/scanner/modules/dns-checker.js', () => ({
  createDnsChecker: vi.fn().mockReturnValue({ name: 'dns-checker', category: 'dns', run: vi.fn() }),
}));
vi.mock('../../services/scanner/modules/fingerprinter.js', () => ({
  createFingerprinter: vi.fn().mockReturnValue({ name: 'fingerprinter', category: 'fingerprint', run: vi.fn() }),
}));
vi.mock('../../services/scanner/modules/cors-checker.js', () => ({
  createCorsChecker: vi.fn().mockReturnValue({ name: 'cors-checker', category: 'cors', run: vi.fn() }),
}));
vi.mock('../../services/scanner/modules/http-methods-checker.js', () => ({
  createHttpMethodsChecker: vi.fn().mockReturnValue({ name: 'http-methods-checker', category: 'http-methods', run: vi.fn() }),
}));
vi.mock('../../services/scanner/modules/security-txt-checker.js', () => ({
  createSecurityTxtChecker: vi.fn().mockReturnValue({ name: 'security-txt-checker', category: 'security-txt', run: vi.fn() }),
}));

// ─── Import handler after mocks ──────────────────────────────────────────────

import { handler } from '../../handlers/scan-handler.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function createPostScanEvent(): APIGatewayProxyEvent {
  return {
    httpMethod: 'POST',
    path: '/scan',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target: 'https://example.com',
      authorizationConfirmed: true,
      sessionId: 'test-session-123',
    }),
    queryStringParameters: null,
    pathParameters: null,
    requestContext: {} as never,
    resource: '',
    multiValueHeaders: {},
    multiValueQueryStringParameters: null,
    stageVariables: null,
    isBase64Encoded: false,
  } as APIGatewayProxyEvent;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('scan-handler CVE enrichment fail-open', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockPut.mockResolvedValue({ persisted: true });
  });

  it('responds 200 with original findings when enrichWithCves rejects', async () => {
    const event = createPostScanEvent();
    const response = await handler(event);

    expect(response.statusCode).toBe(200);

    const body = JSON.parse(response.body);

    // Findings should NOT contain 'known-vulnerabilities' category
    const cveFindings = body.findings.filter(
      (f: { category: string }) => f.category === 'known-vulnerabilities',
    );
    expect(cveFindings).toHaveLength(0);

    // Should contain the original findings from the orchestrator
    expect(body.findings).toHaveLength(1);
    expect(body.findings[0].category).toBe('http-headers');
    expect(body.findings[0].severity).toBe('medium');
    expect(body.findings[0].rawValue).toBe('missing CSP');
  });

  it('persists ScanResult with original findings (without CVEs) to the store', async () => {
    const event = createPostScanEvent();
    await handler(event);

    // Verify store.put was called
    expect(mockPut).toHaveBeenCalledTimes(1);

    const persistedResult = mockPut.mock.calls[0][0];

    // Persisted findings should NOT contain CVE enrichment
    const cveFindings = persistedResult.findings.filter(
      (f: { category: string }) => f.category === 'known-vulnerabilities',
    );
    expect(cveFindings).toHaveLength(0);

    // Should contain only the original findings
    expect(persistedResult.findings).toHaveLength(1);
    expect(persistedResult.findings[0].category).toBe('http-headers');
  });
});
