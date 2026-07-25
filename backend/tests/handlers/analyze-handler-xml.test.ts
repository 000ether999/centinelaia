/**
 * Test de integración: POST /analyze con nmapXml (Ola 13a).
 *
 * Verifica que enviar XML de Nmap a /analyze fusiona los findings
 * (incluyendo NSE) y produce un análisis con score y explicaciones.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { APIGatewayProxyEvent } from 'aws-lambda';
import { handleAnalyzeRequest } from '../../handlers/analyze-handler.js';
import type { AnalysisResult } from '../../services/ai-engine/types.js';
import { analyzeFindings } from '../../services/ai-engine/index.js';

// ─── Mock de fetch global (NVD) ──────────────────────────────────────────────

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

/** Executor con dependencias mockeadas (sin Bedrock, modo fallback). */
async function fallbackAnalyze(request: unknown) {
  return analyzeFindings(request, {
    executionMode: 'fallback',
    cacheClient: {
      get: async () => ({ hit: false }),
      put: async () => true,
      calculateHash: () => 'test-hash',
      config: { tableName: 'test', ttlMinutes: 60 },
    } as any,
    persistenceClient: {
      save: async () => ({ analysisId: 'test-xml-id', persisted: false, storageTruncated: false }),
      getById: async () => null,
      listBySession: async () => [],
      config: { tableName: 'test', maxRetries: 0, ttlDays: 30 },
    } as any,
  });
}

const mockPersistence = {
  getById: vi.fn().mockResolvedValue(null),
  listBySession: vi.fn().mockResolvedValue([]),
};

function buildEvent(body: unknown): APIGatewayProxyEvent {
  return {
    httpMethod: 'POST',
    path: '/analyze',
    body: JSON.stringify(body),
    headers: {},
    queryStringParameters: null,
    pathParameters: null,
    requestContext: {} as any,
    isBase64Encoded: false,
    multiValueHeaders: {},
    multiValueQueryStringParameters: null,
    stageVariables: null,
    resource: '',
  } as APIGatewayProxyEvent;
}

const NMAP_XML = `<?xml version="1.0"?>
<nmaprun>
<host>
<ports>
<port protocol="tcp" portid="443">
  <state state="open" reason="syn-ack"/>
  <service name="https" product="nginx" version="1.18.0"/>
  <script id="ssl-cert" output="Subject: CN=test&#xa;Not valid after: 2020-01-01T00:00:00"/>
  <script id="ssl-enum-ciphers" output="TLSv1.0:&#xa;  ciphers: TLS_RSA_WITH_3DES_EDE_CBC_SHA&#xa;  least strength: C"/>
</port>
</ports>
</host>
</nmaprun>`;

describe('POST /analyze — nmapXml integration (Ola 13a)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    mockFetch.mockReset();
    // NVD returns nothing for simplicity
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => ({ vulnerabilities: [] }),
    });
  });

  it('nmapXml with NSE scripts → 200 with findings merged and analyzed', async () => {
    const event = buildEvent({
      findings: [],
      sessionId: 'test-xml-analyze',
      nmapXml: NMAP_XML,
    });

    const response = await handleAnalyzeRequest(event, {
      executeAnalysis: fallbackAnalyze,
      persistence: mockPersistence,
    });

    expect(response.statusCode).toBe(200);
    const result: AnalysisResult = JSON.parse(response.body);

    // Should have explanations (at minimum for the port-service, ssl-cert, and ssl-enum findings)
    expect(result.explanations.length).toBeGreaterThanOrEqual(3);
    // Should have a valid risk score
    expect(result.riskScore).toBeGreaterThan(0);
    expect(result.riskLevel).toBeDefined();
  });
});
