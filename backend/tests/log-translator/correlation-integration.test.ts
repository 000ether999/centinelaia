/**
 * Test de integración: POST /analyze con nmapOutput (correlación).
 * Verifica que el endpoint fusiona findings del body con findings
 * derivados de Nmap y que el resultado cubre AMBAS fuentes.
 * Usa modo fallback para no depender de Bedrock/DynamoDB reales.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { APIGatewayProxyEvent } from 'aws-lambda';
import { handleAnalyzeRequest } from '../../handlers/analyze-handler.js';
import type { AnalysisResult } from '../../services/ai-engine/types.js';
import { analyzeFindings } from '../../services/ai-engine/index.js';

/**
 * Mock de fetch global: evita llamadas reales al NVD durante estos tests
 * (el analyze-handler ahora invoca enrichWithCves internamente). Responder
 * 404 mantiene el escenario determinista: sin CVEs, solo se agregan los
 * findings de correlación por puerto/servicio.
 */
const mockFetch = vi.fn().mockResolvedValue({ ok: false, status: 404 });
vi.stubGlobal('fetch', mockFetch);

/** Executor con dependencias mockeadas (cache y persistence in-memory). */
async function fallbackAnalyze(request: unknown) {
  return analyzeFindings(request, {
    executionMode: 'fallback',
    cacheClient: {
      get: async () => ({ hit: false }),
      put: async () => true,
      calculateHash: (f: any[]) => 'test-hash',
      config: { tableName: 'test', ttlMinutes: 60 },
    } as any,
    persistenceClient: {
      save: async () => ({ analysisId: 'test-id', persisted: false, storageTruncated: false }),
      getById: async () => null,
      listBySession: async () => [],
      config: { tableName: 'test', maxRetries: 0, ttlDays: 30 },
    } as any,
  });
}

/** Stub de persistencia para el handler. */
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

describe('POST /analyze with nmapOutput — correlation integration', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    mockFetch.mockReset();
    mockFetch.mockResolvedValue({ ok: false, status: 404 });
  });

  it('should merge nmap findings with body findings and return analysis covering both sources', async () => {
    const scannerFinding = {
      category: 'tls-ssl',
      severity: 'high',
      description: 'El servidor acepta TLS 1.0 que es un protocolo obsoleto e inseguro.',
      rawValue: 'TLSv1.0',
    };

    const nmapOutput = `
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.9
443/tcp open  https   nginx 1.18.0
`;

    const event = buildEvent({
      findings: [scannerFinding],
      sessionId: 'test-session-correlation',
      nmapOutput,
    });

    const response = await handleAnalyzeRequest(event, {
      executeAnalysis: fallbackAnalyze,
      persistence: mockPersistence,
    });

    expect(response.statusCode).toBe(200);

    const result: AnalysisResult = JSON.parse(response.body);

    // Debe cubrir findings de las fuentes fusionadas: 1 del scanner + 2 de nmap
    // + 1 de correlación determinista (puerto 443/https ↔ debilidad TLS)
    // + 1 informativo de verificación CVE inconclusa (Ola 11) = 5 total
    expect(result.explanations.length).toBe(5);
    // El primero corresponde al finding de TLS (del scanner)
    expect(result.explanations[0]!.findingIndex).toBe(0);
    // Los de Nmap están en posiciones 1 y 2
    expect(result.explanations[1]!.findingIndex).toBe(1);
    expect(result.explanations[2]!.findingIndex).toBe(2);
    // El finding de correlación va al final
    expect(result.explanations[3]!.findingIndex).toBe(3);
    // Debe tener riskScore > 0 porque hay findings de severidad high
    expect(result.riskScore).toBeGreaterThan(0);
  });

  it('should emit a correlation finding linking the Nmap https service (port 443) with the scanner TLS finding', async () => {
    const scannerFinding = {
      category: 'tls-ssl',
      severity: 'high',
      description: 'El servidor acepta TLS 1.0 que es un protocolo obsoleto e inseguro.',
      rawValue: 'TLSv1.0',
    };

    const nmapOutput = `
PORT    STATE SERVICE VERSION
443/tcp open  https   nginx 1.18.0
`;

    const event = buildEvent({
      findings: [scannerFinding],
      sessionId: 'test-session-correlation-rule',
      nmapOutput,
    });

    const response = await handleAnalyzeRequest(event, {
      executeAnalysis: fallbackAnalyze,
      persistence: mockPersistence,
    });

    expect(response.statusCode).toBe(200);
    const result: AnalysisResult = JSON.parse(response.body);

    // 1 scanner + 1 nmap + 1 correlación + 1 informativo verificación inconclusa (Ola 11) = 4
    expect(result.explanations.length).toBe(4);
  });

  it('should work with nmapOutput only (no scanner findings in body)', async () => {
    const nmapOutput = `
PORT    STATE SERVICE VERSION
80/tcp  open  http    Apache 2.4.52
`;

    const event = buildEvent({
      findings: [],
      sessionId: 'test-session-nmap-only',
      nmapOutput,
    });

    const response = await handleAnalyzeRequest(event, {
      executeAnalysis: fallbackAnalyze,
      persistence: mockPersistence,
    });

    expect(response.statusCode).toBe(200);

    const result: AnalysisResult = JSON.parse(response.body);
    // Debe tener al menos 1 explanation (del finding derivado de Nmap)
    expect(result.explanations.length).toBeGreaterThanOrEqual(1);
  });

  it('should still work normally without nmapOutput (backward compatible)', async () => {
    const event = buildEvent({
      findings: [{
        category: 'http-headers',
        severity: 'medium',
        description: 'El header X-Content-Type-Options no está presente en la respuesta HTTP.',
        rawValue: null,
      }],
      sessionId: 'test-session-normal',
      sourceContext: 'Escaneo web de example.com',
    });

    const response = await handleAnalyzeRequest(event, {
      executeAnalysis: fallbackAnalyze,
      persistence: mockPersistence,
    });

    expect(response.statusCode).toBe(200);

    const result: AnalysisResult = JSON.parse(response.body);
    expect(result.explanations.length).toBe(1);
  });
});
