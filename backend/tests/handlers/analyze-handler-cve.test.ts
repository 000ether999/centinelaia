/**
 * Test de integración: POST /analyze también enriquece con CVEs.
 *
 * Antes de este cambio, enrichWithCves solo se invocaba en scan-handler.
 * Este test cubre el gap: al subir un nmapOutput con versiones de software
 * a /analyze, el mismo motor de CVE enricher debe correr y agregar findings
 * 'known-vulnerabilities' — sin depender de Bedrock (modo fallback).
 *
 * También valida la política fail-open: si el NVD falla, /analyze debe
 * responder igual (200 OK) sin findings de CVE.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { APIGatewayProxyEvent } from 'aws-lambda';
import { handleAnalyzeRequest } from '../../handlers/analyze-handler.js';
import type { AnalysisResult } from '../../services/ai-engine/types.js';
import { analyzeFindings } from '../../services/ai-engine/index.js';

// ─── Mock de fetch global (NVD) ──────────────────────────────────────────────

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

/** Respuesta mock del NVD con un CVE para el producto/versión buscado. */
function nvdResponseWithCve(cveId: string, score: number, description: string) {
  return {
    ok: true,
    json: async () => ({
      vulnerabilities: [
        {
          cve: {
            id: cveId,
            descriptions: [{ lang: 'en', value: description }],
            metrics: { cvssMetricV31: [{ cvssData: { baseScore: score } }] },
          },
        },
      ],
    }),
  };
}

/** Executor con dependencias mockeadas (cache y persistence in-memory, sin Bedrock). */
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
      save: async () => ({ analysisId: 'test-id', persisted: false, storageTruncated: false }),
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

const NMAP_OUTPUT_WITH_VULNERABLE_VERSION = `
PORT     STATE SERVICE  VERSION
443/tcp  open  https    nginx 1.18.0
`;

describe('POST /analyze — CVE enrichment (gap closure)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    mockFetch.mockReset();
  });

  it('adds known-vulnerabilities findings when NVD reports a CVE for a version detected in nmapOutput', async () => {
    mockFetch.mockResolvedValue(
      nvdResponseWithCve('CVE-2021-23017', 9.4, 'nginx resolver off-by-one heap write vulnerability'),
    );

    const event = buildEvent({
      findings: [],
      sessionId: 'test-session-analyze-cve',
      nmapOutput: NMAP_OUTPUT_WITH_VULNERABLE_VERSION,
    });

    const response = await handleAnalyzeRequest(event, {
      executeAnalysis: fallbackAnalyze,
      persistence: mockPersistence,
    });

    expect(response.statusCode).toBe(200);
    const result: AnalysisResult = JSON.parse(response.body);

    // NVD fue consultado (prueba que enrichWithCves corrió dentro de /analyze)
    expect(mockFetch).toHaveBeenCalled();

    // 1 finding derivado de Nmap (servicio https) + 1 known-vulnerabilities
    // generado por el enricher + 1 correlación versión↔CVE = 3 explicaciones.
    expect(result.explanations.length).toBe(3);
    // La explicación del CVE incluye el resumen de la vulnerabilidad en su texto
    // (el fallback-generator usa finding.description, que contiene ese resumen).
    const cveExplanation = result.explanations.find((e) =>
      e.text.includes('nginx resolver off-by-one heap write vulnerability'),
    );
    expect(cveExplanation).toBeDefined();

    // Bonus: la correlación determinista también enlaza el puerto con el CVE
    const correlationExplanation = result.explanations.find((e) => e.text.includes('CVE-2021-23017'));
    expect(correlationExplanation).toBeDefined();
  });

  it('fail-open: responds 200 without CVE findings when NVD is down', async () => {
    mockFetch.mockRejectedValue(new Error('NVD connection failed'));

    const event = buildEvent({
      findings: [],
      sessionId: 'test-session-analyze-cve-failopen',
      nmapOutput: NMAP_OUTPUT_WITH_VULNERABLE_VERSION,
    });

    const response = await handleAnalyzeRequest(event, {
      executeAnalysis: fallbackAnalyze,
      persistence: mockPersistence,
    });

    expect(response.statusCode).toBe(200);
    const result: AnalysisResult = JSON.parse(response.body);

    // Sin CVEs: solo queda el finding derivado de Nmap (servicio https)
    expect(result.explanations.length).toBe(1);
    // Ninguna explicación debe corresponder a la categoría known-vulnerabilities
    const cveExplanation = result.explanations.find((e) => /CVE-\d{4}-\d+/.test(e.text));
    expect(cveExplanation).toBeUndefined();
  });
});
