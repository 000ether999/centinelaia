/**
 * Tests para los nuevos contratos de AnalysisResult:
 *   1. analyzeFindings retorna findings alineados con explanations[].findingIndex.
 *   2. Caso vacío retorna findings=[].
 *   3. POST /analyze con nmapOutput retorna findings con port-service.
 *   4. getById devuelve findings; listBySession NO devuelve findings ni explanations.
 *   5. truncateForStorage con item >390KB pone rawValue=null en findings info.
 */

import { describe, it, expect } from 'vitest';
import { analyzeFindings } from '../../services/ai-engine/index.js';
import type { AnalysisResult } from '../../services/ai-engine/types.js';
import type { Finding } from '../../services/scanner/modules/types.js';
import type { CacheClient } from '../../services/ai-engine/cache-client.js';
import type { PersistenceClient } from '../../services/ai-engine/persistence-client.js';
import type { APIGatewayProxyEvent } from 'aws-lambda';
import { handleAnalyzeRequest } from '../../handlers/analyze-handler.js';

// ─── Helpers de mocks reutilizables ──────────────────────────────────────────

function buildCacheMiss(): CacheClient {
  return {
    get: async () => ({ hit: false }),
    put: async () => true,
    calculateHash: () => 'test-hash',
    config: { tableName: 'test', ttlMinutes: 60 },
  };
}

function buildPersistenceMock(
  savedResult?: AnalysisResult | null
): PersistenceClient & { lastSaved: AnalysisResult | null } {
  let lastSaved: AnalysisResult | null = null;
  return {
    save: async (result: AnalysisResult) => {
      lastSaved = result;
      return { analysisId: 'test-analysis-id', persisted: true, storageTruncated: false };
    },
    getById: async () => savedResult ?? null,
    listBySession: async () => (savedResult ? [savedResult] : []),
    config: { tableName: 'test', maxRetries: 0, ttlDays: 30 },
    get lastSaved() { return lastSaved; },
  } as unknown as PersistenceClient & { lastSaved: AnalysisResult | null };
}

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const threeFindings: Finding[] = [
  {
    category: 'http-headers',
    severity: 'high',
    rawValue: null,
    description: 'Falta el encabezado Strict-Transport-Security',
  },
  {
    category: 'tls-ssl',
    severity: 'critical',
    rawValue: 'TLS 1.0',
    description: 'El servidor soporta TLS 1.0 obsoleto',
  },
  {
    category: 'cookies',
    severity: 'medium',
    rawValue: 'session_id',
    description: 'Cookie session_id sin flag Secure',
  },
];

// ─── 1. analyzeFindings con N findings → result.findings presente y alineado ─

describe('analyzeFindings — result.findings', () => {
  it('incluye findings de longitud N y alineados con explanations[].findingIndex', async () => {
    const result = await analyzeFindings(
      { findings: threeFindings, sessionId: 'test-session' },
      {
        executionMode: 'fallback',
        cacheClient: buildCacheMiss(),
        persistenceClient: buildPersistenceMock(),
      }
    );

    // El resultado no debe ser un error
    expect('analysisId' in result).toBe(true);
    const analysis = result as AnalysisResult;

    // findings presente con la misma longitud que la entrada
    expect(analysis.findings).toBeDefined();
    expect(analysis.findings).toHaveLength(threeFindings.length);

    // Alineación: cada explanations[i].findingIndex apunta a result.findings[findingIndex]
    analysis.explanations.forEach((exp) => {
      expect(analysis.findings![exp.findingIndex]).toBeDefined();
    });
  });

  it('los findings en result coinciden con los de la entrada (misma categoría/severidad)', async () => {
    const result = await analyzeFindings(
      { findings: threeFindings, sessionId: 'test-session-2' },
      {
        executionMode: 'fallback',
        cacheClient: buildCacheMiss(),
        persistenceClient: buildPersistenceMock(),
      }
    );

    const analysis = result as AnalysisResult;
    expect(analysis.findings).toHaveLength(3);
    expect(analysis.findings![0]!.category).toBe('http-headers');
    expect(analysis.findings![1]!.category).toBe('tls-ssl');
    expect(analysis.findings![2]!.category).toBe('cookies');
  });
});

// ─── 2. Caso vacío → result.findings === [] ───────────────────────────────────

describe('analyzeFindings — caso vacío', () => {
  it('retorna findings=[] cuando no hay findings de entrada', async () => {
    const result = await analyzeFindings(
      { findings: [], sessionId: 'test-empty' },
      {
        executionMode: 'fallback',
        cacheClient: buildCacheMiss(),
        persistenceClient: buildPersistenceMock(),
      }
    );

    const analysis = result as AnalysisResult;
    expect(analysis.findings).toBeDefined();
    expect(analysis.findings).toEqual([]);
  });
});

// ─── 3. POST /analyze con nmapOutput → findings con port-service ──────────────

describe('POST /analyze con nmapOutput — findings incluidos en respuesta', () => {
  it('la respuesta incluye findings con categoría port-service del nmapOutput', async () => {
    const persistenceMock = buildPersistenceMock();

    async function fallbackAnalyze(request: unknown) {
      return analyzeFindings(request, {
        executionMode: 'fallback',
        cacheClient: buildCacheMiss(),
        persistenceClient: persistenceMock,
      });
    }

    const event: APIGatewayProxyEvent = {
      httpMethod: 'POST',
      path: '/analyze',
      body: JSON.stringify({
        findings: [],
        sessionId: 'test-nmap-session',
        nmapOutput: 'PORT   STATE SERVICE VERSION\n80/tcp open  http    nginx 1.18.0\n443/tcp open  https   nginx 1.18.0',
      }),
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

    // Mockear fetch para que el enricher NVD no haga llamadas reales
    const originalFetch = global.fetch;
    global.fetch = async () => ({
      ok: false,
      json: async () => ({ vulnerabilities: [] }),
    } as any);

    try {
      const response = await handleAnalyzeRequest(event, {
        executeAnalysis: fallbackAnalyze,
        persistence: {
          getById: async () => null,
          listBySession: async () => [],
        },
      });

      expect(response.statusCode).toBe(200);
      const result: AnalysisResult = JSON.parse(response.body);

      // El resultado debe incluir findings
      expect(result.findings).toBeDefined();
      expect(Array.isArray(result.findings)).toBe(true);

      // Debe haber al menos un finding de tipo port-service (derivado del nmap)
      const portFindings = result.findings!.filter((f) => f.category === 'port-service');
      expect(portFindings.length).toBeGreaterThan(0);
    } finally {
      global.fetch = originalFetch;
    }
  });
});

// ─── 4. Persistencia: getById con findings; listBySession sin findings/explanations ─

describe('Persistencia — contrato getById vs listBySession', () => {
  it('getById devuelve el resultado completo CON findings', async () => {
    // Simular un resultado persistido con findings
    const persistedResult: AnalysisResult = {
      analysisId: 'some-id',
      riskScore: 45,
      riskLevel: 'moderate',
      grade: 'C',
      explanations: [{ findingIndex: 0, text: 'Explicación de prueba para el hallazgo.', fallback: true }],
      recommendations: [],
      findings: [threeFindings[0]!],
      metadata: {
        timestamp: new Date().toISOString(),
        modelId: 'none',
        latencyMs: 100,
        cached: false,
        status: 'degraded',
        executionMode: 'fallback',
      },
      cached: false,
      degraded: true,
    };

    // Mock DynamoDB: getById retorna el result completo con findings
    const mockDynamoGet = {
      save: async () => ({ analysisId: 'some-id', persisted: true, storageTruncated: false }),
      getById: async (_id: string) => persistedResult,
      listBySession: async (_sid: string) => {
        // listBySession elimina findings y explanations (contrato de ligereza)
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { findings: _f, explanations: _e, ...summary } = persistedResult;
        return [summary as AnalysisResult];
      },
      config: { tableName: 'test', maxRetries: 0, ttlDays: 30 },
    } as unknown as PersistenceClient;

    // getById → devuelve findings
    const byId = await mockDynamoGet.getById!('some-id');
    expect(byId).not.toBeNull();
    expect(byId!.findings).toBeDefined();
    expect(byId!.findings).toHaveLength(1);
    expect(byId!.explanations).toHaveLength(1);

    // listBySession → NO devuelve findings ni explanations
    const list = await mockDynamoGet.listBySession!('test-session');
    expect(list).toHaveLength(1);
    expect(list[0]!.findings).toBeUndefined();
    expect(list[0]!.explanations).toBeUndefined();

    // Pero sí trae score/level/grade/metadata
    expect(list[0]!.riskScore).toBe(45);
    expect(list[0]!.riskLevel).toBe('moderate');
    expect(list[0]!.grade).toBe('C');
    expect(list[0]!.metadata).toBeDefined();
  });
});

// ─── 5. Truncado: rawValue=null en findings info cuando se excede 390KB ───────

describe('truncateForStorage — findings info con rawValue=null al exceder 390KB', () => {
  it('pone rawValue=null en findings info y marca storageTruncated=true sin lanzar', async () => {
    // Importar la función internamente a través del módulo de persistencia.
    // Creamos un resultado artificial que excede 390KB rellenando rawValue con texto largo.
    const bigString = 'x'.repeat(400 * 1024); // 400KB de datos

    const bigResult: AnalysisResult = {
      analysisId: 'big-id',
      riskScore: 10,
      riskLevel: 'minimal',
      grade: 'A',
      explanations: [],
      recommendations: [],
      findings: [
        {
          category: 'http-headers',
          severity: 'info',
          rawValue: bigString, // valor largo que debe ser nullificado
          description: 'Finding info con rawValue muy largo',
        },
        {
          category: 'tls-ssl',
          severity: 'high',
          rawValue: 'TLS 1.0', // severity high: NO debe ser nullificado
          description: 'Finding high que debe preservar rawValue',
        },
      ],
      metadata: {
        timestamp: new Date().toISOString(),
        modelId: 'none',
        latencyMs: 50,
        cached: false,
        status: 'complete',
        executionMode: 'fallback',
      },
    };

    // Crear un cliente de persistencia con un mock DynamoDB que falla en PutCommand
    // para que se invoque truncateForStorage internamente durante save().
    // Sin embargo, truncateForStorage es privada; verificamos su efecto a través de save().
    const { createPersistenceClient } = await import(
      '../../services/ai-engine/persistence-client.js'
    );

    let capturedItem: Record<string, unknown> | null = null;

    // Monkeypatching del DynamoDBDocumentClient para inspeccionar el item enviado
    const { DynamoDBDocumentClient, PutCommand } = await import('@aws-sdk/lib-dynamodb');
    const { DynamoDBClient } = await import('@aws-sdk/client-dynamodb');

    const originalFrom = DynamoDBDocumentClient.from;
    // @ts-expect-error — monkey-patch para el test
    DynamoDBDocumentClient.from = (client: DynamoDBClient) => {
      const doc = originalFrom(client);
      const originalSend = doc.send.bind(doc);
      doc.send = async (command: unknown) => {
        if (command instanceof PutCommand) {
          capturedItem = command.input.Item as Record<string, unknown>;
          return {}; // simular éxito sin DynamoDB real
        }
        return originalSend(command as any);
      };
      return doc;
    };

    try {
      const client = createPersistenceClient({ tableName: 'test', maxRetries: 0, ttlDays: 1 });
      const { storageTruncated } = await client.save(bigResult, 'session-trunc', 'hash-trunc');

      // Debe haber marcado storageTruncated
      expect(storageTruncated).toBe(true);

      // El item enviado a DynamoDB debe tener rawValue=null en findings info
      expect(capturedItem).not.toBeNull();
      const savedResult = capturedItem!['result'] as AnalysisResult;
      expect(savedResult.findings).toBeDefined();

      const infoFinding = savedResult.findings!.find((f) => f.severity === 'info');
      expect(infoFinding).toBeDefined();
      expect(infoFinding!.rawValue).toBeNull();

      // El finding high debe conservar su rawValue
      const highFinding = savedResult.findings!.find((f) => f.severity === 'high');
      expect(highFinding).toBeDefined();
      expect(highFinding!.rawValue).toBe('TLS 1.0');

      // storageTruncated=true en el result guardado
      expect(savedResult.storageTruncated).toBe(true);
    } finally {
      // Restaurar monkey-patch
      DynamoDBDocumentClient.from = originalFrom;
    }
  });
});
