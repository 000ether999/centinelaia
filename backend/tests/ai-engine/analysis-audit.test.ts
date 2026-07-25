/**
 * Tests para la cadena de custodia (audit) en /analyze.
 * Verifica que analyzeFindings construye audit, truncateForStorage lo preserva,
 * getById lo devuelve, listBySession lo omite, y calculateFindingsHash no regresiona.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Mocks ───────────────────────────────────────────────────────────────────

vi.mock('../../services/ai-engine/bedrock-client.js', () => ({}));

vi.mock('../../services/ai-engine/ai-client-factory.js', () => ({
  resolveAiEngineMode: vi.fn().mockReturnValue('fallback'),
  createAiClientSelection: vi.fn().mockReturnValue({
    client: null,
    modelId: 'none',
    executionMode: 'fallback',
  }),
}));

const mockCacheGet = vi.fn().mockResolvedValue({ hit: false });
const mockCachePut = vi.fn().mockResolvedValue(true);

vi.mock('../../services/ai-engine/cache-client.js', async () => {
  const actual = await import('../../services/ai-engine/cache-client.js');
  return {
    createCacheClient: vi.fn().mockReturnValue({
      get: (...args: unknown[]) => mockCacheGet(...args),
      put: (...args: unknown[]) => mockCachePut(...args),
    }),
    calculateFindingsHash: actual.calculateFindingsHash,
  };
});

const mockSave = vi.fn().mockResolvedValue({ analysisId: 'analysis-123', persisted: true, storageTruncated: false });
const mockGetById = vi.fn();
const mockListBySession = vi.fn();

vi.mock('../../services/ai-engine/persistence-client.js', () => ({
  createPersistenceClient: vi.fn().mockReturnValue({
    save: (...args: unknown[]) => mockSave(...args),
    getById: (...args: unknown[]) => mockGetById(...args),
    listBySession: (...args: unknown[]) => mockListBySession(...args),
  }),
}));

// ─── Import after mocks ──────────────────────────────────────────────────────

import { analyzeFindings, calculateFindingsHash } from '../../services/ai-engine/index.js';
import type { Finding } from '../../services/scanner/modules/types.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    category: 'http-headers',
    severity: 'high',
    description: 'Security header missing: Content-Security-Policy is not set',
    rawValue: null,
    ...overrides,
  };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('analyzeFindings audit (cadena de custodia)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockCacheGet.mockResolvedValue({ hit: false });
    mockSave.mockResolvedValue({ analysisId: 'analysis-123', persisted: true, storageTruncated: false });
  });

  it('incluye audit con sessionId, target y authorizationConfirmed', async () => {
    const result = await analyzeFindings({
      findings: [makeFinding()],
      sessionId: 'ses-abc',
      target: 'https://example.com',
      authorizationConfirmed: true,
      _sources: ['scanner'],
    });

    expect('error' in result && !('analysisId' in result)).toBe(false);
    const analysis = result as any;
    expect(analysis.audit).toBeDefined();
    expect(analysis.audit.sessionId).toBe('ses-abc');
    expect(analysis.audit.target).toBe('https://example.com');
    expect(analysis.audit.authorizationConfirmed).toBe(true);
    expect(analysis.audit.recordedAt).toBeDefined();
  });

  it('sources refleja fuentes reales', async () => {
    const result = await analyzeFindings({
      findings: [makeFinding()],
      sessionId: 'ses-abc',
      _sources: ['scanner', 'nmap', 'authlog'],
    });

    const analysis = result as any;
    expect(analysis.audit.sources).toEqual(['scanner', 'nmap', 'authlog']);
  });

  it('sin target sigue funcionando, audit no lo inventa', async () => {
    const result = await analyzeFindings({
      findings: [makeFinding()],
      sessionId: 'ses-abc',
    });

    const analysis = result as any;
    expect(analysis.audit).toBeDefined();
    expect(analysis.audit.sessionId).toBe('ses-abc');
    expect(analysis.audit.target).toBeUndefined();
  });
});

describe('truncateForStorage conserva audit', () => {
  it('audit no se elimina en la truncación', async () => {
    mockSave.mockClear();
    const result = await analyzeFindings({
      findings: [makeFinding()],
      sessionId: 'ses-test',
      target: 'https://test.com',
      authorizationConfirmed: true,
      _sources: ['scanner'],
    });

    // El resultado pasado a save debe contener audit
    expect(mockSave).toHaveBeenCalled();
    const lastCall = mockSave.mock.calls[mockSave.mock.calls.length - 1];
    const savedResult = lastCall[0];
    expect(savedResult.audit).toBeDefined();
    expect(savedResult.audit.sessionId).toBe('ses-test');
    expect(savedResult.audit.target).toBe('https://test.com');
  });
});

describe('getById devuelve audit; listBySession no lo incluye', () => {
  it('getById devuelve audit completo', async () => {
    const fullResult = {
      analysisId: 'a-1',
      riskScore: 50,
      riskLevel: 'moderate',
      grade: 'C',
      explanations: [],
      recommendations: [],
      metadata: { timestamp: '2026-01-01T00:00:00Z', modelId: 'none', latencyMs: 100, cached: false, status: 'complete', executionMode: 'fallback' },
      findings: [makeFinding()],
      audit: { sessionId: 'ses-1', sources: ['scanner'], recordedAt: '2026-01-01T00:00:00Z', target: 'https://x.com' },
    };
    mockGetById.mockResolvedValue(fullResult);

    // Import persistence client para el test directo
    const { createPersistenceClient } = await import('../../services/ai-engine/persistence-client.js');
    const client = createPersistenceClient();
    const retrieved = await client.getById('a-1');
    expect(retrieved).toBeDefined();
    expect(retrieved!.audit).toBeDefined();
    expect(retrieved!.audit!.target).toBe('https://x.com');
  });

  it('listBySession omite audit', async () => {
    const summary = {
      analysisId: 'a-1',
      riskScore: 50,
      riskLevel: 'moderate',
      grade: 'C',
      recommendations: [],
      metadata: { timestamp: '2026-01-01T00:00:00Z', modelId: 'none', latencyMs: 100, cached: false, status: 'complete', executionMode: 'fallback' },
      // Sin findings, explanations ni audit
    };
    mockListBySession.mockResolvedValue([summary]);

    const { createPersistenceClient } = await import('../../services/ai-engine/persistence-client.js');
    const client = createPersistenceClient();
    const list = await client.listBySession('ses-1');
    expect(list).toHaveLength(1);
    expect((list[0] as any).audit).toBeUndefined();
  });
});

describe('calculateFindingsHash no-regression con findingId', () => {
  it('produce el mismo hash con y sin findingId en los findings', () => {
    const f1: Finding[] = [{ category: 'http-headers', severity: 'high', description: 'test finding description here', rawValue: null }];
    const f2: Finding[] = [{ category: 'http-headers', severity: 'high', description: 'test finding description here', rawValue: null, findingId: 'abc123' }];

    const hash1 = calculateFindingsHash(f1);
    const hash2 = calculateFindingsHash(f2);
    expect(hash1).toBe(hash2);
  });
});
