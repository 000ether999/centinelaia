/**
 * Test del comportamiento fail-open del Store (Req 10.5).
 * Verifica que cuando DynamoDB falla tras 2 reintentos, el store
 * retorna { persisted: false } sin lanzar excepción, y que el handler
 * respondería 200 con el ScanResult completo + persisted: false.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ScanResult } from '../../models/scan.js';

// ─── Mock del AWS SDK ────────────────────────────────────────────────────────

const mockSend = vi.fn();

vi.mock('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: vi.fn(() => ({})),
}));

vi.mock('@aws-sdk/lib-dynamodb', () => ({
  DynamoDBDocumentClient: {
    from: () => ({ send: mockSend }),
  },
  PutCommand: vi.fn((input: unknown) => ({ input })),
  GetCommand: vi.fn((input: unknown) => ({ input })),
  QueryCommand: vi.fn((input: unknown) => ({ input })),
}));

import { createDynamoStore } from '../../services/scanner/store.js';

// ─── Fixture ─────────────────────────────────────────────────────────────────

const fakeScanResult: ScanResult = {
  scanId: 'test-scan-123',
  target: 'https://example.com',
  timestamp: '2026-07-22T00:00:00.000Z',
  durationMs: 1500,
  totalFindings: 1,
  status: 'complete',
  sessionId: 'session-abc',
  consent: {
    authorizationConfirmed: true,
    target: 'https://example.com',
    confirmedAt: '2026-07-22T00:00:00.000Z',
  },
  findings: [
    {
      category: 'http-headers',
      severity: 'high',
      rawValue: null,
      description: 'Security header missing: Content-Security-Policy',
    },
  ],
  persisted: true,
};

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('Store fail-open behavior (Req 10.5)', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it('should return { persisted: false } after 3 consecutive DynamoDB failures (1 attempt + 2 retries)', async () => {
    // Arrange: DynamoDB siempre falla
    mockSend.mockRejectedValue(new Error('ServiceUnavailableException: DynamoDB is down'));

    const store = createDynamoStore('centinelaia-scans');

    // Act
    const result = await store.put(fakeScanResult);

    // Assert
    expect(result.persisted).toBe(false);

    // Confirmar que se hicieron 3 intentos (1 original + 2 retries)
    expect(mockSend).toHaveBeenCalledTimes(3);
  });

  it('should NOT throw an exception — the promise resolves normally', async () => {
    // Arrange: DynamoDB siempre falla
    mockSend.mockRejectedValue(new Error('InternalServerError'));

    const store = createDynamoStore('centinelaia-scans');

    // Act & Assert: no debe lanzar
    await expect(store.put(fakeScanResult)).resolves.toEqual({ persisted: false });
  });

  it('should return { persisted: true } on success', async () => {
    // Arrange: DynamoDB funciona
    mockSend.mockResolvedValue({});

    const store = createDynamoStore('centinelaia-scans');

    // Act
    const result = await store.put(fakeScanResult);

    // Assert
    expect(result.persisted).toBe(true);
    expect(mockSend).toHaveBeenCalledTimes(1); // Sin reintentos
  });

  it('should succeed on 2nd attempt after 1 failure (retries work)', async () => {
    // Arrange: primera vez falla, segunda vez OK
    mockSend
      .mockRejectedValueOnce(new Error('ProvisionedThroughputExceededException'))
      .mockResolvedValueOnce({});

    const store = createDynamoStore('centinelaia-scans');

    // Act
    const result = await store.put(fakeScanResult);

    // Assert
    expect(result.persisted).toBe(true);
    expect(mockSend).toHaveBeenCalledTimes(2);
  });
});
