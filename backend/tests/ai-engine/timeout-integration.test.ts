/**
 * Test de integración: verifica que el timeout global del orchestrator
 * cancela correctamente la llamada a Bedrock y produce un resultado degradado.
 */

import { describe, it, expect } from 'vitest';
import { analyzeFindings } from '../../services/ai-engine/index.js';
import type { BedrockClient } from '../../services/ai-engine/bedrock-client.js';
import type { CacheClient } from '../../services/ai-engine/cache-client.js';
import type { PersistenceClient } from '../../services/ai-engine/persistence-client.js';

// ─── Mocks ───────────────────────────────────────────────────────────────────

/**
 * Mock de Bedrock Client que NUNCA resuelve (simula timeout infinito).
 * Si el AbortSignal funciona correctamente, la promesa se rechaza
 * antes de que pasen 25s.
 */
function createNeverResolvingBedrockClient(): BedrockClient {
  return {
    invoke: (_prompt: string, signal?: AbortSignal): Promise<string> => {
      return new Promise((_resolve, reject) => {
        // Si la señal ya está abortada, rechazar inmediatamente
        if (signal?.aborted) {
          reject(new Error('Aborted'));
          return;
        }
        // Escuchar señal de abort
        const onAbort = () => reject(new Error('Aborted: timeout global alcanzado'));
        signal?.addEventListener('abort', onAbort, { once: true });
        // NUNCA resolver — depende del abort signal para salir
      });
    },
    config: {
      modelId: 'amazon.nova-micro-v1:0',
      maxTokens: 2048,
      temperature: 0.3,
      timeoutMs: 6000,
      maxRetries: 2,
    },
  };
}

/** Mock de cache que siempre retorna miss */
function createMockCacheClient(): CacheClient {
  return {
    get: async () => ({ hit: false }),
    put: async () => true,
    calculateHash: () => 'mock-hash',
    config: { tableName: 'test-cache', ttlMinutes: 60 },
  };
}

/** Mock de persistence que siempre reporta éxito */
function createMockPersistenceClient(): PersistenceClient {
  return {
    save: async () => ({ analysisId: 'test-id-123', persisted: true, storageTruncated: false }),
    getById: async () => null,
    listBySession: async () => [],
    config: { tableName: 'test-analyses', maxRetries: 2, ttlDays: 30 },
  };
}

// ─── Test fixtures ───────────────────────────────────────────────────────────

const validRequest = {
  findings: [
    {
      category: 'http-headers',
      severity: 'high',
      rawValue: null,
      description: 'El header Strict-Transport-Security no está presente',
    },
    {
      category: 'tls-ssl',
      severity: 'critical',
      rawValue: 'TLS 1.0',
      description: 'El servidor soporta TLS 1.0, un protocolo obsoleto con vulnerabilidades',
    },
    {
      category: 'cookies',
      severity: 'medium',
      rawValue: 'session_id',
      description: 'La cookie session_id no tiene el flag Secure configurado correctamente',
    },
  ],
  sessionId: 'test-session-timeout',
};

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('AI Engine — Timeout global y degradación', () => {
  it('debe cancelar Bedrock y retornar resultado degradado cuando Bedrock nunca responde', async () => {
    // Reducir el timeout global para el test (no esperar 25s reales)
    const originalEnv = process.env['ORCHESTRATOR_TIMEOUT_MS'];
    process.env['ORCHESTRATOR_TIMEOUT_MS'] = '500'; // 500ms para el test

    try {
      const startTime = Date.now();

      const result = await analyzeFindings(validRequest, {
        bedrockClient: createNeverResolvingBedrockClient(),
        cacheClient: createMockCacheClient(),
        persistenceClient: createMockPersistenceClient(),
      });

      const elapsed = Date.now() - startTime;

      // 1. La función RETORNÓ (no quedó colgada)
      expect(result).toBeDefined();

      // 2. Retornó dentro de un tiempo razonable (< 2s, no infinito)
      expect(elapsed).toBeLessThan(2000);

      // 3. Es un AnalysisResult, no un error genérico
      expect('riskScore' in result).toBe(true);
      expect('degraded' in result).toBe(true);

      const analysisResult = result as Record<string, unknown>;

      // 4. Está marcado como degradado
      expect(analysisResult['degraded']).toBe(true);

      // 5. El Risk Score es correcto (calculado con fórmula determinista)
      // 1 critical (25) + 1 high (15) + 1 medium (8) = 48 base
      // Diversidad: 3 categorías con medium+ → +30% → 48 * 1.3 = 62.4 → 62
      expect(analysisResult['riskScore']).toBe(62);
      expect(analysisResult['riskLevel']).toBe('high');

      // 6. Tiene explicaciones (fallback) para cada finding
      const explanations = analysisResult['explanations'] as Array<unknown>;
      expect(explanations).toHaveLength(3);

      // 7. Tiene recomendaciones (genéricas)
      const recommendations = analysisResult['recommendations'] as Array<unknown>;
      expect(recommendations.length).toBeGreaterThan(0);

      // 8. Metadata indica status degraded
      const metadata = analysisResult['metadata'] as Record<string, unknown>;
      expect(metadata['status']).toBe('degraded');
      expect(metadata['modelId']).toBe('none');
    } finally {
      // Restaurar env
      if (originalEnv !== undefined) {
        process.env['ORCHESTRATOR_TIMEOUT_MS'] = originalEnv;
      } else {
        delete process.env['ORCHESTRATOR_TIMEOUT_MS'];
      }
    }
  }, 10000); // timeout del test: 10s (mucho más que los 500ms del orchestrator)
});
