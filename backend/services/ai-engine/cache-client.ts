/**
 * Cliente de caché para el AI Engine.
 * Gestiona la caché de resultados de análisis en DynamoDB.
 * Calcula hash SHA-256 determinista para findings (independiente del orden),
 * y opera en modo fail-open: errores se loguean pero no bloquean el flujo.
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import { createHash } from 'node:crypto';
import type { Finding } from '../scanner/modules/types.js';
import type { AnalysisResult } from './types.js';

/** Configuración del cliente de caché */
export interface CacheClientConfig {
  tableName: string;
  ttlMinutes: number;
}

/** Resultado de búsqueda en caché */
export interface CacheLookupResult {
  hit: boolean;
  result?: AnalysisResult;
}

/**
 * Calcula un hash SHA-256 determinista para un arreglo de findings.
 * Ordena los findings por (category, severity, description) antes de hashear
 * para garantizar que el mismo conjunto produce el mismo hash sin importar
 * el orden original del arreglo.
 */
export function calculateFindingsHash(findings: Finding[]): string {
  // Ordenar findings de forma determinista
  const sorted = [...findings].sort((a, b) => {
    // Ordenar por category primero
    const catCompare = a.category.localeCompare(b.category);
    if (catCompare !== 0) return catCompare;

    // Luego por severity
    const sevCompare = a.severity.localeCompare(b.severity);
    if (sevCompare !== 0) return sevCompare;

    // Finalmente por description
    return a.description.localeCompare(b.description);
  });

  // Serializar de forma estable (sin rawValue para evitar variaciones no relevantes)
  const serialized = JSON.stringify(
    sorted.map((f) => ({
      category: f.category,
      severity: f.severity,
      description: f.description,
    }))
  );

  // Calcular SHA-256
  return createHash('sha256').update(serialized).digest('hex');
}

/**
 * Crea el cliente de caché con la configuración dada.
 * Retorna funciones para buscar y almacenar resultados cacheados.
 */
export function createCacheClient(config?: Partial<CacheClientConfig>) {
  const resolvedConfig: CacheClientConfig = {
    tableName: process.env['CACHE_TABLE'] || 'centinelaia-analysis-cache',
    ttlMinutes: parseInt(process.env['CACHE_TTL_MINUTES'] || '60', 10),
    ...config,
  };

  const dynamoClient = new DynamoDBClient({});
  const docClient = DynamoDBDocumentClient.from(dynamoClient);

  /**
   * Busca un resultado cacheado por hash de findings.
   * Fail-open: si ocurre un error, retorna cache miss y loguea.
   * Await con timeout de 2s.
   */
  async function get(findingsHash: string): Promise<CacheLookupResult> {
    try {
      const result = await withTimeout(
        docClient.send(
          new GetCommand({
            TableName: resolvedConfig.tableName,
            Key: { findingsHash },
          })
        ),
        2000
      );

      if (!result.Item) {
        return { hit: false };
      }

      // Verificar TTL (doble validación — DynamoDB puede no haber limpiado aún)
      const expiresAt = result.Item['expiresAt'] as number | undefined;
      if (expiresAt && expiresAt < Math.floor(Date.now() / 1000)) {
        return { hit: false };
      }

      return {
        hit: true,
        result: result.Item['result'] as AnalysisResult,
      };
    } catch (error: unknown) {
      console.warn(
        '[CacheClient] Error al leer caché (fail-open, continuando sin caché):',
        (error as Error).message || 'unknown'
      );
      return { hit: false };
    }
  }

  /**
   * Almacena un resultado en caché con TTL.
   * Fail-open: si ocurre un error, se loguea y se continúa.
   * Await con timeout de 2s.
   */
  async function put(findingsHash: string, result: AnalysisResult): Promise<boolean> {
    try {
      const now = new Date();
      const expiresAt = Math.floor(now.getTime() / 1000) + resolvedConfig.ttlMinutes * 60;

      await withTimeout(
        docClient.send(
          new PutCommand({
            TableName: resolvedConfig.tableName,
            Item: {
              findingsHash,
              result,
              createdAt: now.toISOString(),
              expiresAt,
            },
          })
        ),
        2000
      );

      return true;
    } catch (error: unknown) {
      console.warn(
        '[CacheClient] Error al escribir caché (fail-open, continuando):',
        (error as Error).message || 'unknown'
      );
      return false;
    }
  }

  return { get, put, calculateHash: calculateFindingsHash, config: resolvedConfig };
}

/**
 * Envuelve una promesa con un timeout.
 * Si la promesa no se resuelve antes del timeout, rechaza con error.
 */
function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`Timeout de ${timeoutMs}ms excedido`));
    }, timeoutMs);

    promise
      .then((result) => {
        clearTimeout(timer);
        resolve(result);
      })
      .catch((error) => {
        clearTimeout(timer);
        reject(error);
      });
  });
}

/** Tipo exportado del cliente para dependency injection */
export type CacheClient = ReturnType<typeof createCacheClient>;
