/**
 * Persistencia de resultados de escaneo en DynamoDB.
 * Implementa reintentos con backoff exponencial y truncamiento
 * automático si el item excede 390KB (límite DynamoDB = 400KB).
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand,
  QueryCommand,
} from '@aws-sdk/lib-dynamodb';
import { ScanResult } from '../../models/scan.js';

export interface ScanStore {
  /** Guarda un ScanResult. Reintenta hasta 2 veces con backoff exponencial. */
  put(result: ScanResult): Promise<{ persisted: boolean }>;

  /** Recupera un ScanResult por scanId. */
  get(scanId: string): Promise<ScanResult | null>;

  /** Lista ScanResults por sessionId, ordenados por timestamp desc, max 50. */
  listBySession(sessionId: string): Promise<ScanResult[]>;
}

/** Límite de tamaño en bytes antes de truncar (deja 10KB de margen). */
const MAX_ITEM_BYTES = 390 * 1024;

/** Configuración de reintentos. */
const RETRY_CONFIG = {
  maxRetries: 2,
  baseDelayMs: 100,
  backoffMultiplier: 2,
} as const;

/**
 * Pausa la ejecución por `ms` milisegundos.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Trunca rawValue de Findings con severidad "info" hasta que el item
 * serializado quepa en MAX_ITEM_BYTES. Muta el objeto y marca truncated=true.
 */
function truncateIfNeeded(result: ScanResult): ScanResult {
  let serialized = JSON.stringify(result);

  if (serialized.length <= MAX_ITEM_BYTES) {
    return result;
  }

  // Recortar rawValue de findings con severidad "info"
  for (const finding of result.findings) {
    if (finding.severity === 'info' && finding.rawValue !== null) {
      finding.rawValue = null;
      serialized = JSON.stringify(result);
      if (serialized.length <= MAX_ITEM_BYTES) {
        result.truncated = true;
        return result;
      }
    }
  }

  // Si aún excede tras truncar todos los "info", marcar como truncado
  result.truncated = true;
  return result;
}

/**
 * Crea una instancia de ScanStore respaldada por DynamoDB.
 */
export function createDynamoStore(tableName: string): ScanStore {
  const client = new DynamoDBClient({});
  const docClient = DynamoDBDocumentClient.from(client);

  return {
    async put(result: ScanResult): Promise<{ persisted: boolean }> {
      const item = truncateIfNeeded({ ...result, findings: result.findings.map((f) => ({ ...f })) });

      for (let attempt = 0; attempt <= RETRY_CONFIG.maxRetries; attempt++) {
        try {
          await docClient.send(
            new PutCommand({
              TableName: tableName,
              Item: item,
            }),
          );
          return { persisted: true };
        } catch (error: unknown) {
          if (attempt < RETRY_CONFIG.maxRetries) {
            const delay =
              RETRY_CONFIG.baseDelayMs *
              Math.pow(RETRY_CONFIG.backoffMultiplier, attempt);
            await sleep(delay);
          } else {
            console.error('DynamoDB put failed after retries:', error);
            return { persisted: false };
          }
        }
      }

      // Inalcanzable, pero satisface el compilador
      return { persisted: false };
    },

    async get(scanId: string): Promise<ScanResult | null> {
      try {
        const response = await docClient.send(
          new GetCommand({
            TableName: tableName,
            Key: { scanId },
          }),
        );
        return (response.Item as ScanResult) ?? null;
      } catch (error: unknown) {
        console.error('DynamoDB get failed:', error);
        return null;
      }
    },

    async listBySession(sessionId: string): Promise<ScanResult[]> {
      try {
        const response = await docClient.send(
          new QueryCommand({
            TableName: tableName,
            IndexName: 'sessionId-timestamp-index',
            KeyConditionExpression: 'sessionId = :sid',
            ExpressionAttributeValues: {
              ':sid': sessionId,
            },
            ScanIndexForward: false,
            Limit: 50,
          }),
        );
        return (response.Items as ScanResult[]) ?? [];
      } catch (error: unknown) {
        console.error('DynamoDB query failed:', error);
        return [];
      }
    },
  };
}
