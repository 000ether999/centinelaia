/**
 * Cliente de persistencia para el AI Engine.
 * Persiste resultados de análisis en DynamoDB para consulta futura.
 * Genera analysisId (UUID v4), maneja límite de 400KB, y opera
 * en modo fail-open: si falla tras reintentos, reporta persisted=false.
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand, GetCommand, QueryCommand } from '@aws-sdk/lib-dynamodb';
import { v4 as uuidv4 } from 'uuid';
import type { AnalysisResult } from './types.js';

/** Configuración del cliente de persistencia */
export interface PersistenceClientConfig {
  tableName: string;
  maxRetries: number;
  ttlDays: number;
}

/** Límite de DynamoDB para un item (400KB) menos margen de seguridad */
const MAX_ITEM_BYTES = 390 * 1024; // 390KB — margen de seguridad

/**
 * Crea el cliente de persistencia con la configuración dada.
 */
export function createPersistenceClient(config?: Partial<PersistenceClientConfig>) {
  const resolvedConfig: PersistenceClientConfig = {
    tableName: process.env['ANALYSES_TABLE'] || 'centinelaia-analyses',
    maxRetries: 2,
    ttlDays: 30,
    ...config,
  };

  const dynamoClient = new DynamoDBClient({});
  const docClient = DynamoDBDocumentClient.from(dynamoClient);

  /**
   * Persiste un resultado de análisis en DynamoDB.
   * Genera un analysisId UUID v4, maneja el límite de 400KB truncando
   * explanations de findings "info" si es necesario.
   * Retry con backoff (max 2 reintentos). Fail-open.
   */
  async function save(
    result: AnalysisResult,
    sessionId: string,
    findingsHash: string
  ): Promise<{ analysisId: string; persisted: boolean; storageTruncated: boolean }> {
    const analysisId = uuidv4();
    const timestamp = new Date().toISOString();
    const expiresAt = Math.floor(Date.now() / 1000) + resolvedConfig.ttlDays * 24 * 60 * 60;

    // Preparar el resultado para almacenamiento
    let storageResult = { ...result, analysisId };
    let storageTruncated = false;

    // Verificar tamaño y truncar si excede 390KB
    let serialized = JSON.stringify(storageResult);
    if (Buffer.byteLength(serialized, 'utf-8') > MAX_ITEM_BYTES) {
      storageResult = truncateForStorage(storageResult);
      storageTruncated = true;
    }

    const item = {
      analysisId,
      sessionId,
      timestamp,
      findingsHash,
      result: storageResult,
      expiresAt,
    };

    // Intentar guardar con reintentos
    const persisted = await putWithRetry(item);

    return { analysisId, persisted, storageTruncated };
  }

  /**
   * Obtiene un resultado de análisis por su ID.
   */
  async function getById(analysisId: string): Promise<AnalysisResult | null> {
    try {
      const response = await withTimeout(
        docClient.send(
          new GetCommand({
            TableName: resolvedConfig.tableName,
            Key: { analysisId },
          })
        ),
        2000
      );

      if (!response.Item) return null;
      return response.Item['result'] as AnalysisResult;
    } catch (error: unknown) {
      console.warn(
        '[PersistenceClient] Error al obtener por ID (fail-open):',
        (error as Error).message || 'unknown'
      );
      return null;
    }
  }

  /**
   * Lista resultados de análisis por sessionId (máx 20, orden desc por timestamp).
   *
   * Contrato de ligereza: devuelve resúmenes SIN findings ni explanations para
   * mantener la lista liviana. getById() sí devuelve el detalle completo.
   */
  async function listBySession(sessionId: string): Promise<AnalysisResult[]> {
    try {
      const response = await withTimeout(
        docClient.send(
          new QueryCommand({
            TableName: resolvedConfig.tableName,
            IndexName: 'sessionId-timestamp-index',
            KeyConditionExpression: 'sessionId = :sid',
            ExpressionAttributeValues: { ':sid': sessionId },
            ScanIndexForward: false, // orden descendente por timestamp
            Limit: 20,
          })
        ),
        2000
      );

      if (!response.Items || response.Items.length === 0) return [];

      // Omitir findings y explanations para que la lista sea liviana.
      // getById() retorna el detalle completo incluyendo ambos campos.
      return response.Items.map((item) => {
        const full = item['result'] as AnalysisResult;
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { findings: _f, explanations: _e, ...summary } = full;
        return summary as AnalysisResult;
      });
    } catch (error: unknown) {
      console.warn(
        '[PersistenceClient] Error al listar por sesión (fail-open):',
        (error as Error).message || 'unknown'
      );
      return [];
    }
  }

  /**
   * Guarda un item con reintentos y backoff exponencial.
   */
  async function putWithRetry(item: Record<string, unknown>): Promise<boolean> {
    const totalAttempts = resolvedConfig.maxRetries + 1;

    for (let attempt = 0; attempt < totalAttempts; attempt++) {
      try {
        await withTimeout(
          docClient.send(
            new PutCommand({
              TableName: resolvedConfig.tableName,
              Item: item,
            })
          ),
          2000
        );
        return true;
      } catch (error: unknown) {
        const isLastAttempt = attempt >= totalAttempts - 1;
        if (isLastAttempt) {
          console.error(
            `[PersistenceClient] Fallo al persistir tras ${totalAttempts} intentos:`,
            (error as Error).message || 'unknown'
          );
          return false;
        }

        const backoffMs = 500 * Math.pow(2, attempt);
        console.warn(
          `[PersistenceClient] Error en intento ${attempt + 1}/${totalAttempts}. ` +
          `Reintentando en ${backoffMs}ms...`
        );
        await new Promise((resolve) => setTimeout(resolve, backoffMs));
      }
    }

    return false;
  }

  return { save, getById, listBySession, config: resolvedConfig };
}

/**
 * Trunca el resultado para caber en el límite de DynamoDB.
 * Estrategia 1: eliminar texto de explanations con severity "info" primero.
 * Estrategia 2: si sigue excediendo, poner rawValue=null en findings 'info'
 *   (serviceInfo se conserva porque es pequeño).
 */
function truncateForStorage(result: AnalysisResult): AnalysisResult {
  const truncated = { ...result, storageTruncated: true };

  // Reducir explanations de findings "info" a texto mínimo
  truncated.explanations = result.explanations.map((exp) => {
    // Solo truncar fallbacks de baja prioridad
    if (exp.fallback && exp.text.length > 100) {
      return { ...exp, text: exp.text.slice(0, 97) + '...' };
    }
    return exp;
  });

  // Si el resultado todavía es demasiado grande, reducir el peso de findings 'info'
  // poniendo rawValue=null (el campo más largo) — serviceInfo se mantiene intacto
  if (truncated.findings && truncated.findings.length > 0) {
    const serializedAfterExp = JSON.stringify(truncated);
    if (Buffer.byteLength(serializedAfterExp, 'utf-8') > MAX_ITEM_BYTES) {
      truncated.findings = truncated.findings.map((f) => {
        if (f.severity === 'info' && f.rawValue !== null) {
          return { ...f, rawValue: null };
        }
        return f;
      });
    }
  }

  return truncated;
}

/**
 * Envuelve una promesa con un timeout.
 */
function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`Timeout de ${timeoutMs}ms excedido`));
    }, timeoutMs);

    promise
      .then((res) => {
        clearTimeout(timer);
        resolve(res);
      })
      .catch((err) => {
        clearTimeout(timer);
        reject(err);
      });
  });
}

/** Tipo exportado del cliente para dependency injection */
export type PersistenceClient = ReturnType<typeof createPersistenceClient>;
