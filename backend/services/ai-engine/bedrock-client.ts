/**
 * Cliente de Amazon Bedrock para el AI Engine.
 * Encapsula la comunicación con Bedrock InvokeModel, implementa retry
 * con backoff exponencial + jitter, y respeta el AbortSignal del
 * orchestrator para cancelación por timeout global.
 */

import {
  BedrockRuntimeClient,
  InvokeModelCommand,
  ThrottlingException,
  ServiceUnavailableException,
  ValidationException,
  AccessDeniedException,
} from '@aws-sdk/client-bedrock-runtime';

/** Configuración del cliente de Bedrock */
export interface BedrockClientConfig {
  modelId: string;
  maxTokens: number;
  temperature: number;
  timeoutMs: number;
  maxRetries: number;
}

/** Errores transitorios que merecen reintentos */
const TRANSIENT_ERROR_NAMES: ReadonlySet<string> = new Set([
  'ThrottlingException',
  'ServiceUnavailableException',
  'ServiceException',
  'InternalServerException',
  'TimeoutError',
  'ECONNRESET',
  'ETIMEDOUT',
]);

/**
 * Determina si un error es transitorio y merece reintento.
 */
function isTransientError(error: unknown): boolean {
  if (error instanceof ThrottlingException) return true;
  if (error instanceof ServiceUnavailableException) return true;
  if (error instanceof ValidationException) return false;
  if (error instanceof AccessDeniedException) return false;

  if (error && typeof error === 'object') {
    const err = error as Record<string, unknown>;
    const name = err['name'] as string | undefined;
    const code = err['code'] as string | undefined;

    if (name && TRANSIENT_ERROR_NAMES.has(name)) return true;
    if (code && TRANSIENT_ERROR_NAMES.has(code)) return true;
  }

  return false;
}

/**
 * Calcula el backoff exponencial con jitter.
 * Base: 1s, multiplicador: 2x por intento, jitter aleatorio ±50%.
 */
function calculateBackoff(attempt: number): number {
  const baseMs = 1000;
  const exponential = baseMs * Math.pow(2, attempt);
  const jitter = exponential * (0.5 + Math.random());
  return Math.min(jitter, 4000); // Tope de 4s de espera
}

/**
 * Espera un tiempo determinado, abortando si recibe señal de cancelación.
 */
function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error('Aborted'));
      return;
    }

    const timer = setTimeout(resolve, ms);

    if (signal) {
      const onAbort = () => {
        clearTimeout(timer);
        reject(new Error('Aborted'));
      };
      signal.addEventListener('abort', onAbort, { once: true });
    }
  });
}

/**
 * Crea el cliente de Bedrock con la configuración dada.
 * Retorna una función para invocar el modelo con retry y abort.
 */
export function createBedrockClient(config?: Partial<BedrockClientConfig>) {
  const resolvedConfig: BedrockClientConfig = {
    modelId: process.env['BEDROCK_MODEL_ID'] || 'amazon.nova-micro-v1:0',
    maxTokens: parseInt(process.env['BEDROCK_MAX_TOKENS'] || '2048', 10),
    temperature: parseFloat(process.env['BEDROCK_TEMPERATURE'] || '0.3'),
    timeoutMs: 6000,
    maxRetries: 2,
    ...config,
  };

  const client = new BedrockRuntimeClient({
    requestHandler: {
      requestTimeout: resolvedConfig.timeoutMs,
    } as unknown as undefined,
  });

  /**
   * Invoca el modelo de Bedrock con el prompt dado.
   * Implementa retry con backoff exponencial + jitter para errores transitorios.
   * Aborta inmediatamente si recibe señal de cancelación.
   */
  async function invoke(prompt: string, signal?: AbortSignal): Promise<string> {
    const totalAttempts = resolvedConfig.maxRetries + 1;

    for (let attempt = 0; attempt < totalAttempts; attempt++) {
      // Verificar cancelación antes de cada intento
      if (signal?.aborted) {
        throw new Error('Aborted: timeout global alcanzado');
      }

      try {
        const command = new InvokeModelCommand({
          modelId: resolvedConfig.modelId,
          contentType: 'application/json',
          accept: 'application/json',
          body: JSON.stringify({
            messages: [
              {
                role: 'user',
                content: [{ type: 'text', text: prompt }],
              },
            ],
            inferenceConfig: {
              maxTokens: resolvedConfig.maxTokens,
              temperature: resolvedConfig.temperature,
            },
          }),
        });

        const response = await client.send(command, {
          abortSignal: signal,
        });

        // Decodificar respuesta
        const responseBody = new TextDecoder().decode(response.body);

        if (!responseBody || responseBody.trim() === '') {
          // Respuesta vacía — tratar como error transitorio
          if (attempt < totalAttempts - 1) {
            console.warn(
              `[BedrockClient] Respuesta vacía en intento ${attempt + 1}/${totalAttempts}. Reintentando...`
            );
            await sleep(calculateBackoff(attempt), signal);
            continue;
          }
          throw new Error('Bedrock retornó una respuesta vacía tras todos los reintentos');
        }

        // Parsear el JSON de respuesta de Bedrock y extraer el texto
        const parsedResponse = JSON.parse(responseBody);
        const outputText = extractOutputText(parsedResponse);

        if (!outputText) {
          if (attempt < totalAttempts - 1) {
            console.warn(
              `[BedrockClient] Respuesta sin texto en intento ${attempt + 1}/${totalAttempts}. Reintentando...`
            );
            await sleep(calculateBackoff(attempt), signal);
            continue;
          }
          throw new Error('Bedrock retornó una respuesta sin texto generado');
        }

        return outputText;
      } catch (error: unknown) {
        // Si fue abortado, propagar inmediatamente
        if (signal?.aborted) {
          throw new Error('Aborted: timeout global alcanzado');
        }

        // Error no transitorio — propagar sin retry
        if (!isTransientError(error)) {
          throw error;
        }

        // Error transitorio — reintentar si quedan intentos
        const isLastAttempt = attempt >= totalAttempts - 1;
        if (isLastAttempt) {
          throw error;
        }

        const backoffMs = calculateBackoff(attempt);
        console.warn(
          `[BedrockClient] Error transitorio en intento ${attempt + 1}/${totalAttempts}. ` +
          `Esperando ${Math.round(backoffMs)}ms antes de reintentar. ` +
          `Error: ${(error as Error).message || 'unknown'}`
        );

        await sleep(backoffMs, signal);
      }
    }

    // No debería llegar aquí, pero por seguridad
    throw new Error('Bedrock: reintentos agotados');
  }

  return { invoke, config: resolvedConfig };
}

/**
 * Extrae el texto de salida del JSON de respuesta de Bedrock.
 * Soporta formatos de Nova y otros modelos de Bedrock.
 */
function extractOutputText(response: unknown): string | null {
  if (!response || typeof response !== 'object') return null;

  const resp = response as Record<string, unknown>;

  // Formato Nova: { output: { message: { content: [{ text: "..." }] } } }
  if (resp['output'] && typeof resp['output'] === 'object') {
    const output = resp['output'] as Record<string, unknown>;
    if (output['message'] && typeof output['message'] === 'object') {
      const message = output['message'] as Record<string, unknown>;
      if (Array.isArray(message['content'])) {
        const content = message['content'] as Array<Record<string, unknown>>;
        for (const block of content) {
          if (block['type'] === 'text' && typeof block['text'] === 'string') {
            return block['text'];
          }
          // Algunos formatos no incluyen type
          if (typeof block['text'] === 'string') {
            return block['text'];
          }
        }
      }
    }
  }

  // Formato alternativo: { results: [{ outputText: "..." }] }
  if (Array.isArray(resp['results'])) {
    const results = resp['results'] as Array<Record<string, unknown>>;
    if (results[0] && typeof results[0]['outputText'] === 'string') {
      return results[0]['outputText'];
    }
  }

  // Formato Anthropic-like: { content: [{ text: "..." }] }
  if (Array.isArray(resp['content'])) {
    const content = resp['content'] as Array<Record<string, unknown>>;
    for (const block of content) {
      if (typeof block['text'] === 'string') {
        return block['text'];
      }
    }
  }

  // Fallback: si hay un campo "body" o "completion"
  if (typeof resp['completion'] === 'string') return resp['completion'];
  if (typeof resp['body'] === 'string') return resp['body'];

  return null;
}

/** Tipo exportado del cliente para dependency injection */
export type BedrockClient = ReturnType<typeof createBedrockClient>;
