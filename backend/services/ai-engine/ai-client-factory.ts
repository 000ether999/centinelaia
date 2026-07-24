/** Selección explícita del proveedor de texto usado por el AI Engine. */

import { createBedrockClient } from './bedrock-client.js';
import { MockBedrockClient, MOCK_MODEL_ID } from './mock-bedrock-client.js';
import type { AiExecutionMode, AiTextClient } from './types.js';

export type AiClientSelection =
  | { executionMode: 'fallback'; client: null; modelId: 'none' }
  | { executionMode: 'mock' | 'bedrock'; client: AiTextClient; modelId: string };

/** Resuelve el modo configurado; una configuración desconocida falla de forma segura. */
export function resolveAiEngineMode(value = process.env['AI_ENGINE_MODE']): AiExecutionMode {
  if (value === undefined || value.trim() === '') return 'fallback';

  const normalized = value.trim().toLowerCase();
  if (normalized === 'fallback' || normalized === 'mock' || normalized === 'bedrock') {
    return normalized;
  }

  console.warn(
    `[AiClientFactory] AI_ENGINE_MODE="${value}" no es válido; usando fallback seguro.`
  );
  return 'fallback';
}

/** Crea un cliente solo cuando el modo seleccionado realmente lo necesita. */
export function createAiClientSelection(
  executionMode: AiExecutionMode = resolveAiEngineMode(),
  injectedClient?: AiTextClient
): AiClientSelection {
  if (executionMode === 'fallback') {
    return { executionMode, client: null, modelId: 'none' };
  }

  const client = injectedClient ?? (
    executionMode === 'mock' ? new MockBedrockClient() : createBedrockClient()
  );
  const modelId = executionMode === 'mock' ? MOCK_MODEL_ID : client.config.modelId;

  return { executionMode, client, modelId };
}
