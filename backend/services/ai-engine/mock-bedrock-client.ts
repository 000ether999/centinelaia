/**
 * Cliente determinista para ejecutar el contrato del AI Engine sin Bedrock.
 * Produce el mismo esquema JSON solicitado al modelo real.
 */

import type { AiTextClient, BedrockExpectedResponse } from './types.js';

export const MOCK_MODEL_ID = 'mock-ai-text-client-v1';

function extractFindingCount(prompt: string): number {
  const closingTag = '</findings_data>';
  const end = prompt.lastIndexOf(closingTag);
  const start = prompt.lastIndexOf('<findings_data>', end);
  if (start < 0 || end <= start) return 0;

  const serializedFindings = prompt.slice(start + '<findings_data>'.length, end).trim();
  try {
    const findings = JSON.parse(serializedFindings);
    return Array.isArray(findings) ? findings.length : 0;
  } catch {
    return 0;
  }
}

/** Cliente mock mínimo para desarrollo y pruebas de contrato. */
export class MockBedrockClient implements AiTextClient {
  readonly config = { modelId: MOCK_MODEL_ID };

  async invoke(prompt: string, signal?: AbortSignal): Promise<string> {
    if (signal?.aborted) throw new Error('Aborted: timeout global alcanzado');

    const indices = Array.from({ length: extractFindingCount(prompt) }, (_, index) => index);
    const response: BedrockExpectedResponse = {
      explanations: indices.map((findingIndex) => ({
        findingIndex,
        text: `Explicación simulada del hallazgo ${findingIndex}: describe el problema, su impacto potencial y su urgencia relativa de forma clara.`,
      })),
      recommendations: indices.length === 0 ? [] : [{
        title: 'Aplicar correcciones de seguridad simuladas',
        description: 'Revisar y corregir los hallazgos indicados siguiendo una acción determinista para validar el contrato completo del análisis.',
        effort: 'moderate',
        relatedFindings: indices,
      }],
    };

    return JSON.stringify(response);
  }
}
