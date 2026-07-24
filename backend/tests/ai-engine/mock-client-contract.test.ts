import { describe, expect, it } from 'vitest';
import { MockBedrockClient, MOCK_MODEL_ID } from '../../services/ai-engine/mock-bedrock-client.js';
import { buildAnalysisPrompt } from '../../services/ai-engine/prompt-builder.js';
import { parseBedrockResponse } from '../../services/ai-engine/response-parser.js';
import type { Finding } from '../../services/scanner/modules/types.js';

const findings: Finding[] = [
  { category: 'http-headers', severity: 'high', rawValue: null,
    description: 'Falta el encabezado de seguridad Strict-Transport-Security' },
  { category: 'cookies', severity: 'medium', rawValue: 'session_id',
    description: 'La cookie de sesión no incluye el atributo Secure requerido' },
];

describe('MockBedrockClient — contrato con response-parser', () => {
  it('produce una respuesta completa y parseable sin priority en el JSON raw', async () => {
    const client = new MockBedrockClient();
    const raw = await client.invoke(buildAnalysisPrompt(findings));
    const rawResponse = JSON.parse(raw) as Record<string, Array<Record<string, unknown>>>;

    expect(client.config.modelId).toBe(MOCK_MODEL_ID);
    expect(rawResponse['explanations']).toHaveLength(findings.length);
    expect(rawResponse['explanations']?.map((item) => item['findingIndex'])).toEqual([0, 1]);
    expect(rawResponse['recommendations']).toHaveLength(1);
    expect(rawResponse['recommendations']?.[0]).toEqual({
      title: expect.any(String),
      description: expect.any(String),
      effort: 'moderate',
      relatedFindings: [0, 1],
    });
    expect(rawResponse['recommendations']?.[0]).not.toHaveProperty('priority');

    const parsed = parseBedrockResponse(raw, findings);
    expect(parsed.partial).toBe(false);
    expect(parsed.explanations).toHaveLength(findings.length);
    expect(parsed.explanations.every((item) => item.fallback === false)).toBe(true);
    expect(parsed.recommendations).toHaveLength(1);
    expect(parsed.recommendations[0]).toEqual({
      priority: 0,
      title: expect.any(String),
      description: expect.any(String),
      effort: 'moderate',
      relatedFindings: [0, 1],
    });
  });
});
