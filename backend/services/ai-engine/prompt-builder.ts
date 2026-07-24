/**
 * Constructor de prompts para el AI Engine.
 * Inyecta los findings serializados y el contexto opcional en el template,
 * delimitando los datos con tags XML para protección anti-injection.
 */

import type { Finding } from '../scanner/modules/types.js';
import { ANALYSIS_PROMPT_TEMPLATE } from './prompts/analysis.js';

/**
 * Construye el prompt final para enviar a Bedrock.
 * Serializa los findings como JSON dentro de tags XML delimitadores
 * e inyecta el sourceContext si está presente.
 */
export function buildAnalysisPrompt(findings: Finding[], sourceContext?: string): string {
  // Serializar findings como JSON (datos a analizar)
  const findingsJson = JSON.stringify(findings, null, 2);

  // Construir bloque de source context (solo si fue proporcionado)
  const sourceContextBlock = sourceContext
    ? `<source_context>\n${sourceContext}\n</source_context>`
    : '';

  // Inyectar datos en el template
  const prompt = ANALYSIS_PROMPT_TEMPLATE
    .replace('{{FINDINGS_DATA}}', findingsJson)
    .replace('{{SOURCE_CONTEXT}}', sourceContextBlock);

  return prompt;
}
