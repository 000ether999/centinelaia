import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { isAuthorized, unauthorizedResponse } from './auth.js';
import { translateNmapOutput } from '../services/log-translator/nmap-parser.js';

const RESPONSE_HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
} as const;

function jsonResponse(statusCode: number, body: unknown): APIGatewayProxyResult {
  return { statusCode, headers: RESPONSE_HEADERS, body: JSON.stringify(body) };
}

/** Handler liviano para traducir texto de Nmap sin invocar el AI Engine. */
export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  if (!isAuthorized(event)) return unauthorizedResponse();

  let body: unknown;

  try {
    body = JSON.parse(event.body ?? '');
  } catch {
    return jsonResponse(400, { error: 'El body debe ser un objeto JSON válido.' });
  }

  if (
    typeof body !== 'object' ||
    body === null ||
    typeof (body as Record<string, unknown>)['nmapOutput'] !== 'string' ||
    !(body as Record<string, string>)['nmapOutput']!.trim()
  ) {
    return jsonResponse(400, { error: "El campo 'nmapOutput' es obligatorio y no puede estar vacío." });
  }

  const findings = translateNmapOutput((body as Record<string, string>)['nmapOutput']!);
  if (findings.length === 0) {
    return jsonResponse(400, { error: 'La salida de Nmap no contiene filas de servicio parseables.' });
  }

  return jsonResponse(200, { findings });
}
