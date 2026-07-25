import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { isAuthorized, unauthorizedResponse } from './auth.js';
import { jsonResponse } from './http.js';
import { translateNmapOutput } from '../services/log-translator/nmap-parser.js';
import { translateAuthLog } from '../services/log-translator/authlog-parser.js';


/** Handler liviano para traducir texto de Nmap o auth.log sin invocar el AI Engine. */
export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  if (!isAuthorized(event)) return unauthorizedResponse();

  let body: unknown;

  try {
    body = JSON.parse(event.body ?? '');
  } catch {
    return jsonResponse(400, { error: 'El body debe ser un objeto JSON válido.' });
  }

  if (typeof body !== 'object' || body === null) {
    return jsonResponse(400, { error: 'El body debe ser un objeto JSON válido.' });
  }

  const raw = body as Record<string, unknown>;
  const hasNmap = typeof raw['nmapOutput'] === 'string' && (raw['nmapOutput'] as string).trim();
  const hasAuth = typeof raw['authLog'] === 'string' && (raw['authLog'] as string).trim();

  if (!hasNmap && !hasAuth) {
    return jsonResponse(400, { error: "Se requiere al menos uno de los campos 'nmapOutput' o 'authLog'." });
  }

  const findings = [
    ...(hasNmap ? translateNmapOutput(raw['nmapOutput'] as string) : []),
    ...(hasAuth ? translateAuthLog(raw['authLog'] as string) : []),
  ];

  if (findings.length === 0) {
    return jsonResponse(400, { error: 'El contenido enviado no contiene datos parseables.' });
  }

  return jsonResponse(200, { findings });
}
