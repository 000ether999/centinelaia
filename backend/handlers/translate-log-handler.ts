import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { isAuthorized, unauthorizedResponse } from './auth.js';
import { jsonResponse } from './http.js';
import { translateNmapOutput } from '../services/log-translator/nmap-parser.js';
import { translateAuthLog } from '../services/log-translator/authlog-parser.js';
import { parseNmapXml } from '../services/log-translator/nmap-xml-parser.js';

/**
 * Detecta si un texto es XML de Nmap (empieza por <?xml o <nmaprun tras espacios).
 * Tolerancia: si el usuario pega XML en el campo nmapOutput, lo detectamos y
 * lo procesamos con el parser XML en vez del parser de texto.
 */
function looksLikeNmapXml(text: string): boolean {
  const trimmed = text.trimStart();
  return trimmed.startsWith('<?xml') || trimmed.startsWith('<nmaprun');
}

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
  const hasNmapXml = typeof raw['nmapXml'] === 'string' && (raw['nmapXml'] as string).trim();
  const hasAuth = typeof raw['authLog'] === 'string' && (raw['authLog'] as string).trim();

  if (!hasNmap && !hasNmapXml && !hasAuth) {
    return jsonResponse(400, { error: "Se requiere al menos uno de los campos 'nmapOutput', 'nmapXml' o 'authLog' con contenido no vacío." });
  }

  // Procesar nmapOutput: si parece XML, usar parser XML automáticamente
  let nmapFindings: import('../services/scanner/modules/types.js').Finding[] = [];
  if (hasNmap) {
    const nmapText = raw['nmapOutput'] as string;
    if (looksLikeNmapXml(nmapText)) {
      nmapFindings = parseNmapXml(nmapText);
    } else {
      nmapFindings = translateNmapOutput(nmapText);
    }
  }

  // Procesar nmapXml explícito
  let xmlFindings: import('../services/scanner/modules/types.js').Finding[] = [];
  if (hasNmapXml) {
    xmlFindings = parseNmapXml(raw['nmapXml'] as string);
  }

  const findings = [
    ...nmapFindings,
    ...xmlFindings,
    ...(hasAuth ? translateAuthLog(raw['authLog'] as string) : []),
  ];

  return jsonResponse(200, { findings });
}
