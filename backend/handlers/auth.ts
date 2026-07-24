/**
 * Autenticación mínima por secreto compartido para los handlers HTTP.
 *
 * API Gateway HTTP API no soporta API keys ni usage plans nativos (eso es solo
 * REST API), así que validamos un header `x-api-key` contra la variable de
 * entorno `API_SHARED_SECRET`. El secreto se inyecta vía CloudFormation en el
 * despliegue; nunca se versiona en el repositorio.
 *
 * Comportamiento:
 * - Si `API_SHARED_SECRET` NO está configurado, la autenticación queda
 *   deshabilitada (permite todo). Esto habilita el desarrollo local y los tests
 *   sin fricción. En producción el secreto SIEMPRE debe estar configurado.
 * - Si está configurado, se exige el header `x-api-key` con el valor exacto,
 *   comparado en tiempo constante para evitar ataques de temporización.
 */

import { createHash, timingSafeEqual } from 'node:crypto';
import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';

const AUTH_HEADER = 'x-api-key';

/** Headers CORS/JSON reutilizados en la respuesta 401. */
const RESPONSE_HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
} as const;

/** Lee un header sin distinguir mayúsculas/minúsculas (v1 preserva caso, v2 lo normaliza). */
function getHeader(event: APIGatewayProxyEvent, name: string): string | undefined {
  const headers = event.headers ?? {};
  const target = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === target && typeof value === 'string') {
      return value;
    }
  }
  return undefined;
}

/** Compara dos strings en tiempo constante (vía digest de longitud fija). */
function safeEquals(a: string, b: string): boolean {
  const digestA = createHash('sha256').update(a).digest();
  const digestB = createHash('sha256').update(b).digest();
  return timingSafeEqual(digestA, digestB);
}

/**
 * Determina si la petición está autorizada.
 * Si no hay secreto configurado, la autenticación está deshabilitada.
 */
export function isAuthorized(event: APIGatewayProxyEvent): boolean {
  const secret = process.env['API_SHARED_SECRET'];
  if (!secret || secret.trim() === '') {
    return true; // auth deshabilitada: sin secreto configurado
  }

  const provided = getHeader(event, AUTH_HEADER);
  if (!provided) return false;

  return safeEquals(provided, secret);
}

/** Respuesta estándar 401 sin filtrar detalles internos. */
export function unauthorizedResponse(): APIGatewayProxyResult {
  return {
    statusCode: 401,
    headers: RESPONSE_HEADERS,
    body: JSON.stringify({ error: 'Unauthorized' }),
  };
}
