/**
 * Helpers HTTP compartidos entre los handlers de Lambda.
 * Centraliza la construcción de respuestas JSON y la detección de
 * método/path para soportar tanto API Gateway v1 (REST) como v2 (HTTP API).
 */

import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';

/** Headers CORS/JSON comunes para todas las respuestas */
export const RESPONSE_HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
} as const;

/** Construye una respuesta JSON estándar para API Gateway. */
export function jsonResponse(statusCode: number, body: unknown): APIGatewayProxyResult {
  return {
    statusCode,
    headers: RESPONSE_HEADERS,
    body: JSON.stringify(body),
  };
}

/**
 * Extrae el método HTTP del evento (soporta v1 y v2).
 * v2 HTTP API lo publica en requestContext.http.method;
 * v1 REST API lo expone directamente en event.httpMethod.
 */
export function getMethod(event: APIGatewayProxyEvent): string {
  const httpContext = (event.requestContext as unknown as Record<string, unknown>)['http'] as
    | { method?: string }
    | undefined;
  if (httpContext?.method) return httpContext.method.toUpperCase();
  return event.httpMethod.toUpperCase();
}

/**
 * Extrae el path del evento (soporta v1 y v2).
 * v2 HTTP API lo publica en requestContext.http.path;
 * v1 REST API lo expone en event.path.
 */
export function getPath(event: APIGatewayProxyEvent): string {
  const httpContext = (event.requestContext as unknown as Record<string, unknown>)['http'] as
    | { path?: string }
    | undefined;
  if (httpContext?.path) return httpContext.path;
  return event.path;
}
