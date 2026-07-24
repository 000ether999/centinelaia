/**
 * Tests de la autenticación por secreto compartido.
 * Verifica que la auth se deshabilita sin secreto configurado, y que con
 * secreto exige el header x-api-key exacto (comparación insensible a mayúsculas
 * en la clave del header).
 */

import { describe, it, expect, afterEach } from 'vitest';
import type { APIGatewayProxyEvent } from 'aws-lambda';
import { isAuthorized, unauthorizedResponse } from '../../handlers/auth.js';

function eventWithHeaders(headers: Record<string, string>): APIGatewayProxyEvent {
  return { headers } as unknown as APIGatewayProxyEvent;
}

const ORIGINAL = process.env['API_SHARED_SECRET'];

afterEach(() => {
  if (ORIGINAL === undefined) delete process.env['API_SHARED_SECRET'];
  else process.env['API_SHARED_SECRET'] = ORIGINAL;
});

describe('isAuthorized', () => {
  it('permite todo cuando no hay secreto configurado', () => {
    delete process.env['API_SHARED_SECRET'];
    expect(isAuthorized(eventWithHeaders({}))).toBe(true);
  });

  it('rechaza cuando hay secreto pero falta el header', () => {
    process.env['API_SHARED_SECRET'] = 's3cr3t';
    expect(isAuthorized(eventWithHeaders({}))).toBe(false);
  });

  it('rechaza cuando el header no coincide', () => {
    process.env['API_SHARED_SECRET'] = 's3cr3t';
    expect(isAuthorized(eventWithHeaders({ 'x-api-key': 'wrong' }))).toBe(false);
  });

  it('acepta cuando el header coincide (clave insensible a mayúsculas)', () => {
    process.env['API_SHARED_SECRET'] = 's3cr3t';
    expect(isAuthorized(eventWithHeaders({ 'X-API-KEY': 's3cr3t' }))).toBe(true);
  });
});

describe('unauthorizedResponse', () => {
  it('retorna 401 con cuerpo genérico', () => {
    const res = unauthorizedResponse();
    expect(res.statusCode).toBe(401);
    expect(JSON.parse(res.body)).toEqual({ error: 'Unauthorized' });
  });
});
