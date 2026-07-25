/**
 * Tests del handler /translate-log: traducción de Nmap y auth.log.
 * Verifica que el handler acepta ambos campos y retorna findings correctos.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { APIGatewayProxyEvent } from 'aws-lambda';
import { handler } from '../../handlers/translate-log-handler.js';

/** Construye un evento mínimo de API Gateway para el handler. */
function buildEvent(body: unknown, headers: Record<string, string> = {}): APIGatewayProxyEvent {
  return {
    httpMethod: 'POST',
    path: '/translate-log',
    body: typeof body === 'string' ? body : JSON.stringify(body),
    headers: { 'content-type': 'application/json', ...headers },
    queryStringParameters: null,
    pathParameters: null,
    multiValueHeaders: {},
    multiValueQueryStringParameters: null,
    isBase64Encoded: false,
    stageVariables: null,
    requestContext: {} as any,
    resource: '',
  } as APIGatewayProxyEvent;
}

describe('POST /translate-log', () => {
  beforeEach(() => {
    // Deshabilitar autenticación para los tests
    delete process.env['API_SHARED_SECRET'];
  });

  it('acepta nmapOutput y devuelve findings', async () => {
    const event = buildEvent({
      nmapOutput: '22/tcp   open  ssh     OpenSSH 9.6\n80/tcp   open  http    nginx 1.25',
    });
    const response = await handler(event);
    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.findings).toBeDefined();
    expect(body.findings.length).toBeGreaterThan(0);
  });

  it('acepta authLog y devuelve findings de log-analysis', async () => {
    const authLogText = [
      'Jun 15 10:01:02 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2',
      'Jun 15 10:01:03 server sshd[1235]: Failed password for root from 192.168.1.100 port 22 ssh2',
      'Jun 15 10:01:04 server sshd[1236]: Failed password for root from 192.168.1.100 port 22 ssh2',
    ].join('\n');

    const event = buildEvent({ authLog: authLogText });
    const response = await handler(event);
    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.findings).toBeDefined();
    expect(body.findings.length).toBeGreaterThan(0);
    expect(body.findings[0].category).toBe('log-analysis');
  });

  it('acepta ambos campos y fusiona los findings', async () => {
    const event = buildEvent({
      nmapOutput: '22/tcp   open  ssh     OpenSSH 9.6',
      authLog: 'Jun 15 10:01:02 server sshd[1234]: Failed password for admin from 10.0.0.1 port 22 ssh2',
    });
    const response = await handler(event);
    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.findings.length).toBeGreaterThanOrEqual(2);
  });

  it('retorna 400 si no viene ningún campo de log', async () => {
    const event = buildEvent({ something: 'else' });
    const response = await handler(event);
    expect(response.statusCode).toBe(400);
  });

  it('retorna 400 si el body no es JSON', async () => {
    const event = buildEvent('not json {{{');
    const response = await handler(event);
    expect(response.statusCode).toBe(400);
  });
});


// ─── Tests Ola 12: resultado vacío no es error ───────────────────────────────

describe('POST /translate-log — Ola 12: resultado vacío → 200', () => {
  beforeEach(() => {
    delete process.env['API_SHARED_SECRET'];
  });

  it('auth.log con solo logins legítimos → 200 con findings (login exitoso es un finding)', async () => {
    const authLog = [
      'Jul 25 10:04:11 srv sshd[210]: Accepted password for deploy from 192.0.2.77 port 22 ssh2',
      'Jul 25 10:05:00 srv sshd[211]: Accepted publickey for admin from 10.0.0.1 port 22 ssh2',
    ].join('\n');

    const event = buildEvent({ authLog });
    const response = await handler(event);
    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.findings).toBeDefined();
    // Tiene al menos los findings de login exitoso
    expect(body.findings.length).toBeGreaterThan(0);
  });

  it('Nmap sin puertos abiertos / sin filas parseables → 200 con findings: []', async () => {
    const nmapOutput = `Starting Nmap 7.94SVN at 2025-03-08 10:00 UTC
Nmap scan report for clean.test (203.0.113.10)
Host is up (0.021s latency).
All 1000 scanned ports on clean.test are in ignored states.
Nmap done: 1 IP address (1 host up) scanned in 1.42 seconds`;

    const event = buildEvent({ nmapOutput });
    const response = await handler(event);
    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.findings).toEqual([]);
  });

  it('body no JSON → sigue 400', async () => {
    const event = buildEvent('{{invalid json');
    const response = await handler(event);
    expect(response.statusCode).toBe(400);
  });

  it('sin nmapOutput ni authLog → sigue 400', async () => {
    const event = buildEvent({ unrelated: 'data' });
    const response = await handler(event);
    expect(response.statusCode).toBe(400);
  });

  it('ambos campos vacíos o en blanco → 400', async () => {
    const event = buildEvent({ nmapOutput: '   ', authLog: '' });
    const response = await handler(event);
    expect(response.statusCode).toBe(400);
  });
});
