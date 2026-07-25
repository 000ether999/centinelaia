/**
 * Tests de integración del safe-agent con servidor HTTP local.
 *
 * Verifica que getSafeAgent() bloquea conexiones a IPs privadas/reservadas
 * a nivel de connector (no solo de lookup), usando un servidor HTTP real
 * en loopback para ejercitar el flujo completo de undici.
 */

import { describe, it, expect, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import { getSafeAgent } from '../../services/scanner/safe-agent.js';

// ─── Helper: crear servidor HTTP efímero ─────────────────────────────────────

function startServer(host: string): Promise<{ server: Server; port: number }> {
  return new Promise((resolve, reject) => {
    const server = createServer((req, res) => {
      res.writeHead(200);
      res.end('INTERNAL SECRET BODY');
    });
    server.listen(0, host, () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') {
        resolve({ server, port: addr.port });
      } else {
        reject(new Error('Failed to get server address'));
      }
    });
  });
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('safe-agent integration — IP literal blocking at connector level', () => {
  const servers: Server[] = [];

  afterAll(() => {
    for (const s of servers) {
      s.close();
    }
  });

  it('should block fetch to [::1] (IPv6 loopback)', async () => {
    const { server, port } = await startServer('::1');
    servers.push(server);

    try {
      const response = await fetch(`http://[::1]:${port}/`, {
        dispatcher: getSafeAgent() as any,
      } as RequestInit);
      // If we get here, the agent failed to block
      const body = await response.text();
      expect.fail(`LEAK! Got ${response.status} ${body}`);
    } catch (err: any) {
      const message = err.cause?.message ?? err.message;
      expect(message).toContain('Blocked IP literal');
    }
  });

  it('should block fetch to 127.0.0.1 (IPv4 loopback)', async () => {
    const { server, port } = await startServer('127.0.0.1');
    servers.push(server);

    try {
      const response = await fetch(`http://127.0.0.1:${port}/`, {
        dispatcher: getSafeAgent() as any,
      } as RequestInit);
      const body = await response.text();
      expect.fail(`LEAK! Got ${response.status} ${body}`);
    } catch (err: any) {
      const message = err.cause?.message ?? err.message;
      expect(message).toContain('Blocked IP literal');
    }
  });

  it('should block fetch to [0:0:0:0:0:0:0:1] (non-compressed IPv6 loopback)', async () => {
    const { server, port } = await startServer('::1');
    servers.push(server);

    try {
      const response = await fetch(`http://[0:0:0:0:0:0:0:1]:${port}/`, {
        dispatcher: getSafeAgent() as any,
      } as RequestInit);
      const body = await response.text();
      expect.fail(`LEAK! Got ${response.status} ${body}`);
    } catch (err: any) {
      const message = err.cause?.message ?? err.message;
      expect(message).toContain('Blocked IP literal');
    }
  });
});
