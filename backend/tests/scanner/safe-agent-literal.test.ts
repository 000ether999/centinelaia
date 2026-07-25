/**
 * Tests de safeLookup con literales IP (defensa en profundidad).
 *
 * Verifica que safeLookup bloquea IPs privadas/reservadas sin llamar
 * a DNS, y permite IPs públicas sin resolver DNS.
 *
 * Mockea `node:dns/promises` para confirmar que no se invoca.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Mock de node:dns/promises ───────────────────────────────────────────────

vi.mock('node:dns/promises', () => ({
  resolve4: vi.fn(),
  resolve6: vi.fn(),
}));

import { resolve4, resolve6 } from 'node:dns/promises';
const mockedResolve4 = vi.mocked(resolve4);
const mockedResolve6 = vi.mocked(resolve6);

import { safeLookup } from '../../services/scanner/safe-agent.js';
import type { LookupCallback } from '../../services/scanner/safe-agent.js';

// ─── Helper ──────────────────────────────────────────────────────────────────

function callSafeLookup(hostname: string): Promise<{
  err: Error | null;
  entries: Array<{ address: string; family: number }>;
}> {
  return new Promise((resolve) => {
    safeLookup(hostname, ((err: Error | null, entries: Array<{ address: string; family: number }>) => {
      resolve({ err, entries });
    }) as LookupCallback);
  });
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('safeLookup — IP literal validation (defense in depth)', () => {
  beforeEach(() => {
    mockedResolve4.mockReset();
    mockedResolve6.mockReset();
  });

  it('should block [::1] without calling DNS', async () => {
    const result = await callSafeLookup('[::1]');

    expect(result.err).not.toBeNull();
    expect(result.err!.message).toContain('Blocked IP literal');
    expect(mockedResolve4).not.toHaveBeenCalled();
    expect(mockedResolve6).not.toHaveBeenCalled();
  });

  it('should block 127.0.0.1 without calling DNS', async () => {
    const result = await callSafeLookup('127.0.0.1');

    expect(result.err).not.toBeNull();
    expect(result.err!.message).toContain('Blocked IP literal');
    expect(mockedResolve4).not.toHaveBeenCalled();
    expect(mockedResolve6).not.toHaveBeenCalled();
  });

  it('should block 169.254.169.254 without calling DNS', async () => {
    const result = await callSafeLookup('169.254.169.254');

    expect(result.err).not.toBeNull();
    expect(result.err!.message).toContain('Blocked IP literal');
    expect(mockedResolve4).not.toHaveBeenCalled();
    expect(mockedResolve6).not.toHaveBeenCalled();
  });

  it('should allow 8.8.8.8 without calling DNS and return correct entry', async () => {
    const result = await callSafeLookup('8.8.8.8');

    expect(result.err).toBeNull();
    expect(result.entries).toEqual([{ address: '8.8.8.8', family: 4 }]);
    expect(mockedResolve4).not.toHaveBeenCalled();
    expect(mockedResolve6).not.toHaveBeenCalled();
  });

  it('should follow normal DNS path for domain names (no regression)', async () => {
    mockedResolve4.mockResolvedValue(['93.184.216.34']);
    mockedResolve6.mockRejectedValue(new Error('no AAAA'));

    const result = await callSafeLookup('example.com');

    expect(result.err).toBeNull();
    expect(result.entries).toEqual([{ address: '93.184.216.34', family: 4 }]);
    expect(mockedResolve4).toHaveBeenCalledWith('example.com');
  });
});
