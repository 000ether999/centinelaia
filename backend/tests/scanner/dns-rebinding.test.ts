/**
 * Tests de protección contra DNS rebinding / TOCTOU.
 *
 * Verifica que el safe-agent y el tls-checker bloquean conexiones
 * cuando la resolución DNS devuelve IPs privadas/reservadas, incluso
 * si una validación previa (resolveAndCheckIp) vio una IP pública.
 *
 * Estos tests mockean `node:dns/promises` para simular rotación de
 * registros DNS sin conexiones reales de red.
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

// ─── Tests del safe-agent ────────────────────────────────────────────────────

describe('DNS Rebinding Protection — safe-agent', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    mockedResolve4.mockReset();
    mockedResolve6.mockReset();
  });

  it('should block fetch when DNS resolves to a private IP (169.254.169.254)', async () => {
    // Simular que el DNS devuelve la IP del metadata service de AWS
    mockedResolve4.mockResolvedValue(['169.254.169.254']);
    mockedResolve6.mockRejectedValue(new Error('no AAAA'));

    const { createSafeAgent } = await import('../../services/scanner/safe-agent.js');
    const agent = createSafeAgent();

    // Intentar fetch con el agente seguro — debe rechazar antes de conectar
    try {
      await fetch('http://evil.com/steal-metadata', { dispatcher: agent as any } as RequestInit);
      expect.fail('fetch should have thrown');
    } catch (err: any) {
      // undici envuelve el error del lookup en err.cause
      const message = err.cause?.message ?? err.message;
      expect(message).toMatch(/DNS rebinding blocked.*169\.254\.169\.254/);
    }
  });

  it('should block fetch when DNS resolves to loopback (127.0.0.1)', async () => {
    mockedResolve4.mockResolvedValue(['127.0.0.1']);
    mockedResolve6.mockRejectedValue(new Error('no AAAA'));

    const { createSafeAgent } = await import('../../services/scanner/safe-agent.js');
    const agent = createSafeAgent();

    try {
      await fetch('http://malicious.example.com/', { dispatcher: agent as any } as RequestInit);
      expect.fail('fetch should have thrown');
    } catch (err: any) {
      const message = err.cause?.message ?? err.message;
      expect(message).toMatch(/DNS rebinding blocked.*127\.0\.0\.1/);
    }
  });

  it('should block fetch when DNS resolves to private network (10.x)', async () => {
    mockedResolve4.mockResolvedValue(['10.0.0.1']);
    mockedResolve6.mockRejectedValue(new Error('no AAAA'));

    const { createSafeAgent } = await import('../../services/scanner/safe-agent.js');
    const agent = createSafeAgent();

    try {
      await fetch('http://attacker.com/', { dispatcher: agent as any } as RequestInit);
      expect.fail('fetch should have thrown');
    } catch (err: any) {
      const message = err.cause?.message ?? err.message;
      expect(message).toMatch(/DNS rebinding blocked.*10\.0\.0\.1/);
    }
  });

  it('should block when ANY resolved IP is private (mixed results)', async () => {
    // Un atacante podría devolver IPs públicas Y privadas en round-robin
    mockedResolve4.mockResolvedValue(['93.184.216.34', '192.168.1.1']);
    mockedResolve6.mockRejectedValue(new Error('no AAAA'));

    const { createSafeAgent } = await import('../../services/scanner/safe-agent.js');
    const agent = createSafeAgent();

    try {
      await fetch('http://sneaky.com/', { dispatcher: agent as any } as RequestInit);
      expect.fail('fetch should have thrown');
    } catch (err: any) {
      const message = err.cause?.message ?? err.message;
      expect(message).toMatch(/DNS rebinding blocked.*192\.168\.1\.1/);
    }
  });

  it('should fail when DNS resolution returns no IPs', async () => {
    mockedResolve4.mockRejectedValue(new Error('NXDOMAIN'));
    mockedResolve6.mockRejectedValue(new Error('NXDOMAIN'));

    const { createSafeAgent } = await import('../../services/scanner/safe-agent.js');
    const agent = createSafeAgent();

    try {
      await fetch('http://nonexistent.invalid/', { dispatcher: agent as any } as RequestInit);
      expect.fail('fetch should have thrown');
    } catch (err: any) {
      const message = err.cause?.message ?? err.message;
      expect(message).toMatch(/DNS resolution failed/);
    }
  });
});

// ─── Tests del camino positivo (IPs públicas permitidas) ─────────────────────

describe('DNS Rebinding Protection — safe-agent positive path (safeLookup)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    mockedResolve4.mockReset();
    mockedResolve6.mockReset();
  });

  it('should allow public IPv4 and return correct address/family format', async () => {
    mockedResolve4.mockResolvedValue(['93.184.216.34']);
    mockedResolve6.mockRejectedValue(new Error('no AAAA'));

    const { safeLookup } = await import('../../services/scanner/safe-agent.js');

    const result = await new Promise<{ err: Error | null; entries: Array<{ address: string; family: number }> }>(
      (resolve) => {
        safeLookup('example.com', (err, entries) => {
          resolve({ err, entries });
        });
      },
    );

    expect(result.err).toBeNull();
    expect(result.entries).toEqual([{ address: '93.184.216.34', family: 4 }]);
  });

  it('should allow public IPv6 only and return family 6', async () => {
    mockedResolve4.mockRejectedValue(new Error('no A record'));
    mockedResolve6.mockResolvedValue(['2607:f8b0:4004:800::200e']);

    const { safeLookup } = await import('../../services/scanner/safe-agent.js');

    const result = await new Promise<{ err: Error | null; entries: Array<{ address: string; family: number }> }>(
      (resolve) => {
        safeLookup('ipv6only.example.com', (err, entries) => {
          resolve({ err, entries });
        });
      },
    );

    expect(result.err).toBeNull();
    expect(result.entries).toEqual([{ address: '2607:f8b0:4004:800::200e', family: 6 }]);
  });

  it('should NOT call callback with an error for fully public IPs (dual-stack)', async () => {
    mockedResolve4.mockResolvedValue(['93.184.216.34']);
    mockedResolve6.mockResolvedValue(['2607:f8b0:4004:800::200e']);

    const { safeLookup } = await import('../../services/scanner/safe-agent.js');

    const result = await new Promise<{ err: Error | null; entries: Array<{ address: string; family: number }> }>(
      (resolve) => {
        safeLookup('dual.example.com', (err, entries) => {
          resolve({ err, entries });
        });
      },
    );

    // No error for public IPs
    expect(result.err).toBeNull();
    // Should prefer IPv4 when available
    expect(result.entries).toEqual([{ address: '93.184.216.34', family: 4 }]);
  });
});

// ─── Tests del tls-checker ───────────────────────────────────────────────────

describe('DNS Rebinding Protection — tls-checker', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    mockedResolve4.mockReset();
    mockedResolve6.mockReset();
  });

  it('should block TLS connection when DNS resolves to metadata IP (169.254.169.254)', async () => {
    mockedResolve4.mockResolvedValue(['169.254.169.254']);
    mockedResolve6.mockRejectedValue(new Error('no AAAA'));

    const { createTlsChecker } = await import('../../services/scanner/modules/tls-checker.js');
    const checker = createTlsChecker();

    const findings = await checker.run({
      targetUrl: 'https://evil.com',
      targetDomain: 'evil.com',
      isIpAddress: false,
      timeoutMs: 5000,
    });

    // Debe haber un finding crítico indicando que no se pudo resolver/conectar
    // (el detalle del error se loguea internamente, no se expone en el finding)
    const blockFinding = findings.find(
      f => f.severity === 'critical' && f.description.includes('DNS resolution failed'),
    );
    expect(blockFinding).toBeDefined();
  });

  it('should block TLS connection when DNS resolves to private IP (172.16.0.1)', async () => {
    mockedResolve4.mockResolvedValue(['172.16.0.1']);
    mockedResolve6.mockRejectedValue(new Error('no AAAA'));

    const { createTlsChecker } = await import('../../services/scanner/modules/tls-checker.js');
    const checker = createTlsChecker();

    const findings = await checker.run({
      targetUrl: 'https://malicious.example.com',
      targetDomain: 'malicious.example.com',
      isIpAddress: false,
      timeoutMs: 5000,
    });

    const blockFinding = findings.find(
      f => f.severity === 'critical' && f.description.includes('DNS resolution failed'),
    );
    expect(blockFinding).toBeDefined();
  });
});

// ─── Tests del módulo ip-guard (unidad) ──────────────────────────────────────

describe('ip-guard — isBlockedIp unit tests', () => {
  // Importar directamente sin mocks de DNS (no usa DNS)
  it('should correctly identify blocked IPv4 addresses', async () => {
    const { isBlockedIp, isBlockedIPv4 } = await import('../../services/scanner/ip-guard.js');

    expect(isBlockedIp('127.0.0.1')).toBe(true);
    expect(isBlockedIp('10.0.0.1')).toBe(true);
    expect(isBlockedIp('172.16.0.1')).toBe(true);
    expect(isBlockedIp('192.168.1.1')).toBe(true);
    expect(isBlockedIp('169.254.169.254')).toBe(true);

    // IPs públicas no deben ser bloqueadas
    expect(isBlockedIp('8.8.8.8')).toBe(false);
    expect(isBlockedIp('93.184.216.34')).toBe(false);
    expect(isBlockedIp('1.1.1.1')).toBe(false);

    // isBlockedIPv4 directamente
    expect(isBlockedIPv4('10.255.255.255')).toBe(true);
    expect(isBlockedIPv4('172.31.255.255')).toBe(true);
  });

  it('should correctly identify blocked IPv6 addresses', async () => {
    const { isBlockedIp, isBlockedIPv6 } = await import('../../services/scanner/ip-guard.js');

    expect(isBlockedIp('::1')).toBe(true);
    expect(isBlockedIPv6('fe80::1')).toBe(true);
    expect(isBlockedIPv6('fc00::1')).toBe(true);
    expect(isBlockedIPv6('fd00::1')).toBe(true);

    // IP pública IPv6 no debe ser bloqueada
    expect(isBlockedIPv6('2001:db8::1')).toBe(false);
  });

  it('should block IPv4-mapped IPv6 addresses (SSRF bypass prevention)', async () => {
    const { isBlockedIp } = await import('../../services/scanner/ip-guard.js');

    // IPv4-mapped con forma dotted
    expect(isBlockedIp('::ffff:127.0.0.1')).toBe(true);
    expect(isBlockedIp('::ffff:10.0.0.1')).toBe(true);
    expect(isBlockedIp('::ffff:169.254.169.254')).toBe(true);
    expect(isBlockedIp('::ffff:192.168.1.1')).toBe(true);

    // IPv4-mapped con forma hex (::ffff:7f00:1 = 127.0.0.1)
    expect(isBlockedIp('::ffff:7f00:1')).toBe(true);

    // Público sigue permitido en forma mapped
    expect(isBlockedIp('::ffff:8.8.8.8')).toBe(false);
  });

  it('should block 0.0.0.0 and CGNAT range', async () => {
    const { isBlockedIp } = await import('../../services/scanner/ip-guard.js');

    expect(isBlockedIp('0.0.0.0')).toBe(true);
    expect(isBlockedIp('100.64.0.1')).toBe(true);
  });

  it('should block IPv6 unspecified address (::)', async () => {
    const { isBlockedIp } = await import('../../services/scanner/ip-guard.js');

    expect(isBlockedIp('::')).toBe(true);
  });

  it('should allow public IPs and 2001:db8::1 (documentation prefix)', async () => {
    const { isBlockedIp, isBlockedIPv6 } = await import('../../services/scanner/ip-guard.js');

    expect(isBlockedIp('::ffff:8.8.8.8')).toBe(false);
    expect(isBlockedIp('8.8.8.8')).toBe(false);
    expect(isBlockedIp('2001:db8::1')).toBe(false);
    expect(isBlockedIPv6('2607:f8b0:4004:800::200e')).toBe(false);
  });

  // ─── Nuevos tests C-02: bypass por representación no canónica ────────────────

  it('should block non-compressed loopback (C-02 bypass)', async () => {
    const { isBlockedIp } = await import('../../services/scanner/ip-guard.js');

    // Forma expandida de ::1
    expect(isBlockedIp('0:0:0:0:0:0:0:1')).toBe(true);
  });

  it('should block non-compressed IPv4-mapped addresses (C-02 bypass)', async () => {
    const { isBlockedIp } = await import('../../services/scanner/ip-guard.js');

    // Forma expandida de ::ffff:127.0.0.1
    expect(isBlockedIp('0:0:0:0:0:ffff:127.0.0.1')).toBe(true);
    // Forma completamente expandida en hex
    expect(isBlockedIp('0000:0000:0000:0000:0000:ffff:7f00:0001')).toBe(true);
    // IMDS vía mapped
    expect(isBlockedIp('0:0:0:0:0:ffff:169.254.169.254')).toBe(true);
  });

  it('should block 6to4 addresses embedding private IPv4 (C-02)', async () => {
    const { isBlockedIp } = await import('../../services/scanner/ip-guard.js');

    // 2002:7f00:1::1 → 6to4 con 127.0.0.1 embebida
    expect(isBlockedIp('2002:7f00:1::1')).toBe(true);
    // 2002:0a00:0001::1 → 6to4 con 10.0.0.1 embebida
    expect(isBlockedIp('2002:0a00:0001::1')).toBe(true);
  });

  it('should block Teredo addresses (C-02)', async () => {
    const { isBlockedIp } = await import('../../services/scanner/ip-guard.js');

    // 2001:0:... es Teredo
    expect(isBlockedIp('2001:0:0:0:0:0:0:1')).toBe(true);
  });

  it('should block link-local with zone id (C-02)', async () => {
    const { isBlockedIp } = await import('../../services/scanner/ip-guard.js');

    expect(isBlockedIp('fe80::1%eth0')).toBe(true);
  });

  it('should block ::ffff:0:0 (mapped unspecified)', async () => {
    const { isBlockedIp } = await import('../../services/scanner/ip-guard.js');

    expect(isBlockedIp('::ffff:0:0')).toBe(true);
  });

  it('should block unrecognizable strings (fail-closed)', async () => {
    const { isBlockedIp } = await import('../../services/scanner/ip-guard.js');

    expect(isBlockedIp('no-soy-una-ip')).toBe(true);
  });

  it('should NOT over-block public addresses', async () => {
    const { isBlockedIp } = await import('../../services/scanner/ip-guard.js');

    // 2001:db8::1 es documentación, pero NO privado/reservado en el sentido SSRF
    expect(isBlockedIp('2001:db8::1')).toBe(false);
    // Google public DNS IPv6
    expect(isBlockedIp('2607:f8b0:4004:800::200e')).toBe(false);
    // IPv4-mapped público
    expect(isBlockedIp('::ffff:8.8.8.8')).toBe(false);
    // IPv4 público
    expect(isBlockedIp('8.8.8.8')).toBe(false);
    // Otro público
    expect(isBlockedIp('93.184.216.34')).toBe(false);
  });
});
