/**
 * Tests del parser de logs de autenticación (authlog-parser).
 * Cubre: agregación por IP, severidad por volumen, fail2ban,
 * texto vacío/ilegible, y campos del Finding.
 */

import { describe, it, expect } from 'vitest';
import { translateAuthLog } from '../../services/log-translator/authlog-parser.js';

describe('translateAuthLog — parser de auth.log/fail2ban', () => {
  it('agrupa intentos "Failed password" por IP y cuenta correctamente', () => {
    const log = [
      'Jan  5 03:12:01 server sshd[1234]: Failed password for root from 192.168.1.5 port 22 ssh2',
      'Jan  5 03:12:02 server sshd[1235]: Failed password for root from 192.168.1.5 port 22 ssh2',
      'Jan  5 03:12:03 server sshd[1236]: Failed password for admin from 10.0.0.1 port 22 ssh2',
    ].join('\n');

    const findings = translateAuthLog(log);
    // Dos IPs distintas — ambas por debajo del umbral (5), así que son 'info'
    const ipFindings = findings.filter((f) => f.rawValue?.includes('failed_attempts'));
    expect(ipFindings).toHaveLength(2);

    const ip5 = ipFindings.find((f) => f.rawValue?.includes('192.168.1.5'));
    expect(ip5).toBeDefined();
    expect(ip5!.rawValue).toContain('failed_attempts=2');
    expect(ip5!.severity).toBe('info'); // Ola 12: < 5 → info

    const ip1 = ipFindings.find((f) => f.rawValue?.includes('10.0.0.1'));
    expect(ip1).toBeDefined();
    expect(ip1!.rawValue).toContain('failed_attempts=1');
    expect(ip1!.severity).toBe('info'); // Ola 12: < 5 → info
  });

  it('registra líneas "Invalid user" como intentos fallidos', () => {
    const log = [
      'Jan  5 03:12:01 server sshd[1234]: Invalid user test from 10.0.0.2',
      'Jan  5 03:12:02 server sshd[1235]: Invalid user admin from 10.0.0.2',
      'Jan  5 03:12:03 server sshd[1236]: Failed password for invalid user test from 10.0.0.2 port 22 ssh2',
    ].join('\n');

    const findings = translateAuthLog(log);
    const ipFindings = findings.filter((f) => f.rawValue?.includes('failed_attempts'));
    expect(ipFindings).toHaveLength(1);
    expect(ipFindings[0]!.rawValue).toContain('failed_attempts=3');
    expect(ipFindings[0]!.severity).toBe('info'); // Ola 12: 3 < 5 → info
  });

  it('asigna severity "low" para 1-10 intentos', () => {
    // 5 intentos
    const lines = Array.from({ length: 5 }, (_, i) =>
      `Jan  5 03:12:0${i} server sshd[${i}]: Failed password for root from 1.2.3.4 port 22 ssh2`
    ).join('\n');

    const findings = translateAuthLog(lines);
    const brute = findings.find((f) => f.rawValue?.includes('1.2.3.4'));
    expect(brute!.severity).toBe('low');
  });

  it('asigna severity "medium" para 11-100 intentos', () => {
    const lines = Array.from({ length: 50 }, (_, i) =>
      `Jan  5 03:12:00 server sshd[${i}]: Failed password for root from 1.2.3.4 port 22 ssh2`
    ).join('\n');

    const findings = translateAuthLog(lines);
    const brute = findings.find((f) => f.rawValue?.includes('1.2.3.4'));
    expect(brute!.severity).toBe('medium');
  });

  it('asigna severity "high" para >100 intentos', () => {
    const lines = Array.from({ length: 150 }, (_, i) =>
      `Jan  5 03:12:00 server sshd[${i}]: Failed password for root from 1.2.3.4 port 22 ssh2`
    ).join('\n');

    const findings = translateAuthLog(lines);
    const brute = findings.find((f) => f.rawValue?.includes('1.2.3.4'));
    expect(brute!.severity).toBe('high');
  });

  it('detecta líneas de fail2ban (Ban/Unban/already banned) como findings separados', () => {
    const log = [
      '2024-01-05 03:15:00 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.100',
      '2024-01-05 03:20:00 fail2ban.actions [1234]: NOTICE [sshd] Unban 192.168.1.100',
      '2024-01-05 03:25:00 fail2ban.filter [1234]: 10.0.0.5 already banned',
    ].join('\n');

    const findings = translateAuthLog(log);
    // Ola 12: Ban y Unban separados — 1 ban (192.168.1.100 + 10.0.0.5), 1 unban (192.168.1.100)
    expect(findings.every((f) => f.severity === 'info')).toBe(true);
    // Ban: 192.168.1.100 (from "Ban") + 10.0.0.5 (from "already banned") = 2 bans
    // Unban: 192.168.1.100 = 1 unban
    expect(findings).toHaveLength(3);
    const banFindings = findings.filter(f => f.rawValue?.includes('action=ban'));
    const unbanFindings = findings.filter(f => f.rawValue?.includes('action=unban'));
    expect(banFindings).toHaveLength(2);
    expect(unbanFindings).toHaveLength(1);
    expect(banFindings.some((f) => f.rawValue?.includes('192.168.1.100'))).toBe(true);
    expect(banFindings.some((f) => f.rawValue?.includes('10.0.0.5'))).toBe(true);
    expect(unbanFindings[0]!.rawValue).toContain('192.168.1.100');
  });

  it('retorna arreglo vacío para texto sin líneas reconocibles', () => {
    expect(translateAuthLog('')).toEqual([]);
    expect(translateAuthLog('   ')).toEqual([]);
    expect(translateAuthLog('some random text\nanother line\n')).toEqual([]);
  });

  it('genera mezcla de findings de intentos fallidos + fail2ban', () => {
    const log = [
      'Jan  5 03:12:01 server sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2',
      '2024-01-05 03:15:00 fail2ban.actions [1]: NOTICE [sshd] Ban 1.1.1.1',
    ].join('\n');

    const findings = translateAuthLog(log);
    expect(findings).toHaveLength(2);
    // Ola 12: 1 intento < umbral(5) → info; ban → info
    expect(findings.every((f) => f.severity === 'info')).toBe(true);
    expect(findings.some((f) => f.rawValue?.includes('failed_attempts=1'))).toBe(true);
    expect(findings.some((f) => f.rawValue?.includes('action=ban'))).toBe(true);
  });

  it('todos los findings tienen category "log-analysis", description 10-500 chars, rawValue no vacío', () => {
    const log = [
      'Jan  5 03:12:01 server sshd[1]: Failed password for root from 5.5.5.5 port 22 ssh2',
      '2024-01-05 03:15:00 fail2ban.actions [1]: NOTICE [sshd] Ban 6.6.6.6',
    ].join('\n');

    const findings = translateAuthLog(log);
    for (const f of findings) {
      expect(f.category).toBe('log-analysis');
      expect(f.description.length).toBeGreaterThanOrEqual(10);
      expect(f.description.length).toBeLessThanOrEqual(500);
      expect(f.rawValue).toBeTruthy();
    }
  });

  it('deduplica "Invalid user" + "Failed password" del mismo evento (misma IP y PID)', () => {
    // sshd emite DOS líneas para el mismo evento: "Invalid user" y "Failed password for invalid user"
    // Con el mismo PID deben contar como 1 intento, no 2.
    const log = [
      'Jan  5 03:12:01 server sshd[1234]: Invalid user test from 10.0.0.9',
      'Jan  5 03:12:01 server sshd[1234]: Failed password for invalid user test from 10.0.0.9 port 22 ssh2',
    ].join('\n');

    const findings = translateAuthLog(log);
    const ipFindings = findings.filter((f) => f.rawValue?.includes('failed_attempts'));
    expect(ipFindings).toHaveLength(1);
    expect(ipFindings[0]!.rawValue).toContain('failed_attempts=1');
    expect(ipFindings[0]!.severity).toBe('info'); // Ola 12: 1 < 5 → info
  });

  it('no colapsa intentos rápidos con mismo timestamp pero PIDs distintos (regresión)', () => {
    // 150 intentos en el mismo segundo desde PIDs distintos = ataque de fuerza bruta rápido.
    // Deben contarse como 150 intentos → severidad 'high'.
    const lines = Array.from({ length: 150 }, (_, i) =>
      `Jan  5 03:12:00 server sshd[${i}]: Failed password for root from 1.2.3.4 port 22 ssh2`
    ).join('\n');

    const findings = translateAuthLog(lines);
    const brute = findings.find((f) => f.rawValue?.includes('1.2.3.4'));
    expect(brute!.rawValue).toContain('failed_attempts=150');
    expect(brute!.severity).toBe('high');
  });
});


// ─── Tests Ola 12: detección de compromiso, escalada, ban/unban separados ────

describe('translateAuthLog — Ola 12: nuevos eventos y umbral', () => {
  it('detecta las 4 IPs atacantes en tres formatos (Failed password, Invalid user, max auth attempts)', () => {
    const log = [
      'Jul 25 10:00:01 srv sshd[101]: Failed password for root from 203.0.113.5 port 22 ssh2',
      'Jul 25 10:00:02 srv sshd[102]: Failed password for root from 203.0.113.5 port 22 ssh2',
      'Jul 25 10:00:03 srv sshd[103]: Failed password for root from 203.0.113.5 port 22 ssh2',
      'Jul 25 10:00:04 srv sshd[104]: Failed password for root from 203.0.113.5 port 22 ssh2',
      'Jul 25 10:00:05 srv sshd[105]: Failed password for root from 203.0.113.5 port 22 ssh2',
      'Jul 25 10:01:01 srv sshd[201]: Invalid user test from 198.51.100.10',
      'Jul 25 10:01:02 srv sshd[202]: Invalid user admin from 198.51.100.10',
      'Jul 25 10:01:03 srv sshd[203]: Invalid user root from 198.51.100.10',
      'Jul 25 10:01:04 srv sshd[204]: Invalid user guest from 198.51.100.10',
      'Jul 25 10:01:05 srv sshd[205]: Invalid user oracle from 198.51.100.10',
      'Jul 25 10:02:01 srv sshd[301]: error: maximum authentication attempts exceeded for root from 91.240.118.172 port 22 ssh2',
      'Jul 25 10:02:02 srv sshd[302]: error: maximum authentication attempts exceeded for root from 91.240.118.172 port 22 ssh2',
      'Jul 25 10:02:03 srv sshd[303]: error: maximum authentication attempts exceeded for root from 91.240.118.172 port 22 ssh2',
      'Jul 25 10:02:04 srv sshd[304]: error: maximum authentication attempts exceeded for root from 91.240.118.172 port 22 ssh2',
      'Jul 25 10:02:05 srv sshd[305]: error: maximum authentication attempts exceeded for root from 91.240.118.172 port 22 ssh2',
      'Jul 25 10:03:01 srv sshd[401]: Failed password for admin from 192.0.2.99 port 22 ssh2',
    ].join('\n');

    const findings = translateAuthLog(log);
    // Las 4 IPs aparecen en findings
    expect(findings.some(f => f.rawValue?.includes('203.0.113.5'))).toBe(true);
    expect(findings.some(f => f.rawValue?.includes('198.51.100.10'))).toBe(true);
    expect(findings.some(f => f.rawValue?.includes('91.240.118.172'))).toBe(true);
    expect(findings.some(f => f.rawValue?.includes('192.0.2.99'))).toBe(true);
  });

  it('Accepted password → finding de login exitoso con IP y usuario', () => {
    const log = 'Jul 25 10:04:11 srv sshd[210]: Accepted password for deploy from 192.0.2.77 port 22 ssh2';
    const findings = translateAuthLog(log);
    const loginFinding = findings.find(f => f.rawValue?.includes('action=accepted'));
    expect(loginFinding).toBeDefined();
    expect(loginFinding!.severity).toBe('info');
    expect(loginFinding!.rawValue).toContain('192.0.2.77');
    expect(loginFinding!.rawValue).toContain('deploy');
    expect(loginFinding!.description).toContain('deploy');
    expect(loginFinding!.description).toContain('192.0.2.77');
  });

  it('login exitoso + fuerza bruta desde OTRA IP → finding high de compromiso probable', () => {
    const log = [
      // 5 intentos de fuerza bruta desde 203.0.113.5
      ...Array.from({ length: 5 }, (_, i) =>
        `Jul 25 10:00:0${i} srv sshd[${100 + i}]: Failed password for root from 203.0.113.5 port 22 ssh2`
      ),
      // Login exitoso desde otra IP
      'Jul 25 10:04:11 srv sshd[210]: Accepted password for deploy from 192.0.2.77 port 22 ssh2',
    ].join('\n');

    const findings = translateAuthLog(log);
    const compromise = findings.find(f => f.rawValue?.includes('action=compromise_probable'));
    expect(compromise).toBeDefined();
    expect(compromise!.severity).toBe('high');
    expect(compromise!.rawValue).toContain('192.0.2.77');
    expect(compromise!.rawValue).toContain('deploy');
  });

  it('login exitoso desde LA MISMA IP que fuerza bruta → finding critical', () => {
    const log = [
      // 5 intentos de fuerza bruta desde 203.0.113.5
      ...Array.from({ length: 5 }, (_, i) =>
        `Jul 25 10:00:0${i} srv sshd[${100 + i}]: Failed password for root from 203.0.113.5 port 22 ssh2`
      ),
      // Login exitoso desde la MISMA IP atacante
      'Jul 25 10:04:11 srv sshd[210]: Accepted password for root from 203.0.113.5 port 22 ssh2',
    ].join('\n');

    const findings = translateAuthLog(log);
    const compromise = findings.find(f => f.rawValue?.includes('action=compromise_probable'));
    expect(compromise).toBeDefined();
    expect(compromise!.severity).toBe('critical');
  });

  it('sudo → root → finding de escalada; medium sin login exitoso, high con él', () => {
    // Sin login exitoso → medium
    const logNoLogin = 'Jul 25 10:04:30 srv sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash';
    const findingsNoLogin = translateAuthLog(logNoLogin);
    const escNoLogin = findingsNoLogin.find(f => f.rawValue?.includes('action=sudo_root'));
    expect(escNoLogin).toBeDefined();
    expect(escNoLogin!.severity).toBe('medium');
    expect(escNoLogin!.rawValue).toContain('deploy');
    expect(escNoLogin!.description).toContain('/bin/bash');

    // Con login exitoso → high
    const logWithLogin = [
      'Jul 25 10:04:11 srv sshd[210]: Accepted password for deploy from 192.0.2.77 port 22 ssh2',
      'Jul 25 10:04:30 srv sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash',
    ].join('\n');
    const findingsWithLogin = translateAuthLog(logWithLogin);
    const escWithLogin = findingsWithLogin.find(f => f.rawValue?.includes('action=sudo_root'));
    expect(escWithLogin).toBeDefined();
    expect(escWithLogin!.severity).toBe('high');
  });

  it('Ban y Unban de la misma IP → DOS findings distintos', () => {
    const log = [
      '2024-01-05 03:15:00 fail2ban.actions [1]: NOTICE [sshd] Ban 203.0.113.5',
      '2024-01-05 04:15:00 fail2ban.actions [1]: NOTICE [sshd] Unban 203.0.113.5',
    ].join('\n');

    const findings = translateAuthLog(log);
    const banFinding = findings.find(f => f.rawValue?.includes('action=ban'));
    const unbanFinding = findings.find(f => f.rawValue?.includes('action=unban'));
    expect(banFinding).toBeDefined();
    expect(unbanFinding).toBeDefined();
    expect(banFinding!.description).toContain('bloqueó');
    expect(unbanFinding!.description).toContain('desbloqueada');
    expect(unbanFinding!.description).toContain('no está contenida');
  });

  it('2 intentos fallidos con umbral por defecto → finding info que NO dice fuerza bruta', () => {
    const log = [
      'Jan  5 03:12:01 server sshd[1]: Failed password for root from 5.5.5.5 port 22 ssh2',
      'Jan  5 03:12:02 server sshd[2]: Failed password for root from 5.5.5.5 port 22 ssh2',
    ].join('\n');

    const findings = translateAuthLog(log);
    const f = findings.find(f => f.rawValue?.includes('5.5.5.5'));
    expect(f).toBeDefined();
    expect(f!.severity).toBe('info');
    expect(f!.description).not.toContain('fuerza bruta');
  });

  it('5 intentos fallidos → sí se clasifica como fuerza bruta', () => {
    const log = Array.from({ length: 5 }, (_, i) =>
      `Jan  5 03:12:0${i} server sshd[${i}]: Failed password for root from 5.5.5.5 port 22 ssh2`
    ).join('\n');

    const findings = translateAuthLog(log);
    const f = findings.find(f => f.rawValue?.includes('5.5.5.5') && f.rawValue?.includes('failed_attempts'));
    expect(f).toBeDefined();
    expect(f!.severity).toBe('low'); // 5 intentos → low (en la escala de volumen)
    expect(f!.description).toContain('fuerza bruta');
  });

  it('translateAuthLog(log, { bruteForceMinAttempts: 2 }) → con 2 intentos sí clasifica como fuerza bruta', () => {
    const log = [
      'Jan  5 03:12:01 server sshd[1]: Failed password for root from 5.5.5.5 port 22 ssh2',
      'Jan  5 03:12:02 server sshd[2]: Failed password for root from 5.5.5.5 port 22 ssh2',
    ].join('\n');

    const findings = translateAuthLog(log, { bruteForceMinAttempts: 2 });
    const f = findings.find(f => f.rawValue?.includes('5.5.5.5'));
    expect(f).toBeDefined();
    expect(f!.description).toContain('fuerza bruta');
    expect(f!.severity).toBe('low'); // 2 intentos ≥ threshold → brute force → low
  });

  it('dedup por PID sigue funcionando con el nuevo umbral', () => {
    // Mismo PID para Invalid user + Failed password = 1 intento, no 2
    const log = [
      'Jan  5 03:12:01 server sshd[1234]: Invalid user test from 10.0.0.9',
      'Jan  5 03:12:01 server sshd[1234]: Failed password for invalid user test from 10.0.0.9 port 22 ssh2',
    ].join('\n');

    const findings = translateAuthLog(log);
    const f = findings.find(f => f.rawValue?.includes('10.0.0.9'));
    expect(f).toBeDefined();
    expect(f!.rawValue).toContain('failed_attempts=1');
  });
});
