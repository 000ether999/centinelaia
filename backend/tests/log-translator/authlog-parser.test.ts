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
    // Dos IPs distintas
    const bruteFindings = findings.filter((f) => f.severity !== 'info');
    expect(bruteFindings).toHaveLength(2);

    const ip5 = bruteFindings.find((f) => f.rawValue?.includes('192.168.1.5'));
    expect(ip5).toBeDefined();
    expect(ip5!.rawValue).toContain('failed_attempts=2');

    const ip1 = bruteFindings.find((f) => f.rawValue?.includes('10.0.0.1'));
    expect(ip1).toBeDefined();
    expect(ip1!.rawValue).toContain('failed_attempts=1');
  });

  it('registra líneas "Invalid user" como intentos fallidos', () => {
    const log = [
      'Jan  5 03:12:01 server sshd[1234]: Invalid user test from 10.0.0.2',
      'Jan  5 03:12:02 server sshd[1235]: Invalid user admin from 10.0.0.2',
      'Jan  5 03:12:03 server sshd[1236]: Failed password for invalid user test from 10.0.0.2 port 22 ssh2',
    ].join('\n');

    const findings = translateAuthLog(log);
    const bruteFindings = findings.filter((f) => f.severity !== 'info');
    expect(bruteFindings).toHaveLength(1);
    expect(bruteFindings[0]!.rawValue).toContain('failed_attempts=3');
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

  it('detecta líneas de fail2ban (Ban/Unban/already banned) con severity "info"', () => {
    const log = [
      '2024-01-05 03:15:00 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.100',
      '2024-01-05 03:20:00 fail2ban.actions [1234]: NOTICE [sshd] Unban 192.168.1.100',
      '2024-01-05 03:25:00 fail2ban.filter [1234]: 10.0.0.5 already banned',
    ].join('\n');

    const findings = translateAuthLog(log);
    // Todas con severity 'info'
    expect(findings.every((f) => f.severity === 'info')).toBe(true);
    expect(findings).toHaveLength(2); // Dos IPs únicas en el set de baneados
    expect(findings.some((f) => f.rawValue?.includes('192.168.1.100'))).toBe(true);
    expect(findings.some((f) => f.rawValue?.includes('10.0.0.5'))).toBe(true);
  });

  it('retorna arreglo vacío para texto sin líneas reconocibles', () => {
    expect(translateAuthLog('')).toEqual([]);
    expect(translateAuthLog('   ')).toEqual([]);
    expect(translateAuthLog('some random text\nanother line\n')).toEqual([]);
  });

  it('genera mezcla de findings de fuerza bruta + fail2ban', () => {
    const log = [
      'Jan  5 03:12:01 server sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2',
      '2024-01-05 03:15:00 fail2ban.actions [1]: NOTICE [sshd] Ban 1.1.1.1',
    ].join('\n');

    const findings = translateAuthLog(log);
    expect(findings).toHaveLength(2);
    expect(findings.some((f) => f.severity === 'low')).toBe(true);
    expect(findings.some((f) => f.severity === 'info')).toBe(true);
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
});
