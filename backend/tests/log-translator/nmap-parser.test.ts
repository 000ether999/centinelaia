import { describe, expect, it } from 'vitest';
import type { Finding } from '../../services/scanner/modules/types.js';
import {
  convertNmapServiceRowToFinding,
  parseNmapServiceRows,
} from '../../services/log-translator/nmap-parser.js';

describe('Nmap service parser', () => {
  it('extracts realistic SSH and HTTP rows and converts them to findings', () => {
    const output = `Starting Nmap 7.94SVN at 2025-03-08 10:00 UTC
Nmap scan report for example.test (203.0.113.10)
Host is up (0.021s latency).

PORT    STATE    SERVICE VERSION
22/tcp  open     ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
80/tcp  open     http    Apache httpd 2.4.58 ((Ubuntu))
443/tcp filtered https

Service detection performed. Please report any incorrect results.
Nmap done: 1 IP address (1 host up) scanned in 8.42 seconds`;

    const rows = parseNmapServiceRows(output);
    expect(rows).toEqual([
      {
        port: 22,
        protocol: 'tcp',
        state: 'open',
        service: 'ssh',
        version: 'OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)',
      },
      {
        port: 80,
        protocol: 'tcp',
        state: 'open',
        service: 'http',
        version: 'Apache httpd 2.4.58 ((Ubuntu))',
      },
      { port: 443, protocol: 'tcp', state: 'filtered', service: 'https', version: '' },
    ]);

    const findings: Finding[] = rows.map(convertNmapServiceRowToFinding);
    expect(findings).toHaveLength(3);
    expect(findings.map(({ category, severity }) => ({ category, severity }))).toEqual([
      { category: 'port-service', severity: 'medium' },  // ssh → medium (Ola 12)
      { category: 'port-service', severity: 'low' },
      { category: 'port-service', severity: 'info' },
    ]);
    // rawValue es un string legible, no JSON
    expect(findings[0]!.rawValue).toBe('22/tcp ssh OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)');
    expect(findings[2]!.rawValue).toBe('443/tcp https');
    // serviceInfo debe estar poblado con datos estructurados
    expect(findings[0]!.serviceInfo).toEqual(rows[0]);
    expect(findings[2]!.serviceInfo).toEqual(rows[2]);
    expect(findings.every(({ description }) => description.length >= 10 && description.length <= 500)).toBe(true);
  });
});


// ─── Tests Ola 12: severidad por servicio expuesto ───────────────────────────

describe('Nmap service parser — Ola 12: severidad por servicio', () => {
  it('redis abierto → high', () => {
    const output = '6379/tcp  open  redis   Redis key-value store 7.0';
    const findings = parseNmapServiceRows(output).map(convertNmapServiceRowToFinding);
    expect(findings[0]!.severity).toBe('high');
  });

  it('mysql abierto → medium', () => {
    const output = '3306/tcp  open  mysql   MySQL 5.7.29';
    const findings = parseNmapServiceRows(output).map(convertNmapServiceRowToFinding);
    expect(findings[0]!.severity).toBe('medium');
  });

  it('http abierto → low', () => {
    const output = '80/tcp  open  http    nginx 1.18.0';
    const findings = parseNmapServiceRows(output).map(convertNmapServiceRowToFinding);
    expect(findings[0]!.severity).toBe('low');
  });

  it('cualquier servicio filtered → info', () => {
    const output = '6379/tcp  filtered  redis';
    const findings = parseNmapServiceRows(output).map(convertNmapServiceRowToFinding);
    expect(findings[0]!.severity).toBe('info');
  });

  it('elasticsearch abierto → high', () => {
    const output = '9200/tcp  open  elasticsearch';
    const findings = parseNmapServiceRows(output).map(convertNmapServiceRowToFinding);
    expect(findings[0]!.severity).toBe('high');
  });

  it('mongodb abierto → high', () => {
    const output = '27017/tcp  open  mongodb  MongoDB 4.4.6';
    const findings = parseNmapServiceRows(output).map(convertNmapServiceRowToFinding);
    expect(findings[0]!.severity).toBe('high');
  });

  it('ssh abierto → medium', () => {
    const output = '22/tcp  open  ssh     OpenSSH 9.6';
    const findings = parseNmapServiceRows(output).map(convertNmapServiceRowToFinding);
    expect(findings[0]!.severity).toBe('medium');
  });

  it('ftp abierto → medium', () => {
    const output = '21/tcp  open  ftp     vsftpd 3.0.5';
    const findings = parseNmapServiceRows(output).map(convertNmapServiceRowToFinding);
    expect(findings[0]!.severity).toBe('medium');
  });

  it('serviceInfo y rawValue siguen poblándose (no regresión Ola 3a)', () => {
    const output = '6379/tcp  open  redis   Redis key-value store 7.0';
    const findings = parseNmapServiceRows(output).map(convertNmapServiceRowToFinding);
    expect(findings[0]!.serviceInfo).toBeDefined();
    expect(findings[0]!.serviceInfo!.port).toBe(6379);
    expect(findings[0]!.serviceInfo!.service).toBe('redis');
    expect(findings[0]!.rawValue).toContain('6379/tcp');
    expect(findings[0]!.rawValue).toContain('redis');
  });
});
