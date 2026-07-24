/**
 * Módulo compartido de bloqueo de IPs privadas/reservadas.
 * Extraído de validator.ts para reutilización en el safe-agent
 * y en los módulos que necesitan validar IPs resueltas por DNS
 * sin pasar por resolveAndCheckIp (prevención de DNS rebinding / TOCTOU).
 */

import { isIP } from 'node:net';

// ─── Constantes de rangos SSRF bloqueados ────────────────────────────────────

/**
 * Rangos IPv4 privados/reservados en formato [baseNumérica, máscara].
 */
const BLOCKED_IPV4_RANGES: Array<{ base: number; mask: number }> = [
  { base: ipv4ToNum('10.0.0.0'), mask: 0xff000000 },       // 10.0.0.0/8
  { base: ipv4ToNum('172.16.0.0'), mask: 0xfff00000 },     // 172.16.0.0/12
  { base: ipv4ToNum('192.168.0.0'), mask: 0xffff0000 },    // 192.168.0.0/16
  { base: ipv4ToNum('127.0.0.0'), mask: 0xff000000 },      // 127.0.0.0/8
  { base: ipv4ToNum('169.254.0.0'), mask: 0xffff0000 },    // 169.254.0.0/16
];

// ─── Funciones de validación de IP ───────────────────────────────────────────

export function ipv4ToNum(ip: string): number {
  const parts = ip.split('.').map(Number);
  return ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
}

export function isBlockedIPv4(ip: string): boolean {
  const num = ipv4ToNum(ip);
  return BLOCKED_IPV4_RANGES.some(({ base, mask }) => (num & mask) === (base & mask));
}

export function isBlockedIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase();
  // ::1 loopback
  if (normalized === '::1' || normalized === '0000:0000:0000:0000:0000:0000:0000:0001') {
    return true;
  }
  // Expandir para comparar prefijos
  const expanded = expandIPv6(normalized);
  // fe80::/10 (link-local)
  if (expanded.startsWith('fe8') || expanded.startsWith('fe9') ||
      expanded.startsWith('fea') || expanded.startsWith('feb')) {
    return true;
  }
  // fc00::/7 (unique local)
  const firstByte = parseInt(expanded.substring(0, 2), 16);
  if ((firstByte & 0xfe) === 0xfc) {
    return true;
  }
  return false;
}

function expandIPv6(ip: string): string {
  // Manejo de :: (double colon)
  let groups: string[];
  if (ip.includes('::')) {
    const [left, right] = ip.split('::');
    const leftGroups = left ? left.split(':') : [];
    const rightGroups = right ? right.split(':') : [];
    const missingGroups = 8 - leftGroups.length - rightGroups.length;
    groups = [...leftGroups, ...Array(missingGroups).fill('0'), ...rightGroups];
  } else {
    groups = ip.split(':');
  }
  return groups.map(g => g.padStart(4, '0')).join('');
}

export function isBlockedIp(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) return isBlockedIPv4(ip);
  if (version === 6) return isBlockedIPv6(ip);
  return false;
}
