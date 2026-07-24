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
  { base: ipv4ToNum('0.0.0.0'), mask: 0xff000000 },        // 0.0.0.0/8 (this network)
  { base: ipv4ToNum('10.0.0.0'), mask: 0xff000000 },       // 10.0.0.0/8
  { base: ipv4ToNum('100.64.0.0'), mask: 0xffc00000 },     // 100.64.0.0/10 (Shared Address / CGNAT)
  { base: ipv4ToNum('127.0.0.0'), mask: 0xff000000 },      // 127.0.0.0/8
  { base: ipv4ToNum('169.254.0.0'), mask: 0xffff0000 },    // 169.254.0.0/16
  { base: ipv4ToNum('172.16.0.0'), mask: 0xfff00000 },     // 172.16.0.0/12
  { base: ipv4ToNum('192.0.2.0'), mask: 0xffffff00 },      // 192.0.2.0/24 (TEST-NET-1)
  { base: ipv4ToNum('192.168.0.0'), mask: 0xffff0000 },    // 192.168.0.0/16
  { base: ipv4ToNum('198.18.0.0'), mask: 0xfffe0000 },     // 198.18.0.0/15 (benchmarking)
  { base: ipv4ToNum('198.51.100.0'), mask: 0xffffff00 },   // 198.51.100.0/24 (TEST-NET-2)
  { base: ipv4ToNum('203.0.113.0'), mask: 0xffffff00 },    // 203.0.113.0/24 (TEST-NET-3)
  { base: ipv4ToNum('224.0.0.0'), mask: 0xf0000000 },      // 224.0.0.0/4 (multicast)
  { base: ipv4ToNum('240.0.0.0'), mask: 0xf0000000 },      // 240.0.0.0/4 (reserved/future)
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

/**
 * Intenta extraer una dirección IPv4 embebida en una dirección IPv6.
 * Soporta:
 *  - IPv4-mapped:     ::ffff:a.b.c.d  o  ::ffff:XXYY:ZZWW (forma hex)
 *  - IPv4-compatible: ::a.b.c.d
 *  - NAT64:           64:ff9b::a.b.c.d o 64:ff9b::XXYY:ZZWW
 * Retorna la IPv4 como string o null si no aplica.
 */
function extractEmbeddedIPv4(ip: string): string | null {
  const normalized = ip.toLowerCase();

  // Detectar forma con puntos (::ffff:1.2.3.4, ::1.2.3.4, 64:ff9b::1.2.3.4)
  const dottedMatch = normalized.match(
    /^(?:::ffff:|::(?!ffff)|64:ff9b::)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/,
  );
  if (dottedMatch) {
    return dottedMatch[1]!;
  }

  // Detectar forma hex de IPv4-mapped: ::ffff:XXYY:ZZWW
  const hexMappedMatch = normalized.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hexMappedMatch) {
    const high = parseInt(hexMappedMatch[1]!, 16);
    const low = parseInt(hexMappedMatch[2]!, 16);
    return `${(high >> 8) & 0xff}.${high & 0xff}.${(low >> 8) & 0xff}.${low & 0xff}`;
  }

  // Detectar forma hex de NAT64: 64:ff9b::XXYY:ZZWW
  const nat64HexMatch = normalized.match(/^64:ff9b::([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (nat64HexMatch) {
    const high = parseInt(nat64HexMatch[1]!, 16);
    const low = parseInt(nat64HexMatch[2]!, 16);
    return `${(high >> 8) & 0xff}.${high & 0xff}.${(low >> 8) & 0xff}.${low & 0xff}`;
  }

  return null;
}

export function isBlockedIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase();

  // :: (IPv6 unspecified)
  if (normalized === '::' || normalized === '0000:0000:0000:0000:0000:0000:0000:0000') {
    return true;
  }

  // ::1 loopback
  if (normalized === '::1' || normalized === '0000:0000:0000:0000:0000:0000:0000:0001') {
    return true;
  }

  // Comprobar IPv4 embebida (mapped/compatible/NAT64) ANTES de expandir
  const embeddedIPv4 = extractEmbeddedIPv4(normalized);
  if (embeddedIPv4 !== null) {
    return isBlockedIPv4(embeddedIPv4);
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
