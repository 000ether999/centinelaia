/**
 * Módulo compartido de bloqueo de IPs privadas/reservadas.
 * Extraído de validator.ts para reutilización en el safe-agent
 * y en los módulos que necesitan validar IPs resueltas por DNS
 * sin pasar por resolveAndCheckIp (prevención de DNS rebinding / TOCTOU).
 *
 * La lógica de IPv6 opera a nivel de bytes (16 octetos) para eliminar
 * bypass por formas de representación no canónicas (C-02).
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
 * Comprueba si 4 bytes representan una IPv4 bloqueada.
 * Recibe un slice del array de 16 bytes (posiciones relevantes).
 */
function isBlockedIPv4Bytes(bytes: number[]): boolean {
  const ip = `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
  return isBlockedIPv4(ip);
}

// ─── Conversión IPv6 a 16 bytes ──────────────────────────────────────────────

/**
 * Convierte cualquier representación válida de IPv6 a exactamente 16 bytes.
 * Maneja:
 *  - Compresión :: en cualquier posición
 *  - Sufijo IPv4 con puntos (::ffff:1.2.3.4, 64:ff9b::1.2.3.4)
 *  - Zone ID (fe80::1%eth0)
 * Retorna null si no es parseable.
 */
export function ipv6ToBytes(ip: string): number[] | null {
  // Eliminar zone id si existe (ej. fe80::1%eth0)
  const percentIdx = ip.indexOf('%');
  let addr = percentIdx >= 0 ? ip.substring(0, percentIdx) : ip;
  addr = addr.toLowerCase();

  // Verificar si tiene sufijo IPv4 con puntos
  let ipv4Suffix: number[] | null = null;
  const lastColon = addr.lastIndexOf(':');
  if (lastColon >= 0) {
    const afterColon = addr.substring(lastColon + 1);
    if (afterColon.includes('.')) {
      // Parsear la parte IPv4
      const parts = afterColon.split('.');
      if (parts.length !== 4) return null;
      const bytes: number[] = [];
      for (const p of parts) {
        const n = parseInt(p, 10);
        if (isNaN(n) || n < 0 || n > 255) return null;
        bytes.push(n);
      }
      ipv4Suffix = bytes;
      // Quitar la parte IPv4 del string para parsear solo los grupos hex
      addr = addr.substring(0, lastColon + 1);
      // Si termina en :: necesitamos preservar el ::
      // Si termina en :X: (un solo :) necesitamos quitar el último :
      if (!addr.endsWith(':')) {
        // No debería ocurrir; si lastColon es el último : y lo incluimos, termina en :
      }
    }
  }

  // Expandir :: (double colon)
  let groups: string[];
  if (addr.includes('::')) {
    const parts = addr.split('::');
    if (parts.length > 2) return null; // Más de un :: no es válido

    const left = parts[0] ? parts[0].split(':').filter(g => g !== '') : [];
    const right = parts[1] ? parts[1].split(':').filter(g => g !== '') : [];

    // Cada grupo hex es 2 bytes; la parte IPv4 ocupa 4 bytes = 2 grupos
    const totalGroupSlots = ipv4Suffix ? 6 : 8;
    const missingGroups = totalGroupSlots - left.length - right.length;
    if (missingGroups < 0) return null;

    groups = [...left, ...Array(missingGroups).fill('0'), ...right];
  } else {
    // Sin ::, separar por :
    groups = addr.split(':').filter(g => g !== '');
    const totalGroupSlots = ipv4Suffix ? 6 : 8;
    if (groups.length !== totalGroupSlots) return null;
  }

  // Convertir grupos hex a bytes
  const result: number[] = [];
  for (const g of groups) {
    if (g.length === 0 || g.length > 4) return null;
    const val = parseInt(g, 16);
    if (isNaN(val) || val < 0 || val > 0xffff) return null;
    result.push((val >> 8) & 0xff);
    result.push(val & 0xff);
  }

  // Agregar sufijo IPv4 si existe
  if (ipv4Suffix) {
    result.push(...ipv4Suffix);
  }

  if (result.length !== 16) return null;
  return result;
}

// ─── Decisión IPv6 a nivel de bytes ──────────────────────────────────────────

export function isBlockedIPv6(ip: string): boolean {
  const bytes = ipv6ToBytes(ip);

  // Si no se puede parsear → bloquear (fail-closed: dirección no comprensible)
  if (bytes === null) return true;

  // Unspecified :: → todos los bytes 0
  if (bytes.every(b => b === 0)) return true;

  // Loopback ::1 → bytes 0-14 son 0 y byte 15 === 1
  if (bytes.slice(0, 15).every(b => b === 0) && bytes[15] === 1) return true;

  // IPv4-mapped (::ffff:0:0/96): bytes 0-9 son 0, bytes 10-11 === 0xff
  if (
    bytes.slice(0, 10).every(b => b === 0) &&
    bytes[10] === 0xff && bytes[11] === 0xff
  ) {
    return isBlockedIPv4Bytes(bytes.slice(12, 16));
  }

  // IPv4-compatible (::a.b.c.d): bytes 0-11 son 0 y no es loopback/unspecified
  // (ya cubrimos esos arriba)
  if (bytes.slice(0, 12).every(b => b === 0)) {
    return isBlockedIPv4Bytes(bytes.slice(12, 16));
  }

  // NAT64 64:ff9b::/96 → bytes 0-1 === 0x00,0x64; bytes 2-3 === 0xff,0x9b;
  // bytes 4-11 son 0 → delegar últimos 4 bytes
  if (
    bytes[0] === 0x00 && bytes[1] === 0x64 &&
    bytes[2] === 0xff && bytes[3] === 0x9b &&
    bytes.slice(4, 12).every(b => b === 0)
  ) {
    return isBlockedIPv4Bytes(bytes.slice(12, 16));
  }

  // 6to4 2002::/16 (bytes 0-1 === 0x20, 0x02): bytes 2-5 codifican la IPv4
  if (bytes[0] === 0x20 && bytes[1] === 0x02) {
    return isBlockedIPv4Bytes(bytes.slice(2, 6));
  }

  // Teredo 2001:0::/32 (bytes 0-3 === 0x20, 0x01, 0x00, 0x00)
  if (
    bytes[0] === 0x20 && bytes[1] === 0x01 &&
    bytes[2] === 0x00 && bytes[3] === 0x00
  ) {
    return true;
  }

  // Link-local fe80::/10: (byte0 === 0xfe) && ((byte1 & 0xc0) === 0x80)
  if (bytes[0] === 0xfe && (bytes[1]! & 0xc0) === 0x80) return true;

  // Unique local fc00::/7: (byte0 & 0xfe) === 0xfc
  if ((bytes[0]! & 0xfe) === 0xfc) return true;

  return false;
}

// ─── Función principal ───────────────────────────────────────────────────────

/**
 * Determina si una dirección IP debe ser bloqueada (privada/reservada/no-routable).
 *
 * Fail-closed: si isIP() no reconoce la cadena como IP válida, se bloquea.
 * Razón: si no podemos determinar que la dirección es pública y segura,
 * no debemos permitir la conexión. Esto cierra vectores de bypass SSRF
 * que explotan representaciones no estándar de IPs.
 */
export function isBlockedIp(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) return isBlockedIPv4(ip);
  if (version === 6) return isBlockedIPv6(ip);

  // isIP() === 0: no es una IP reconocible. Fail-closed para prevenir bypass SSRF.
  // Si la cadena no se reconoce como IP válida, no podemos garantizar que sea
  // una dirección pública segura, así que la bloqueamos por precaución.
  return true;
}
