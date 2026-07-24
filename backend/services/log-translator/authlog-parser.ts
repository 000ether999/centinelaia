/**
 * Parser de logs de autenticación (auth.log / fail2ban).
 * Traduce texto de log a Finding[], siguiendo el mismo patrón de nmap-parser.ts.
 */

import type { Finding } from '../scanner/modules/types.js';

// ─── Patrones regex ──────────────────────────────────────────────────────────

/** "Failed password for [invalid user] X from <IP> port ..." */
const FAILED_PASSWORD_PATTERN = /Failed password for (?:invalid user )?(\S+) from (\S+) port/;

/** "Invalid user X from <IP>" */
const INVALID_USER_PATTERN = /Invalid user \S+ from (\S+)/;

/** fail2ban "Ban <IP>" */
const BAN_PATTERN = /\bBan (\S+)/;

/** fail2ban "Unban <IP>" */
const UNBAN_PATTERN = /\bUnban (\S+)/;

/** fail2ban "already banned" — IP suele aparecer antes de "already banned" */
const ALREADY_BANNED_PATTERN = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*already banned/;

// ─── Lógica de traducción ────────────────────────────────────────────────────

/**
 * Convierte texto de logs de autenticación a hallazgos estructurados.
 * Agrega intentos fallidos por IP y detecta baneos de fail2ban.
 */
export function translateAuthLog(text: string): Finding[] {
  if (!text || !text.trim()) return [];

  // Mapas de agregación
  const failedAttempts = new Map<string, number>();
  const bannedIps = new Set<string>();

  for (const line of text.split(/\r?\n/)) {
    // Intentos fallidos: "Failed password..."
    const failedMatch = line.match(FAILED_PASSWORD_PATTERN);
    if (failedMatch) {
      const ip = failedMatch[2]!;
      failedAttempts.set(ip, (failedAttempts.get(ip) ?? 0) + 1);
      continue;
    }

    // Intentos fallidos: "Invalid user..."
    const invalidMatch = line.match(INVALID_USER_PATTERN);
    if (invalidMatch) {
      const ip = invalidMatch[1]!;
      failedAttempts.set(ip, (failedAttempts.get(ip) ?? 0) + 1);
      continue;
    }

    // fail2ban: Ban
    const banMatch = line.match(BAN_PATTERN);
    if (banMatch) {
      bannedIps.add(banMatch[1]!);
      continue;
    }

    // fail2ban: Unban
    const unbanMatch = line.match(UNBAN_PATTERN);
    if (unbanMatch) {
      bannedIps.add(unbanMatch[1]!);
      continue;
    }

    // fail2ban: already banned
    const alreadyMatch = line.match(ALREADY_BANNED_PATTERN);
    if (alreadyMatch) {
      bannedIps.add(alreadyMatch[1]!);
      continue;
    }
  }

  const findings: Finding[] = [];

  // Emitir findings de fuerza bruta por IP
  for (const [ip, count] of failedAttempts) {
    findings.push({
      category: 'log-analysis',
      severity: getSeverityByVolume(count),
      description: buildBruteForceDescription(ip, count),
      rawValue: `IP=${ip} failed_attempts=${count}`,
    });
  }

  // Emitir findings de defensa activa (fail2ban) por IP
  for (const ip of bannedIps) {
    findings.push({
      category: 'log-analysis',
      severity: 'info',
      description: `Defensa activa detectada: la IP ${ip} fue procesada por fail2ban (ban/unban/already banned).`,
      rawValue: `IP=${ip} action=fail2ban`,
    });
  }

  return findings;
}

// ─── Helpers internos ────────────────────────────────────────────────────────

/** Mapea volumen de intentos a severidad. */
function getSeverityByVolume(count: number): 'high' | 'medium' | 'low' {
  if (count > 100) return 'high';
  if (count >= 11) return 'medium';
  return 'low';
}

/** Genera descripción legible para un hallazgo de fuerza bruta. */
function buildBruteForceDescription(ip: string, count: number): string {
  const base = `Se detectaron ${count} intentos fallidos de autenticación desde la IP ${ip}, indicando un posible ataque de fuerza bruta.`;
  // Garantizar entre 10 y 500 caracteres
  return base.length > 500 ? base.slice(0, 497) + '...' : base;
}
