/**
 * Parser de logs de autenticación (auth.log / fail2ban).
 * Traduce texto de log a Finding[], siguiendo el mismo patrón de nmap-parser.ts.
 */

import type { Finding, FindingSeverity } from '../scanner/modules/types.js';

// ─── Patrones regex ──────────────────────────────────────────────────────────

/** "Failed password for [invalid user] X from <IP> port ..." */
const FAILED_PASSWORD_PATTERN = /Failed password for (?:invalid user )?(\S+) from (\S+) port/;

/** "Invalid user X from <IP>" */
const INVALID_USER_PATTERN = /Invalid user \S+ from (\S+)/;

/** "maximum authentication attempts exceeded for <user> from <IP> port <n>" */
const MAX_AUTH_ATTEMPTS_PATTERN = /maximum authentication attempts exceeded for (\S+) from (\S+) port/;

/** Extrae el PID de sshd (ej. "sshd[1234]" → "1234") */
const SSHD_PID_PATTERN = /sshd\[(\d+)\]/;

/** "Accepted password for <user> from <IP> port <n>" o "Accepted publickey for ..." */
const ACCEPTED_PATTERN = /Accepted (\S+) for (\S+) from (\S+) port/;

/** sudo con USER=root (formato: "sudo: <user> : TTY=... ; PWD=... ; USER=root ; COMMAND=<cmd>") */
const SUDO_PATTERN = /sudo:\s+(\S+)\s+:.*USER=root\s*;\s*COMMAND=(.+)/;

/** fail2ban "Ban <IP>" */
const BAN_PATTERN = /\bBan (\S+)/;

/** fail2ban "Unban <IP>" */
const UNBAN_PATTERN = /\bUnban (\S+)/;

/** fail2ban "already banned" — IP suele aparecer antes de "already banned" */
const ALREADY_BANNED_PATTERN = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*already banned/;

// ─── Umbral configurable de fuerza bruta ─────────────────────────────────────

/**
 * Número mínimo de intentos fallidos por IP para clasificar como ataque de fuerza bruta.
 * Por debajo de este umbral se reporta como "intentos fallidos aislados" (info).
 * Puede sobrescribirse con el parámetro `options.bruteForceMinAttempts`.
 */
const BRUTE_FORCE_MIN_ATTEMPTS = 5;

// ─── Opciones del parser ─────────────────────────────────────────────────────

export interface AuthLogOptions {
  /** Umbral mínimo de intentos fallidos para clasificar como fuerza bruta (default: 5). */
  bruteForceMinAttempts?: number;
}

// ─── Lógica de traducción ────────────────────────────────────────────────────

/**
 * Convierte texto de logs de autenticación a hallazgos estructurados.
 * Detecta: intentos fallidos, logins exitosos, escaladas de privilegios,
 * compromisos probables, y acciones de fail2ban (ban/unban separados).
 */
export function translateAuthLog(text: string, options?: AuthLogOptions): Finding[] {
  if (!text || !text.trim()) return [];

  const threshold = options?.bruteForceMinAttempts ?? BRUTE_FORCE_MIN_ATTEMPTS;

  // Mapas de agregación
  const failedAttempts = new Map<string, number>();
  const bannedIps = new Set<string>();
  const unbannedIps = new Set<string>();
  // Logins exitosos: {ip, user, method}
  const successfulLogins: Array<{ ip: string; user: string; method: string }> = [];
  // Escaladas de privilegios: {user, command}
  const sudoEscalations: Array<{ user: string; command: string }> = [];
  // Deduplicación por (IP + PID): evita contar "Invalid user" + "Failed password" del mismo evento.
  const seenEvents = new Set<string>();

  for (const line of text.split(/\r?\n/)) {
    // Extraer PID de sshd si existe (usado para deduplicar mismo evento)
    const pidMatch = line.match(SSHD_PID_PATTERN);
    const pid = pidMatch ? pidMatch[1]! : '';

    // Login exitoso: "Accepted password/publickey for ..."
    const acceptedMatch = line.match(ACCEPTED_PATTERN);
    if (acceptedMatch) {
      successfulLogins.push({
        method: acceptedMatch[1]!,
        user: acceptedMatch[2]!,
        ip: acceptedMatch[3]!,
      });
      continue;
    }

    // Escalada de privilegios: sudo con USER=root
    const sudoMatch = line.match(SUDO_PATTERN);
    if (sudoMatch) {
      sudoEscalations.push({
        user: sudoMatch[1]!,
        command: sudoMatch[2]!.trim(),
      });
      continue;
    }

    // Intentos fallidos: "Failed password..." (priorizado sobre "Invalid user")
    const failedMatch = line.match(FAILED_PASSWORD_PATTERN);
    if (failedMatch) {
      const ip = failedMatch[2]!;
      if (pid) {
        const eventKey = `${ip}|${pid}`;
        if (!seenEvents.has(eventKey)) {
          seenEvents.add(eventKey);
          failedAttempts.set(ip, (failedAttempts.get(ip) ?? 0) + 1);
        }
      } else {
        failedAttempts.set(ip, (failedAttempts.get(ip) ?? 0) + 1);
      }
      continue;
    }

    // "maximum authentication attempts exceeded" — cuenta como intento fallido
    const maxAuthMatch = line.match(MAX_AUTH_ATTEMPTS_PATTERN);
    if (maxAuthMatch) {
      const ip = maxAuthMatch[2]!;
      if (pid) {
        const eventKey = `${ip}|${pid}`;
        if (!seenEvents.has(eventKey)) {
          seenEvents.add(eventKey);
          failedAttempts.set(ip, (failedAttempts.get(ip) ?? 0) + 1);
        }
      } else {
        failedAttempts.set(ip, (failedAttempts.get(ip) ?? 0) + 1);
      }
      continue;
    }

    // Intentos fallidos: "Invalid user..." — solo contar si no hay evento con mismo IP+PID ya registrado
    const invalidMatch = line.match(INVALID_USER_PATTERN);
    if (invalidMatch) {
      const ip = invalidMatch[1]!;
      if (pid) {
        const eventKey = `${ip}|${pid}`;
        if (!seenEvents.has(eventKey)) {
          seenEvents.add(eventKey);
          failedAttempts.set(ip, (failedAttempts.get(ip) ?? 0) + 1);
        }
      } else {
        failedAttempts.set(ip, (failedAttempts.get(ip) ?? 0) + 1);
      }
      continue;
    }

    // fail2ban: Ban (y already banned)
    // Verificar Unban ANTES de Ban porque "Unban" contiene "ban" como substring
    const unbanMatch = line.match(UNBAN_PATTERN);
    if (unbanMatch && !line.includes('already banned')) {
      unbannedIps.add(unbanMatch[1]!);
      continue;
    }

    const banMatch = line.match(BAN_PATTERN);
    if (banMatch) {
      bannedIps.add(banMatch[1]!);
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

  // Determinar si hay actividad de fuerza bruta en el log (para detección de compromiso)
  const hasBruteForce = Array.from(failedAttempts.values()).some(count => count >= threshold);
  const bruteForceIps = new Set(
    Array.from(failedAttempts.entries())
      .filter(([, count]) => count >= threshold)
      .map(([ip]) => ip)
  );

  // Emitir findings de intentos fallidos por IP
  for (const [ip, count] of failedAttempts) {
    if (count >= threshold) {
      // Clasificar como fuerza bruta
      findings.push({
        category: 'log-analysis',
        severity: getSeverityByVolume(count),
        description: buildBruteForceDescription(ip, count),
        rawValue: `IP=${ip} failed_attempts=${count}`,
      });
    } else {
      // Por debajo del umbral: intentos fallidos aislados (info), NO fuerza bruta
      findings.push({
        category: 'log-analysis',
        severity: 'info',
        description: `Se detectaron ${count} intento(s) fallido(s) de autenticación desde la IP ${ip}. Cantidad insuficiente para clasificarse como ataque.`,
        rawValue: `IP=${ip} failed_attempts=${count}`,
      });
    }
  }

  // Emitir findings de logins exitosos
  for (const login of successfulLogins) {
    findings.push({
      category: 'log-analysis',
      severity: 'info',
      description: `Login exitoso detectado: el usuario "${login.user}" accedió desde la IP ${login.ip} mediante ${login.method}.`,
      rawValue: `IP=${login.ip} user=${login.user} method=${login.method} action=accepted`,
    });
  }

  // Emitir findings de compromiso probable (login exitoso + fuerza bruta en el log)
  if (successfulLogins.length > 0 && hasBruteForce) {
    for (const login of successfulLogins) {
      const isAttackerIp = bruteForceIps.has(login.ip);
      const severity: FindingSeverity = isAttackerIp ? 'critical' : 'high';
      const qualifier = isAttackerIp
        ? `La IP ${login.ip} del login coincide con una de las IPs atacantes — compromiso directo probable.`
        : `Se detectó un acceso concedido al usuario "${login.user}" desde la IP ${login.ip} en un log que también contiene ataques de fuerza bruta. Debe verificarse si la sesión es legítima.`;

      findings.push({
        category: 'log-analysis',
        severity,
        description: qualifier,
        rawValue: `IP=${login.ip} user=${login.user} action=compromise_probable`,
      });
    }
  }

  // Emitir findings de escalada de privilegios
  for (const esc of sudoEscalations) {
    // Si hay un login exitoso en el log, la escalada es más grave
    const severity: FindingSeverity = successfulLogins.length > 0 ? 'high' : 'medium';
    findings.push({
      category: 'log-analysis',
      severity,
      description: `Escalada de privilegios detectada: el usuario "${esc.user}" ejecutó como root el comando: ${esc.command}`.slice(0, 500),
      rawValue: `user=${esc.user} action=sudo_root command=${esc.command}`,
    });
  }

  // Emitir findings de defensa activa: Ban (separado de Unban)
  for (const ip of bannedIps) {
    findings.push({
      category: 'log-analysis',
      severity: 'info',
      description: `Defensa activa detectada: fail2ban bloqueó la IP ${ip}. La IP está contenida.`,
      rawValue: `IP=${ip} action=ban`,
    });
  }

  // Emitir findings de Unban (IP desbloqueada — ya no está contenida)
  for (const ip of unbannedIps) {
    findings.push({
      category: 'log-analysis',
      severity: 'info',
      description: `La IP ${ip} fue desbloqueada por fail2ban (unban). Ya no está contenida y puede volver a intentar acceso.`,
      rawValue: `IP=${ip} action=unban`,
    });
  }

  return findings;
}

// ─── Helpers internos ────────────────────────────────────────────────────────

/** Mapea volumen de intentos a severidad (aplica solo cuando count >= umbral de fuerza bruta). */
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
