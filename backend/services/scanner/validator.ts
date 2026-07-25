/**
 * Validador de solicitudes de escaneo.
 * Verifica campos requeridos, formato del target (URL, dominio, IP),
 * prevención de SSRF mediante resolución DNS y bloqueo de rangos privados.
 *
 * La función resolveAndCheckIp se exporta como standalone reutilizable
 * para que los módulos que siguen redirecciones (Header Analyzer, Cookie Inspector,
 * Fingerprinter) puedan invocarla en cada salto de redirección.
 */

import { resolve4, resolve6 } from 'node:dns/promises';
import { isIP } from 'node:net';
import { isBlockedIp } from './ip-guard.js';

// ─── Tipos ───────────────────────────────────────────────────────────────────

export interface ValidationResult {
  valid: boolean;
  error?: { code: number; message: string };
  /** Si es válido, contiene los datos normalizados */
  normalized?: {
    targetUrl: string;
    targetDomain: string | null;
    isIpAddress: boolean;
  };
}

// ─── Validación de dominio ───────────────────────────────────────────────────

/**
 * Regex simple para dominio válido (sin esquema).
 * Acepta: example.com, sub.example.co.uk, etc.
 */
const DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

// ─── Funciones públicas ──────────────────────────────────────────────────────

/**
 * Valida y normaliza el request completo de escaneo.
 * Orden: 1) campos requeridos, 2) authorization, 3) target format, 4) SSRF check.
 */
export async function validateScanRequest(body: unknown): Promise<ValidationResult> {
  // 1) Verificar que body sea un objeto válido
  if (body === null || body === undefined || typeof body !== 'object' || Array.isArray(body)) {
    return {
      valid: false,
      error: { code: 400, message: 'Request body must be valid JSON' },
    };
  }

  const obj = body as Record<string, unknown>;

  // 2) Campos requeridos: target
  if (!obj['target'] || typeof obj['target'] !== 'string' || obj['target'].trim() === '') {
    return {
      valid: false,
      error: { code: 400, message: "Field 'target' is required" },
    };
  }

  // 3) Campo requerido: sessionId
  if (!obj['sessionId'] || typeof obj['sessionId'] !== 'string' || obj['sessionId'].trim() === '') {
    return {
      valid: false,
      error: { code: 400, message: "Field 'sessionId' is required" },
    };
  }

  // 4) Authorization
  if (obj['authorizationConfirmed'] !== true) {
    return {
      valid: false,
      error: { code: 403, message: 'Authorization confirmation is required' },
    };
  }

  // 5) Validar formato del target
  const targetResult = validateTarget(obj['target'] as string);
  if (!targetResult.valid) {
    return targetResult;
  }

  // 6) Verificación SSRF
  const ssrfResult = await resolveAndCheckIp(
    targetResult.normalized!.targetDomain,
    targetResult.normalized!.isIpAddress ? extractIpFromUrl(targetResult.normalized!.targetUrl) : null,
  );

  if (!ssrfResult.allowed) {
    return {
      valid: false,
      error: { code: 400, message: ssrfResult.error! },
    };
  }

  return targetResult;
}

/**
 * Valida y normaliza solo el target (URL, dominio o IP).
 * Extrae dominio, determina si es IP, aplica HTTPS por defecto.
 */
export function validateTarget(target: string): ValidationResult {
  // Longitud máxima
  if (target.length > 2048) {
    return {
      valid: false,
      error: { code: 400, message: 'Target exceeds maximum length of 2048 characters' },
    };
  }

  // Caso 1: El target tiene esquema (URL completa)
  if (/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//i.test(target)) {
    return validateUrlWithScheme(target);
  }

  // Caso 2: El target es una dirección IP (IPv4 o IPv6)
  // IPv6 entre brackets: [::1]
  const ipv6BracketMatch = target.match(/^\[([^\]]+)\]$/);
  if (ipv6BracketMatch) {
    const ipAddr = ipv6BracketMatch[1]!;
    if (isIP(ipAddr) === 6) {
      return {
        valid: true,
        normalized: {
          targetUrl: `https://[${ipAddr}]`,
          targetDomain: null,
          isIpAddress: true,
        },
      };
    }
  }

  // IPv4 o IPv6 sin brackets
  if (isIP(target) !== 0) {
    const url = isIP(target) === 6 ? `https://[${target}]` : `https://${target}`;
    return {
      valid: true,
      normalized: {
        targetUrl: url,
        targetDomain: null,
        isIpAddress: true,
      },
    };
  }

  // Caso 3: Dominio sin esquema
  if (DOMAIN_REGEX.test(target)) {
    return {
      valid: true,
      normalized: {
        targetUrl: `https://${target}`,
        targetDomain: target,
        isIpAddress: false,
      },
    };
  }

  // No es nada reconocible
  return {
    valid: false,
    error: { code: 400, message: 'Target is not a valid URL, domain, or IP address' },
  };
}

/**
 * Resuelve el dominio a IP(s) y verifica que ninguna pertenezca a rangos
 * privados, loopback, link-local o reservados (prevención de SSRF).
 *
 * Exportada como standalone reutilizable para que los módulos que siguen
 * redirecciones puedan invocarla en cada salto de redirección.
 *
 * Si el dominio resuelve a múltiples IPs (round-robin), TODAS se validan.
 * Si alguna cae en rango prohibido, se rechaza la solicitud completa.
 */
export async function resolveAndCheckIp(
  targetDomain: string | null,
  targetIp: string | null,
): Promise<{ allowed: boolean; resolvedIp?: string; error?: string }> {
  // Si se proporcionó una IP directa, validarla
  if (targetIp) {
    if (isBlockedIp(targetIp)) {
      return {
        allowed: false,
        error: 'Target resolves to a non-routable or private IP address',
      };
    }
    return { allowed: true, resolvedIp: targetIp };
  }

  // Fail-closed: sin dominio ni IP no hay nada que validar, así que no
  // podemos garantizar que el destino sea público. Rechazar por seguridad.
  if (!targetDomain) {
    return { allowed: false, error: 'Target resolves to a non-routable or private IP address' };
  }

  // Resolver DNS del dominio
  let ipv4Addresses: string[] = [];
  let ipv6Addresses: string[] = [];

  try {
    ipv4Addresses = await resolve4(targetDomain);
  } catch {
    // Puede que solo tenga AAAA records
  }

  try {
    ipv6Addresses = await resolve6(targetDomain);
  } catch {
    // Puede que solo tenga A records
  }

  const allIps = [...ipv4Addresses, ...ipv6Addresses];

  // Si no se pudo resolver ninguna IP
  if (allIps.length === 0) {
    return {
      allowed: false,
      error: 'Target resolves to a non-routable or private IP address',
    };
  }

  // Validar TODAS las IPs resueltas
  for (const ip of allIps) {
    if (isBlockedIp(ip)) {
      return {
        allowed: false,
        error: 'Target resolves to a non-routable or private IP address',
      };
    }
  }

  return { allowed: true, resolvedIp: allIps[0] };
}

// ─── Funciones privadas auxiliares ───────────────────────────────────────────

function validateUrlWithScheme(target: string): ValidationResult {
  let parsed: URL;
  try {
    parsed = new URL(target);
  } catch {
    return {
      valid: false,
      error: { code: 400, message: 'Target is not a valid URL, domain, or IP address' },
    };
  }

  // Solo HTTP y HTTPS
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      valid: false,
      error: { code: 400, message: 'Only HTTP and HTTPS schemes are supported' },
    };
  }

  // Extraer el hostname (sin puerto)
  const hostname = parsed.hostname;

  // Determinar si es una IP
  const ipVersion = isIP(hostname);
  const isIpAddress = ipVersion !== 0;

  // Si es dominio, validar formato
  if (!isIpAddress && !DOMAIN_REGEX.test(hostname)) {
    return {
      valid: false,
      error: { code: 400, message: 'Target is not a valid URL, domain, or IP address' },
    };
  }

  // URL normalizada: sin fragmento
  const normalizedUrl = target.replace(/#.*$/, '');

  return {
    valid: true,
    normalized: {
      targetUrl: normalizedUrl,
      targetDomain: isIpAddress ? null : hostname,
      isIpAddress,
    },
  };
}

/**
 * Extrae la IP de una URL normalizada (ya validada).
 * Elimina los brackets de IPv6 que URL.hostname incluye (ej. [::1] → ::1)
 * para que isIP() pueda reconocer la dirección correctamente (C-01).
 */
function extractIpFromUrl(url: string): string | null {
  try {
    const parsed = new URL(url);
    // URL.hostname devuelve brackets para IPv6 (ej. "[::1]"), los quitamos
    const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
    if (isIP(hostname) !== 0) {
      return hostname;
    }
  } catch {
    // No debería ocurrir con URLs ya validadas
  }
  return null;
}
