/**
 * Módulo Cookie Inspector — verifica flags de seguridad en cookies.
 *
 * Realiza un GET al target con redirecciones manuales (máx 5 saltos),
 * valida cada destino de redirección contra SSRF, y analiza las cookies
 * recolectadas de todas las respuestas acumuladas.
 *
 * Genera Findings por flags ausentes (Secure, HttpOnly, SameSite),
 * cookies malformadas, ausencia total de cookies, y bloqueos SSRF.
 */

import type { Finding, ScanModule, ScanModuleInput } from './types.js';
import { resolveAndCheckIp } from '../validator.js';

// ─── Constantes ──────────────────────────────────────────────────────────────

const MAX_REDIRECTS = 5;
const MAX_COOKIES = 50;

// ─── Interfaz interna para cookie parseada ───────────────────────────────────

interface ParsedCookie {
  name: string;
  hasSecure: boolean;
  hasHttpOnly: boolean;
  sameSite: string | null; // 'strict' | 'lax' | 'none' | null (absent)
}

// ─── Factory ─────────────────────────────────────────────────────────────────

/**
 * Crea una instancia del módulo Cookie Inspector.
 * Implementa la interfaz ScanModule para uso por el orquestador.
 */
export function createCookieInspector(): ScanModule {
  return {
    name: 'Cookie Inspector',
    category: 'cookies',

    async run(input: ScanModuleInput): Promise<Finding[]> {
      const findings: Finding[] = [];
      const allSetCookieHeaders: string[] = [];

      let currentUrl = input.targetUrl;
      let redirectCount = 0;
      let ssrfBlocked = false;

      // Seguir redirecciones manualmente hasta MAX_REDIRECTS saltos
      while (redirectCount <= MAX_REDIRECTS) {
        const response = await fetch(currentUrl, {
          redirect: 'manual',
          signal: AbortSignal.timeout(input.timeoutMs),
        });

        // Recolectar cookies de esta respuesta
        const setCookies = response.headers.getSetCookie();
        allSetCookieHeaders.push(...setCookies);

        // Verificar si es una redirección
        const statusCode = response.status;
        const isRedirect = statusCode >= 300 && statusCode < 400;
        const location = response.headers.get('location');

        if (!isRedirect || !location) {
          break;
        }

        redirectCount++;
        if (redirectCount > MAX_REDIRECTS) {
          break;
        }

        // Resolver URL relativa vs absoluta
        let redirectUrl: URL;
        try {
          redirectUrl = new URL(location, currentUrl);
        } catch {
          // Location malformada, detenemos la cadena
          break;
        }

        // Validar SSRF en el destino de la redirección
        const hostname = redirectUrl.hostname;
        const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(hostname) ||
                     hostname.includes(':');
        const ssrfCheck = await resolveAndCheckIp(
          isIp ? null : hostname,
          isIp ? hostname : null,
        );

        if (!ssrfCheck.allowed) {
          ssrfBlocked = true;
          findings.push({
            category: 'cookies',
            severity: 'medium',
            rawValue: redirectUrl.href,
            description: `Redirect to ${redirectUrl.href} blocked: SSRF protection detected redirection to a non-routable or private IP address`,
          });
          break;
        }

        currentUrl = redirectUrl.href;
      }

      // Parsear cookies recolectadas (máximo MAX_COOKIES)
      const cookiesToAnalyze = allSetCookieHeaders.slice(0, MAX_COOKIES);

      if (cookiesToAnalyze.length === 0 && !ssrfBlocked) {
        findings.push({
          category: 'cookies',
          severity: 'info',
          rawValue: null,
          description: 'No cookies detected in any HTTP response from the target',
        });
        return findings;
      }

      if (cookiesToAnalyze.length === 0 && ssrfBlocked) {
        // SSRF bloqueó antes de recolectar cookies, ya tenemos el finding de SSRF
        findings.push({
          category: 'cookies',
          severity: 'info',
          rawValue: null,
          description: 'No cookies detected before SSRF redirect was blocked',
        });
        return findings;
      }

      // Analizar cada cookie
      for (const rawCookie of cookiesToAnalyze) {
        const parsed = parseCookie(rawCookie);

        if (parsed === null) {
          // Cookie malformada
          findings.push({
            category: 'cookies',
            severity: 'low',
            rawValue: rawCookie,
            description: 'Malformed Set-Cookie header detected: unable to parse cookie name or attributes',
          });
          continue;
        }

        // Verificar flag Secure
        if (!parsed.hasSecure) {
          findings.push({
            category: 'cookies',
            severity: 'medium',
            rawValue: parsed.name,
            description: `Cookie "${parsed.name}" is missing the Secure flag: may be transmitted over unencrypted connections`,
          });
        }

        // Verificar flag HttpOnly
        if (!parsed.hasHttpOnly) {
          findings.push({
            category: 'cookies',
            severity: 'medium',
            rawValue: parsed.name,
            description: `Cookie "${parsed.name}" is missing the HttpOnly flag: accessible from JavaScript`,
          });
        }

        // Verificar flag SameSite
        if (parsed.sameSite === null) {
          findings.push({
            category: 'cookies',
            severity: 'medium',
            rawValue: parsed.name,
            description: `Cookie "${parsed.name}" is missing the SameSite attribute: vulnerable to CSRF attacks`,
          });
        } else if (parsed.sameSite === 'none' && !parsed.hasSecure) {
          findings.push({
            category: 'cookies',
            severity: 'medium',
            rawValue: parsed.name,
            description: `Cookie "${parsed.name}" has SameSite=None without Secure flag: vulnerable to CSRF attacks`,
          });
        }
      }

      return findings;
    },
  };
}

// ─── Funciones auxiliares ────────────────────────────────────────────────────

/**
 * Parsea un header Set-Cookie individual y extrae nombre y atributos de seguridad.
 * Retorna null si la cookie está malformada (no se puede extraer el nombre).
 */
function parseCookie(raw: string): ParsedCookie | null {
  const parts = raw.split(';').map(p => p.trim());

  // La primera parte debe ser name=value
  const nameValuePart = parts[0];
  if (!nameValuePart) {
    return null;
  }

  const equalsIndex = nameValuePart.indexOf('=');
  if (equalsIndex <= 0) {
    // No hay '=' o el nombre está vacío
    return null;
  }

  const name = nameValuePart.substring(0, equalsIndex).trim();
  if (name === '') {
    return null;
  }

  // Analizar atributos (case-insensitive)
  let hasSecure = false;
  let hasHttpOnly = false;
  let sameSite: string | null = null;

  for (let i = 1; i < parts.length; i++) {
    const attr = parts[i]!.toLowerCase();

    if (attr === 'secure') {
      hasSecure = true;
    } else if (attr === 'httponly') {
      hasHttpOnly = true;
    } else if (attr.startsWith('samesite')) {
      const eqIdx = attr.indexOf('=');
      if (eqIdx !== -1) {
        sameSite = attr.substring(eqIdx + 1).trim();
      } else {
        // SameSite sin valor = presente pero sin valor definido, se trata como presente
        sameSite = '';
      }
    }
  }

  return { name, hasSecure, hasHttpOnly, sameSite };
}
