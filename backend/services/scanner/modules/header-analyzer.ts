/**
 * Módulo de análisis de headers HTTP de seguridad.
 *
 * Verifica la presencia y configuración correcta de 7 headers de seguridad
 * estándar. Implementa seguimiento manual de redirecciones con protección SSRF
 * para evitar que un servidor malicioso redirija a direcciones internas.
 *
 * Validates: Requirements 2.5, 4.1, 4.2, 4.3, 4.4, 4.6, 12.1
 */

import { resolveAndCheckIp } from '../validator.js';
import { getSafeAgent } from '../safe-agent.js';
import type { Finding, FindingCategory, FindingSeverity, ScanModule, ScanModuleInput } from './types.js';

// ─── Configuración de severidad por header ───────────────────────────────────

interface HeaderSeverityConfig {
  absent: FindingSeverity;
  insecure: FindingSeverity;
}

const SECURITY_HEADERS_CONFIG: Record<string, HeaderSeverityConfig> = {
  'Strict-Transport-Security': { absent: 'high', insecure: 'medium' },
  'Content-Security-Policy':   { absent: 'high', insecure: 'medium' },
  'X-Frame-Options':           { absent: 'medium', insecure: 'medium' },
  'X-Content-Type-Options':    { absent: 'medium', insecure: 'medium' },
  'Permissions-Policy':        { absent: 'medium', insecure: 'medium' },
  'Referrer-Policy':           { absent: 'low', insecure: 'medium' },
};

/**
 * X-XSS-Protection está deprecado (Mozilla recomienda value "0").
 * No se penaliza su ausencia. Si está presente con valor distinto de "0",
 * se emite un finding informativo sugiriendo desactivarlo.
 */
const DEPRECATED_HEADERS: Record<string, { presentInsecure: FindingSeverity }> = {
  'X-XSS-Protection': { presentInsecure: 'low' },
};

/** Máximo de redirecciones manuales para evitar loops infinitos */
const MAX_REDIRECTS = 5;

// ─── Validación de valores inseguros ─────────────────────────────────────────

/**
 * Determina si el valor de un header es inseguro.
 * Retorna true si el valor es considerado una configuración débil o peligrosa.
 */
function isInsecureValue(headerName: string, value: string): boolean {
  const normalizedName = headerName.toLowerCase();
  const normalizedValue = value.toLowerCase();

  switch (normalizedName) {
    case 'x-frame-options':
      // ALLOW-FROM es obsoleto y considerado inseguro
      return normalizedValue.startsWith('allow-from');

    case 'content-security-policy':
      // unsafe-inline y unsafe-eval debilitan significativamente la CSP
      return normalizedValue.includes("'unsafe-inline'") || normalizedValue.includes("'unsafe-eval'");

    case 'strict-transport-security': {
      // max-age menor a 31536000 (1 año) es insuficiente
      const maxAgeMatch = normalizedValue.match(/max-age\s*=\s*(\d+)/);
      if (!maxAgeMatch) {
        // Sin max-age es inválido/inseguro
        return true;
      }
      const maxAge = parseInt(maxAgeMatch[1]!, 10);
      if (maxAge < 31536000) {
        return true;
      }
      // Falta includeSubDomains es inseguro
      if (!normalizedValue.includes('includesubdomains')) {
        return true;
      }
      return false;
    }

    case 'x-content-type-options': {
      // Solo "nosniff" es un valor seguro
      const trimmed = normalizedValue.replace(/\s/g, '');
      return trimmed !== 'nosniff';
    }

    default:
      return false;
  }
}

// ─── Seguimiento manual de redirecciones con protección SSRF ─────────────────

/**
 * Realiza un GET con seguimiento manual de redirecciones.
 * En cada salto verifica que el destino no apunte a una IP privada/reservada.
 * Retorna la respuesta final y opcionalmente un Finding si se bloqueó un redirect SSRF.
 */
async function fetchWithSsrfProtection(
  targetUrl: string,
  timeoutMs: number,
): Promise<{ response: Response; ssrfFinding: Finding | null }> {
  let currentUrl = targetUrl;
  let ssrfFinding: Finding | null = null;

  for (let i = 0; i < MAX_REDIRECTS; i++) {
    const response = await fetch(currentUrl, {
      method: 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
      dispatcher: getSafeAgent() as any,
    } as RequestInit);

    // Si no es una redirección 3xx, retornar la respuesta
    if (response.status < 300 || response.status >= 400) {
      return { response, ssrfFinding };
    }

    // Es una redirección — verificar Location header
    const location = response.headers.get('location');
    if (!location) {
      // Redirección sin Location — retornar la respuesta tal cual
      return { response, ssrfFinding };
    }

    // Resolver la URL de destino (puede ser relativa)
    let redirectUrl: URL;
    try {
      redirectUrl = new URL(location, currentUrl);
    } catch {
      // URL inválida en Location — abortar seguimiento
      return { response, ssrfFinding };
    }

    // Extraer hostname del destino y validar contra SSRF
    const hostname = redirectUrl.hostname;
    const ssrfCheck = await resolveAndCheckIp(hostname, null);

    if (!ssrfCheck.allowed) {
      // Redirección a IP privada/reservada — bloquear y generar Finding
      ssrfFinding = {
        category: 'http-headers',
        severity: 'medium',
        rawValue: `Location: ${location}`,
        description: `Redirect to private/reserved IP blocked (SSRF protection): ${location}`,
      };
      return { response, ssrfFinding };
    }

    // IP válida — seguir la redirección
    currentUrl = redirectUrl.href;
  }

  // Se agotaron los saltos permitidos — hacer un último fetch sin seguir más
  const finalResponse = await fetch(currentUrl, {
    method: 'GET',
    redirect: 'manual',
    signal: AbortSignal.timeout(timeoutMs),
    dispatcher: getSafeAgent() as any,
  } as RequestInit);

  return { response: finalResponse, ssrfFinding };
}

// ─── Análisis de headers de seguridad ────────────────────────────────────────

/**
 * Analiza los headers de la respuesta y genera Findings según la configuración.
 */
function analyzeSecurityHeaders(responseHeaders: Headers): Finding[] {
  const findings: Finding[] = [];

  for (const [headerName, config] of Object.entries(SECURITY_HEADERS_CONFIG)) {
    const value = responseHeaders.get(headerName);

    if (!value) {
      // Header ausente
      findings.push({
        category: 'http-headers',
        severity: config.absent,
        rawValue: null,
        description: `Security header missing: ${headerName}`,
      });
    } else if (isInsecureValue(headerName, value)) {
      // Header presente pero con valor inseguro
      findings.push({
        category: 'http-headers',
        severity: config.insecure,
        rawValue: value,
        description: `Security header present with insecure value: ${headerName}`,
      });
    } else {
      // Header presente con valor seguro
      findings.push({
        category: 'http-headers',
        severity: 'info',
        rawValue: value,
        description: `Security header correctly configured: ${headerName}`,
      });
    }
  }

  // Manejar headers deprecados (X-XSS-Protection): no penalizar ausencia
  for (const [headerName, config] of Object.entries(DEPRECATED_HEADERS)) {
    const value = responseHeaders.get(headerName);

    if (value) {
      const trimmedValue = value.trim();
      if (trimmedValue === '0') {
        // Valor recomendado (desactivado) — info
        findings.push({
          category: 'http-headers',
          severity: 'info',
          rawValue: value,
          description: `Security header correctly configured: ${headerName}`,
        });
      } else {
        // Valor distinto de "0" — informativo sugiriendo desactivar
        findings.push({
          category: 'http-headers',
          severity: config.presentInsecure,
          rawValue: value,
          description: `Deprecated header ${headerName} is present with value "${value}". Consider setting to "0" or removing it`,
        });
      }
    }
    // Ausencia: no genera finding (el header está deprecado)
  }

  return findings;
}

// ─── Factory del módulo ──────────────────────────────────────────────────────

/**
 * Crea una instancia del módulo de análisis de headers HTTP de seguridad.
 * Implementa la interfaz ScanModule para integración con el orquestador.
 */
export function createHeaderAnalyzer(): ScanModule {
  return {
    name: 'header-analyzer',
    category: 'http-headers' as FindingCategory,

    async run(input: ScanModuleInput): Promise<Finding[]> {
      const { targetUrl, timeoutMs } = input;
      const findings: Finding[] = [];

      try {
        // Realizar fetch con protección SSRF en redirecciones
        const { response, ssrfFinding } = await fetchWithSsrfProtection(targetUrl, timeoutMs);

        // Si se bloqueó una redirección SSRF, incluir el hallazgo
        if (ssrfFinding) {
          findings.push(ssrfFinding);
        }

        // Analizar headers de seguridad de la respuesta final
        const headerFindings = analyzeSecurityHeaders(response.headers);
        findings.push(...headerFindings);
      } catch (error) {
        // En caso de timeout u otro error de red, loguear detalle y generar finding genérico
        const message = error instanceof Error ? error.message : 'Unknown error';
        console.warn(`[header-analyzer] Unable to analyze headers:`, message);
        findings.push({
          category: 'http-headers',
          severity: 'medium',
          rawValue: null,
          description: `Unable to analyze headers: connection to target failed`,
        });
      }

      return findings;
    },
  };
}
