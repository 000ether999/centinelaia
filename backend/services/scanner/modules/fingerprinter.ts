/**
 * Módulo de Fingerprinting de tecnología del servidor.
 *
 * Examina los headers de respuesta HTTP (Server, X-Powered-By, X-AspNet-Version,
 * X-Generator) para identificar tecnología expuesta. Sigue redirecciones
 * manualmente con validación anti-SSRF en cada salto.
 *
 * Requisitos: 2.5, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 12.1
 */

import { resolveAndCheckIp } from '../validator.js';
import { getSafeAgent } from '../safe-agent.js';
import type { Finding, ScanModule, ScanModuleInput } from './types.js';

// ─── Constantes ──────────────────────────────────────────────────────────────

/** Headers que revelan tecnología del servidor */
const TECHNOLOGY_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator'] as const;

/** Máximo de redirecciones manuales a seguir */
const MAX_REDIRECTS = 5;

// ─── Implementación ──────────────────────────────────────────────────────────

/**
 * Factory que crea el módulo Fingerprinter.
 * Retorna un ScanModule listo para ser registrado en el orquestador.
 */
export function createFingerprinter(): ScanModule {
  return {
    name: 'Fingerprinter',
    category: 'server-fingerprint',

    async run(input: ScanModuleInput): Promise<Finding[]> {
      const findings: Finding[] = [];

      let response: Response;
      try {
        response = await fetchWithSsrfProtection(input.targetUrl, input.timeoutMs, findings);
      } catch (error: unknown) {
        // Req 8.6: Error de conexión → Finding info con el error
        const errorMessage = error instanceof Error ? error.message : String(error);
        findings.push({
          category: 'server-fingerprint',
          severity: 'info',
          rawValue: null,
          description: `No se pudo realizar el fingerprinting del servidor: ${errorMessage}`,
        });
        return findings;
      }

      // Examinar headers de tecnología en la respuesta final
      analyzeResponseHeaders(response, findings);

      return findings;
    },
  };
}

// ─── Funciones auxiliares ────────────────────────────────────────────────────

/**
 * Realiza un fetch con redirecciones manuales y validación anti-SSRF
 * en cada salto de redirección (Req 2.5).
 */
async function fetchWithSsrfProtection(
  url: string,
  timeoutMs: number,
  findings: Finding[],
): Promise<Response> {
  let currentUrl = url;
  let redirectCount = 0;

  while (redirectCount <= MAX_REDIRECTS) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    let response: Response;
    try {
      response = await fetch(currentUrl, {
        method: 'GET',
        redirect: 'manual',
        signal: controller.signal,
        dispatcher: getSafeAgent() as any,
      } as RequestInit);
    } finally {
      clearTimeout(timeoutId);
    }

    // Si no es una redirección, retornar la respuesta
    const statusCode = response.status;
    if (statusCode < 300 || statusCode >= 400) {
      return response;
    }

    // Es una redirección 3xx: validar destino
    const location = response.headers.get('location');
    if (!location) {
      // Redirección sin Location, retornar esta respuesta
      return response;
    }

    // Resolver la URL de destino (puede ser relativa)
    let destinationUrl: URL;
    try {
      destinationUrl = new URL(location, currentUrl);
    } catch {
      // URL inválida en Location, retornar la respuesta actual
      return response;
    }

    // Extraer host/IP del destino y validar SSRF
    const hostname = destinationUrl.hostname;
    const isIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname) ||
                 hostname.includes(':'); // IPv6

    const ssrfCheck = await resolveAndCheckIp(
      isIp ? null : hostname,
      isIp ? hostname : null,
    );

    if (!ssrfCheck.allowed) {
      // Req 2.5: Redirección a IP prohibida → Finding medium + abortar seguimiento
      findings.push({
        category: 'server-fingerprint',
        severity: 'medium',
        rawValue: location,
        description: `Redirección bloqueada por protección SSRF: destino ${hostname} resuelve a IP privada/reservada`,
      });
      return response;
    }

    // IP válida: seguir la redirección manualmente
    currentUrl = destinationUrl.href;
    redirectCount++;
  }

  // Exceso de redirecciones, lanzar error
  throw new Error(`Se excedió el máximo de ${MAX_REDIRECTS} redirecciones`);
}

/**
 * Analiza los headers de tecnología en la respuesta HTTP.
 * Genera un Finding "low" por cada header presente, o un Finding "info"
 * si ninguno revela tecnología.
 */
function analyzeResponseHeaders(response: Response, findings: Finding[]): void {
  let technologyDetected = false;

  for (const headerName of TECHNOLOGY_HEADERS) {
    const value = response.headers.get(headerName);

    if (value && value.trim() !== '') {
      technologyDetected = true;

      // Req 8.2, 8.3, 8.4: Finding low por cada header con valor
      const description = getHeaderDescription(headerName, value);
      findings.push({
        category: 'server-fingerprint',
        severity: 'low',
        rawValue: `${headerName}: ${value}`,
        description,
      });
    }
  }

  // Req 8.5: Ningún header divulga tecnología
  if (!technologyDetected) {
    findings.push({
      category: 'server-fingerprint',
      severity: 'info',
      rawValue: null,
      description: 'El servidor no divulga información de tecnología mediante headers HTTP',
    });
  }
}

/**
 * Genera descripción apropiada según el tipo de header detectado.
 */
function getHeaderDescription(headerName: string, value: string): string {
  switch (headerName) {
    case 'server':
      return `Tecnología de servidor detectada: ${value}`;
    case 'x-powered-by':
      return `Divulgación de tecnología backend: ${value}`;
    case 'x-aspnet-version':
      return `Versión de ASP.NET expuesta: ${value}`;
    case 'x-generator':
      return `Generador/framework expuesto: ${value}`;
    default:
      return `Header de tecnología detectado (${headerName}): ${value}`;
  }
}
