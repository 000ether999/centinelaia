/**
 * Módulo de verificación de redirección HTTP → HTTPS.
 *
 * Comprueba que el servidor redirige correctamente el tráfico HTTP a HTTPS.
 * Fuerza la petición en HTTP (aunque el target use HTTPS) y sigue hasta 3
 * redirecciones manualmente buscando un salto que eleve a HTTPS.
 *
 * Corrige A-05: ahora sigue la cadena completa de redirects en vez de
 * evaluar solo el primer hop, y forceHttp limpia el puerto correctamente.
 *
 * Usa categoría existente `http-headers` (no añade categoría nueva).
 */

import { getSafeAgent } from '../safe-agent.js';
import type { Finding, FindingSeverity, ScanModule, ScanModuleInput } from './types.js';

// ─── Constantes ───────────────────────────────────────────────────────────────

const MAX_REDIRECTS = 3;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function finding(severity: FindingSeverity, description: string): Finding {
  return { category: 'http-headers', severity, rawValue: null, description };
}

/**
 * Construye la URL HTTP equivalente al target dado, independientemente de
 * si el target original usa HTTPS.
 *
 * Limpia el puerto siempre que el protocolo original sea https:, porque
 * cualquier puerto TLS (443, 8443, etc.) no va a servir HTTP.
 */
function forceHttp(targetUrl: string): string {
  try {
    const parsed = new URL(targetUrl);
    const wasHttps = parsed.protocol === 'https:';
    parsed.protocol = 'http:';
    // Si el original era HTTPS, limpiar el puerto para usar 80 por defecto.
    // Dejar el puerto de un target originalmente HTTP sin tocar.
    if (wasHttps) parsed.port = '';
    return parsed.toString();
  } catch {
    return targetUrl;
  }
}

// ─── Factory del módulo ───────────────────────────────────────────────────────

/**
 * Crea el módulo de verificación de redirección HTTP → HTTPS.
 * Implementa la interfaz ScanModule.
 */
export function createRedirectChecker(): ScanModule {
  return {
    name: 'redirect-checker',
    category: 'http-headers',

    async run(input: ScanModuleInput): Promise<Finding[]> {
      const httpUrl = forceHttp(input.targetUrl);

      try {
        let currentUrl = httpUrl;

        for (let hop = 0; hop < MAX_REDIRECTS; hop++) {
          const response = await fetch(currentUrl, {
            method: 'GET',
            redirect: 'manual',
            signal: AbortSignal.timeout(input.timeoutMs),
            dispatcher: getSafeAgent() as any,
          } as RequestInit);

          const status = response.status;

          // Respuesta final sin redirección
          if (status < 300 || status >= 400) {
            if (hop === 0) {
              // Primer request no redirige → no hay upgrade HTTP→HTTPS
              return [finding('medium', 'No HTTP to HTTPS redirect detected')];
            }
            // Llegamos al final de la cadena sin subir a HTTPS
            return [finding('medium', 'HTTP redirect does not upgrade to HTTPS')];
          }

          // Es un redirect (3xx) — extraer Location
          const location = response.headers.get('location');
          if (!location) {
            return [finding('medium', 'HTTP redirect does not upgrade to HTTPS')];
          }

          let redirectUrl: URL;
          try {
            redirectUrl = new URL(location, currentUrl);
          } catch {
            return [finding('medium', 'HTTP redirect does not upgrade to HTTPS')];
          }

          // Si el destino es HTTPS → upgrade correcto, sin importar el hop
          if (redirectUrl.protocol === 'https:') {
            return [finding('info', 'HTTP to HTTPS redirect correctly configured')];
          }

          // Destino sigue siendo HTTP → continuar siguiendo la cadena
          currentUrl = redirectUrl.href;
        }

        // Se agotaron los saltos sin encontrar HTTPS
        return [finding('medium', 'HTTP redirect does not upgrade to HTTPS')];
      } catch (error) {
        // Error de red o timeout → info, fail-open
        console.warn('[redirect-checker] Redirect check failed:', error instanceof Error ? error.message : error);
        return [finding('info', 'Redirect check failed: connection error')];
      }
    },
  };
}
