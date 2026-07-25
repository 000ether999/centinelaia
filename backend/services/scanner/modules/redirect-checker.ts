/**
 * Módulo de verificación de redirección HTTP → HTTPS.
 *
 * Comprueba que el servidor redirige correctamente el tráfico HTTP a HTTPS.
 * Fuerza la petición en HTTP (aunque el target use HTTPS) y sigue hasta 3
 * redirecciones manualmente buscando un salto que eleve a HTTPS.
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
 */
function forceHttp(targetUrl: string): string {
  try {
    const parsed = new URL(targetUrl);
    parsed.protocol = 'http:';
    // HTTP usa puerto 80 por defecto; eliminar puerto explícito si coincide
    if (parsed.port === '443') parsed.port = '';
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

          // Respuesta final sin redirección en el primer salto
          if (hop === 0 && (status < 300 || status >= 400)) {
            return [finding('medium', 'No HTTP to HTTPS redirect detected')];
          }

          // Respuesta no-redirect en saltos posteriores → terminó sin subir a HTTPS
          if (status < 300 || status >= 400) {
            return [finding('medium', 'HTTP redirect does not upgrade to HTTPS')];
          }

          const location = response.headers.get('location');
          if (!location) {
            // Redirect sin Location header
            return [finding('medium', 'HTTP redirect does not upgrade to HTTPS')];
          }

          let redirectUrl: URL;
          try {
            redirectUrl = new URL(location, currentUrl);
          } catch {
            return [finding('medium', 'HTTP redirect does not upgrade to HTTPS')];
          }

          // ¿El primer salto eleva a HTTPS?
          if (hop === 0 && redirectUrl.protocol === 'https:') {
            return [finding('info', 'HTTP to HTTPS redirect correctly configured')];
          }

          // El primer salto no va a HTTPS
          if (hop === 0 && redirectUrl.protocol !== 'https:') {
            return [finding('medium', 'HTTP redirect does not upgrade to HTTPS')];
          }

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
