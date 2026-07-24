/**
 * Módulo de verificación de presencia de security.txt (RFC 9116).
 *
 * Verifica si el target publica un archivo security.txt en la ruta
 * estándar (/.well-known/security.txt) con fallback a /security.txt.
 * Su presencia indica buenas prácticas de divulgación responsable.
 *
 * Validates: Requirements 3.1, 3.2, 3.3, 4.1, 4.2, 4.3
 */

import { getSafeAgent } from '../safe-agent.js';
import type { Finding, FindingSeverity, ScanModule, ScanModuleInput } from './types.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function finding(severity: FindingSeverity, rawValue: string | null, description: string): Finding {
  return { category: 'http-headers', severity, rawValue, description };
}

function errorMsg(err: unknown): string {
  return err instanceof Error ? err.message : 'Unknown error';
}

// ─── Factory del módulo ──────────────────────────────────────────────────────

/**
 * Crea el módulo de verificación de security.txt.
 * Implementa la interfaz ScanModule.
 */
export function createSecurityTxtChecker(): ScanModule {
  return {
    name: 'security-txt-checker',
    category: 'http-headers',

    async run(input: ScanModuleInput): Promise<Finding[]> {
      const origin = new URL(input.targetUrl).origin;
      const fetchOpts = {
        method: 'GET',
        redirect: 'follow' as const,
        signal: AbortSignal.timeout(input.timeoutMs),
        dispatcher: getSafeAgent() as any,
      } as RequestInit;

      try {
        // Intento principal: ruta estándar RFC 9116
        const primary = await fetch(`${origin}/.well-known/security.txt`, fetchOpts);
        if (primary.status === 200) {
          return [finding('info', null, 'security.txt present at /.well-known/security.txt (RFC 9116)')];
        }

        // Fallback: ruta legacy
        const fallback = await fetch(`${origin}/security.txt`, fetchOpts);
        if (fallback.status === 200) {
          return [finding('info', null, 'security.txt found at /security.txt (non-standard path)')];
        }

        // Ambos non-200 → ausente
        return [finding('low', null, 'security.txt not found — consider adding per RFC 9116')];
      } catch (error) {
        // Error de red/timeout → info, sin propagar
        return [finding('info', null, `security.txt check failed: ${errorMsg(error)}`)];
      }
    },
  };
}
