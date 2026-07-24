/**
 * Módulo de detección de métodos HTTP peligrosos.
 *
 * Envía una petición OPTIONS y analiza los headers Allow y
 * Access-Control-Allow-Methods para identificar métodos que
 * representan un riesgo de seguridad (TRACE/XST, PUT, DELETE, CONNECT).
 *
 * Validates: Requirements 2.1, 2.2, 2.3, 2.4, 4.1, 4.2, 4.3
 */

import { getSafeAgent } from '../safe-agent.js';
import type { Finding, FindingSeverity, ScanModule, ScanModuleInput } from './types.js';

// ─── Constantes ──────────────────────────────────────────────────────────────

/** Métodos considerados peligrosos */
const DANGEROUS_METHODS = ['TRACE', 'PUT', 'DELETE', 'CONNECT'] as const;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function finding(severity: FindingSeverity, rawValue: string | null, description: string): Finding {
  return { category: 'http-headers', severity, rawValue, description };
}

function errorMsg(err: unknown): string {
  return err instanceof Error ? err.message : 'Unknown error';
}

// ─── Factory del módulo ──────────────────────────────────────────────────────

/**
 * Crea el módulo de verificación de métodos HTTP peligrosos.
 * Implementa la interfaz ScanModule.
 */
export function createHttpMethodsChecker(): ScanModule {
  return {
    name: 'http-methods-checker',
    category: 'http-headers',

    async run(input: ScanModuleInput): Promise<Finding[]> {
      try {
        const res = await fetch(input.targetUrl, {
          method: 'OPTIONS',
          signal: AbortSignal.timeout(input.timeoutMs),
          dispatcher: getSafeAgent() as any,
        } as RequestInit);

        // Buscar en Allow o Access-Control-Allow-Methods
        const allow = res.headers.get('allow') ?? res.headers.get('access-control-allow-methods');

        if (!allow) {
          return [finding('info', null, 'No Allow header in OPTIONS response')];
        }

        const methods = allow.split(',').map(m => m.trim().toUpperCase());
        const dangerous = methods.filter(m =>
          (DANGEROUS_METHODS as readonly string[]).includes(m),
        );

        if (dangerous.length === 0) {
          return [finding('info', allow, 'Only safe HTTP methods exposed')];
        }

        // Un finding por cada método peligroso detectado
        return dangerous.map(m => finding(
          'medium',
          allow,
          m === 'TRACE'
            ? 'TRACE method enabled — XST risk'
            : `Dangerous HTTP method exposed: ${m}`,
        ));
      } catch (error) {
        // Error de red/timeout → info, sin propagar
        return [finding('info', null, `HTTP methods check failed: ${errorMsg(error)}`)];
      }
    },
  };
}
