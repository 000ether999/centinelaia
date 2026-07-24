/**
 * Módulo de detección de CORS mal configurado.
 *
 * Envía un GET con un Origin arbitrario y evalúa si el servidor refleja
 * ese origen con credenciales habilitadas (riesgo alto), permite wildcard
 * o refleja sin credenciales (riesgo medio), o restringe correctamente (info).
 *
 * Validates: Requirements 1.1, 1.2, 1.3, 4.1, 4.2, 4.3
 */

import { getSafeAgent } from '../safe-agent.js';
import type { Finding, FindingSeverity, ScanModule, ScanModuleInput } from './types.js';

// ─── Constantes ──────────────────────────────────────────────────────────────

/** Origin de prueba para detectar reflexión permisiva */
const TEST_ORIGIN = 'https://evil.example.com';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function finding(severity: FindingSeverity, rawValue: string | null, description: string): Finding {
  return { category: 'http-headers', severity, rawValue, description };
}

function errorMsg(err: unknown): string {
  return err instanceof Error ? err.message : 'Unknown error';
}

// ─── Factory del módulo ──────────────────────────────────────────────────────

/**
 * Crea el módulo de verificación de CORS.
 * Implementa la interfaz ScanModule.
 */
export function createCorsChecker(): ScanModule {
  return {
    name: 'cors-checker',
    category: 'http-headers',

    async run(input: ScanModuleInput): Promise<Finding[]> {
      try {
        const res = await fetch(input.targetUrl, {
          method: 'GET',
          headers: { Origin: TEST_ORIGIN },
          redirect: 'follow',
          signal: AbortSignal.timeout(input.timeoutMs),
          dispatcher: getSafeAgent() as any,
        } as RequestInit);

        const acao = res.headers.get('access-control-allow-origin');
        const acac = res.headers.get('access-control-allow-credentials');

        // Caso 1: Origin reflejado CON credenciales → high
        if (acao === TEST_ORIGIN && acac?.toLowerCase() === 'true') {
          return [finding('high', acao, 'Origin reflected with credentials — high CORS risk')];
        }

        // Caso 2: Wildcard o reflejado SIN credenciales → medium
        if (acao === '*' || acao === TEST_ORIGIN) {
          return [finding('medium', acao, 'Permissive CORS policy (wildcard or reflected without credentials)')];
        }

        // Caso 3: Restrictivo → info
        return [finding('info', acao, 'CORS policy is restrictive')];
      } catch (error) {
        // Error de red/timeout → info, sin propagar
        return [finding('info', null, `CORS check failed: ${errorMsg(error)}`)];
      }
    },
  };
}
