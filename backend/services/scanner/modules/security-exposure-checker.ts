/**
 * Módulo de detección de exposición de recursos sensibles del servidor.
 *
 * Verifica en paralelo si rutas comúnmente sensibles son accesibles
 * públicamente y devuelven contenido que confirma la exposición:
 *   - /.git/HEAD  → exposición del repositorio git
 *   - /.env       → exposición de variables de entorno
 *   - /phpinfo.php → exposición de información PHP
 *
 * Usa la categoría nueva `security-exposure` (triple-consistencia aplicada
 * en types.ts, validator.ts y fallback-generator.ts).
 *
 * Fail-open: errores de red son silenciosos (no emiten finding).
 * 404 y similares son silenciosos.
 * Solo 200 + evidencia real emite finding `high`.
 *
 * Para evitar falsos positivos (A-04), la detección de evidencia usa
 * predicados regex estrictos en lugar de substring matching, y descarta
 * respuestas que son HTML (SPAs que devuelven index.html para rutas 404).
 */

import { getSafeAgent } from '../safe-agent.js';
import type { Finding, FindingSeverity, ScanModule, ScanModuleInput } from './types.js';

// ─── Constantes ───────────────────────────────────────────────────────────────

/** Máximo de bytes del body a leer para detección de evidencia */
const MAX_BODY_BYTES = 2048;

interface SensitivePath {
  path: string;
  /** Predicado que valida el formato real del contenido sensible */
  matches: (body: string) => boolean;
  description: string;
}

const SENSITIVE_PATHS: SensitivePath[] = [
  {
    path: '/.git/HEAD',
    // Formato real: "ref: refs/heads/main" o similar
    matches: (body) => /^ref:\s*refs\//m.test(body),
    description: 'Repositorio Git expuesto públicamente — el archivo .git/HEAD es accesible',
  },
  {
    path: '/.env',
    // Formato dotenv real: KEY=value o export KEY=value
    matches: (body) => /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=/m.test(body),
    description: 'Archivo .env expuesto públicamente — variables de entorno accesibles',
  },
  {
    path: '/phpinfo.php',
    // Contenido real de phpinfo(): "PHP Version X.Y.Z" o "PHP Version</td>"
    matches: (body) => /PHP Version\s*(?:<|\d)/.test(body),
    description: 'phpinfo.php expuesto públicamente — información de configuración PHP accesible',
  },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function finding(severity: FindingSeverity, rawValue: string | null, description: string): Finding {
  return { category: 'security-exposure', severity, rawValue, description };
}

/**
 * Comprueba una sola ruta sensible y retorna un Finding o null.
 * null = silencio (404, error de red, sin evidencia relevante).
 */
async function checkPath(
  baseUrl: string,
  sensitive: SensitivePath,
  timeoutMs: number,
): Promise<Finding | null> {
  const url = new URL(sensitive.path, baseUrl).toString();

  try {
    const response = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: AbortSignal.timeout(timeoutMs),
      dispatcher: getSafeAgent() as any,
    } as RequestInit);

    const status = response.status;

    // 403/401 → ruta protegida, info
    if (status === 403 || status === 401) {
      return finding('info', sensitive.path, `Path protected (access denied): ${sensitive.path}`);
    }

    // 404 u otros → silencioso
    if (status !== 200) {
      return null;
    }

    // 200 → leer solo los primeros 2 KB del body
    const bodyText = await response.text().then(t => t.slice(0, MAX_BODY_BYTES));

    // Descartar respuestas HTML (SPAs que devuelven index.html para rutas 404)
    // Esto elimina el falso positivo A-04 donde "=" en atributos HTML
    // disparaba high en /.env
    if (bodyText.trimStart().startsWith('<')) {
      return finding('info', sensitive.path, `Path accessible but no sensitive content detected: ${sensitive.path}`);
    }

    // Verificar que el body contenga evidencia real con predicado estricto
    if (sensitive.matches(bodyText)) {
      return finding('high', sensitive.path, sensitive.description);
    }

    // 200 pero sin evidencia → info
    return finding('info', sensitive.path, `Path accessible but no sensitive content detected: ${sensitive.path}`);
  } catch {
    // Error de red → silencioso (fail-open)
    return null;
  }
}

// ─── Factory del módulo ───────────────────────────────────────────────────────

/**
 * Crea el módulo de verificación de exposición de recursos sensibles.
 * Implementa la interfaz ScanModule.
 */
export function createSecurityExposureChecker(): ScanModule {
  return {
    name: 'security-exposure-checker',
    category: 'security-exposure',

    async run(input: ScanModuleInput): Promise<Finding[]> {
      const baseUrl = new URL(input.targetUrl).origin;

      // Verificar todas las rutas en paralelo (fail-open individual)
      const results = await Promise.allSettled(
        SENSITIVE_PATHS.map(sp => checkPath(baseUrl, sp, input.timeoutMs)),
      );

      const findings: Finding[] = [];
      for (const result of results) {
        if (result.status === 'fulfilled' && result.value !== null) {
          findings.push(result.value);
        }
        // rejected o null → silencio
      }

      return findings;
    },
  };
}
