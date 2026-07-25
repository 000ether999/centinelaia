/**
 * Orquestador del módulo de escaneo.
 * Ejecuta todos los módulos de verificación en paralelo con timeouts
 * individuales y global, maneja errores sin interrumpir el flujo,
 * y genera el ScanResult final con metadatos.
 */

import { v4 as uuidv4 } from 'uuid';
import { ScanModule, ScanModuleInput, Finding } from './modules/types.js';
import { ScanResult, ScanStatus } from '../../models/scan.js';

/**
 * Configuración del orquestador de escaneo.
 */
export interface OrchestratorConfig {
  /** Timeout por módulo en ms (default: 5000, rango: 1000-10000) */
  moduleTimeoutMs: number;
  /** Timeout global en ms (default: 25000) */
  globalTimeoutMs: number;
  /** Módulos registrados para ejecutar */
  modules: ScanModule[];
}

/**
 * Resultado parcial del orquestador — sin campos que agrega el handler.
 */
export type OrchestratorResult = Omit<ScanResult, 'sessionId' | 'consent' | 'persisted'>;

/** Resultado interno de un módulo: findings + indicador de éxito real. */
interface ModuleOutcome {
  findings: Finding[];
  /** true si el módulo terminó correctamente; false si hubo timeout o error. */
  ok: boolean;
}

/**
 * Ejecuta todos los módulos de verificación en paralelo,
 * maneja timeouts individuales y globales,
 * y genera el ScanResult final (sin sessionId, consent ni persisted).
 */
export async function executeScan(
  input: ScanModuleInput,
  config: OrchestratorConfig
): Promise<OrchestratorResult> {
  const startTime = Date.now();
  const scanId = uuidv4();
  const timestamp = new Date().toISOString();

  const globalAbortController = new AbortController();
  const { signal: globalSignal } = globalAbortController;

  // Timer de seguridad global (25s por defecto)
  const globalTimer = setTimeout(() => {
    globalAbortController.abort();
  }, config.globalTimeoutMs);

  try {
    const modulePromises = config.modules.map((mod) =>
      runModuleWithTimeout(mod, input, config.moduleTimeoutMs, globalSignal)
    );

    const results = await Promise.allSettled(modulePromises);

    const allFindings: Finding[] = [];
    let successCount = 0;
    let failureCount = 0;

    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      const mod = config.modules[i];

      if (result.status === 'fulfilled') {
        const outcome = result.value;
        allFindings.push(...outcome.findings);
        if (outcome.ok) {
          successCount++;
        } else {
          failureCount++;
        }
      } else {
        // No debería pasar porque runModuleWithTimeout siempre resuelve,
        // pero por seguridad se maneja
        failureCount++;
        allFindings.push(createErrorFinding(mod, result.reason));
      }
    }

    const status = determineStatus(successCount, failureCount, config.modules.length);
    const durationMs = Date.now() - startTime;

    return {
      scanId,
      target: input.targetUrl,
      timestamp,
      durationMs,
      totalFindings: allFindings.length,
      status,
      findings: allFindings,
    };
  } finally {
    clearTimeout(globalTimer);
  }
}

/**
 * Ejecuta un módulo individual con timeout propio.
 * Si el módulo excede el timeout o lanza excepción, retorna un ModuleOutcome
 * con ok:false y un Finding descriptivo.
 */
async function runModuleWithTimeout(
  mod: ScanModule,
  input: ScanModuleInput,
  timeoutMs: number,
  globalSignal: AbortSignal
): Promise<ModuleOutcome> {
  // Si el timeout global ya se disparó antes de empezar
  if (globalSignal.aborted) {
    return { findings: [createTimeoutFinding(mod, timeoutMs, 'global')], ok: false };
  }

  return new Promise<ModuleOutcome>((resolve) => {
    let settled = false;

    // Timer individual del módulo
    const moduleTimer = setTimeout(() => {
      if (!settled) {
        settled = true;
        resolve({ findings: [createTimeoutFinding(mod, timeoutMs, 'module')], ok: false });
      }
    }, timeoutMs);

    // Listener del abort global (safety net)
    const onGlobalAbort = () => {
      if (!settled) {
        settled = true;
        clearTimeout(moduleTimer);
        resolve({ findings: [createTimeoutFinding(mod, timeoutMs, 'global')], ok: false });
      }
    };
    globalSignal.addEventListener('abort', onGlobalAbort, { once: true });

    // Ejecutar el módulo
    mod
      .run(input)
      .then((findings) => {
        if (!settled) {
          settled = true;
          clearTimeout(moduleTimer);
          globalSignal.removeEventListener('abort', onGlobalAbort);
          resolve({ findings, ok: true });
        }
      })
      .catch((error: unknown) => {
        if (!settled) {
          settled = true;
          clearTimeout(moduleTimer);
          globalSignal.removeEventListener('abort', onGlobalAbort);
          resolve({ findings: [createErrorFinding(mod, error)], ok: false });
        }
      });
  });
}

/**
 * Determina el status final del escaneo según cuántos módulos terminaron OK.
 * - 'complete': todos los módulos terminaron sin errores ni timeouts.
 * - 'partial': al menos un módulo tuvo éxito, pero uno o más fallaron/timeout.
 * - 'unreachable': ningún módulo tuvo éxito (todos fallaron o agotaron timeout).
 */
function determineStatus(
  successCount: number,
  _failureCount: number,
  totalModules: number
): ScanStatus {
  if (totalModules === 0) {
    return 'complete';
  }
  if (successCount === totalModules) {
    return 'complete';
  }
  if (successCount > 0) {
    return 'partial';
  }
  // Todos fallaron
  return 'unreachable';
}

/**
 * Genera un Finding de error cuando un módulo lanza una excepción.
 */
function createErrorFinding(mod: ScanModule, error: unknown): Finding {
  // Loguear detalle interno para debugging, sin exponerlo en el finding
  const message = error instanceof Error ? error.message : String(error);
  console.warn(`[orchestrator] Module ${mod.name} failed:`, message);
  return {
    category: mod.category,
    severity: 'info',
    rawValue: null,
    description: `Module ${mod.name} encountered an unexpected error`,
  };
}

/**
 * Genera un Finding de timeout cuando un módulo excede su tiempo asignado.
 */
function createTimeoutFinding(
  mod: ScanModule,
  timeoutMs: number,
  source: 'module' | 'global'
): Finding {
  const reason = source === 'global' ? 'global timeout reached' : `exceeded ${timeoutMs}ms`;
  return {
    category: mod.category,
    severity: 'low',
    rawValue: null,
    description: `Module ${mod.name} timed out: ${reason}`,
  };
}
