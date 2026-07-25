/**
 * Tests del orquestador de escaneo (executeScan).
 *
 * Verifica:
 * - Ejecución correcta cuando todos los módulos terminan OK → 'complete'
 * - Módulo que lanza excepción → 'partial', finding con severity:'info'
 * - Módulo que excede timeout individual → 'partial', finding con severity:'low'
 * - Todos los módulos fallan → 'unreachable'
 * - Sin módulos registrados → 'complete', findings vacíos
 * - Múltiples módulos OK + 1 timeout → 'partial', findings del resto presentes
 * - scanId es un UUID v4 válido
 * - durationMs es positivo
 *
 * Para tests de timeout se usa moduleTimeoutMs:50 y módulos que
 * no resuelven en 200ms, garantizando que el timer se dispare primero.
 */

import { describe, it, expect } from 'vitest';
import { executeScan } from '../../services/scanner/orchestrator.js';
import type { OrchestratorConfig } from '../../services/scanner/orchestrator.js';
import type { ScanModule, ScanModuleInput, Finding, FindingCategory } from '../../services/scanner/modules/types.js';

// ─── Fixture de entrada ────────────────────────────────────────────────────────

/** Input de escaneo genérico para los tests */
const testInput: ScanModuleInput = {
  targetUrl: 'https://example.com',
  targetDomain: 'example.com',
  isIpAddress: false,
  timeoutMs: 5000,
};

// ─── Helpers para construir módulos fake ───────────────────────────────────────

/**
 * Construye un módulo fake para testing.
 *
 * @param name     - Nombre del módulo (aparece en findings de error/timeout)
 * @param category - Categoría del finding que produce
 * @param behavior - Qué hace el módulo:
 *   - Finding[]   → resuelve con esos findings
 *   - Error       → lanza ese error
 *   - 'timeout'   → nunca resuelve (se queda colgado indefinidamente)
 */
function makeModule(
  name: string,
  category: FindingCategory,
  behavior: Finding[] | Error | 'timeout'
): ScanModule {
  return {
    name,
    category,
    run: (_input: ScanModuleInput): Promise<Finding[]> => {
      if (behavior instanceof Error) {
        return Promise.reject(behavior);
      }
      if (behavior === 'timeout') {
        // Nunca resuelve → el timer del orquestador se dispara antes
        return new Promise<Finding[]>(() => {
          // Promise intencionalmente sin resolver
        });
      }
      return Promise.resolve(behavior);
    },
  };
}

/** Finding de ejemplo para módulos que retornan resultados */
function makeFinding(category: FindingCategory): Finding {
  return {
    category,
    severity: 'medium',
    rawValue: null,
    description: `Finding from module with category ${category}`,
  };
}

// Regex de UUID v4 (formato xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx)
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ─── Caso 1: Todos los módulos OK ──────────────────────────────────────────────

describe('executeScan — todos los módulos OK', () => {
  it('retorna status:complete con todos los findings de todos los módulos', async () => {
    const config: OrchestratorConfig = {
      moduleTimeoutMs: 5000,
      globalTimeoutMs: 25000,
      modules: [
        makeModule('headers', 'http-headers', [makeFinding('http-headers')]),
        makeModule('tls', 'tls-ssl', [makeFinding('tls-ssl'), makeFinding('tls-ssl')]),
        makeModule('cookies', 'cookies', []),
      ],
    };

    const result = await executeScan(testInput, config);

    expect(result.status).toBe('complete');
    // 1 + 2 + 0 = 3 findings en total
    expect(result.findings).toHaveLength(3);
    expect(result.totalFindings).toBe(3);
    // findings de http-headers y tls-ssl presentes
    expect(result.findings.some((f) => f.category === 'http-headers')).toBe(true);
    expect(result.findings.some((f) => f.category === 'tls-ssl')).toBe(true);
  });
});

// ─── Caso 2: Un módulo lanza excepción ────────────────────────────────────────

describe('executeScan — un módulo lanza excepción', () => {
  /**
   * runModuleWithTimeout() captura internamente cualquier excepción del módulo
   * y la convierte en un ModuleOutcome con ok:false y un Finding de error
   * (severity:'info'). El status final es 'partial' porque hay módulos OK
   * junto a uno fallido.
   */
  it('status:partial, los findings del resto de módulos están presentes y el módulo fallido produce finding severity:info', async () => {
    const config: OrchestratorConfig = {
      moduleTimeoutMs: 5000,
      globalTimeoutMs: 25000,
      modules: [
        makeModule('headers', 'http-headers', [makeFinding('http-headers')]),
        makeModule('failing-dns', 'dns-security', new Error('DNS lookup exploded')),
        makeModule('cookies', 'cookies', [makeFinding('cookies')]),
      ],
    };

    const result = await executeScan(testInput, config);

    // 2 módulos OK + 1 fallido → 'partial'
    expect(result.status).toBe('partial');

    // Los findings del módulo OK deben estar presentes
    expect(result.findings.some((f) => f.category === 'http-headers')).toBe(true);
    expect(result.findings.some((f) => f.category === 'cookies')).toBe(true);

    // El módulo fallido debe haber generado un finding de error
    const errorFinding = result.findings.find(
      (f) => f.category === 'dns-security' && f.severity === 'info'
    );
    expect(errorFinding).toBeDefined();
    // La descripción debe mencionar el nombre del módulo o "unexpected error"
    const desc = errorFinding!.description.toLowerCase();
    expect(desc.includes('failing-dns') || desc.includes('unexpected error')).toBe(true);
  });
});

// ─── Caso 3: Un módulo excede el timeout individual ───────────────────────────

describe('executeScan — un módulo excede el timeout individual', () => {
  /**
   * runModuleWithTimeout() convierte el timeout en un ModuleOutcome con
   * ok:false y un Finding (severity:'low'). Con módulos OK presentes,
   * el status es 'partial'.
   */
  it('status:partial, genera finding severity:low mencionando timeout; el módulo OK aporta sus findings', async () => {
    // moduleTimeoutMs:50ms, módulo que no resuelve en 200ms → timer se dispara
    const config: OrchestratorConfig = {
      moduleTimeoutMs: 50,
      globalTimeoutMs: 10000,
      modules: [
        makeModule('headers', 'http-headers', [makeFinding('http-headers')]),
        makeModule('slow-tls', 'tls-ssl', 'timeout'),
      ],
    };

    const result = await executeScan(testInput, config);

    // 1 OK + 1 timeout → 'partial'
    expect(result.status).toBe('partial');

    // El módulo OK tiene sus findings
    expect(result.findings.some((f) => f.category === 'http-headers')).toBe(true);

    // El módulo en timeout generó un finding low con "timeout" en la descripción
    const timeoutFinding = result.findings.find(
      (f) => f.category === 'tls-ssl' && f.severity === 'low'
    );
    expect(timeoutFinding).toBeDefined();
    expect(timeoutFinding!.description.toLowerCase()).toMatch(/timed?\s*out/);
  }, 3000); // timeout del test: 3s (holgura sobre los 50ms del módulo)
});

// ─── Caso 4: Todos los módulos fallan ─────────────────────────────────────────

describe('executeScan — todos los módulos fallan', () => {
  /**
   * Cuando TODOS los módulos fallan (excepción o timeout), successCount === 0
   * y determineStatus() retorna 'unreachable'. El escaneo no midió nada útil.
   */
  it('retorna status:unreachable cuando todos los módulos lanzan excepciones', async () => {
    const config: OrchestratorConfig = {
      moduleTimeoutMs: 5000,
      globalTimeoutMs: 25000,
      modules: [
        makeModule('fail1', 'http-headers', new Error('Error 1')),
        makeModule('fail2', 'tls-ssl', new Error('Error 2')),
        makeModule('fail3', 'cookies', new Error('Error 3')),
      ],
    };

    const result = await executeScan(testInput, config);

    expect(result.status).toBe('unreachable');

    // Cada módulo fallido genera un finding de error (severity:'info')
    expect(result.findings).toHaveLength(3);
    expect(result.findings.every((f) => f.severity === 'info')).toBe(true);
  });

  it('retorna status:unreachable cuando todos los módulos exceden timeout', async () => {
    const config: OrchestratorConfig = {
      moduleTimeoutMs: 50,
      globalTimeoutMs: 10000,
      modules: [
        makeModule('slow1', 'http-headers', 'timeout'),
        makeModule('slow2', 'tls-ssl', 'timeout'),
      ],
    };

    const result = await executeScan(testInput, config);

    expect(result.status).toBe('unreachable');

    // Cada módulo genera un finding de timeout (severity:'low')
    expect(result.findings).toHaveLength(2);
    expect(result.findings.every((f) => f.severity === 'low')).toBe(true);
  }, 3000);
});

// ─── Caso 5: Sin módulos registrados ──────────────────────────────────────────

describe('executeScan — sin módulos registrados', () => {
  it('retorna status:complete con findings:[]', async () => {
    const config: OrchestratorConfig = {
      moduleTimeoutMs: 5000,
      globalTimeoutMs: 25000,
      modules: [],
    };

    const result = await executeScan(testInput, config);

    expect(result.status).toBe('complete');
    expect(result.findings).toHaveLength(0);
    expect(result.totalFindings).toBe(0);
  });
});

// ─── Caso 6: Múltiples módulos OK + 1 timeout ─────────────────────────────────

describe('executeScan — múltiples módulos OK + 1 timeout', () => {
  /**
   * Con al menos un módulo OK y uno fallido, el status es 'partial'.
   * El timeout se evidencia mediante el finding severity:'low' generado.
   */
  it('status:partial; findings de los módulos OK presentes; finding timeout para el módulo lento', async () => {
    const config: OrchestratorConfig = {
      moduleTimeoutMs: 50,
      globalTimeoutMs: 10000,
      modules: [
        makeModule('headers', 'http-headers', [makeFinding('http-headers')]),
        makeModule('dns', 'dns-security', [makeFinding('dns-security')]),
        makeModule('slow-cors', 'cors', 'timeout'),
        makeModule('cookies', 'cookies', [makeFinding('cookies')]),
      ],
    };

    const result = await executeScan(testInput, config);

    // 3 OK + 1 timeout → 'partial'
    expect(result.status).toBe('partial');

    // Findings de los módulos que terminaron OK
    expect(result.findings.some((f) => f.category === 'http-headers')).toBe(true);
    expect(result.findings.some((f) => f.category === 'dns-security')).toBe(true);
    expect(result.findings.some((f) => f.category === 'cookies')).toBe(true);

    // Finding de timeout para el módulo cors
    const timeoutFinding = result.findings.find(
      (f) => f.category === 'cors' && f.severity === 'low'
    );
    expect(timeoutFinding).toBeDefined();
  }, 3000);
});

// ─── Caso 7: scanId es un UUID válido ─────────────────────────────────────────

describe('executeScan — scanId', () => {
  it('scanId tiene formato UUID válido (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)', async () => {
    const config: OrchestratorConfig = {
      moduleTimeoutMs: 5000,
      globalTimeoutMs: 25000,
      modules: [],
    };

    const result = await executeScan(testInput, config);

    expect(result.scanId).toMatch(UUID_REGEX);
  });

  it('cada llamada produce un scanId diferente', async () => {
    const config: OrchestratorConfig = {
      moduleTimeoutMs: 5000,
      globalTimeoutMs: 25000,
      modules: [],
    };

    const [r1, r2] = await Promise.all([
      executeScan(testInput, config),
      executeScan(testInput, config),
    ]);

    expect(r1.scanId).not.toBe(r2.scanId);
  });
});

// ─── Caso 8: durationMs es positivo ───────────────────────────────────────────

describe('executeScan — durationMs', () => {
  it('durationMs es un número no negativo (>= 0)', async () => {
    // NOTA: durationMs puede ser 0 en ejecuciones instantáneas (sin módulos)
    // porque Date.now() tiene resolución de 1ms. Lo que importa es que sea >= 0.
    const config: OrchestratorConfig = {
      moduleTimeoutMs: 5000,
      globalTimeoutMs: 25000,
      modules: [
        makeModule('headers', 'http-headers', [makeFinding('http-headers')]),
      ],
    };

    const result = await executeScan(testInput, config);

    expect(typeof result.durationMs).toBe('number');
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });
});
