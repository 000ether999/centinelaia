/**
 * Agente HTTP seguro contra DNS rebinding / TOCTOU.
 *
 * Usa undici (incluido en Node 22) con un lookup personalizado que resuelve
 * DNS y valida TODAS las IPs contra isBlockedIp ANTES de establecer la
 * conexión TCP. Esto elimina la ventana de tiempo entre la validación DNS
 * y la conexión real que un atacante podría explotar rotando registros DNS.
 */

import { Agent } from 'undici';
import { resolve4, resolve6 } from 'node:dns/promises';
import { isBlockedIp } from './ip-guard.js';

/** Tipo del callback estándar de lookup (compatible con undici/net). */
export type LookupCallback = (
  err: Error | null,
  result: Array<{ address: string; family: 4 | 6 }>,
) => void;

/**
 * Lógica de lookup segura extraída para ser testeable de forma unitaria.
 * Resuelve DNS para hostname, valida IPs contra isBlockedIp y llama al
 * callback con la primera IP pública válida o con un error si alguna IP
 * es privada o la resolución falla.
 */
export function safeLookup(hostname: string, callback: LookupCallback): void {
  Promise.all([
    resolve4(hostname).catch(() => [] as string[]),
    resolve6(hostname).catch(() => [] as string[]),
  ]).then(([ipv4s, ipv6s]) => {
    const allIps = [...ipv4s, ...ipv6s];

    if (allIps.length === 0) {
      callback(new Error(`DNS resolution failed for ${hostname}`), []);
      return;
    }

    // Validar TODAS las IPs resueltas
    for (const ip of allIps) {
      if (isBlockedIp(ip)) {
        callback(
          new Error(`DNS rebinding blocked: ${hostname} resolved to blocked IP ${ip}`),
          [],
        );
        return;
      }
    }

    // Retornar la primera IP válida con su familia
    const address = ipv4s.length > 0 ? ipv4s[0]! : ipv6s[0]!;
    const family: 4 | 6 = ipv4s.length > 0 ? 4 : 6;
    callback(null, [{ address, family }]);
  }).catch((err) => {
    callback(err instanceof Error ? err : new Error(String(err)), []);
  });
}

/**
 * Crea un Agent de undici con lookup personalizado que valida IPs resueltas.
 * Cada conexión pasa por el lookup → si el DNS devuelve una IP bloqueada,
 * la conexión se rechaza antes de que se abra el socket.
 */
export function createSafeAgent(): Agent {
  return new Agent({
    connect: {
      // Lookup personalizado que intercepta la resolución DNS
      lookup(hostname: string, _options: unknown, callback: Function) {
        safeLookup(hostname, callback as LookupCallback);
      },
    },
  });
}

// ─── Singleton — reutilizable entre módulos y entre invocaciones de Lambda ──

let _safeAgent: Agent | null = null;

export function getSafeAgent(): Agent {
  if (!_safeAgent) {
    _safeAgent = createSafeAgent();
  }
  return _safeAgent;
}
