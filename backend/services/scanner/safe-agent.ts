/**
 * Agente HTTP seguro contra DNS rebinding / TOCTOU.
 *
 * Usa undici (incluido en Node 22) con un lookup personalizado que resuelve
 * DNS y valida TODAS las IPs contra isBlockedIp ANTES de establecer la
 * conexión TCP. Esto elimina la ventana de tiempo entre la validación DNS
 * y la conexión real que un atacante podría explotar rotando registros DNS.
 *
 * Además, incluye un connector personalizado que valida IP literals ANTES
 * de conectar — undici no invoca el lookup para IP literales, solo para
 * dominios, así que la validación en safeLookup no se ejecuta cuando la
 * URL contiene un IP literal directamente (ej. http://[::1]:8099/).
 */

import { Agent, buildConnector } from 'undici';
import { resolve4, resolve6 } from 'node:dns/promises';
import { isIP } from 'node:net';
import { isBlockedIp } from './ip-guard.js';

// ─── Modo laboratorio (CLI local) ───────────────────────────────────────────

/**
 * Determina si el modo laboratorio está habilitado.
 *
 * El modo laboratorio permite escanear targets privados (localhost, IPs RFC1918,
 * etc.) para uso en laboratorios de entrenamiento o auditorías de activos propios.
 *
 * Requiere DOS condiciones simultáneas:
 * 1. La variable CENTINELAIA_ALLOW_PRIVATE_TARGETS === 'true'
 * 2. El proceso NO está corriendo en AWS Lambda (AWS_LAMBDA_FUNCTION_NAME ausente o vacío)
 *
 * El segundo control es el candado que impide desactivar la protección SSRF
 * en el servicio público, incluso si alguien configurara la variable por error
 * en el despliegue. En Lambda siempre se devuelve false.
 */
export function isLabModeEnabled(): boolean {
  const allowPrivate = process.env['CENTINELAIA_ALLOW_PRIVATE_TARGETS'] === 'true';
  const inLambda = !!(process.env['AWS_LAMBDA_FUNCTION_NAME']?.trim());
  return allowPrivate && !inLambda;
}

/** Flag para emitir el warning de modo laboratorio una sola vez por proceso. */
let _labModeWarned = false;

/**
 * Emite un warning una sola vez por proceso indicando que la protección
 * anti-SSRF está desactivada por modo laboratorio.
 */
function warnLabModeOnce(): void {
  if (!_labModeWarned) {
    _labModeWarned = true;
    console.warn(
      '\n⚠️  ═══════════════════════════════════════════════════════════════\n' +
      '⚠️  MODO LABORATORIO ACTIVO: protección anti-SSRF DESACTIVADA.\n' +
      '⚠️  Solo use esta configuración contra activos PROPIOS o de laboratorio.\n' +
      '⚠️  ═══════════════════════════════════════════════════════════════\n',
    );
  }
}

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
 *
 * Si el hostname ya es un literal IP (con o sin brackets), lo valida
 * directamente sin resolver DNS — esto cubre tanto input directo como
 * redirecciones vía Location: a literales IP (defensa en profundidad).
 */
export function safeLookup(hostname: string, callback: LookupCallback): void {
  // Eliminar brackets de IPv6 si están presentes (ej. [::1] → ::1)
  const stripped = hostname.replace(/^\[|\]$/g, '');
  const ipVersion = isIP(stripped);

  // Si es un literal IP, validar directamente sin DNS
  if (ipVersion !== 0) {
    if (isBlockedIp(stripped) && !isLabModeEnabled()) {
      callback(new Error(`Blocked IP literal: ${stripped}`), []);
    } else {
      if (isLabModeEnabled() && isBlockedIp(stripped)) warnLabModeOnce();
      callback(null, [{ address: stripped, family: ipVersion as 4 | 6 }]);
    }
    return;
  }

  // No es un literal IP → resolver DNS normalmente
  Promise.all([
    resolve4(hostname).catch(() => [] as string[]),
    resolve6(hostname).catch(() => [] as string[]),
  ]).then(([ipv4s, ipv6s]) => {
    const allIps = [...ipv4s, ...ipv6s];

    if (allIps.length === 0) {
      callback(new Error(`DNS resolution failed for ${hostname}`), []);
      return;
    }

    // Validar TODAS las IPs resueltas (saltar en modo laboratorio)
    if (!isLabModeEnabled()) {
      for (const ip of allIps) {
        if (isBlockedIp(ip)) {
          callback(
            new Error(`DNS rebinding blocked: ${hostname} resolved to blocked IP ${ip}`),
            [],
          );
          return;
        }
      }
    } else {
      warnLabModeOnce();
    }

    // Retornar la primera IP válida con su familia
    const address = ipv4s.length > 0 ? ipv4s[0]! : ipv6s[0]!;
    const family: 4 | 6 = ipv4s.length > 0 ? 4 : 6;
    callback(null, [{ address, family }]);
  }).catch((err) => {
    callback(err instanceof Error ? err : new Error(String(err)), []);
  });
}

// ─── Connector seguro ────────────────────────────────────────────────────────

/**
 * Connector base con lookup seguro — protege contra DNS rebinding para dominios.
 */
const baseConnector = buildConnector({
  lookup(hostname: string, _opts: unknown, cb: Function) {
    safeLookup(hostname, cb as LookupCallback);
  },
});

/**
 * Connector envolvente que valida IP literales ANTES de conectar.
 * undici no invoca el lookup cuando el host ya es un IP literal,
 * así que esta capa intercepta ese caso y bloquea IPs privadas/reservadas.
 * En modo laboratorio, permite la conexión a IPs privadas.
 */
function safeConnector(options: buildConnector.Options, callback: buildConnector.Callback): void {
  const host = String(options.hostname ?? '').replace(/^\[|\]$/g, '');
  if (isIP(host) !== 0 && isBlockedIp(host)) {
    if (!isLabModeEnabled()) {
      callback(new Error(`Blocked IP literal: ${host}`), null);
      return;
    }
    warnLabModeOnce();
  }
  baseConnector(options, callback);
}

// ─── Creación del agente ─────────────────────────────────────────────────────

/**
 * Crea un Agent de undici con connector personalizado que:
 * 1. Valida IP literales directamente en el connector (pre-conexión)
 * 2. Usa un lookup seguro que valida IPs resueltas por DNS (anti-rebinding)
 */
export function createSafeAgent(): Agent {
  return new Agent({ connect: safeConnector });
}

// ─── Singleton — reutilizable entre módulos y entre invocaciones de Lambda ──

let _safeAgent: Agent | null = null;

export function getSafeAgent(): Agent {
  if (!_safeAgent) {
    _safeAgent = createSafeAgent();
  }
  return _safeAgent;
}
