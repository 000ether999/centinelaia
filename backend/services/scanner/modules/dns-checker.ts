/**
 * Módulo de verificación de registros DNS de seguridad.
 *
 * Consulta registros TXT del dominio para verificar la presencia y configuración
 * de SPF, DMARC y DKIM. Estas verificaciones permiten detectar configuraciones
 * que facilitan la suplantación de identidad por correo electrónico.
 *
 * Requisitos: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8, 1.5, 12.1
 */

import dns from 'node:dns/promises';
import type { Finding, ScanModule, ScanModuleInput } from './types.js';

// ─── Constantes ──────────────────────────────────────────────────────────────

/** Selectores DKIM comunes a verificar */
const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2'] as const;

/** Timeout por consulta DNS individual (ms) */
const DNS_QUERY_TIMEOUT_MS = 5_000;

/** Códigos de error DNS que significan "registro no existe" (no son errores reales) */
const DNS_NOT_FOUND_CODES = ['ENOTFOUND', 'ENODATA', 'NXDOMAIN'];

// ─── Implementación ──────────────────────────────────────────────────────────

/**
 * Factory que crea el módulo DNS Checker.
 * Retorna un ScanModule listo para ser registrado en el orquestador.
 */
export function createDnsChecker(): ScanModule {
  return {
    name: 'DNS Checker',
    category: 'dns-security',

    async run(input: ScanModuleInput): Promise<Finding[]> {
      // Req 1.5: DNS no aplica para IPs directas
      if (input.isIpAddress) {
        return [
          {
            category: 'dns-security',
            severity: 'info',
            rawValue: null,
            description: 'Las verificaciones DNS no aplican para objetivos que son direcciones IP directas',
          },
        ];
      }

      const domain = input.targetDomain;
      if (!domain) {
        return [
          {
            category: 'dns-security',
            severity: 'info',
            rawValue: null,
            description: 'No se pudo determinar el dominio del objetivo para verificaciones DNS',
          },
        ];
      }

      const findings: Finding[] = [];

      // Ejecutar verificaciones en paralelo
      const [spfFindings, dmarcFindings, dkimFindings] = await Promise.all([
        checkSpf(domain),
        checkDmarc(domain),
        checkDkim(domain),
      ]);

      findings.push(...spfFindings, ...dmarcFindings, ...dkimFindings);

      return findings;
    },
  };
}

// ─── Verificación SPF ────────────────────────────────────────────────────────

/**
 * Verifica la presencia y configuración del registro SPF del dominio.
 * Req 7.1, 7.2, 7.3
 */
async function checkSpf(domain: string): Promise<Finding[]> {
  let txtRecords: string[][];

  try {
    txtRecords = await resolveTxtWithTimeout(domain);
  } catch (error: unknown) {
    if (isDnsNotFoundError(error)) {
      // Sin registros TXT = sin SPF
      return [
        {
          category: 'dns-security',
          severity: 'high',
          rawValue: null,
          description: `El dominio ${domain} no tiene registro SPF configurado, es vulnerable a email spoofing`,
        },
      ];
    }
    // Error de consulta real (timeout, red, etc.)
    return [createDnsErrorFinding(domain, 'SPF', error)];
  }

  // Aplanar los arrays de TXT y buscar el registro SPF
  const allRecords = txtRecords.map((chunks) => chunks.join(''));
  const spfRecord = allRecords.find((record) => record.startsWith('v=spf1'));

  if (!spfRecord) {
    // Req 7.2: Sin registro SPF → high
    return [
      {
        category: 'dns-security',
        severity: 'high',
        rawValue: null,
        description: `El dominio ${domain} no tiene registro SPF configurado, es vulnerable a email spoofing`,
      },
    ];
  }

  // Req 7.3: SPF con +all → high
  if (spfRecord.includes('+all')) {
    return [
      {
        category: 'dns-security',
        severity: 'high',
        rawValue: spfRecord,
        description: `El registro SPF del dominio ${domain} incluye "+all", permitiendo envío desde cualquier origen`,
      },
    ];
  }

  // SPF válido y razonable → info
  return [
    {
      category: 'dns-security',
      severity: 'info',
      rawValue: spfRecord,
      description: `Registro SPF encontrado para ${domain}`,
    },
  ];
}

// ─── Verificación DMARC ──────────────────────────────────────────────────────

/**
 * Verifica la presencia y configuración del registro DMARC del dominio.
 * Req 7.1, 7.4, 7.5
 */
async function checkDmarc(domain: string): Promise<Finding[]> {
  const dmarcDomain = `_dmarc.${domain}`;
  let txtRecords: string[][];

  try {
    txtRecords = await resolveTxtWithTimeout(dmarcDomain);
  } catch (error: unknown) {
    if (isDnsNotFoundError(error)) {
      // Req 7.4: Sin DMARC → high
      return [
        {
          category: 'dns-security',
          severity: 'high',
          rawValue: null,
          description: `El dominio ${domain} no tiene registro DMARC configurado, no hay política de autenticación de correo definida`,
        },
      ];
    }
    return [createDnsErrorFinding(domain, 'DMARC', error)];
  }

  const allRecords = txtRecords.map((chunks) => chunks.join(''));
  const dmarcRecord = allRecords.find((record) => record.startsWith('v=DMARC1'));

  if (!dmarcRecord) {
    // Req 7.4: Sin DMARC → high
    return [
      {
        category: 'dns-security',
        severity: 'high',
        rawValue: null,
        description: `El dominio ${domain} no tiene registro DMARC configurado, no hay política de autenticación de correo definida`,
      },
    ];
  }

  // Extraer la política (p=none, p=quarantine, p=reject)
  const policyMatch = dmarcRecord.match(/;\s*p=([^;\s]+)/i) ?? dmarcRecord.match(/\bp=([^;\s]+)/i);
  const policy = policyMatch?.[1]?.toLowerCase();

  // Req 7.5: DMARC con p=none → medium
  if (policy === 'none') {
    return [
      {
        category: 'dns-security',
        severity: 'medium',
        rawValue: dmarcRecord,
        description: `El dominio ${domain} tiene DMARC con política "none", no rechaza correo no autenticado`,
      },
    ];
  }

  // DMARC con p=quarantine o p=reject → info
  return [
    {
      category: 'dns-security',
      severity: 'info',
      rawValue: dmarcRecord,
      description: `Registro DMARC encontrado para ${domain} con política "${policy ?? 'configurada'}"`,
    },
  ];
}

// ─── Verificación DKIM ───────────────────────────────────────────────────────

/**
 * Verifica la presencia de registros DKIM en selectores comunes.
 * Req 7.1, 7.6, 7.7
 */
async function checkDkim(domain: string): Promise<Finding[]> {
  const results = await Promise.allSettled(
    DKIM_SELECTORS.map((selector) => checkDkimSelector(domain, selector)),
  );

  // Buscar si algún selector tiene DKIM
  for (let i = 0; i < results.length; i++) {
    const result = results[i];
    if (result.status === 'fulfilled' && result.value !== null) {
      // Req 7.6: DKIM encontrado → info
      return [
        {
          category: 'dns-security',
          severity: 'info',
          rawValue: result.value,
          description: `Registro DKIM encontrado para ${domain} en el selector "${DKIM_SELECTORS[i]}"`,
        },
      ];
    }
  }

  // Req 7.7: DKIM no encontrado en ningún selector → medium
  return [
    {
      category: 'dns-security',
      severity: 'medium',
      rawValue: null,
      description: `No se pudo confirmar la presencia de DKIM en ${domain} (selectores verificados: ${DKIM_SELECTORS.join(', ')})`,
    },
  ];
}

/**
 * Verifica un selector DKIM individual.
 * Retorna el registro encontrado o null si no existe.
 */
async function checkDkimSelector(domain: string, selector: string): Promise<string | null> {
  const dkimDomain = `${selector}._domainkey.${domain}`;

  try {
    const txtRecords = await resolveTxtWithTimeout(dkimDomain);
    const allRecords = txtRecords.map((chunks) => chunks.join(''));
    // Cualquier registro TXT en el subdominio DKIM indica presencia
    if (allRecords.length > 0 && allRecords[0].length > 0) {
      return allRecords[0];
    }
    return null;
  } catch (error: unknown) {
    if (isDnsNotFoundError(error)) {
      return null;
    }
    // Para errores reales en DKIM individuales, se ignoran silenciosamente
    // ya que se verifica en múltiples selectores
    return null;
  }
}

// ─── Utilidades DNS ──────────────────────────────────────────────────────────

/**
 * Ejecuta dns.promises.resolveTxt con un timeout de 5 segundos
 * usando AbortController (Req 7.8).
 */
async function resolveTxtWithTimeout(domain: string): Promise<string[][]> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), DNS_QUERY_TIMEOUT_MS);

  try {
    const resolver = new dns.Resolver();
    resolver.setServers(dns.getServers());

    // Node.js dns.Resolver no soporta AbortSignal directamente,
    // usamos Promise.race con un timeout manual
    const result = await Promise.race([
      resolver.resolveTxt(domain),
      abortPromise<string[][]>(controller.signal, domain),
    ]);

    return result;
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Promise que rechaza cuando se dispara el AbortSignal.
 * Se usa para implementar timeout en consultas DNS.
 */
function abortPromise<T>(signal: AbortSignal, domain: string): Promise<T> {
  return new Promise<T>((_, reject) => {
    if (signal.aborted) {
      reject(new DnsTimeoutError(domain));
      return;
    }
    signal.addEventListener(
      'abort',
      () => reject(new DnsTimeoutError(domain)),
      { once: true },
    );
  });
}

/**
 * Error personalizado para timeouts DNS.
 */
class DnsTimeoutError extends Error {
  readonly code = 'ETIMEOUT';
  constructor(domain: string) {
    super(`DNS query timed out for ${domain} after ${DNS_QUERY_TIMEOUT_MS}ms`);
    this.name = 'DnsTimeoutError';
  }
}

/**
 * Verifica si un error DNS indica que el registro no existe
 * (ENOTFOUND/ENODATA/NXDOMAIN) vs un error de red real.
 */
function isDnsNotFoundError(error: unknown): boolean {
  if (error instanceof Error && 'code' in error) {
    const code = (error as NodeJS.ErrnoException).code;
    return code !== undefined && DNS_NOT_FOUND_CODES.includes(code);
  }
  return false;
}

/**
 * Genera un Finding de error para fallos de consulta DNS (timeout, red, etc).
 * Req 7.8: severity "low" para problemas de consulta DNS.
 */
function createDnsErrorFinding(domain: string, recordType: string, error: unknown): Finding {
  const message = error instanceof Error ? error.message : String(error);
  const isTimeout = error instanceof DnsTimeoutError ||
    (error instanceof Error && 'code' in error && (error as NodeJS.ErrnoException).code === 'ETIMEOUT');

  return {
    category: 'dns-security',
    severity: 'low',
    rawValue: null,
    description: isTimeout
      ? `No se pudieron consultar los registros DNS (${recordType}) de ${domain}: timeout de ${DNS_QUERY_TIMEOUT_MS / 1000}s excedido`
      : `No se pudieron consultar los registros DNS (${recordType}) de ${domain}: ${message}`,
  };
}
