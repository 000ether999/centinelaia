/**
 * Módulo de correlación determinista (sin IA) entre hallazgos de distintas
 * fuentes (scanner propio + logs de Nmap traducidos + CVEs del enricher +
 * logs de autenticación auth.log).
 *
 * Arquitectura de registry extensible:
 * Cada regla implementa `CorrelationRule` y se registra en el array `RULES`.
 * El dispatcher `correlateFindings` itera el registry y acumula resultados,
 * manteniendo el try/catch fail-open global.
 *
 * Reglas implementadas:
 *  1. port-with-tls      — servicio HTTPS/SSL/TLS en Nmap ↔ hallazgo TLS/SSL
 *  2. version-with-cves  — versión de servicio en Nmap ↔ CVE del enricher
 *  3. authlog-ssh-exposure — fuerza bruta SSH en auth.log ↔ puerto SSH abierto
 *  4. cors-csp-amplification — CORS permisivo ↔ CSP débil/ausente
 *  5. cert-hsts-gap      — problema de cadena TLS ↔ HSTS débil/ausente
 */

import type { Finding, FindingSeverity } from '../scanner/modules/types.js';

// ---------------------------------------------------------------------------
// Constantes y utilidades compartidas
// ---------------------------------------------------------------------------

/** Longitud máxima del fragmento citado dentro de una descripción de correlación. */
const QUOTE_MAX_LENGTH = 150;

/** Límite de caracteres del campo description (contrato del AI Engine). */
const MAX_DESCRIPTION_LENGTH = 500;

/** Orden de severidad para elegir el hallazgo TLS más relevante a citar. */
const SEVERITY_ORDER: Record<FindingSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** Patrón de servicios relacionados con TLS/SSL/HTTPS en la columna SERVICE de Nmap. */
const HTTPS_SERVICE_PATTERN = /https|ssl|tls/i;

/** Fila de servicio de Nmap reconstruida desde un Finding 'port-service'. */
interface DetectedNmapRow {
  port: number;
  service: string;
  version: string;
}

/** Trunca un texto a una longitud máxima, agregando "..." si fue recortado. */
function truncate(text: string, maxLength: number): string {
  return text.length <= maxLength ? text : `${text.slice(0, maxLength - 3)}...`;
}

/** Recorta una descripción de correlación al límite del contrato del AI Engine. */
function clampDescription(text: string): string {
  return truncate(text, MAX_DESCRIPTION_LENGTH);
}

/**
 * Intenta reconstruir una fila de servicio de Nmap desde un Finding.
 * Los findings derivados de Nmap (ver `nmap-parser.ts`) tienen
 * category 'port-service' y serviceInfo con port/service/version.
 * Retorna null si el finding no proviene de Nmap.
 */
function tryParseNmapRow(finding: Finding): DetectedNmapRow | null {
  // Camino principal: findings 'port-service' con serviceInfo estructurado
  if (finding.category === 'port-service' && finding.serviceInfo) {
    const { port, service, version } = finding.serviceInfo;
    if (typeof port !== 'number' || typeof service !== 'string' || service.trim() === '') {
      return null;
    }
    return {
      port,
      service,
      version: typeof version === 'string' ? version.trim() : '',
    };
  }

  return null;
}

/**
 * Elige el hallazgo TLS/SSL más relevante (mayor severidad) del escaneo.
 * Prioriza hallazgos que no sean puramente informativos.
 */
function pickMostRelevantTlsFinding(findings: Finding[]): Finding | null {
  const tlsFindings = findings.filter((f) => f.category === 'tls-ssl');
  if (tlsFindings.length === 0) return null;

  const nonInfo = tlsFindings.filter((f) => f.severity !== 'info');
  const pool = nonInfo.length > 0 ? nonInfo : tlsFindings;

  return pool.slice().sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])[0]!;
}

// ---------------------------------------------------------------------------
// Interfaz del registry extensible
// ---------------------------------------------------------------------------

/**
 * Interfaz que toda regla de correlación debe implementar.
 * Cada regla recibe el conjunto completo de findings y retorna
 * los findings de correlación que genera (puede ser []).
 */
interface CorrelationRule {
  name: string;
  run(findings: Finding[]): Finding[];
}

// ---------------------------------------------------------------------------
// Regla 1: port-with-tls (migrada desde correlatePortWithTls)
// ---------------------------------------------------------------------------

/**
 * Enlaza un servicio HTTPS/TLS/SSL detectado en Nmap con los hallazgos
 * TLS/SSL del escaneo del mismo objetivo.
 * Emite como máximo un finding de correlación por puerto detectado.
 */
const portWithTlsRule: CorrelationRule = {
  name: 'port-with-tls',
  run(findings: Finding[]): Finding[] {
    // Calcular nmapRows internamente desde el conjunto completo de findings
    const nmapRows = findings
      .map((f) => tryParseNmapRow(f))
      .filter((row): row is DetectedNmapRow => row !== null);

    const correlations: Finding[] = [];
    const tlsFinding = pickMostRelevantTlsFinding(findings);
    if (!tlsFinding) return correlations;

    const correlatedPorts = new Set<number>();

    for (const row of nmapRows) {
      if (!HTTPS_SERVICE_PATTERN.test(row.service)) continue;
      if (correlatedPorts.has(row.port)) continue;
      correlatedPorts.add(row.port);

      const quote = truncate(tlsFinding.description, QUOTE_MAX_LENGTH);
      const description = clampDescription(
        `El servicio ${row.service.toUpperCase()} detectado en el log (puerto ${row.port}) coincide ` +
          `con una debilidad TLS del escaneo: "${quote}"`,
      );

      correlations.push({
        category: 'correlation',
        severity: tlsFinding.severity,
        rawValue: `port:${row.port}/${row.service} ↔ tls-ssl`,
        description,
        correlationInfo: {
          rule: 'port-with-tls',
          emergent: false,
        },
      });
    }

    return correlations;
  },
};

// ---------------------------------------------------------------------------
// Regla 2: version-with-cves (migrada desde correlateVersionWithCves)
// ---------------------------------------------------------------------------

/**
 * Enlaza un servicio con versión detectada en Nmap con un CVE generado por
 * el cve-enricher para ese mismo producto+versión.
 * Camino principal: compara por vulnInfo.product/version (campos estructurados).
 * Fallback: substring en la descripción (retrocompatibilidad con findings antiguos).
 */
const versionWithCvesRule: CorrelationRule = {
  name: 'version-with-cves',
  run(findings: Finding[]): Finding[] {
    // Calcular nmapRows internamente desde el conjunto completo de findings
    const nmapRows = findings
      .map((f) => tryParseNmapRow(f))
      .filter((row): row is DetectedNmapRow => row !== null);

    const correlations: Finding[] = [];
    const cveFindings = findings.filter((f) => f.category === 'known-vulnerabilities');
    if (cveFindings.length === 0) return correlations;

    for (const row of nmapRows) {
      if (!row.version) continue;

      for (const cve of cveFindings) {
        let matches = false;

        // Camino principal: comparación por campos estructurados vulnInfo.product/version
        if (cve.vulnInfo?.product && cve.vulnInfo?.version) {
          const cveVersion = cve.vulnInfo.version.trim().toLowerCase();
          const cveProduct = cve.vulnInfo.product.trim().toLowerCase();
          const rowVersion = row.version.trim().toLowerCase();

          // Coincidencia directa de versión
          if (cveVersion === rowVersion) {
            matches = true;
          }
          // Producto contenido en el campo version de la fila Nmap Y la versión
          // del CVE también está contenida (cubre servicios genéricos donde
          // "nginx 1.18.0" vive en row.version y el CVE apunta a nginx/1.18.0)
          else if (rowVersion.includes(cveProduct) && rowVersion.includes(cveVersion)) {
            matches = true;
          }
        } else {
          // Fallback de substring para CVEs sin vulnInfo.product/version
          // (retrocompatibilidad con findings antiguos persistidos)
          const searchPatterns: string[] = [];
          const servicePrefix = `${row.service.toLowerCase()} ${row.version}:`.toLowerCase();
          searchPatterns.push(servicePrefix);

          const genericServices = new Set(['http', 'https', 'ssl', 'tls', 'unknown']);
          if (genericServices.has(row.service.toLowerCase()) && row.version.includes(' ')) {
            searchPatterns.push(`${row.version.toLowerCase()}:`);
          }

          const descLower = cve.description.toLowerCase();
          matches = searchPatterns.some((pattern) => descLower.includes(pattern));
        }

        if (!matches) continue;

        const cveId = cve.rawValue?.split(' ')[0] ?? 'un CVE conocido';
        const description = clampDescription(
          `El puerto ${row.port} abierto (${row.service}) expone la versión "${row.version}", ` +
            `afectada por ${cveId} detectado en el enriquecimiento de vulnerabilidades.`,
        );

        correlations.push({
          category: 'correlation',
          severity: cve.severity,
          rawValue: `port:${row.port} ↔ ${cveId}`,
          description,
          correlationInfo: {
            rule: 'version-with-cves',
            emergent: false,
          },
        });
      }
    }

    return correlations;
  },
};

// ---------------------------------------------------------------------------
// Regla 3: authlog-ssh-exposure (nueva)
// ---------------------------------------------------------------------------

/** Regex para extraer la IP del rawValue de un finding log-analysis. */
const AUTH_LOG_IP_PATTERN = /IP=([^\s]+)/;

/**
 * Correlaciona intentos de fuerza bruta SSH (auth.log) con puertos SSH
 * abiertos detectados por Nmap. Emite un finding por cada par (IP, puerto)
 * único, con dedup estricto.
 */
const authlogSshExposureRule: CorrelationRule = {
  name: 'authlog-ssh-exposure',
  run(findings: Finding[]): Finding[] {
    // Buscar findings de fuerza bruta: log-analysis con failed_attempts en rawValue
    const bruteForceFindings = findings.filter(
      (f) =>
        f.category === 'log-analysis' &&
        typeof f.rawValue === 'string' &&
        f.rawValue.includes('failed_attempts'),
    );
    if (bruteForceFindings.length === 0) return [];

    // Buscar puertos SSH abiertos en findings port-service
    const sshPortFindings = findings.filter(
      (f) =>
        f.category === 'port-service' &&
        f.serviceInfo != null &&
        /^ssh/i.test(f.serviceInfo.service),
    );
    if (sshPortFindings.length === 0) return [];

    const correlations: Finding[] = [];
    // Conjunto de dedup: "ip:port"
    const seen = new Set<string>();

    for (const bruteForce of bruteForceFindings) {
      // Extraer IP del rawValue (fail-open: omitir si no parseable)
      const ipMatch = AUTH_LOG_IP_PATTERN.exec(bruteForce.rawValue ?? '');
      if (!ipMatch || !ipMatch[1]) continue;
      const attackerIp = ipMatch[1];

      for (const sshFinding of sshPortFindings) {
        const port = sshFinding.serviceInfo!.port;
        const dedupKey = `${attackerIp}:${port}`;
        if (seen.has(dedupKey)) continue;
        seen.add(dedupKey);

        const description = clampDescription(
          `IP atacante ${attackerIp} realizó intentos de fuerza bruta SSH (auth.log) ` +
            `y el puerto ${port}/ssh está expuesto públicamente (Nmap). ` +
            `Riesgo de compromiso de credenciales: un atacante persistente podría ` +
            `lograr acceso no autorizado al servidor.`,
        );

        correlations.push({
          category: 'correlation',
          severity: 'high',
          rawValue: `auth:IP=${attackerIp} ↔ port:${port}/ssh`,
          description,
          correlationInfo: {
            rule: 'authlog-ssh-exposure',
            emergent: true,
          },
        });
      }
    }

    return correlations;
  },
};

// ---------------------------------------------------------------------------
// Regla 4: cors-csp-amplification (nueva)
// ---------------------------------------------------------------------------

/**
 * Correlaciona CORS permisivo (high/critical) con CSP débil o ausente
 * (high/medium), amplificando el riesgo de XSS/data-exfiltration.
 * Emite como máximo un finding de correlación.
 */
const corsCspAmplificationRule: CorrelationRule = {
  name: 'cors-csp-amplification',
  run(findings: Finding[]): Finding[] {
    // Necesita al menos un finding CORS con severidad high o critical
    const hasDangerousCors = findings.some(
      (f) =>
        f.category === 'cors' && (f.severity === 'high' || f.severity === 'critical'),
    );
    if (!hasDangerousCors) return [];

    // Necesita al menos un finding http-headers sobre CSP con severidad high o medium
    const hasWeakCsp = findings.some(
      (f) =>
        f.category === 'http-headers' &&
        (f.severity === 'high' || f.severity === 'medium') &&
        f.description.includes('Content-Security-Policy'),
    );
    if (!hasWeakCsp) return [];

    const description = clampDescription(
      'CORS permisivo (high/critical) combinado con Content-Security-Policy débil o ausente ' +
        'amplifica significativamente el riesgo de XSS y data-exfiltration: un atacante puede ' +
        'hacer que el navegador de la víctima envíe datos sensibles a un origen externo sin ' +
        'que la política CSP lo bloquee.',
    );

    return [
      {
        category: 'correlation',
        severity: 'high',
        rawValue: 'cors-high ↔ csp-weak',
        description,
        correlationInfo: {
          rule: 'cors-csp-amplification',
          emergent: true,
        },
      },
    ];
  },
};

// ---------------------------------------------------------------------------
// Regla 5: cert-hsts-gap (nueva)
// ---------------------------------------------------------------------------

/** Patrones en la descripción de un finding TLS que indican problema de cadena/confianza. */
const TLS_CHAIN_PATTERN = /expired|self-signed|not trusted|chain/i;

/**
 * Correlaciona un problema de cadena/confianza TLS (critical/high) con
 * HSTS débil o ausente (high/medium), lo que permite downgrade HTTP.
 * Emite como máximo un finding de correlación.
 */
const certHstsGapRule: CorrelationRule = {
  name: 'cert-hsts-gap',
  run(findings: Finding[]): Finding[] {
    // Necesita al menos un finding TLS con problema de cadena/confianza (critical o high)
    const hasTlsChainIssue = findings.some(
      (f) =>
        f.category === 'tls-ssl' &&
        (f.severity === 'critical' || f.severity === 'high') &&
        TLS_CHAIN_PATTERN.test(f.description),
    );
    if (!hasTlsChainIssue) return [];

    // Necesita al menos un finding http-headers sobre HSTS con severidad high o medium
    const hasWeakHsts = findings.some(
      (f) =>
        f.category === 'http-headers' &&
        (f.severity === 'high' || f.severity === 'medium') &&
        f.description.includes('Strict-Transport-Security'),
    );
    if (!hasWeakHsts) return [];

    const description = clampDescription(
      'Un certificado TLS con problema de cadena o confianza (expirado, auto-firmado, ' +
        'cadena rota) combinado con HSTS débil o ausente permite un ataque de downgrade HTTP: ' +
        'el navegador no fuerza HTTPS y el usuario puede conectarse por HTTP plano, ' +
        'exponiendo credenciales y sesiones al tráfico en claro.',
    );

    return [
      {
        category: 'correlation',
        severity: 'high',
        rawValue: 'tls-chain-issue ↔ hsts-missing',
        description,
        correlationInfo: {
          rule: 'cert-hsts-gap',
          emergent: true,
        },
      },
    ];
  },
};

// ---------------------------------------------------------------------------
// Registry de reglas
// ---------------------------------------------------------------------------

/**
 * Registry de todas las reglas de correlación activas.
 * Para agregar una nueva regla: implementa CorrelationRule y añádela aquí.
 */
const RULES: CorrelationRule[] = [
  portWithTlsRule,
  versionWithCvesRule,
  authlogSshExposureRule,
  corsCspAmplificationRule,
  certHstsGapRule,
];

// ---------------------------------------------------------------------------
// API pública
// ---------------------------------------------------------------------------

/**
 * Genera findings de correlación deterministas (sin IA) a partir del conjunto
 * combinado de hallazgos (scanner + Nmap + CVE + auth.log). Itera el registry
 * de reglas y acumula resultados, con aislamiento de fallos por regla.
 *
 * Es puramente defensivo: si no hay coincidencias entre fuentes, retorna un
 * arreglo vacío sin romper el flujo del caller (nunca lanza excepciones).
 * Una regla que lance no descarta las correlaciones de las demás.
 */
export function correlateFindings(findings: Finding[]): Finding[] {
  try {
    const result: Finding[] = [];
    for (const rule of RULES) {
      try {
        const ruleFindings = rule.run(findings);
        result.push(...ruleFindings);
      } catch (ruleError: unknown) {
        // Aislamiento por regla: una regla que falle no descarta el resto
        console.warn(
          `[correlate-findings] Error en regla "${rule.name}", se omite:`,
          ruleError instanceof Error ? ruleError.message : ruleError,
        );
      }
    }
    return result;
  } catch (error: unknown) {
    // Red de seguridad final: fallo del propio bucle/infraestructura
    console.warn(
      '[correlate-findings] Error durante la correlación, se omite sin romper el flujo:',
      error instanceof Error ? error.message : error,
    );
    return [];
  }
}
