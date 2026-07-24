/**
 * Módulo de correlación determinista (sin IA) entre hallazgos de distintas
 * fuentes (scanner propio + logs de Nmap traducidos + CVEs del enricher).
 *
 * Reglas implementadas:
 *  1. Puerto/servicio: un servicio HTTPS/SSL/TLS detectado en el log de Nmap
 *     coincide con hallazgos TLS/SSL del escaneo del mismo objetivo.
 *  2. Versión + CVE: un servicio con versión detectada en Nmap coincide con
 *     un CVE generado por el cve-enricher para esa misma versión.
 *
 * Es puramente defensivo: si no hay coincidencias entre fuentes, retorna un
 * arreglo vacío y nunca lanza excepciones (fail-open, igual que cve-enricher).
 */

import type { Finding, FindingSeverity } from '../scanner/modules/types.js';

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

/** Fila de servicio de Nmap reconstruida desde un Finding 'server-fingerprint'. */
interface DetectedNmapRow {
  port: number;
  service: string;
  version: string;
}

/**
 * Intenta reconstruir una fila de servicio de Nmap desde un Finding.
 * Los findings derivados de Nmap (ver `nmap-parser.ts`) tienen
 * category 'server-fingerprint' y rawValue como JSON con port/service/version.
 * Retorna null si el finding no proviene de Nmap (ej. headers del fingerprinter).
 */
function tryParseNmapRow(finding: Finding): DetectedNmapRow | null {
  if (finding.category !== 'server-fingerprint' || !finding.rawValue) return null;

  try {
    const parsed = JSON.parse(finding.rawValue) as Record<string, unknown>;
    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      typeof parsed.port !== 'number' ||
      typeof parsed.service !== 'string' ||
      parsed.service.trim() === ''
    ) {
      return null;
    }

    return {
      port: parsed.port,
      service: parsed.service,
      version: typeof parsed.version === 'string' ? parsed.version.trim() : '',
    };
  } catch {
    // rawValue no es JSON (ej. "server: nginx/1.18.0" del fingerprinter) → no es fila Nmap
    return null;
  }
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

/**
 * Regla 1: enlaza un servicio HTTPS/TLS/SSL detectado en Nmap con los
 * hallazgos TLS/SSL del escaneo del mismo objetivo.
 * Emite como máximo un finding de correlación por puerto detectado.
 */
function correlatePortWithTls(nmapRows: DetectedNmapRow[], allFindings: Finding[]): Finding[] {
  const correlations: Finding[] = [];
  const tlsFinding = pickMostRelevantTlsFinding(allFindings);
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
    });
  }

  return correlations;
}

/**
 * Regla 2: enlaza un servicio con versión detectada en Nmap con un CVE
 * generado por el cve-enricher para ese mismo producto+versión.
 * El cve-enricher construye la descripción del CVE como
 * "{product} {version}: {resumen}", donde product/version provienen
 * exactamente del mismo rawValue JSON de la fila de Nmap (ver extract-software.ts),
 * lo que permite un match determinista por prefijo.
 */
function correlateVersionWithCves(nmapRows: DetectedNmapRow[], allFindings: Finding[]): Finding[] {
  const correlations: Finding[] = [];
  const cveFindings = allFindings.filter((f) => f.category === 'known-vulnerabilities');
  if (cveFindings.length === 0) return correlations;

  for (const row of nmapRows) {
    if (!row.version) continue;

    const prefix = `${row.service.toLowerCase()} ${row.version}:`.toLowerCase();

    for (const cve of cveFindings) {
      if (!cve.description.toLowerCase().startsWith(prefix)) continue;

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
      });
    }
  }

  return correlations;
}

/**
 * Genera findings de correlación deterministas (sin IA) a partir del conjunto
 * combinado de hallazgos (scanner + Nmap + CVE). Es puramente defensivo:
 * si no hay coincidencias entre fuentes, retorna un arreglo vacío sin romper
 * el flujo del caller (nunca lanza excepciones).
 */
export function correlateFindings(findings: Finding[]): Finding[] {
  try {
    const nmapRows = findings
      .map((finding) => tryParseNmapRow(finding))
      .filter((row): row is DetectedNmapRow => row !== null);

    if (nmapRows.length === 0) return [];

    return [
      ...correlatePortWithTls(nmapRows, findings),
      ...correlateVersionWithCves(nmapRows, findings),
    ];
  } catch (error: unknown) {
    // Fail-open: la correlación es un extra, nunca debe romper el análisis.
    console.warn(
      '[correlate-findings] Error durante la correlación, se omite sin romper el flujo:',
      error instanceof Error ? error.message : error,
    );
    return [];
  }
}
