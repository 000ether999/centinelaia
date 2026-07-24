import type { Finding } from '../scanner/modules/types.js';

/** Fila de servicio normalizada desde la salida estándar de Nmap. */
export interface NmapServiceRow {
  port: number;
  protocol: string;
  state: string;
  service: string;
  version: string;
}

const SERVICE_ROW_PATTERN = /^(\d{1,5})\/(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*))?$/;

/** Extrae únicamente las filas de la tabla PORT/STATE/SERVICE/VERSION. */
export function parseNmapServiceRows(nmapOutput: string): NmapServiceRow[] {
  const rows: NmapServiceRow[] = [];

  for (const sourceLine of nmapOutput.split(/\r?\n/)) {
    const match = sourceLine.trim().match(SERVICE_ROW_PATTERN);
    if (!match) continue;

    const port = Number(match[1]);
    if (!Number.isInteger(port) || port < 0 || port > 65535) continue;

    rows.push({
      port,
      protocol: match[2]!,
      state: match[3]!,
      service: match[4]!,
      version: match[5]?.trim() ?? '',
    });
  }

  return rows;
}

/** Convierte una fila normalizada al contrato compartido con el AI Engine. */
export function convertNmapServiceRowToFinding(row: NmapServiceRow): Finding {
  const versionDetail = row.version
    ? ` con la versión detectada "${row.version}"`
    : ' sin una versión identificada';
  const description =
    `El puerto ${row.port}/${row.protocol} está en estado "${row.state}" y corresponde ` +
    `al servicio "${row.service}"${versionDetail}.`;

  // rawValue legible (no JSON) para consumo humano
  const rawValue = `${row.port}/${row.protocol} ${row.service} ${row.version}`.trim();

  return {
    category: 'port-service',
    severity: row.state === 'open' ? 'low' : 'info',
    rawValue,
    description: description.length <= 500 ? description : `${description.slice(0, 497)}...`,
    serviceInfo: {
      port: row.port,
      protocol: row.protocol,
      state: row.state,
      service: row.service,
      version: row.version,
    },
  };
}

/** Traduce una salida completa de Nmap a hallazgos estructurados. */
export function translateNmapOutput(nmapOutput: string): Finding[] {
  return parseNmapServiceRows(nmapOutput).map(convertNmapServiceRowToFinding);
}
