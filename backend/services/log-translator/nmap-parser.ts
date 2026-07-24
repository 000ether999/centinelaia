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

  return {
    category: 'server-fingerprint',
    severity: row.state === 'open' ? 'low' : 'info',
    rawValue: JSON.stringify(row),
    description: description.length <= 500 ? description : `${description.slice(0, 497)}...`,
  };
}

/** Traduce una salida completa de Nmap a hallazgos estructurados. */
export function translateNmapOutput(nmapOutput: string): Finding[] {
  return parseNmapServiceRows(nmapOutput).map(convertNmapServiceRowToFinding);
}
