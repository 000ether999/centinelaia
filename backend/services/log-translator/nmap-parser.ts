import type { Finding, FindingSeverity } from '../scanner/modules/types.js';

/** Fila de servicio normalizada desde la salida estándar de Nmap. */
export interface NmapServiceRow {
  port: number;
  protocol: string;
  state: string;
  service: string;
  version: string;
}

const SERVICE_ROW_PATTERN = /^(\d{1,5})\/(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*))?$/;

// ─── Clasificación de severidad por servicio expuesto (Ola 12) ───────────────
// Refleja el nivel de EXPOSICIÓN del servicio, no una vulnerabilidad confirmada.
// No afirma que el servicio carezca de autenticación (no lo comprobamos).

/**
 * Servicios históricamente expuestos sin autenticación por defecto.
 * Un redis/elasticsearch/memcached abierto es entrada directa al sistema.
 */
const HIGH_SEVERITY_SERVICES = new Set([
  'redis', 'mongodb', 'elasticsearch', 'memcached',
  'cassandra', 'couchdb', 'kibana', 'zookeeper',
]);

/**
 * Servicios de administración, acceso remoto y bases de datos con autenticación
 * por defecto pero con superficie de ataque significativa.
 */
const MEDIUM_SEVERITY_SERVICES = new Set([
  'mysql', 'postgresql', 'mssql', 'oracle',
  'ssh', 'telnet', 'rdp', 'ms-wbt-server', 'vnc',
  'ftp', 'smb', 'microsoft-ds', 'netbios-ssn',
  'ldap', 'rpcbind', 'docker', 'kubernetes',
]);

/**
 * Determina la severidad de un servicio abierto según su tipo.
 * Compara el nombre del servicio en minúsculas y de forma tolerante
 * (coincide si el servicio empieza por alguno de los nombres conocidos).
 */
function getServiceSeverity(service: string): FindingSeverity {
  const svc = service.toLowerCase();

  // Coincidencia exacta primero
  if (HIGH_SEVERITY_SERVICES.has(svc)) return 'high';
  if (MEDIUM_SEVERITY_SERVICES.has(svc)) return 'medium';

  // Coincidencia tolerante: el servicio empieza por alguno de los conocidos
  for (const known of HIGH_SEVERITY_SERVICES) {
    if (svc.startsWith(known)) return 'high';
  }
  for (const known of MEDIUM_SEVERITY_SERVICES) {
    if (svc.startsWith(known)) return 'medium';
  }

  return 'low';
}

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

  // Severidad: info para no-open, clasificación por servicio para open
  const severity: FindingSeverity = row.state === 'open'
    ? getServiceSeverity(row.service)
    : 'info';

  return {
    category: 'port-service',
    severity,
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
