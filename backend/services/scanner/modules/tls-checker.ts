/**
 * Módulo de verificación TLS/SSL.
 * Analiza la configuración de protocolos, cipher suites y certificados
 * del servidor objetivo. Usa el módulo nativo `tls` de Node.js para
 * establecer conexiones y extraer información criptográfica.
 *
 * Limitación conocida: Node 20 no puede conectar con SSLv2/SSLv3
 * (deshabilitados en OpenSSL); se reportan como "no testable directamente".
 */

import tls from 'node:tls';
import type { TLSSocket, SecureVersion } from 'node:tls';
import { resolve4, resolve6 } from 'node:dns/promises';
import { isBlockedIp } from '../ip-guard.js';
import type { Finding, ScanModule, ScanModuleInput } from './types.js';

// ─── Constantes ──────────────────────────────────────────────────────────────

/**
 * Versiones de protocolo TLS que Node 20 puede negociar.
 */
const TESTABLE_PROTOCOLS: Array<{ version: SecureVersion; label: string }> = [
  { version: 'TLSv1', label: 'TLS 1.0' },
  { version: 'TLSv1.1', label: 'TLS 1.1' },
  { version: 'TLSv1.2', label: 'TLS 1.2' },
  { version: 'TLSv1.3', label: 'TLS 1.3' },
];

/**
 * Patrones que indican cifrados inseguros.
 */
const INSECURE_CIPHER_PATTERNS = [
  /RC4/i,
  /\bDES\b/i,
  /3DES/i,
  /DES-CBC3/i,
  /MD5/i,
  /EXPORT/i,
  /NULL/i,
  /anon/i,
];

/**
 * Umbral en días para advertir sobre expiración próxima del certificado.
 */
const CERT_EXPIRY_WARNING_DAYS = 30;

/**
 * Puerto TLS/HTTPS por defecto.
 */
const DEFAULT_TLS_PORT = 443;

// ─── Resolución DNS segura ───────────────────────────────────────────────────

/**
 * Resuelve el host via DNS y valida TODAS las IPs contra isBlockedIp.
 * Retorna la primera IP válida y su familia. Lanza si alguna IP es bloqueada
 * o si la resolución falla (prevención de DNS rebinding / TOCTOU).
 */
async function resolveAndValidateHost(host: string): Promise<{ ip: string; family: 4 | 6 }> {
  const ipv4s = await resolve4(host).catch(() => [] as string[]);
  const ipv6s = await resolve6(host).catch(() => [] as string[]);
  const allIps = [...ipv4s, ...ipv6s];

  if (allIps.length === 0) {
    throw new Error(`DNS resolution failed for ${host}`);
  }

  for (const ip of allIps) {
    if (isBlockedIp(ip)) {
      throw new Error(`DNS rebinding blocked: ${host} resolved to blocked IP ${ip}`);
    }
  }

  const ip = ipv4s.length > 0 ? ipv4s[0]! : ipv6s[0]!;
  const family: 4 | 6 = ipv4s.length > 0 ? 4 : 6;
  return { ip, family };
}

// ─── Factory ─────────────────────────────────────────────────────────────────

/**
 * Crea una instancia del módulo TLS Checker.
 */
export function createTlsChecker(): ScanModule {
  return {
    name: 'TLS Checker',
    category: 'tls-ssl',
    async run(input: ScanModuleInput): Promise<Finding[]> {
      const findings: Finding[] = [];
      const { host, port } = extractHostPort(input);

      if (!host) {
        findings.push({
          category: 'tls-ssl',
          severity: 'critical',
          rawValue: null,
          description: 'Cannot determine host for TLS verification from the target URL',
        });
        return findings;
      }

      // Reportar SSLv2/SSLv3 como no testables (limitación de Node 20)
      findings.push(
        createInfoFinding(
          'SSLv2 not testable directly from Node.js 20 (disabled in OpenSSL)',
          'SSLv2',
        ),
        createInfoFinding(
          'SSLv3 not testable directly from Node.js 20 (disabled in OpenSSL)',
          'SSLv3',
        ),
      );

      // Verificar protocolos TLS 1.0-1.3
      const protocolFindings = await checkProtocols(host, port, input.timeoutMs);
      findings.push(...protocolFindings);

      // Verificar cipher suites y certificado usando la mejor conexión disponible
      const connectionFindings = await checkCipherAndCertificate(
        host,
        port,
        input.timeoutMs,
        input.targetDomain,
      );
      findings.push(...connectionFindings);

      return findings;
    },
  };
}

// ─── Funciones internas ──────────────────────────────────────────────────────

/**
 * Extrae host y puerto del targetUrl o targetDomain.
 */
function extractHostPort(input: ScanModuleInput): { host: string | null; port: number } {
  // Intentar extraer de la URL
  try {
    const url = new URL(input.targetUrl);
    const host = input.targetDomain ?? url.hostname;
    const port = url.port ? parseInt(url.port, 10) : DEFAULT_TLS_PORT;
    return { host, port };
  } catch {
    // Fallback al dominio directo
    if (input.targetDomain) {
      return { host: input.targetDomain, port: DEFAULT_TLS_PORT };
    }
    return { host: null, port: DEFAULT_TLS_PORT };
  }
}

/**
 * Intenta conexión TLS con cada versión de protocolo y reporta soporte.
 */
async function checkProtocols(
  host: string,
  port: number,
  timeoutMs: number,
): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Resolver el host UNA VEZ y reutilizar la IP para todas las pruebas de protocolo
  let resolvedIp: string;
  try {
    const resolved = await resolveAndValidateHost(host);
    resolvedIp = resolved.ip;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`[tls-checker] Cannot resolve host for TLS verification:`, message);
    findings.push({
      category: 'tls-ssl',
      severity: 'critical',
      rawValue: null,
      description: `Cannot resolve host for TLS verification: DNS resolution failed`,
    });
    return findings;
  }

  for (const { version, label } of TESTABLE_PROTOCOLS) {
    const supported = await testProtocolVersion(resolvedIp, port, version, timeoutMs, host);

    if (supported === 'timeout') {
      findings.push({
        category: 'tls-ssl',
        severity: 'critical',
        rawValue: null,
        description: `TLS connection timed out while testing ${label} support (timeout: ${timeoutMs}ms)`,
      });
      break;
    } else if (supported === true) {
      if (version === 'TLSv1' || version === 'TLSv1.1') {
        findings.push({
          category: 'tls-ssl',
          severity: 'high',
          rawValue: label,
          description: `Server supports obsolete protocol ${label} which has known vulnerabilities and should be disabled`,
        });
      } else {
        findings.push({
          category: 'tls-ssl',
          severity: 'info',
          rawValue: label,
          description: `Server supports modern protocol ${label}`,
        });
      }
    } else {
      findings.push({
        category: 'tls-ssl',
        severity: 'info',
        rawValue: label,
        description: `Server does not support ${label}`,
      });
    }
  }

  return findings;
}

/**
 * Prueba si el servidor soporta una versión de protocolo TLS específica.
 * Retorna true/false/'timeout'.
 * @param ip - IP resuelta del host (conexión real)
 * @param port - Puerto TLS
 * @param version - Versión de protocolo a probar
 * @param timeoutMs - Timeout en ms
 * @param servername - Hostname original para SNI
 */
function testProtocolVersion(
  ip: string,
  port: number,
  version: SecureVersion,
  timeoutMs: number,
  servername: string,
): Promise<boolean | 'timeout'> {
  return new Promise((resolve) => {
    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        socket.destroy();
        resolve('timeout');
      }
    }, timeoutMs);

    const socket: TLSSocket = tls.connect(
      {
        host: ip,
        port,
        minVersion: version,
        maxVersion: version,
        rejectUnauthorized: false, // Queremos probar incluso con certs inválidos
        servername,
      },
      () => {
        // Conexión exitosa → protocolo soportado
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          socket.destroy();
          resolve(true);
        }
      },
    );

    socket.on('error', () => {
      // Conexión rechazada → protocolo no soportado
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        resolve(false);
      }
    });
  });
}

/**
 * Establece una conexión TLS normal (sin restricción de versión) para
 * analizar cipher suites y certificado.
 */
async function checkCipherAndCertificate(
  host: string,
  port: number,
  timeoutMs: number,
  targetDomain: string | null,
): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Resolver el host y validar IPs antes de conectar
  let resolvedIp: string;
  try {
    const resolved = await resolveAndValidateHost(host);
    resolvedIp = resolved.ip;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`[tls-checker] Cannot resolve host for cipher/certificate verification:`, message);
    findings.push({
      category: 'tls-ssl',
      severity: 'critical',
      rawValue: null,
      description: `Cannot resolve host for cipher/certificate verification: DNS resolution failed`,
    });
    return findings;
  }

  const result = await connectAndInspect(resolvedIp, port, timeoutMs, host);

  if (result === 'timeout') {
    findings.push({
      category: 'tls-ssl',
      severity: 'critical',
      rawValue: null,
      description: `Could not establish TLS connection to verify cipher suites and certificate (timeout: ${timeoutMs}ms)`,
    });
    return findings;
  }

  if (result === 'error') {
    findings.push({
      category: 'tls-ssl',
      severity: 'critical',
      rawValue: null,
      description: 'Could not establish TLS connection to verify cipher suites and certificate',
    });
    return findings;
  }

  // Analizar cipher suite
  const cipherFindings = analyzeCipher(result.cipher);
  findings.push(...cipherFindings);

  // Analizar certificado con el veredicto real de OpenSSL
  const certFindings = analyzeCertificate(
    result.certificate,
    targetDomain ?? host,
    result.authorized,
    result.authorizationError,
  );
  findings.push(...certFindings);

  return findings;
}

/**
 * Resultado de la inspección de una conexión TLS.
 */
interface TlsInspectionResult {
  cipher: tls.CipherNameAndProtocol;
  certificate: tls.DetailedPeerCertificate;
  authorized: boolean;
  authorizationError?: string;
}

/**
 * Conecta al servidor y extrae información de cipher y certificado.
 * @param ip - IP resuelta (conexión real)
 * @param port - Puerto TLS
 * @param timeoutMs - Timeout en ms
 * @param servername - Hostname original para SNI
 */
function connectAndInspect(
  ip: string,
  port: number,
  timeoutMs: number,
  servername: string,
): Promise<TlsInspectionResult | 'timeout' | 'error'> {
  return new Promise((resolve) => {
    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        socket.destroy();
        resolve('timeout');
      }
    }, timeoutMs);

    const socket: TLSSocket = tls.connect(
      {
        host: ip,
        port,
        rejectUnauthorized: false, // Necesitamos inspeccionar certs inválidos también
        servername,
      },
      () => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);

          const cipher = socket.getCipher();
          const certificate = socket.getPeerCertificate(true) as tls.DetailedPeerCertificate;
          const authorized = socket.authorized;
          const authorizationError = socket.authorizationError;

          socket.destroy();

          resolve({
            cipher,
            certificate,
            authorized,
            authorizationError: authorizationError
              ? String(authorizationError)
              : undefined,
          });
        }
      },
    );

    socket.on('error', () => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        resolve('error');
      }
    });
  });
}

/**
 * Analiza el cipher suite negociado en busca de algoritmos inseguros.
 */
function analyzeCipher(cipher: tls.CipherNameAndProtocol): Finding[] {
  const findings: Finding[] = [];
  const cipherName = cipher.name || '';
  const standardName = cipher.standardName || '';

  const isInsecure = INSECURE_CIPHER_PATTERNS.some(
    (pattern) => pattern.test(cipherName) || pattern.test(standardName),
  );

  if (isInsecure) {
    findings.push({
      category: 'tls-ssl',
      severity: 'high',
      rawValue: `${cipherName} (${standardName})`,
      description: `Insecure cipher suite detected: ${cipherName}. This cipher uses weak cryptographic algorithms vulnerable to known attacks`,
    });
  } else {
    findings.push({
      category: 'tls-ssl',
      severity: 'info',
      rawValue: `${cipherName} (${standardName})`,
      description: `Cipher suite in use: ${cipherName} — no known weaknesses detected`,
    });
  }

  return findings;
}

/**
 * Analiza el certificado del servidor: expiración, cadena de confianza,
 * y coincidencia de dominio (CN/SAN).
 * Recibe el veredicto nativo de OpenSSL (authorized/authorizationError)
 * como fuente primaria para la validación de cadena.
 */
export function analyzeCertificate(
  cert: tls.DetailedPeerCertificate,
  expectedDomain: string,
  authorized: boolean,
  authorizationError?: string,
): Finding[] {
  const findings: Finding[] = [];

  // Si no hay certificado disponible
  if (!cert || !cert.valid_to) {
    findings.push({
      category: 'tls-ssl',
      severity: 'high',
      rawValue: null,
      description: 'No certificate information available from the server',
    });
    return findings;
  }

  // 1. Verificar expiración
  const expiryFindings = checkCertificateExpiry(cert);
  findings.push(...expiryFindings);

  // 2. Verificar cadena de confianza (veredicto OpenSSL + chequeo manual)
  const chainFindings = checkCertificateChain(cert, authorized, authorizationError);
  findings.push(...chainFindings);

  // 3. Verificar coincidencia de dominio
  const domainFindings = checkDomainMatch(cert, expectedDomain);
  findings.push(...domainFindings);

  return findings;
}

/**
 * Verifica la fecha de expiración del certificado.
 */
function checkCertificateExpiry(cert: tls.DetailedPeerCertificate): Finding[] {
  const findings: Finding[] = [];
  const now = new Date();
  const expiryDate = new Date(cert.valid_to);

  if (isNaN(expiryDate.getTime())) {
    findings.push({
      category: 'tls-ssl',
      severity: 'high',
      rawValue: cert.valid_to,
      description: 'Certificate expiration date could not be parsed',
    });
    return findings;
  }

  if (expiryDate < now) {
    // Certificado ya expirado
    findings.push({
      category: 'tls-ssl',
      severity: 'critical',
      rawValue: cert.valid_to,
      description: `Certificate expired on ${expiryDate.toISOString().split('T')[0]}. The certificate is invalid and browsers will show security warnings`,
    });
  } else {
    const daysRemaining = Math.ceil(
      (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24),
    );

    if (daysRemaining <= CERT_EXPIRY_WARNING_DAYS) {
      findings.push({
        category: 'tls-ssl',
        severity: 'medium',
        rawValue: `${daysRemaining} days remaining (expires: ${cert.valid_to})`,
        description: `Certificate expires in ${daysRemaining} days (on ${expiryDate.toISOString().split('T')[0]}). Renew soon to avoid service disruption`,
      });
    } else {
      findings.push({
        category: 'tls-ssl',
        severity: 'info',
        rawValue: `${daysRemaining} days remaining (expires: ${cert.valid_to})`,
        description: `Certificate is valid with ${daysRemaining} days until expiration`,
      });
    }
  }

  return findings;
}

/**
 * Verifica la cadena de confianza del certificado.
 * Usa el veredicto nativo de OpenSSL (authorized/authorizationError) como
 * fuente primaria. Mantiene chequeos manuales como complemento.
 */
function checkCertificateChain(
  cert: tls.DetailedPeerCertificate,
  authorized: boolean,
  authorizationError?: string,
): Finding[] {
  const findings: Finding[] = [];

  // Fuente primaria: veredicto de OpenSSL
  if (authorized === false && authorizationError) {
    const errorLower = authorizationError.toLowerCase();

    // Determinar descripción y severidad según el error de autorización
    if (errorLower.includes('self_signed') || errorLower.includes('self signed')) {
      findings.push({
        category: 'tls-ssl',
        severity: 'high',
        rawValue: `authorizationError: ${authorizationError}`,
        description: 'Certificate is self-signed and cannot be verified against a trusted Certificate Authority',
      });
    } else if (errorLower.includes('expired') || errorLower.includes('cert_has_expired')) {
      findings.push({
        category: 'tls-ssl',
        severity: 'critical',
        rawValue: `authorizationError: ${authorizationError}`,
        description: 'Certificate chain verification failed: certificate has expired',
      });
    } else if (errorLower.includes('hostname') || errorLower.includes('host name')) {
      findings.push({
        category: 'tls-ssl',
        severity: 'high',
        rawValue: `authorizationError: ${authorizationError}`,
        description: 'Certificate chain verification failed: hostname mismatch',
      });
    } else {
      // Error genérico de verificación de cadena
      findings.push({
        category: 'tls-ssl',
        severity: 'high',
        rawValue: `authorizationError: ${authorizationError}`,
        description: `Certificate chain is not trusted: ${authorizationError}`,
      });
    }
    return findings;
  }

  // Si authorized es true, la cadena está OK — confirmación positiva
  if (authorized === true) {
    findings.push({
      category: 'tls-ssl',
      severity: 'info',
      rawValue: `Issuer: ${formatCertName(cert.issuer)}`,
      description: `Certificate chain is valid and trusted. Issued by: ${formatCertName(cert.issuer)}`,
    });
    return findings;
  }

  // Fallback: chequeos manuales si authorized no es informativo
  const isSelfSigned = isCertSelfSigned(cert);

  if (isSelfSigned) {
    findings.push({
      category: 'tls-ssl',
      severity: 'high',
      rawValue: `Issuer: ${formatCertName(cert.issuer)}`,
      description: 'Certificate is self-signed and cannot be verified against a trusted Certificate Authority',
    });
    return findings;
  }

  if (!cert.issuerCertificate) {
    findings.push({
      category: 'tls-ssl',
      severity: 'high',
      rawValue: `Issuer: ${formatCertName(cert.issuer)}`,
      description: 'Certificate chain is incomplete — missing intermediate CA certificate',
    });
  } else {
    findings.push({
      category: 'tls-ssl',
      severity: 'info',
      rawValue: `Issuer: ${formatCertName(cert.issuer)}`,
      description: `Certificate chain is present. Issued by: ${formatCertName(cert.issuer)}`,
    });
  }

  return findings;
}

/**
 * Verifica que el dominio del target coincida con el CN o SAN del certificado.
 */
function checkDomainMatch(
  cert: tls.DetailedPeerCertificate,
  expectedDomain: string,
): Finding[] {
  const findings: Finding[] = [];

  // Extraer dominios del certificado
  const certDomains = extractCertDomains(cert);

  if (certDomains.length === 0) {
    findings.push({
      category: 'tls-ssl',
      severity: 'high',
      rawValue: `Expected: ${expectedDomain}, Certificate domains: none found`,
      description: `Certificate does not contain any domain names (CN or SAN) to verify against ${expectedDomain}`,
    });
    return findings;
  }

  // Verificar si el dominio esperado coincide con algún dominio del certificado
  const matches = certDomains.some((certDomain) =>
    domainMatchesCert(expectedDomain, certDomain),
  );

  if (!matches) {
    findings.push({
      category: 'tls-ssl',
      severity: 'high',
      rawValue: `Expected: ${expectedDomain}, Certificate domains: ${certDomains.join(', ')}`,
      description: `Domain mismatch: ${expectedDomain} does not match certificate names [${certDomains.join(', ')}]`,
    });
  } else {
    findings.push({
      category: 'tls-ssl',
      severity: 'info',
      rawValue: `${expectedDomain} matches certificate`,
      description: `Domain ${expectedDomain} correctly matches the certificate`,
    });
  }

  return findings;
}

// ─── Utilidades internas ─────────────────────────────────────────────────────

/**
 * Determina si un certificado es autofirmado comparando issuer y subject.
 */
function isCertSelfSigned(cert: tls.DetailedPeerCertificate): boolean {
  if (!cert.issuer || !cert.subject) return false;

  return (
    cert.issuer.CN === cert.subject.CN &&
    cert.issuer.O === cert.subject.O &&
    cert.issuer.C === cert.subject.C
  );
}

/**
 * Formatea el nombre distinguido del certificado para presentación.
 */
function formatCertName(name: { CN?: string; O?: string; C?: string } | undefined): string {
  if (!name) return 'Unknown';
  const parts: string[] = [];
  if (name.CN) parts.push(`CN=${name.CN}`);
  if (name.O) parts.push(`O=${name.O}`);
  if (name.C) parts.push(`C=${name.C}`);
  return parts.length > 0 ? parts.join(', ') : 'Unknown';
}

/**
 * Extrae todos los dominios válidos del certificado (CN + SANs).
 */
function extractCertDomains(cert: tls.DetailedPeerCertificate): string[] {
  const domains: string[] = [];

  // Common Name
  if (cert.subject?.CN) {
    domains.push(cert.subject.CN.toLowerCase());
  }

  // Subject Alternative Names (formato: "DNS:example.com, DNS:*.example.com")
  if (cert.subjectaltname) {
    const sanEntries = cert.subjectaltname.split(',').map((s) => s.trim());
    for (const entry of sanEntries) {
      const dnsMatch = entry.match(/^DNS:(.+)$/i);
      if (dnsMatch && dnsMatch[1]) {
        domains.push(dnsMatch[1].toLowerCase());
      }
    }
  }

  return [...new Set(domains)]; // Deduplicar
}

/**
 * Verifica si un dominio coincide con un patrón de certificado
 * (soporta wildcards como *.example.com).
 */
function domainMatchesCert(domain: string, certDomain: string): boolean {
  const normalizedDomain = domain.toLowerCase();
  const normalizedCert = certDomain.toLowerCase();

  if (normalizedDomain === normalizedCert) {
    return true;
  }

  // Wildcard matching: *.example.com coincide con sub.example.com
  if (normalizedCert.startsWith('*.')) {
    const certBase = normalizedCert.slice(2); // "example.com"
    const domainParts = normalizedDomain.split('.');
    const certParts = certBase.split('.');

    // El wildcard solo cubre un nivel de subdominio
    if (domainParts.length === certParts.length + 1) {
      return normalizedDomain.endsWith(`.${certBase}`);
    }
  }

  return false;
}

/**
 * Crea un Finding informativo estándar.
 */
function createInfoFinding(description: string, rawValue: string | null): Finding {
  return {
    category: 'tls-ssl',
    severity: 'info',
    rawValue,
    description,
  };
}
