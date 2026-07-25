/**
 * Parser de salida XML de Nmap (-oX).
 *
 * Extractor acotado: NO es un parser XML general. Solo procesa las estructuras
 * específicas de la salida de Nmap XML que necesitamos: <port>, <service>,
 * <script> (NSE), y <hostscript>.
 *
 * No añade dependencias externas — opera con regex y string manipulation.
 * Fail-open: XML malformado → [], nunca lanza.
 */

import type { Finding, FindingSeverity, FindingCategory } from '../scanner/modules/types.js';
import { convertNmapServiceRowToFinding, type NmapServiceRow } from './nmap-parser.js';

// ─── Decodificación de entidades XML ─────────────────────────────────────────

/** Decodifica las entidades XML que Nmap emite en los atributos. */
function decodeXmlEntities(str: string): string {
  return str
    .replace(/&#xa;/gi, '\n')
    .replace(/&#x9;/gi, '\t')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&'); // &amp; último para no re-decodificar
}

// ─── Extracción de atributos ─────────────────────────────────────────────────

/**
 * Extrae el valor de un atributo de un tag XML.
 * Tolerante al orden de atributos y a comillas simples o dobles.
 */
function getAttr(tag: string, name: string): string {
  // Buscar name="value" o name='value'
  const regex = new RegExp(`${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)')`, 's');
  const match = tag.match(regex);
  if (!match) return '';
  return decodeXmlEntities(match[1] ?? match[2] ?? '');
}

// ─── Análisis de scripts NSE ─────────────────────────────────────────────────

/** Ciphers débiles conocidos (patrones para buscar en ssl-enum-ciphers). */
const WEAK_CIPHERS = ['3DES', 'RC4', 'EXPORT', 'NULL', 'anon'];

/**
 * Procesa un script ssl-cert y devuelve un finding si el certificado está expirado.
 */
function processSslCert(output: string, port: number, protocol: string): Finding {
  // Buscar "Not valid after: <fecha>"
  const dateMatch = output.match(/Not valid after:\s*(\d{4}-\d{2}-\d{2})/i);

  if (dateMatch) {
    const expiryDate = new Date(dateMatch[1]!);
    const now = new Date();

    if (expiryDate < now) {
      const desc = `Certificate on port ${port}/${protocol} expired on ${dateMatch[1]}. An expired certificate breaks trust and exposes connections to MITM attacks.`;
      return {
        category: 'tls-ssl' as FindingCategory,
        severity: 'high' as FindingSeverity,
        rawValue: `ssl-cert: expired ${dateMatch[1]}`,
        description: desc.slice(0, 500),
      };
    }

    // Certificado válido (no expirado)
    const desc = `Certificate on port ${port}/${protocol} is valid until ${dateMatch[1]} (ssl-cert script result).`;
    return {
      category: 'tls-ssl' as FindingCategory,
      severity: 'info' as FindingSeverity,
      rawValue: `ssl-cert: valid until ${dateMatch[1]}`,
      description: desc.slice(0, 500),
    };
  }

  // No se encontró fecha → info genérico
  const desc = `ssl-cert script result on port ${port}/${protocol}: ${output.replace(/\n/g, ' ').slice(0, 400)}`;
  return {
    category: 'tls-ssl' as FindingCategory,
    severity: 'info' as FindingSeverity,
    rawValue: `ssl-cert`,
    description: desc.length >= 10 ? desc.slice(0, 500) : 'ssl-cert script executed without actionable findings.',
  };
}

/**
 * Procesa un script ssl-enum-ciphers y devuelve un finding basado en los protocolos/ciphers.
 */
function processSslEnumCiphers(output: string, port: number, protocol: string): Finding {
  const hasObsoleteProtocol = /TLSv1\.0|TLSv1\.1|SSLv[23]/i.test(output);
  const hasWeakCipher = WEAK_CIPHERS.some(c => output.toUpperCase().includes(c.toUpperCase()));

  if (hasObsoleteProtocol) {
    const proto = output.match(/(TLSv1\.[01]|SSLv[23])/i)?.[1] ?? 'obsolete protocol';
    const desc = `Port ${port}/${protocol} supports deprecated ${proto}. This protocol has known vulnerabilities and should be disabled.`;
    return {
      category: 'tls-ssl' as FindingCategory,
      severity: 'high' as FindingSeverity,
      rawValue: `ssl-enum-ciphers: ${proto} supported`,
      description: desc.slice(0, 500),
    };
  }

  if (hasWeakCipher) {
    const found = WEAK_CIPHERS.filter(c => output.toUpperCase().includes(c.toUpperCase()));
    const desc = `Port ${port}/${protocol} uses weak cipher(s): ${found.join(', ')}. These ciphers are cryptographically broken and should be removed.`;
    return {
      category: 'tls-ssl' as FindingCategory,
      severity: 'high' as FindingSeverity,
      rawValue: `ssl-enum-ciphers: weak ciphers (${found.join(', ')})`,
      description: desc.slice(0, 500),
    };
  }

  // Sin protocolos obsoletos ni ciphers débiles: verificar la letra del grado
  const strengthMatch = output.match(/least strength:\s*([A-F])/i);
  if (strengthMatch) {
    const grade = strengthMatch[1]!.toUpperCase();
    if (grade === 'A' || grade === 'B') {
      const desc = `Port ${port}/${protocol} cipher suite strength is rated "${grade}" by ssl-enum-ciphers. No immediate action required.`;
      return {
        category: 'tls-ssl' as FindingCategory,
        severity: 'info' as FindingSeverity,
        rawValue: `ssl-enum-ciphers: least strength ${grade}`,
        description: desc.slice(0, 500),
      };
    }
    // Grado C, D, E, F sin haber encontrado ciphers explícitamente débiles arriba
    const desc = `Port ${port}/${protocol} cipher suite rated "${grade}" by ssl-enum-ciphers. Consider upgrading cipher configuration.`;
    return {
      category: 'tls-ssl' as FindingCategory,
      severity: 'high' as FindingSeverity,
      rawValue: `ssl-enum-ciphers: least strength ${grade}`,
      description: desc.slice(0, 500),
    };
  }

  // Fallback info
  const desc = `ssl-enum-ciphers result on port ${port}/${protocol}: ${output.replace(/\n/g, ' ').slice(0, 400)}`;
  return {
    category: 'tls-ssl' as FindingCategory,
    severity: 'info' as FindingSeverity,
    rawValue: 'ssl-enum-ciphers',
    description: desc.length >= 10 ? desc.slice(0, 500) : 'ssl-enum-ciphers script ran without notable findings.',
  };
}

/**
 * Procesa un script NSE genérico (no ssl-cert ni ssl-enum-ciphers).
 */
function processGenericScript(scriptId: string, output: string, port: number, protocol: string): Finding {
  const excerpt = output.replace(/\n/g, ' ').trim().slice(0, 400);
  let desc = `NSE script "${scriptId}" on port ${port}/${protocol}: ${excerpt}`;
  // Asegurar mínimo 10 caracteres
  if (desc.length < 10) {
    desc = `NSE script "${scriptId}" executed on port ${port}/${protocol} without output.`;
  }

  return {
    category: 'server-fingerprint' as FindingCategory,
    severity: 'info' as FindingSeverity,
    rawValue: `${scriptId}: ${excerpt}`.slice(0, 500) || null,
    description: desc.slice(0, 500),
  };
}

// ─── Parser principal ────────────────────────────────────────────────────────

/**
 * Parsea la salida XML de Nmap (-oX) y extrae findings de puertos/servicios
 * y resultados de scripts NSE.
 *
 * Fail-open: XML malformado o vacío → [], nunca lanza.
 * Determinismo: findings en el orden del documento (puertos en orden, luego scripts por puerto).
 */
export function parseNmapXml(xml: string): Finding[] {
  try {
    if (!xml || !xml.trim()) return [];

    const findings: Finding[] = [];

    // Extraer todos los bloques <port>...</port> (incluyendo self-closing y con contenido)
    const portBlocks = extractPortBlocks(xml);

    for (const block of portBlocks) {
      const portTag = block.openTag;
      const portId = Number(getAttr(portTag, 'portid'));
      const protocol = getAttr(portTag, 'protocol') || 'tcp';

      if (!portId || portId < 0 || portId > 65535) continue;

      // Extraer estado
      const stateMatch = block.content.match(/<state\s[^>]*>/i);
      const state = stateMatch ? getAttr(stateMatch[0], 'state') : 'unknown';

      // Extraer servicio
      const serviceMatch = block.content.match(/<service\s[^>]*\/?>/i);
      let serviceName = '';
      let version = '';
      if (serviceMatch) {
        serviceName = getAttr(serviceMatch[0], 'name') || 'unknown';
        const product = getAttr(serviceMatch[0], 'product');
        const ver = getAttr(serviceMatch[0], 'version');
        const extrainfo = getAttr(serviceMatch[0], 'extrainfo');
        // Componer version a partir de product + version + extrainfo
        const parts = [product, ver, extrainfo].filter(Boolean);
        version = parts.join(' ');
      }

      // Generar finding de servicio usando la función compartida del parser de texto
      const row: NmapServiceRow = { port: portId, protocol, state, service: serviceName, version };
      findings.push(convertNmapServiceRowToFinding(row));

      // Extraer scripts NSE dentro del bloque <port>
      const scripts = extractScripts(block.content);
      for (const script of scripts) {
        const finding = processScript(script.id, script.output, portId, protocol);
        if (finding) findings.push(finding);
      }
    }

    // Extraer scripts de <hostscript>
    const hostScriptMatch = xml.match(/<hostscript>([\s\S]*?)<\/hostscript>/i);
    if (hostScriptMatch) {
      const scripts = extractScripts(hostScriptMatch[1]!);
      for (const script of scripts) {
        const finding = processScript(script.id, script.output, 0, 'tcp');
        if (finding) findings.push(finding);
      }
    }

    return findings;
  } catch {
    // Fail-open: cualquier error inesperado → []
    return [];
  }
}

// ─── Helpers internos ────────────────────────────────────────────────────────

interface PortBlock {
  openTag: string;
  content: string;
}

/**
 * Extrae bloques <port ...>...</port> del XML.
 * Tolerante a self-closing y a atributos en cualquier orden.
 */
function extractPortBlocks(xml: string): PortBlock[] {
  const blocks: PortBlock[] = [];
  const regex = /<port\s([^>]*)>([\s\S]*?)<\/port>/gi;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(xml)) !== null) {
    blocks.push({
      openTag: `<port ${match[1]}>`,
      content: match[2]!,
    });
  }

  // También manejar <port .../> self-closing (poco común pero posible)
  const selfClosing = /<port\s([^>]*)\/>/gi;
  while ((match = selfClosing.exec(xml)) !== null) {
    blocks.push({
      openTag: `<port ${match[1]}>`,
      content: '',
    });
  }

  return blocks;
}

interface ScriptInfo {
  id: string;
  output: string;
}

/**
 * Extrae tags <script> con sus atributos id y output.
 */
function extractScripts(content: string): ScriptInfo[] {
  const scripts: ScriptInfo[] = [];
  const regex = /<script\s([^>]*?)(?:\/>|>([\s\S]*?)<\/script>)/gi;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(content)) !== null) {
    const attrs = match[1]!;
    const id = getAttr(`<script ${attrs}>`, 'id');
    const output = getAttr(`<script ${attrs}>`, 'output');
    if (id) {
      scripts.push({ id, output });
    }
  }

  return scripts;
}

/**
 * Procesa un script NSE individual y devuelve el finding apropiado.
 */
function processScript(id: string, output: string, port: number, protocol: string): Finding | null {
  const decodedOutput = output; // Ya decodificado por getAttr

  switch (id) {
    case 'ssl-cert':
      return processSslCert(decodedOutput, port, protocol);
    case 'ssl-enum-ciphers':
      return processSslEnumCiphers(decodedOutput, port, protocol);
    default:
      return processGenericScript(id, decodedOutput, port, protocol);
  }
}
