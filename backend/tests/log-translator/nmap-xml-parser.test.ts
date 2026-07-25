/**
 * Tests del parser de Nmap XML (-oX) — Ola 13a.
 *
 * Verifica la extracción de puertos/servicios, scripts NSE (ssl-cert,
 * ssl-enum-ciphers, genéricos), decodificación de entidades, determinismo,
 * y fail-open ante XML malformado.
 */

import { describe, it, expect } from 'vitest';
import { parseNmapXml } from '../../services/log-translator/nmap-xml-parser.js';
import { extractSoftware } from '../../services/cve-enricher/extract-software.js';
import type { FindingCategory } from '../../services/scanner/modules/types.js';

// ─── Fixtures ────────────────────────────────────────────────────────────────

const XML_TWO_PORTS = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -A target" start="1700000000">
<host>
<ports>
<port protocol="tcp" portid="22">
  <state state="open" reason="syn-ack"/>
  <service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu Linux; protocol 2.0"/>
</port>
<port protocol="tcp" portid="6379">
  <state state="open" reason="syn-ack"/>
  <service name="redis" product="Redis" version="6.0.9" extrainfo=""/>
</port>
</ports>
</host>
</nmaprun>`;

const XML_SSL_CERT_EXPIRED = `<?xml version="1.0"?>
<nmaprun>
<host>
<ports>
<port protocol="tcp" portid="443">
  <state state="open" reason="syn-ack"/>
  <service name="https" product="nginx" version="1.18.0"/>
  <script id="ssl-cert" output="Subject: commonName=lab.local&#xa;Not valid after: 2020-01-01T00:00:00"/>
</port>
</ports>
</host>
</nmaprun>`;

const XML_SSL_CERT_VALID = `<?xml version="1.0"?>
<nmaprun>
<host>
<ports>
<port protocol="tcp" portid="443">
  <state state="open" reason="syn-ack"/>
  <service name="https" product="nginx" version="1.18.0"/>
  <script id="ssl-cert" output="Subject: commonName=valid.test&#xa;Not valid after: 2030-12-31T23:59:59"/>
</port>
</ports>
</host>
</nmaprun>`;

const XML_SSL_ENUM_CIPHERS_OBSOLETE = `<?xml version="1.0"?>
<nmaprun>
<host>
<ports>
<port protocol="tcp" portid="443">
  <state state="open" reason="syn-ack"/>
  <service name="https"/>
  <script id="ssl-enum-ciphers" output="TLSv1.0:&#xa;  ciphers:&#xa;    TLS_RSA_WITH_3DES_EDE_CBC_SHA (cbc 168)&#xa;  least strength: C"/>
</port>
</ports>
</host>
</nmaprun>`;

const XML_SSL_ENUM_CIPHERS_WEAK = `<?xml version="1.0"?>
<nmaprun>
<host>
<ports>
<port protocol="tcp" portid="443">
  <state state="open" reason="syn-ack"/>
  <service name="https"/>
  <script id="ssl-enum-ciphers" output="TLSv1.2:&#xa;  ciphers:&#xa;    TLS_RSA_WITH_3DES_EDE_CBC_SHA (cbc 168)&#xa;  least strength: C"/>
</port>
</ports>
</host>
</nmaprun>`;

const XML_SSL_ENUM_CIPHERS_GOOD = `<?xml version="1.0"?>
<nmaprun>
<host>
<ports>
<port protocol="tcp" portid="443">
  <state state="open" reason="syn-ack"/>
  <service name="https"/>
  <script id="ssl-enum-ciphers" output="TLSv1.3:&#xa;  ciphers:&#xa;    TLS_AES_256_GCM_SHA384&#xa;  least strength: A"/>
</port>
</ports>
</host>
</nmaprun>`;

const XML_GENERIC_SCRIPT = `<?xml version="1.0"?>
<nmaprun>
<host>
<ports>
<port protocol="tcp" portid="80">
  <state state="open" reason="syn-ack"/>
  <service name="http"/>
  <script id="http-title" output="Welcome to nginx! &amp; &quot;fast&quot;"/>
</port>
</ports>
</host>
</nmaprun>`;

const XML_WITH_ENTITIES = `<?xml version="1.0"?>
<nmaprun>
<host>
<ports>
<port protocol="tcp" portid="443">
  <state state="open" reason="syn-ack"/>
  <service name="https" product="Apache" version="2.4.29"/>
  <script id="ssl-cert" output="Subject: CN=test &amp; &quot;lab&quot;&#xa;Not valid after: 2019-06-15T00:00:00"/>
</port>
</ports>
</host>
</nmaprun>`;

const VALID_CATEGORIES: FindingCategory[] = [
  'http-headers', 'tls-ssl', 'cookies', 'dns-security', 'server-fingerprint',
  'port-service', 'cors', 'http-methods', 'security-txt', 'log-analysis',
  'known-vulnerabilities', 'correlation', 'security-exposure',
];

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('parseNmapXml — ports and services', () => {
  it('extracts 2 ports with correct serviceInfo and severity', () => {
    const findings = parseNmapXml(XML_TWO_PORTS);

    // 2 port-service findings
    const portFindings = findings.filter(f => f.category === 'port-service');
    expect(portFindings).toHaveLength(2);

    // SSH (port 22) — medium severity
    const ssh = portFindings.find(f => f.serviceInfo?.port === 22);
    expect(ssh).toBeDefined();
    expect(ssh!.serviceInfo!.service).toBe('ssh');
    expect(ssh!.serviceInfo!.state).toBe('open');
    expect(ssh!.serviceInfo!.version).toBe('OpenSSH 8.2p1 Ubuntu Linux; protocol 2.0');
    expect(ssh!.severity).toBe('medium');

    // Redis (port 6379) — high severity (historically exposed without auth)
    const redis = portFindings.find(f => f.serviceInfo?.port === 6379);
    expect(redis).toBeDefined();
    expect(redis!.serviceInfo!.service).toBe('redis');
    expect(redis!.severity).toBe('high');
    expect(redis!.serviceInfo!.version).toBe('Redis 6.0.9');
  });

  it('composes version from product + version + extrainfo for extractSoftware', () => {
    const findings = parseNmapXml(XML_TWO_PORTS);
    const ssh = findings.find(f => f.serviceInfo?.port === 22);

    // extractSoftware should derive OpenSSH as product
    const pairs = extractSoftware([ssh!]);
    expect(pairs.length).toBeGreaterThan(0);
    expect(pairs[0]!.product).toBe('openssh');
    expect(pairs[0]!.version).toContain('8.2p1');
  });
});

describe('parseNmapXml — ssl-cert script', () => {
  it('produces tls-ssl high finding for expired certificate', () => {
    const findings = parseNmapXml(XML_SSL_CERT_EXPIRED);
    const tlsFindings = findings.filter(f => f.category === 'tls-ssl');
    expect(tlsFindings.length).toBeGreaterThanOrEqual(1);

    const expired = tlsFindings.find(f => f.severity === 'high');
    expect(expired).toBeDefined();
    expect(expired!.description).toContain('expired');
    expect(expired!.description).toContain('2020-01-01');
  });

  it('produces tls-ssl info finding for valid (future) certificate', () => {
    const findings = parseNmapXml(XML_SSL_CERT_VALID);
    const tlsFindings = findings.filter(f => f.category === 'tls-ssl');
    const info = tlsFindings.find(f => f.severity === 'info' && f.description.includes('2030'));
    expect(info).toBeDefined();
  });
});

describe('parseNmapXml — ssl-enum-ciphers script', () => {
  it('TLSv1.0 → tls-ssl high (obsolete protocol)', () => {
    const findings = parseNmapXml(XML_SSL_ENUM_CIPHERS_OBSOLETE);
    const tlsHigh = findings.filter(f => f.category === 'tls-ssl' && f.severity === 'high');
    expect(tlsHigh.length).toBeGreaterThanOrEqual(1);
    const obsolete = tlsHigh.find(f => f.description.includes('TLSv1.0') || f.description.includes('deprecated'));
    expect(obsolete).toBeDefined();
  });

  it('3DES cipher → tls-ssl high (weak cipher)', () => {
    const findings = parseNmapXml(XML_SSL_ENUM_CIPHERS_WEAK);
    const tlsHigh = findings.filter(f => f.category === 'tls-ssl' && f.severity === 'high');
    expect(tlsHigh.length).toBeGreaterThanOrEqual(1);
    const weak = tlsHigh.find(f => f.description.includes('3DES') || f.description.includes('weak'));
    expect(weak).toBeDefined();
  });

  it('least strength: A without obsolete protocols → info', () => {
    const findings = parseNmapXml(XML_SSL_ENUM_CIPHERS_GOOD);
    const tlsFindings = findings.filter(f => f.category === 'tls-ssl');
    // El script finding debe ser info (no high)
    const scriptFinding = tlsFindings.find(f => f.rawValue?.includes('ssl-enum-ciphers'));
    expect(scriptFinding).toBeDefined();
    expect(scriptFinding!.severity).toBe('info');
  });
});

describe('parseNmapXml — generic NSE scripts', () => {
  it('unknown script (http-title) → server-fingerprint info with script id', () => {
    const findings = parseNmapXml(XML_GENERIC_SCRIPT);
    const generic = findings.find(f => f.category === 'server-fingerprint' && f.severity === 'info');
    expect(generic).toBeDefined();
    expect(generic!.description).toContain('http-title');
  });
});

describe('parseNmapXml — XML entity decoding', () => {
  it('decodes &#xa;, &amp;, &quot; in descriptions', () => {
    const findings = parseNmapXml(XML_WITH_ENTITIES);
    // El ssl-cert expired finding debería tener la entidad decodificada
    const cert = findings.find(f => f.category === 'tls-ssl' && f.severity === 'high');
    expect(cert).toBeDefined();
    // El contenido del description no debe tener &amp; raw
    expect(cert!.description).not.toContain('&amp;');
    expect(cert!.description).not.toContain('&#xa;');
  });
});

describe('parseNmapXml — fail-open (resilience)', () => {
  it('returns [] for empty string', () => {
    expect(parseNmapXml('')).toEqual([]);
  });

  it('returns [] for malformed XML', () => {
    expect(parseNmapXml('<port invalid<><>><><')).toEqual([]);
  });

  it('returns [] for XML without ports', () => {
    const noPortsXml = '<?xml version="1.0"?><nmaprun><host><status state="up"/></host></nmaprun>';
    expect(parseNmapXml(noPortsXml)).toEqual([]);
  });

  it('returns [] for null-ish input', () => {
    expect(parseNmapXml(null as any)).toEqual([]);
    expect(parseNmapXml(undefined as any)).toEqual([]);
  });
});

describe('parseNmapXml — contract compliance', () => {
  it('all descriptions are between 10 and 500 characters', () => {
    const allXmls = [
      XML_TWO_PORTS, XML_SSL_CERT_EXPIRED, XML_SSL_CERT_VALID,
      XML_SSL_ENUM_CIPHERS_OBSOLETE, XML_SSL_ENUM_CIPHERS_WEAK,
      XML_SSL_ENUM_CIPHERS_GOOD, XML_GENERIC_SCRIPT, XML_WITH_ENTITIES,
    ];

    for (const xml of allXmls) {
      const findings = parseNmapXml(xml);
      for (const f of findings) {
        expect(f.description.length).toBeGreaterThanOrEqual(10);
        expect(f.description.length).toBeLessThanOrEqual(500);
      }
    }
  });

  it('all categories are valid FindingCategory values', () => {
    const allXmls = [
      XML_TWO_PORTS, XML_SSL_CERT_EXPIRED, XML_SSL_ENUM_CIPHERS_OBSOLETE,
      XML_GENERIC_SCRIPT,
    ];

    for (const xml of allXmls) {
      const findings = parseNmapXml(xml);
      for (const f of findings) {
        expect(VALID_CATEGORIES).toContain(f.category);
      }
    }
  });
});

describe('parseNmapXml — determinism', () => {
  it('two invocations with the same XML produce identical arrays', () => {
    const first = parseNmapXml(XML_TWO_PORTS);
    const second = parseNmapXml(XML_TWO_PORTS);
    expect(first).toEqual(second);
  });

  it('port order matches document order', () => {
    const findings = parseNmapXml(XML_TWO_PORTS);
    const portFindings = findings.filter(f => f.category === 'port-service');
    expect(portFindings[0]!.serviceInfo!.port).toBe(22);
    expect(portFindings[1]!.serviceInfo!.port).toBe(6379);
  });
});
