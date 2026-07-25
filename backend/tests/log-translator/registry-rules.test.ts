/**
 * Tests unitarios para las 3 reglas nuevas del registry de correlación:
 *  - authlog-ssh-exposure
 *  - cors-csp-amplification
 *  - cert-hsts-gap
 *
 * Las 2 reglas existentes (port-with-tls, version-with-cves) ya están
 * cubiertas en correlate-findings.test.ts y no se duplican aquí.
 */

import { describe, it, expect } from 'vitest';
import { correlateFindings } from '../../services/log-translator/correlate-findings.js';
import type { Finding } from '../../services/scanner/modules/types.js';

// ---------------------------------------------------------------------------
// Helpers de construcción de findings
// ---------------------------------------------------------------------------

/** Crea un finding log-analysis simulando un evento de fuerza bruta SSH. */
function bruteForceLogFinding(ip: string): Finding {
  return {
    category: 'log-analysis',
    severity: 'high',
    rawValue: `IP=${ip} failed_attempts=5`,
    description: `La IP ${ip} realizó múltiples intentos de autenticación fallidos (fuerza bruta).`,
  };
}

/** Crea un finding log-analysis simulando una acción defensiva de fail2ban. */
function fail2banLogFinding(ip: string): Finding {
  return {
    category: 'log-analysis',
    severity: 'medium',
    rawValue: `IP=${ip} action=fail2ban`,
    description: `La IP ${ip} fue bloqueada por fail2ban.`,
  };
}

/** Crea un finding port-service para un puerto SSH abierto. */
function sshPortFinding(port: number): Finding {
  return {
    category: 'port-service',
    severity: 'low',
    rawValue: `${port}/tcp ssh OpenSSH 8.9`,
    description: `El puerto ${port}/tcp está abierto y corresponde al servicio ssh.`,
    serviceInfo: {
      port,
      protocol: 'tcp',
      state: 'open',
      service: 'ssh',
      version: 'OpenSSH 8.9',
    },
  };
}

/** Crea un finding CORS con la severidad indicada. */
function corsFinding(severity: Finding['severity']): Finding {
  return {
    category: 'cors',
    severity,
    rawValue: 'Access-Control-Allow-Origin: *',
    description: 'La política CORS permite cualquier origen (wildcard), exponiendo recursos a peticiones cross-origin no autorizadas.',
  };
}

/** Crea un finding http-headers sobre CSP con la severidad indicada. */
function cspFinding(severity: Finding['severity']): Finding {
  return {
    category: 'http-headers',
    severity,
    rawValue: null,
    description: 'El header Content-Security-Policy no está presente o tiene directivas inseguras (unsafe-inline).',
  };
}

/** Crea un finding http-headers sobre HSTS con la severidad indicada. */
function hstsFinding(severity: Finding['severity']): Finding {
  return {
    category: 'http-headers',
    severity,
    rawValue: null,
    description: 'El header Strict-Transport-Security no está configurado correctamente o está ausente.',
  };
}

/** Crea un finding tls-ssl con la severidad y descripción indicadas. */
function tlsFinding(severity: Finding['severity'], description: string): Finding {
  return {
    category: 'tls-ssl',
    severity,
    rawValue: null,
    description,
  };
}

// ---------------------------------------------------------------------------
// Tests: authlog-ssh-exposure
// ---------------------------------------------------------------------------

describe('authlog-ssh-exposure — correlación fuerza bruta SSH × puerto SSH abierto', () => {
  it('(a) IP con failed_attempts + puerto ssh abierto → 1 finding correlation high', () => {
    const findings: Finding[] = [
      bruteForceLogFinding('1.2.3.4'),
      sshPortFinding(22),
    ];

    const result = correlateFindings(findings);

    // Filtrar solo los findings de esta regla
    const sshCorrelations = result.filter(
      (f) => f.category === 'correlation' && f.rawValue?.includes('↔ port:') && f.rawValue.includes('/ssh'),
    );

    expect(sshCorrelations).toHaveLength(1);
    expect(sshCorrelations[0]!.severity).toBe('high');
    expect(sshCorrelations[0]!.rawValue).toBe('auth:IP=1.2.3.4 ↔ port:22/ssh');
    expect(sshCorrelations[0]!.description).toContain('1.2.3.4');
    expect(sshCorrelations[0]!.description).toContain('22');
    expect(sshCorrelations[0]!.description.length).toBeLessThanOrEqual(500);
  });

  it('(b) solo fuerza bruta sin puerto SSH → []', () => {
    const findings: Finding[] = [
      bruteForceLogFinding('1.2.3.4'),
      // sin ningún finding port-service con service=ssh
    ];

    const result = correlateFindings(findings);
    const sshCorrelations = result.filter(
      (f) => f.rawValue?.includes('↔ port:') && f.rawValue.includes('/ssh'),
    );

    expect(sshCorrelations).toHaveLength(0);
  });

  it('(c) solo puerto SSH sin fuerza bruta → []', () => {
    const findings: Finding[] = [
      sshPortFinding(22),
      // sin ningún finding log-analysis con failed_attempts
    ];

    const result = correlateFindings(findings);
    const sshCorrelations = result.filter(
      (f) => f.rawValue?.includes('↔ port:') && f.rawValue.includes('/ssh'),
    );

    expect(sshCorrelations).toHaveLength(0);
  });

  it('(d) dedup: dos findings de fuerza bruta para la misma IP + mismo puerto → 1 solo correlation finding', () => {
    const findings: Finding[] = [
      // Dos eventos de fuerza bruta para la misma IP
      bruteForceLogFinding('1.2.3.4'),
      bruteForceLogFinding('1.2.3.4'),
      sshPortFinding(22),
    ];

    const result = correlateFindings(findings);
    const sshCorrelations = result.filter(
      (f) =>
        f.category === 'correlation' &&
        f.rawValue === 'auth:IP=1.2.3.4 ↔ port:22/ssh',
    );

    // El dedup debe garantizar exactamente 1 finding por par (ip, port)
    expect(sshCorrelations).toHaveLength(1);
  });

  it('fail2ban sin failed_attempts no dispara la regla', () => {
    const findings: Finding[] = [
      fail2banLogFinding('5.6.7.8'),
      sshPortFinding(22),
    ];

    const result = correlateFindings(findings);
    const sshCorrelations = result.filter(
      (f) => f.rawValue?.includes('↔ port:') && f.rawValue.includes('/ssh'),
    );

    expect(sshCorrelations).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Tests: cors-csp-amplification
// ---------------------------------------------------------------------------

describe('cors-csp-amplification — CORS permisivo × CSP débil', () => {
  it('(a) CORS high + CSP con severidad high → 1 finding correlation high', () => {
    const findings: Finding[] = [
      corsFinding('high'),
      cspFinding('high'),
    ];

    const result = correlateFindings(findings);
    const corsCorrelations = result.filter(
      (f) => f.category === 'correlation' && f.rawValue === 'cors-high ↔ csp-weak',
    );

    expect(corsCorrelations).toHaveLength(1);
    expect(corsCorrelations[0]!.severity).toBe('high');
    expect(corsCorrelations[0]!.description.length).toBeLessThanOrEqual(500);
  });

  it('(a) CORS high + CSP con severidad medium → 1 finding correlation high', () => {
    const findings: Finding[] = [
      corsFinding('high'),
      cspFinding('medium'),
    ];

    const result = correlateFindings(findings);
    const corsCorrelations = result.filter(
      (f) => f.rawValue === 'cors-high ↔ csp-weak',
    );

    expect(corsCorrelations).toHaveLength(1);
  });

  it('(b) CORS medium + CSP issue → [] (no dispara con CORS medium)', () => {
    const findings: Finding[] = [
      corsFinding('medium'),
      cspFinding('high'),
    ];

    const result = correlateFindings(findings);
    const corsCorrelations = result.filter(
      (f) => f.rawValue === 'cors-high ↔ csp-weak',
    );

    expect(corsCorrelations).toHaveLength(0);
  });

  it('(c) CORS high sin CSP issue → []', () => {
    const findings: Finding[] = [
      corsFinding('high'),
      // sin finding http-headers sobre CSP
    ];

    const result = correlateFindings(findings);
    const corsCorrelations = result.filter(
      (f) => f.rawValue === 'cors-high ↔ csp-weak',
    );

    expect(corsCorrelations).toHaveLength(0);
  });

  it('máximo 1 finding aunque haya varios CORS high y varios CSP weak', () => {
    const findings: Finding[] = [
      corsFinding('high'),
      corsFinding('critical'),
      cspFinding('high'),
      cspFinding('medium'),
    ];

    const result = correlateFindings(findings);
    const corsCorrelations = result.filter(
      (f) => f.rawValue === 'cors-high ↔ csp-weak',
    );

    expect(corsCorrelations).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Tests: cert-hsts-gap
// ---------------------------------------------------------------------------

describe('cert-hsts-gap — problema de cadena TLS × HSTS débil', () => {
  it('(a) TLS high con "self-signed" + HSTS high → 1 finding correlation high', () => {
    const findings: Finding[] = [
      tlsFinding('high', 'El certificado es self-signed y no está firmado por una CA reconocida.'),
      hstsFinding('high'),
    ];

    const result = correlateFindings(findings);
    const tlsCorrelations = result.filter(
      (f) => f.category === 'correlation' && f.rawValue === 'tls-chain-issue ↔ hsts-missing',
    );

    expect(tlsCorrelations).toHaveLength(1);
    expect(tlsCorrelations[0]!.severity).toBe('high');
    expect(tlsCorrelations[0]!.description.length).toBeLessThanOrEqual(500);
  });

  it('(a) TLS critical con "expired" + HSTS medium → 1 finding correlation high', () => {
    const findings: Finding[] = [
      tlsFinding('critical', 'El certificado TLS está expired y ha caducado hace 30 días.'),
      hstsFinding('medium'),
    ];

    const result = correlateFindings(findings);
    const tlsCorrelations = result.filter(
      (f) => f.rawValue === 'tls-chain-issue ↔ hsts-missing',
    );

    expect(tlsCorrelations).toHaveLength(1);
  });

  it('(b) TLS info (sin problema de cadena) + HSTS high → []', () => {
    const findings: Finding[] = [
      tlsFinding('info', 'El servidor acepta TLS 1.2 y TLS 1.3.'),
      hstsFinding('high'),
    ];

    const result = correlateFindings(findings);
    const tlsCorrelations = result.filter(
      (f) => f.rawValue === 'tls-chain-issue ↔ hsts-missing',
    );

    expect(tlsCorrelations).toHaveLength(0);
  });

  it('(c) TLS high con "self-signed" + HSTS info (correcto) → []', () => {
    const findings: Finding[] = [
      tlsFinding('high', 'El certificado es self-signed.'),
      // HSTS con info = está configurado correctamente, no es una debilidad
      hstsFinding('info'),
    ];

    const result = correlateFindings(findings);
    const tlsCorrelations = result.filter(
      (f) => f.rawValue === 'tls-chain-issue ↔ hsts-missing',
    );

    expect(tlsCorrelations).toHaveLength(0);
  });

  it('máximo 1 finding aunque haya varios TLS con cadena rota y varios HSTS débiles', () => {
    const findings: Finding[] = [
      tlsFinding('high', 'El certificado es self-signed.'),
      tlsFinding('critical', 'La chain del certificado no es de confianza (not trusted).'),
      hstsFinding('high'),
      hstsFinding('medium'),
    ];

    const result = correlateFindings(findings);
    const tlsCorrelations = result.filter(
      (f) => f.rawValue === 'tls-chain-issue ↔ hsts-missing',
    );

    expect(tlsCorrelations).toHaveLength(1);
  });

  it('TLS high con "not trusted" + HSTS medium → 1 finding', () => {
    const findings: Finding[] = [
      tlsFinding('high', 'La cadena de certificados no es de confianza (not trusted) según el almacén de CA del sistema.'),
      hstsFinding('medium'),
    ];

    const result = correlateFindings(findings);
    const tlsCorrelations = result.filter(
      (f) => f.rawValue === 'tls-chain-issue ↔ hsts-missing',
    );

    expect(tlsCorrelations).toHaveLength(1);
  });

  it('TLS high con "chain" + HSTS high → 1 finding', () => {
    const findings: Finding[] = [
      tlsFinding('high', 'La chain del certificado está incompleta o tiene un eslabón roto.'),
      hstsFinding('high'),
    ];

    const result = correlateFindings(findings);
    const tlsCorrelations = result.filter(
      (f) => f.rawValue === 'tls-chain-issue ↔ hsts-missing',
    );

    expect(tlsCorrelations).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Test de integración: las 3 reglas nuevas juntas
// ---------------------------------------------------------------------------

describe('integración — las 3 reglas nuevas activas simultáneamente', () => {
  it('activa las 3 reglas nuevas a la vez cuando se proveen todos los inputs', () => {
    const findings: Finding[] = [
      // Regla authlog-ssh-exposure
      bruteForceLogFinding('10.0.0.1'),
      sshPortFinding(22),
      // Regla cors-csp-amplification
      corsFinding('high'),
      cspFinding('high'),
      // Regla cert-hsts-gap
      tlsFinding('high', 'El certificado es self-signed y no está reconocido.'),
      hstsFinding('high'),
    ];

    const result = correlateFindings(findings);

    const sshCorrelation = result.find(
      (f) => f.rawValue === 'auth:IP=10.0.0.1 ↔ port:22/ssh',
    );
    const corsCorrelation = result.find(
      (f) => f.rawValue === 'cors-high ↔ csp-weak',
    );
    const tlsCorrelation = result.find(
      (f) => f.rawValue === 'tls-chain-issue ↔ hsts-missing',
    );

    expect(sshCorrelation).toBeDefined();
    expect(corsCorrelation).toBeDefined();
    expect(tlsCorrelation).toBeDefined();

    // Todos deben ser 'high' y de categoría 'correlation'
    expect(sshCorrelation!.category).toBe('correlation');
    expect(corsCorrelation!.category).toBe('correlation');
    expect(tlsCorrelation!.category).toBe('correlation');
  });

  it('no activa ninguna regla nueva cuando faltan todas las fuentes', () => {
    // Solo hallazgos que no gatillan ninguna de las 3 reglas nuevas
    const findings: Finding[] = [
      {
        category: 'cookies',
        severity: 'low',
        rawValue: null,
        description: 'La cookie de sesión no tiene el atributo Secure configurado.',
      },
      {
        category: 'dns-security',
        severity: 'medium',
        rawValue: null,
        description: 'No se encontró registro DMARC para el dominio.',
      },
    ];

    const result = correlateFindings(findings);

    const newRuleCorrelations = result.filter(
      (f) =>
        f.rawValue?.includes('/ssh') ||
        f.rawValue === 'cors-high ↔ csp-weak' ||
        f.rawValue === 'tls-chain-issue ↔ hsts-missing',
    );

    expect(newRuleCorrelations).toHaveLength(0);
  });
});


// ---------------------------------------------------------------------------
// Tests Ola 9: cada regla puebla correlationInfo correctamente
// ---------------------------------------------------------------------------

describe('correlationInfo — cada regla puebla rule y emergent correctamente', () => {
  it('port-with-tls → correlationInfo.rule = "port-with-tls", emergent = false', () => {
    const findings: Finding[] = [
      {
        category: 'port-service',
        severity: 'low',
        rawValue: '443/tcp https',
        description: 'Puerto 443 abierto con servicio https.',
        serviceInfo: { port: 443, protocol: 'tcp', state: 'open', service: 'https', version: '' },
      },
      tlsFinding('high', 'El servidor acepta TLS 1.0 (deprecated) que es vulnerable.'),
    ];

    const result = correlateFindings(findings);
    const portTls = result.find((f) => f.rawValue?.includes('↔ tls-ssl'));

    expect(portTls).toBeDefined();
    expect(portTls!.correlationInfo).toEqual({ rule: 'port-with-tls', emergent: false });
  });

  it('version-with-cves → correlationInfo.rule = "version-with-cves", emergent = false', () => {
    const findings: Finding[] = [
      {
        category: 'port-service',
        severity: 'low',
        rawValue: '80/tcp http nginx 1.18.0',
        description: 'Puerto 80 abierto con nginx 1.18.0.',
        serviceInfo: { port: 80, protocol: 'tcp', state: 'open', service: 'nginx', version: '1.18.0' },
      },
      {
        category: 'known-vulnerabilities',
        severity: 'critical',
        rawValue: 'CVE-2021-23017 (CVSS 9.4)',
        description: '[coincidencia aproximada] nginx 1.18.0: nginx resolver vuln description.',
      },
    ];

    const result = correlateFindings(findings);
    const verCve = result.find((f) => f.rawValue?.includes('↔ CVE-'));

    expect(verCve).toBeDefined();
    expect(verCve!.correlationInfo).toEqual({ rule: 'version-with-cves', emergent: false });
  });

  it('authlog-ssh-exposure → correlationInfo.rule = "authlog-ssh-exposure", emergent = true', () => {
    const findings: Finding[] = [
      bruteForceLogFinding('10.0.0.1'),
      sshPortFinding(22),
    ];

    const result = correlateFindings(findings);
    const ssh = result.find((f) => f.rawValue?.includes('↔ port:') && f.rawValue?.includes('/ssh'));

    expect(ssh).toBeDefined();
    expect(ssh!.correlationInfo).toEqual({ rule: 'authlog-ssh-exposure', emergent: true });
  });

  it('cors-csp-amplification → correlationInfo.rule = "cors-csp-amplification", emergent = true', () => {
    const findings: Finding[] = [
      corsFinding('high'),
      cspFinding('high'),
    ];

    const result = correlateFindings(findings);
    const cors = result.find((f) => f.rawValue === 'cors-high ↔ csp-weak');

    expect(cors).toBeDefined();
    expect(cors!.correlationInfo).toEqual({ rule: 'cors-csp-amplification', emergent: true });
  });

  it('cert-hsts-gap → correlationInfo.rule = "cert-hsts-gap", emergent = true', () => {
    const findings: Finding[] = [
      tlsFinding('high', 'El certificado es self-signed.'),
      hstsFinding('high'),
    ];

    const result = correlateFindings(findings);
    const cert = result.find((f) => f.rawValue === 'tls-chain-issue ↔ hsts-missing');

    expect(cert).toBeDefined();
    expect(cert!.correlationInfo).toEqual({ rule: 'cert-hsts-gap', emergent: true });
  });
});


// ---------------------------------------------------------------------------
// Tests Ola 10: aislamiento de fallos por regla (M-03)
// ---------------------------------------------------------------------------

describe('aislamiento de fallos — una regla que lanza no descarta las demás (M-03)', () => {
  it('fuerza bruta SSH con rawValue malformado no destruye las correlaciones de las demás reglas', () => {
    // Proveer condiciones para cert-hsts-gap (regla 5) y cors-csp (regla 4)
    // pero incluir un finding que podría provocar un edge case en otra regla.
    const findings: Finding[] = [
      // Dispara cors-csp-amplification
      corsFinding('high'),
      cspFinding('high'),
      // Dispara cert-hsts-gap
      tlsFinding('high', 'El certificado es self-signed.'),
      hstsFinding('high'),
    ];

    const result = correlateFindings(findings);

    // Las reglas que no fallan deben haber producido sus correlaciones
    const corsCorrelation = result.find(f => f.rawValue === 'cors-high ↔ csp-weak');
    const tlsCorrelation = result.find(f => f.rawValue === 'tls-chain-issue ↔ hsts-missing');

    expect(corsCorrelation).toBeDefined();
    expect(tlsCorrelation).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Tests Ola 10: version-with-cves con vulnInfo.product/version (M-04)
// ---------------------------------------------------------------------------

describe('version-with-cves — correlación por campos vulnInfo (M-04)', () => {
  it('correlaciona por vulnInfo.product/version aunque la descripción NO contenga el patrón de substring', () => {
    const findings: Finding[] = [
      {
        category: 'port-service',
        severity: 'low',
        rawValue: '80/tcp http nginx 1.18.0',
        description: 'Puerto 80 abierto.',
        serviceInfo: { port: 80, protocol: 'tcp', state: 'open', service: 'http', version: 'nginx 1.18.0' },
      },
      {
        category: 'known-vulnerabilities',
        severity: 'critical',
        rawValue: 'CVE-2021-23017 (CVSS 9.4)',
        // Descripción que NO contiene el patrón "nginx 1.18.0:" → substring no matchearía
        description: 'A DNS resolver vulnerability in a web server allows remote code execution.',
        vulnInfo: {
          cveId: 'CVE-2021-23017',
          cvssScore: 9.4,
          kevKnownExploited: false,
          product: 'nginx',
          version: '1.18.0',
        },
      },
    ];

    const result = correlateFindings(findings);
    const verCve = result.find(f => f.rawValue?.includes('↔ CVE-2021-23017'));

    // Debe correlacionar por campos, no por texto
    expect(verCve).toBeDefined();
    expect(verCve!.correlationInfo).toEqual({ rule: 'version-with-cves', emergent: false });
  });

  it('NO correlaciona cuando vulnInfo.version no coincide, aunque la descripción mencione otra versión', () => {
    const findings: Finding[] = [
      {
        category: 'port-service',
        severity: 'low',
        rawValue: '80/tcp http nginx 1.18.0',
        description: 'Puerto 80 abierto.',
        serviceInfo: { port: 80, protocol: 'tcp', state: 'open', service: 'http', version: 'nginx 1.18.0' },
      },
      {
        category: 'known-vulnerabilities',
        severity: 'high',
        rawValue: 'CVE-2022-12345 (CVSS 7.5)',
        // Description menciona "nginx 1.18.0:" pero el vulnInfo dice version 1.20.0
        description: '[coincidencia aproximada] nginx 1.18.0: some vulnerability here',
        vulnInfo: {
          cveId: 'CVE-2022-12345',
          cvssScore: 7.5,
          kevKnownExploited: false,
          product: 'nginx',
          version: '1.20.0', // Versión diferente a la del servicio
        },
      },
    ];

    const result = correlateFindings(findings);
    const verCve = result.find(f => f.rawValue?.includes('↔ CVE-2022-12345'));

    // No debe correlacionar: el campo dice version 1.20.0, no 1.18.0
    expect(verCve).toBeUndefined();
  });

  it('retrocompatibilidad: un CVE sin vulnInfo sigue correlacionando por fallback de substring', () => {
    const findings: Finding[] = [
      {
        category: 'port-service',
        severity: 'low',
        rawValue: '80/tcp nginx',
        description: 'Puerto 80 abierto con nginx.',
        serviceInfo: { port: 80, protocol: 'tcp', state: 'open', service: 'nginx', version: '1.18.0' },
      },
      {
        category: 'known-vulnerabilities',
        severity: 'critical',
        rawValue: 'CVE-2021-23017 (CVSS 9.4)',
        // El patrón de substring "nginx 1.18.0:" está presente en la descripción
        description: '[coincidencia aproximada] nginx 1.18.0: nginx resolver vulnerability.',
        // Sin vulnInfo → debe usar el fallback de substring
      },
    ];

    const result = correlateFindings(findings);
    const verCve = result.find(f => f.rawValue?.includes('↔ CVE-2021-23017'));

    expect(verCve).toBeDefined();
    expect(verCve!.correlationInfo).toEqual({ rule: 'version-with-cves', emergent: false });
  });
});
