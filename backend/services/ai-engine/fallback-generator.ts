/**
 * Generador de fallbacks (modo degradado) del AI Engine.
 * Produce explicaciones y recomendaciones genéricas basadas en severidad
 * y categoría cuando Bedrock no está disponible o responde de forma parcial.
 */

import type { Finding, FindingCategory, FindingSeverity } from '../scanner/modules/types.js';
import type { Explanation, Recommendation, EffortLevel } from './types.js';

// ─── Mapas de texto genérico por categoría ───────────────────────────────────

const CATEGORY_DESCRIPTIONS: Record<FindingCategory, string> = {
  'http-headers': 'configuración de cabeceras de seguridad HTTP',
  'tls-ssl': 'configuración de cifrado TLS/SSL',
  'cookies': 'configuración de cookies',
  'dns-security': 'registros DNS de seguridad',
  'server-fingerprint': 'exposición de información del servidor',
  'port-service': 'servicio de red detectado en un puerto abierto',
  'cors': 'configuración CORS (Cross-Origin Resource Sharing)',
  'http-methods': 'métodos HTTP habilitados',
  'security-txt': 'publicación de security.txt (RFC 9116)',
  'log-analysis': 'eventos de seguridad en logs de autenticación',
  'known-vulnerabilities': 'vulnerabilidades conocidas (CVE) en software detectado',
  'correlation': 'coincidencias detectadas entre distintas fuentes de información (scanner y logs)',
  'security-exposure': 'exposición de recursos sensibles del servidor',
};

const CATEGORY_RECOMMENDATIONS: Record<FindingCategory, string> = {
  'http-headers': 'Revisar y corregir las cabeceras de seguridad HTTP ausentes o mal configuradas (Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, etc.).',
  'tls-ssl': 'Actualizar la configuración TLS del servidor para usar protocolos y cifrados modernos, y renovar certificados si es necesario.',
  'cookies': 'Agregar los atributos de seguridad (Secure, HttpOnly, SameSite) a las cookies del sitio.',
  'dns-security': 'Configurar los registros DNS de seguridad (SPF, DKIM, DMARC) en el proveedor de dominio.',
  'server-fingerprint': 'Ocultar la información de versión del servidor y frameworks en las respuestas HTTP.',
  'port-service': 'Cerrar o filtrar puertos innecesarios y mantener el software del servicio actualizado a la última versión estable.',
  'cors': 'Restringir Access-Control-Allow-Origin a orígenes confiables específicos y no combinar wildcard (*) con credenciales.',
  'http-methods': 'Deshabilitar métodos HTTP peligrosos (TRACE, PUT, DELETE, CONNECT) en el servidor si no son necesarios para la aplicación.',
  'security-txt': 'Publicar un archivo /.well-known/security.txt con información de contacto de seguridad según RFC 9116.',
  'log-analysis': 'Endurecer el acceso SSH: deshabilitar login de root, usar autenticación por llaves en lugar de contraseñas, configurar fail2ban para bloqueo automático y limitar las IPs que pueden conectarse al servicio.',
  'known-vulnerabilities': 'actualizar/parchear el software a una versión que corrija la vulnerabilidad; revisar el aviso del CVE',
  'correlation': 'Revisar en conjunto los hallazgos relacionados entre fuentes: suelen indicar el mismo servicio o vulnerabilidad vista desde ángulos distintos, por lo que priorizar su corrección reduce el riesgo en múltiples frentes a la vez.',
  'security-exposure': 'Bloquear o eliminar el acceso a rutas sensibles (.git, .env, phpinfo.php) mediante reglas del servidor web o eliminando los archivos del directorio público.',
};

const SEVERITY_URGENCY: Record<FindingSeverity, string> = {
  critical: 'urgencia máxima — requiere atención inmediata',
  high: 'urgencia alta — se recomienda corregir lo antes posible',
  medium: 'urgencia moderada — planificar corrección a corto plazo',
  low: 'urgencia baja — mejorable cuando sea conveniente',
  info: 'informativo — no requiere acción inmediata',
};

const SEVERITY_EFFORT: Record<FindingSeverity, EffortLevel> = {
  critical: 'moderate',
  high: 'moderate',
  medium: 'quick-win',
  low: 'quick-win',
  info: 'quick-win',
};

/** Orden de severidad para priorización (menor número = más grave) */
const SEVERITY_PRIORITY: Record<FindingSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/**
 * Genera explicaciones genéricas (fallback) para cada finding.
 * Cada explicación describe el problema basándose en la severidad y categoría.
 */
export function generateFallbackExplanations(findings: Finding[]): Explanation[] {
  return findings.map((finding, index) => {
    const categoryDesc = CATEGORY_DESCRIPTIONS[finding.category];
    const urgency = SEVERITY_URGENCY[finding.severity];

    const text = `Se detectó un problema de seguridad de nivel ${finding.severity} en la categoría de ${categoryDesc}. ` +
      `${finding.description} ` +
      `Nivel de ${urgency}.`;

    // Asegurar que el texto esté entre 50-500 caracteres
    const trimmedText = text.length > 500 ? text.slice(0, 497) + '...' : text;

    return {
      findingIndex: index,
      text: trimmedText,
      fallback: true,
    };
  });
}

/**
 * Genera recomendaciones genéricas agrupadas por categoría.
 * Las recomendaciones se ordenan por la severidad más alta de cada grupo.
 */
export function generateFallbackRecommendations(findings: Finding[]): Recommendation[] {
  // Caso especial: solo findings "info"
  const allInfo = findings.every((f) => f.severity === 'info');
  if (allInfo) {
    return [
      {
        priority: 1,
        title: 'Configuración aceptable',
        description: 'No se requieren acciones correctivas inmediatas. Los hallazgos detectados son informativos y la configuración actual es aceptable.',
        effort: 'quick-win',
        relatedFindings: findings.map((_, i) => i),
      },
    ];
  }

  // Agrupar findings por categoría
  const categoryGroups = new Map<FindingCategory, { indices: number[]; maxSeverity: FindingSeverity }>();

  for (let i = 0; i < findings.length; i++) {
    const finding = findings[i];
    const existing = categoryGroups.get(finding.category);

    if (existing) {
      existing.indices.push(i);
      // Actualizar maxSeverity si la actual es más grave
      if (SEVERITY_PRIORITY[finding.severity] < SEVERITY_PRIORITY[existing.maxSeverity]) {
        existing.maxSeverity = finding.severity;
      }
    } else {
      categoryGroups.set(finding.category, {
        indices: [i],
        maxSeverity: finding.severity,
      });
    }
  }

  // Convertir a recomendaciones y ordenar por severidad del grupo
  const recommendations: Recommendation[] = [...categoryGroups.entries()]
    .sort((a, b) => SEVERITY_PRIORITY[a[1].maxSeverity] - SEVERITY_PRIORITY[b[1].maxSeverity])
    .map(([category, group]) => ({
      priority: 0, // se asigna después
      title: `Corregir ${CATEGORY_DESCRIPTIONS[category]}`,
      description: CATEGORY_RECOMMENDATIONS[category],
      effort: SEVERITY_EFFORT[group.maxSeverity],
      relatedFindings: group.indices,
    }));

  // Asignar prioridad secuencial
  recommendations.forEach((rec, idx) => {
    rec.priority = idx + 1;
  });

  return recommendations;
}
