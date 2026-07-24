/**
 * Tipos e interfaces comunes del módulo de escaneo.
 * Define el contrato que todo módulo de verificación debe cumplir,
 * así como la estructura de los hallazgos de seguridad.
 */

/**
 * Categorías válidas de hallazgos — una por módulo de verificación.
 */
export type FindingCategory =
  | 'http-headers'
  | 'tls-ssl'
  | 'cookies'
  | 'dns-security'
  | 'server-fingerprint'
  | 'log-analysis'
  | 'known-vulnerabilities';

/**
 * Niveles de severidad ordenados de mayor a menor impacto.
 */
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * Un hallazgo individual de seguridad.
 * Esta estructura es el "contrato" entre el scanner y el motor de IA (Spec 2).
 */
export interface Finding {
  category: FindingCategory;
  severity: FindingSeverity;
  rawValue: string | null;
  description: string; // 10-500 caracteres
}

/**
 * Configuración que recibe cada módulo de verificación.
 */
export interface ScanModuleInput {
  /** URL completa (con esquema) para verificaciones HTTP */
  targetUrl: string;
  /** Dominio extraído (sin esquema ni path) para verificaciones DNS/TLS */
  targetDomain: string | null;
  /** Si el target es una IP en vez de dominio */
  isIpAddress: boolean;
  /** Timeout en milisegundos para este módulo */
  timeoutMs: number;
}

/**
 * Interfaz que TODO módulo de verificación debe implementar.
 *
 * ¿Por qué una interfaz común?
 * → Permite al orquestador tratar todos los módulos de forma uniforme.
 * → Agregar un módulo nuevo = implementar esta interfaz + registrarlo.
 * → Cada módulo se puede probar de forma aislada pasándole un ScanModuleInput.
 */
export interface ScanModule {
  readonly name: string;
  readonly category: FindingCategory;
  run(input: ScanModuleInput): Promise<Finding[]>;
}
