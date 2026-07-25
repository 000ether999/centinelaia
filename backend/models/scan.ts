/**
 * Modelos de datos del resultado de escaneo.
 * Define la estructura del ScanResult completo, la evidencia de consentimiento
 * y el body esperado en las solicitudes de escaneo.
 */

import { Finding } from '../services/scanner/modules/types.js';

/**
 * Estados posibles del resultado de un escaneo.
 * - 'complete': todos los módulos terminaron sin errores ni timeouts.
 * - 'partial': al menos un módulo tuvo éxito, pero uno o más fallaron o
 *   agotaron su timeout; los hallazgos de esos módulos se reemplazan por
 *   findings informativos de error/timeout.
 * - 'unreachable': ningún módulo completó con éxito (todos fallaron o
 *   agotaron su timeout). Indica que el escaneo no pudo medir nada útil.
 */
export type ScanStatus = 'complete' | 'partial' | 'unreachable';

/**
 * Resultado completo de un escaneo de seguridad.
 */
export interface ScanResult {
  scanId: string;
  target: string;
  timestamp: string;
  durationMs: number;
  totalFindings: number;
  status: ScanStatus;
  sessionId: string;
  consent: ConsentEvidence;
  findings: Finding[];
  persisted: boolean;
  truncated?: boolean;
}

/**
 * Evidencia del consentimiento del usuario para escanear el target.
 */
export interface ConsentEvidence {
  authorizationConfirmed: boolean;
  target: string;
  confirmedAt: string; // ISO 8601
}

/**
 * Body esperado en la solicitud POST /scan.
 */
export interface ScanRequestBody {
  target: string;
  authorizationConfirmed: boolean;
  sessionId: string;
}
