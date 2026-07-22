/**
 * Punto de entrada público del módulo scanner.
 * Re-exporta todos los tipos para que los consumidores puedan importar
 * desde un único lugar: import { ... } from '../services/scanner/index.js'
 */

export type {
  FindingCategory,
  FindingSeverity,
  Finding,
  ScanModuleInput,
  ScanModule,
} from './modules/types.js';

export type {
  ScanStatus,
  ScanResult,
  ConsentEvidence,
  ScanRequestBody,
} from '../../models/scan.js';

export {
  validateScanRequest,
  validateTarget,
  resolveAndCheckIp,
} from './validator.js';

export type { ValidationResult } from './validator.js';
