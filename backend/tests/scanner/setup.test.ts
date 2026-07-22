/**
 * Smoke test — verifica que el entorno de testing está correctamente configurado.
 */
import { describe, it, expect } from 'vitest';

describe('Project setup', () => {
  it('should have vitest configured correctly', () => {
    expect(true).toBe(true);
  });

  it('should support ES2022 features', () => {
    // Verificar que structuredClone (ES2022) está disponible
    const original = { a: 1, b: { c: 2 } };
    const cloned = structuredClone(original);
    expect(cloned).toEqual(original);
    expect(cloned).not.toBe(original);
  });
});
