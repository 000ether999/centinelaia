import { describe, expect, it } from 'vitest';
import {
  getExecutionModeText,
  getScoreClass,
  sortRecommendations,
} from '../../../frontend/helpers.js';

describe('helpers de presentación del frontend', () => {
  it('presenta el origen honestamente, clasifica el score y ordena prioridades', () => {
    expect(getExecutionModeText('bedrock')).toBe('Análisis con Amazon Nova');
    expect(getExecutionModeText('mock')).toBe('Modo de simulación');
    expect(getExecutionModeText('fallback')).toBe(
      'Análisis básico — IA temporalmente no disponible'
    );
    expect(getScoreClass(81)).toBe('critical');
    expect(getScoreClass(20)).toBe('minimal');
    expect(sortRecommendations([{ priority: 3 }, { priority: 1 }, { priority: 2 }]))
      .toEqual([{ priority: 1 }, { priority: 2 }, { priority: 3 }]);
  });
});
