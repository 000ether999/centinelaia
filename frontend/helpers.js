const MODE_LABELS = Object.freeze({
  bedrock: 'Análisis con Amazon Nova',
  mock: 'Modo de simulación',
  fallback: 'Análisis básico — IA temporalmente no disponible',
});

export function getExecutionModeText(mode) {
  return MODE_LABELS[mode] ?? 'Origen del análisis no disponible';
}

export function getScoreClass(score) {
  const normalizedScore = Number.isFinite(Number(score)) ? Number(score) : 0;
  if (normalizedScore >= 81) return 'critical';
  if (normalizedScore >= 61) return 'high';
  if (normalizedScore >= 41) return 'moderate';
  if (normalizedScore >= 21) return 'low';
  return 'minimal';
}

export function sortRecommendations(recommendations = []) {
  return [...recommendations].sort((left, right) => {
    const leftPriority = Number.isFinite(Number(left?.priority)) ? Number(left.priority) : Infinity;
    const rightPriority = Number.isFinite(Number(right?.priority)) ? Number(right.priority) : Infinity;
    return leftPriority - rightPriority;
  });
}
