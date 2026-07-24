import { API_BASE_URL, API_KEY } from './config.js';
import { getExecutionModeText, getScoreClass, sortRecommendations } from './helpers.js';

const elements = {
  sessionId: document.querySelector('#sessionId'),
  demoNotice: document.querySelector('#demoNotice'),
  authorizationBadge: document.querySelector('#authorizationBadge'),
  scanForm: document.querySelector('#scanForm'),
  target: document.querySelector('#target'),
  authorization: document.querySelector('#authorizationConfirmed'),
  scanButton: document.querySelector('#scanButton'),
  scanStep: document.querySelector('#scanStep'),
  analyzeStep: document.querySelector('#analyzeStep'),
  scanStatus: document.querySelector('#scanStatus'),
  nmapForm: document.querySelector('#nmapForm'),
  nmapOutput: document.querySelector('#nmapOutput'),
  nmapFile: document.querySelector('#nmapFile'),
  nmapButton: document.querySelector('#nmapButton'),
  nmapStatus: document.querySelector('#nmapStatus'),
  resultsPanel: document.querySelector('#resultsPanel'),
  executionMode: document.querySelector('#executionMode'),
  scoreGauge: document.querySelector('#scoreGauge'),
  riskScore: document.querySelector('#riskScore'),
  riskLevel: document.querySelector('#riskLevel'),
  findingsList: document.querySelector('#findingsList'),
  recommendationsList: document.querySelector('#recommendationsList'),
  refreshHistory: document.querySelector('#refreshHistory'),
  historyStatus: document.querySelector('#historyStatus'),
  scanHistory: document.querySelector('#scanHistory'),
  analysisHistory: document.querySelector('#analysisHistory'),
  correlateCheckbox: document.querySelector('#correlateWithScan'),
};

const sessionId = getOrCreateSessionId();
elements.sessionId.textContent = sessionId;
let demoStarted = false;
let lastScanFindings = null;

function getOrCreateSessionId() {
  const storageKey = 'centinelaia.sessionId';
  const stored = localStorage.getItem(storageKey);
  if (stored) return stored;
  const created = globalThis.crypto?.randomUUID?.() ?? `session-${Date.now()}`;
  localStorage.setItem(storageKey, created);
  return created;
}

async function requestJson(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        // Solo se envía el header de auth si hay una API key configurada.
        ...(API_KEY ? { 'x-api-key': API_KEY } : {}),
        ...(options.headers ?? {}),
      },
    });
  } catch {
    throw new Error('No se pudo conectar con la API. Inténtalo de nuevo.');
  }

  const rawBody = await response.text();
  let body;
  try {
    body = rawBody ? JSON.parse(rawBody) : null;
  } catch {
    throw new Error(`La API devolvió una respuesta no válida (HTTP ${response.status}).`);
  }
  if (!response.ok) throw new Error(body?.error ?? `La solicitud falló (HTTP ${response.status}).`);
  return body;
}

function setBusy(isBusy) {
  elements.scanButton.disabled = isBusy;
  elements.nmapButton.disabled = isBusy;
  elements.refreshHistory.disabled = isBusy;
}

function setProgress(stage) {
  elements.scanStep.className = stage === 'scan' ? 'active' : stage === 'analyze' || stage === 'done' ? 'complete' : '';
  elements.analyzeStep.className = stage === 'analyze' ? 'active' : stage === 'done' ? 'complete' : '';
}

function setStatus(element, message, isError = false) {
  element.textContent = message;
  element.classList.toggle('error', isError);
}

async function analyzeFindings(findings, sourceContext) {
  return requestJson('/analyze', {
    method: 'POST',
    body: JSON.stringify({ findings, sessionId, sourceContext }),
  });
}

function renderAnalysis(findings, analysis) {
  const score = Math.min(100, Math.max(0, Number(analysis.riskScore) || 0));
  const scoreClass = getScoreClass(score);
  elements.resultsPanel.hidden = false;
  elements.riskScore.textContent = String(score);
  elements.riskLevel.textContent = analysis.riskLevel ?? scoreClass;
  elements.executionMode.textContent = getExecutionModeText(analysis.metadata?.executionMode);
  elements.scoreGauge.className = `score-gauge ${scoreClass}`;
  elements.scoreGauge.setAttribute('aria-label', `Score de riesgo ${score} de 100`);

  const explanationByIndex = new Map(
    (analysis.explanations ?? []).map((explanation) => [explanation.findingIndex, explanation])
  );
  elements.findingsList.replaceChildren();
  findings.forEach((finding, index) => {
    const item = document.createElement('li');
    const heading = document.createElement('div');
    heading.className = 'finding-title';
    const category = document.createElement('strong');
    category.textContent = finding.category ?? 'Sin categoría';
    const severity = document.createElement('span');
    severity.className = 'severity';
    severity.textContent = finding.severity ?? 'unknown';
    heading.append(category, severity);

    const description = document.createElement('p');
    description.className = 'finding-description';
    description.textContent = finding.description ?? 'Sin descripción técnica.';
    const explanation = document.createElement('p');
    explanation.className = 'explanation';
    explanation.textContent = explanationByIndex.get(index)?.text ?? 'No hay explicación disponible.';
    item.append(heading, description, explanation);
    if (finding.rawValue) {
      const evidence = document.createElement('p');
      evidence.className = 'raw-value';
      evidence.textContent = `Evidencia: ${finding.rawValue}`;
      item.append(evidence);
    }
    elements.findingsList.append(item);
  });

  if (findings.length === 0) appendEmpty(elements.findingsList, 'No se detectaron hallazgos.');
  renderRecommendations(analysis.recommendations ?? []);
  elements.resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderRecommendations(recommendations) {
  elements.recommendationsList.replaceChildren();
  for (const recommendation of sortRecommendations(recommendations)) {
    const item = document.createElement('li');
    const title = document.createElement('strong');
    title.textContent = `${recommendation.priority ?? '—'}. ${recommendation.title ?? 'Recomendación'}`;
    const description = document.createElement('p');
    description.textContent = recommendation.description ?? 'Sin detalle disponible.';
    const metadata = document.createElement('span');
    metadata.className = 'recommendation-meta';
    const related = Array.isArray(recommendation.relatedFindings)
      ? recommendation.relatedFindings.join(', ')
      : '—';
    metadata.textContent = `Esfuerzo: ${recommendation.effort ?? 'sin estimar'} · Hallazgos: ${related}`;
    item.append(title, description, metadata);
    elements.recommendationsList.append(item);
  }
  if (recommendations.length === 0) {
    appendEmpty(elements.recommendationsList, 'No hay recomendaciones para este resultado.');
  }
}

function appendEmpty(list, message) {
  const item = document.createElement('li');
  item.className = 'empty';
  item.textContent = message;
  list.append(item);
}

async function runScannerFlow() {
  const target = elements.target.value.trim();
  if (!elements.authorization.checked) {
    setStatus(elements.scanStatus, 'Debes confirmar que tienes autorización.', true);
    elements.authorization.focus();
    return;
  }
  setBusy(true);
  setProgress('scan');
  setStatus(elements.scanStatus, 'Escaneando el objetivo…');
  try {
    const scan = await requestJson('/scan', {
      method: 'POST',
      body: JSON.stringify({ target, authorizationConfirmed: true, sessionId }),
    });
    // Guardar findings del scanner para correlación con Nmap
    lastScanFindings = scan.findings ?? [];
    setProgress('analyze');
    setStatus(elements.scanStatus, 'Interpretando los hallazgos…');
    const analysis = await analyzeFindings(scan.findings ?? [], `Escaneo web de ${target}`);
    renderAnalysis(scan.findings ?? [], analysis);
    setProgress('done');
    setStatus(elements.scanStatus, 'Análisis completado.');
  } catch (error) {
    setStatus(elements.scanStatus, error.message, true);
  } finally {
    setBusy(false);
    await refreshHistory();
  }
}

async function runNmapFlow() {
  setBusy(true);
  setStatus(elements.nmapStatus, 'Analizando la salida de Nmap…');
  try {
    // Usar el endpoint correlacionado: envía nmapOutput directo a /analyze
    // que traduce + analiza en una sola llamada.
    const payload = {
      findings: [],
      sessionId,
      nmapOutput: elements.nmapOutput.value,
    };

    // Si hay un escaneo reciente en memoria, correlacionar con esos findings
    if (lastScanFindings && lastScanFindings.length > 0 && elements.correlateCheckbox?.checked) {
      payload.findings = lastScanFindings;
      setStatus(elements.nmapStatus, 'Correlacionando con el último escaneo + Nmap…');
    }

    const analysis = await requestJson('/analyze', {
      method: 'POST',
      body: JSON.stringify(payload),
    });

    // Reconstruir la lista de findings para renderizar (directos + los de Nmap fusionados)
    const totalFindings = [...payload.findings];
    // Los findings de Nmap fueron fusionados en el backend; las explanations cubren todos
    // Agregamos placeholders para renderizar correctamente los índices de Nmap
    const nmapFindingsCount = (analysis.explanations?.length ?? 0) - payload.findings.length;
    for (let i = 0; i < nmapFindingsCount; i++) {
      totalFindings.push({
        category: 'server-fingerprint',
        severity: 'low',
        description: `Hallazgo #${payload.findings.length + i + 1} derivado de la salida de Nmap.`,
        rawValue: null,
      });
    }

    renderAnalysis(totalFindings, analysis);
    setStatus(elements.nmapStatus, 'Salida de Nmap analizada correctamente.');
  } catch (error) {
    setStatus(elements.nmapStatus, error.message, true);
  } finally {
    setBusy(false);
    await refreshHistory();
  }
}

function formatDate(value) {
  if (!value) return 'Fecha no disponible';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('es');
}

function renderScanHistory(scans) {
  elements.scanHistory.replaceChildren();
  for (const scan of scans) {
    const item = document.createElement('li');
    const title = document.createElement('strong');
    title.textContent = scan.target ?? 'Objetivo no disponible';
    const details = document.createElement('span');
    details.textContent = `${formatDate(scan.timestamp)} · ${scan.totalFindings ?? scan.findings?.length ?? 0} hallazgos · ${scan.status ?? 'sin estado'}`;
    item.append(title, details);
    elements.scanHistory.append(item);
  }
  if (scans.length === 0) appendEmpty(elements.scanHistory, 'Todavía no hay escaneos guardados.');
}

function renderAnalysisHistory(analyses) {
  elements.analysisHistory.replaceChildren();
  for (const analysis of analyses) {
    const item = document.createElement('li');
    const title = document.createElement('strong');
    title.textContent = `Score ${analysis.riskScore ?? '—'}/100 · ${analysis.riskLevel ?? 'sin nivel'}`;
    const details = document.createElement('span');
    details.textContent = `${formatDate(analysis.metadata?.timestamp)} · ${getExecutionModeText(analysis.metadata?.executionMode)}`;
    item.append(title, details);
    elements.analysisHistory.append(item);
  }
  if (analyses.length === 0) appendEmpty(elements.analysisHistory, 'Todavía no hay análisis guardados.');
}

async function refreshHistory() {
  setStatus(elements.historyStatus, 'Actualizando historial…');
  const encodedSession = encodeURIComponent(sessionId);
  const [scanResult, analysisResult] = await Promise.allSettled([
    requestJson(`/scan?sessionId=${encodedSession}`),
    requestJson(`/analyze?sessionId=${encodedSession}`),
  ]);

  if (scanResult.status === 'fulfilled') renderScanHistory(Array.isArray(scanResult.value) ? scanResult.value : []);
  else renderScanHistory([]);
  if (analysisResult.status === 'fulfilled') {
    renderAnalysisHistory(Array.isArray(analysisResult.value) ? analysisResult.value : []);
  } else renderAnalysisHistory([]);

  const failures = [scanResult, analysisResult].filter((result) => result.status === 'rejected').length;
  setStatus(
    elements.historyStatus,
    failures ? 'El análisis funciona, pero parte del historial no pudo cargarse.' : 'Historial actualizado.',
    failures > 0
  );
}

elements.scanForm.addEventListener('submit', (event) => {
  event.preventDefault();
  void runScannerFlow();
});

elements.nmapForm.addEventListener('submit', (event) => {
  event.preventDefault();
  void runNmapFlow();
});

elements.nmapFile.addEventListener('change', async () => {
  const [file] = elements.nmapFile.files ?? [];
  if (!file) return;
  try {
    elements.nmapOutput.value = await file.text();
    setStatus(elements.nmapStatus, `Archivo “${file.name}” cargado.`);
  } catch {
    setStatus(elements.nmapStatus, 'No se pudo leer el archivo seleccionado.', true);
  }
});

elements.refreshHistory.addEventListener('click', () => void refreshHistory());
void refreshHistory();

if (new URLSearchParams(window.location.search).get('demo') === '1' && !demoStarted) {
  demoStarted = true;
  elements.demoNotice.hidden = false;
  elements.authorizationBadge.hidden = false;
  elements.target.value = 'https://example.com';
  elements.authorization.checked = true;
  setStatus(elements.scanStatus, 'Demo autorizada preparada; iniciando análisis…');
  void runScannerFlow();
}
