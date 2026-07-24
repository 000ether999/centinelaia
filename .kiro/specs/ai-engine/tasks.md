# Implementation Plan: AI Engine (CentinelaIA)

## Overview

Implementación del módulo AI Engine como servicio compartido en `backend/services/ai-engine/`. El plan sigue un orden de dependencias: tipos e interfaces primero, luego componentes puros (sin I/O), después clientes de infraestructura, orquestador, handler HTTP, infraestructura SAM, y finalmente tests. Cada tarea es independientemente testeable y construye sobre las anteriores.

## Tasks

- [ ] 1. Definir tipos e interfaces del módulo
  - [x] 1.1 Crear archivo de tipos del AI Engine
    - Crear `backend/services/ai-engine/types.ts` con todas las interfaces y tipos: `AnalysisRequest`, `AnalysisResult`, `RiskLevel`, `Explanation`, `Recommendation`, `EffortLevel`, `AnalysisMetadata`, `AnalysisStatus`, `ErrorResponse`, `BedrockExpectedResponse`, `ValidationResult`
    - Importar `Finding`, `FindingCategory`, `FindingSeverity` desde `backend/services/scanner/modules/types.ts` (reutilizar, no duplicar)
    - Exportar todos los tipos para consumo externo del módulo
    - _Requirements: 1.1, 11.1, 11.2, 11.3, 11.6_

- [ ] 2. Implementar componentes puros (sin dependencias externas)
  - [ ] 2.1 Implementar el validador de entrada
    - Crear `backend/services/ai-engine/validator.ts`
    - Validar campos obligatorios: `findings` (array), `sessionId` (string no vacía)
    - Validar cada Finding: `category` en FindingCategory, `severity` en FindingSeverity, `description` entre 10-500 caracteres
    - Sanitizar `rawValue` y `description`: remover caracteres de control ASCII 0-31 (excepto \n y \t)
    - Truncar a 50 findings por severidad descendente si excede límite, marcar `truncated=true` y `truncatedCount`
    - Retornar `ValidationResult` con `valid`, `error`, y `sanitizedInput`
    - _Requirements: 1.2, 1.4, 1.5, 1.6, 7.3_

  - [ ] 2.2 Implementar la calculadora de Risk Score
    - Crear `backend/services/ai-engine/risk-score.ts`
    - Implementar pesos: critical=25, high=15, medium=8, low=3, info=0
    - Calcular score base: MIN(sum(peso × cantidad por severidad), 100)
    - Calcular factor de diversidad: +10% por categoría distinta con findings medium+, máx +50%
    - Aplicar tope final en 100, retornar entero
    - Determinar `riskLevel`: critical (81-100), high (61-80), moderate (41-60), low (21-40), minimal (0-20)
    - Garantizar determinismo: resultado independiente del orden de entrada
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6_

  - [ ] 2.3 Implementar el prompt builder
    - Crear `backend/services/ai-engine/prompts/analysis.ts` con el template principal como constante
    - Crear `backend/services/ai-engine/prompt-builder.ts` con función que construye el prompt final
    - Delimitar findings con tags XML `<findings_data>...</findings_data>`
    - Delimitar sourceContext con `<source_context>...</source_context>` si presente
    - Incluir instrucción anti-injection explícita
    - Incluir instrucciones de formato de salida JSON (campos esperados: explanations, recommendations)
    - Incluir en el Prompt_Template instrucciones de contenido para cada explicación: debe describir el problema en lenguaje simple sin jerga sin definir, indicar el impacto potencial para el usuario o su sitio, e indicar el nivel de urgencia relativo comparado con los demás hallazgos del mismo análisis
    - Inyectar findings serializados como JSON dentro del template
    - _Requirements: 2.2, 6.1, 6.2, 6.3, 6.4, 6.5, 7.1_

  - [ ] 2.4 Implementar el response parser
    - Crear `backend/services/ai-engine/response-parser.ts`
    - Extraer JSON de la respuesta de texto de Bedrock
    - Validar campos esperados (`explanations`, `recommendations`)
    - Descartar campos no declarados en el esquema (protección anti-injection)
    - Generar fallbacks para campos faltantes
    - Marcar resultado como `partial` si hay campos incompletos
    - _Requirements: 7.4, 9.2, 11.4_

  - [ ] 2.5 Implementar el generador de fallbacks (modo degradado)
    - Crear `backend/services/ai-engine/fallback-generator.ts`
    - Generar explicaciones genéricas basadas en severidad+categoría para cada Finding
    - Generar recomendaciones genéricas ordenadas por severidad
    - Agrupar findings de misma categoría en recomendaciones únicas
    - Respetar formato: texto en español, 50-500 chars para explanations, 50-300 para recommendations
    - Manejar caso especial: solo findings "info" → recomendación indicando configuración aceptable
    - _Requirements: 2.5, 9.1, 9.2_

  - [ ] 2.6 Implementar el priorizador de recomendaciones
    - Crear `backend/services/ai-engine/recommendation-prioritizer.ts`
    - Recibir las recomendaciones sin priorizar (de Bedrock o del fallback generator) junto con los Findings originales
    - Ordenar aplicando criterios del Requisito 4.2 en orden: (1) severidad del Finding más grave asociado a cada recomendación (critical > high > medium > low), descendente; (2) cantidad de Findings que resuelve la misma recomendación, descendente; (3) campo effort como desempate (quick-win < moderate < complex)
    - Asignar campo `priority` como entero secuencial 1 a N según el orden resultante
    - Si hay más de 10 recomendaciones tras ordenar, agrupar las de posiciones 11+ en una única Recommendation final con título "Otras mejoras menores", concatenando los relatedFindings de todas las agrupadas
    - Caso especial: si todos los Findings de entrada son severidad "info", retornar una única Recommendation con priority=1 indicando que no se requieren acciones correctivas inmediatas
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.6_

- [ ] 3. Checkpoint - Verificar componentes puros
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 4. Implementar clientes de infraestructura
  - [ ] 4.1 Implementar el Bedrock Client
    - Crear `backend/services/ai-engine/bedrock-client.ts`
    - Usar `@aws-sdk/client-bedrock-runtime` con `InvokeModelCommand`
    - Configuración: modelId desde env `BEDROCK_MODEL_ID` (default: `amazon.nova-micro-v1:0`), maxTokens desde env `BEDROCK_MAX_TOKENS` (default: 2048), temperature 0.3, timeout 6s por invocación
    - Implementar retry con backoff exponencial + jitter: 2 reintentos (3 intentos totales)
    - Retry solo para errores transitorios: ThrottlingException, ServiceUnavailableException, timeout, respuesta vacía
    - Propagar errores no transitorios sin retry (ValidationException, AccessDeniedException)
    - Aceptar `AbortSignal` del orchestrator para cancelación por timeout global
    - Abortar inmediatamente si recibe señal de cancelación
    - Registrar en logs eventos de throttling con timestamp, número de reintento, tiempo de espera
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 10.1, 10.2_

  - [ ] 4.2 Implementar el Cache Client
    - Crear `backend/services/ai-engine/cache-client.ts`
    - Calcular SHA-256 hash determinista: serializar findings ordenados por (category, severity, description), luego hash
    - Buscar resultado cacheado por hash en tabla `centinelaia-analysis-cache`
    - Verificar TTL (configurable via env `CACHE_TTL_MINUTES`, default 60 min)
    - Almacenar resultado nuevo con TTL (await con timeout de 2s, fail-open)
    - Fail-open: errores de lectura/escritura se loguean y se continúa
    - Garantizar hash idéntico para mismos findings en diferente orden
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6_

  - [ ] 4.3 Implementar el Persistence Client
    - Crear `backend/services/ai-engine/persistence-client.ts`
    - Generar `analysisId` (UUID v4)
    - Guardar `AnalysisResult` en tabla `centinelaia-analyses` con atributos: analysisId, sessionId, timestamp, findingsHash, result, expiresAt
    - Retry con backoff (max 2 reintentos)
    - Manejar límite de 400KB: truncar explanations de findings "info" si excede 390KB
    - Reportar `persisted: false` si falla sin bloquear respuesta
    - Await con timeout 2s, fail-open
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5_

- [ ] 5. Implementar el orquestador
  - [ ] 5.1 Implementar el orchestrator principal
    - Crear `backend/services/ai-engine/index.ts` como punto de entrada del módulo
    - Implementar timeout global de 25s con AbortController
    - Flujo: validar → calcular hash → buscar caché → construir prompt → invocar Bedrock → parsear respuesta → **priorizar recomendaciones** (invocar recommendation-prioritizer sobre las recomendaciones de Bedrock, parciales, o del fallback generator, pasando los Findings originales) → calcular score → ensamblar resultado → escribir caché (await 2s, fail-open) → persistir (await, fail-open) → retornar
    - Si timeout global alcanzado: abort Bedrock, forzar degradación inmediata
    - Si Bedrock falla tras reintentos: generar resultado degradado (fallback-generator) → priorizar recomendaciones genéricas
    - Caso findings vacío: retornar score 0, arrays vacíos, sin invocar Bedrock
    - Incluir metadata: timestamp, modelId, latencyMs, cached, status
    - Exponer como servicio importable (export de función `analyzeFindings`)
    - Usar dependency injection para Bedrock Client, Cache Client, Persistence Client (permitir mocks en tests)
    - _Requirements: 1.3, 2.1, 2.2, 2.3, 2.4, 4.5, 7.2, 9.1, 9.3, 9.4, 9.5, 11.1_

- [ ] 6. Implementar el Lambda Handler
  - [ ] 6.1 Crear el handler HTTP para análisis
    - Crear `backend/handlers/analyze-handler.ts`
    - Parsear evento API Gateway (body JSON)
    - Rutear: POST /analyze → invocar orchestrator, GET /analyze/{analysisId} → consultar por ID en DynamoDB, GET /analyze?sessionId= → consultar por session (máx 20 resultados, orden desc por timestamp)
    - Formatear respuestas HTTP: 200 con AnalysisResult, 400 para validación, 404 para no encontrado, 500 para errores internos
    - No exponer stack traces ni detalles internos en errores 500
    - Handler liviano: solo parsea y delega, sin lógica de negocio
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6_

- [ ] 7. Checkpoint - Verificar integración del módulo
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 8. Configurar infraestructura SAM
  - [ ] 8.1 Agregar recursos al template SAM
    - Modificar `infra/template.yaml` para agregar: AnalyzeFunction (Lambda, 29s timeout, 256MB), AnalysesTable (DynamoDB on-demand con GSI sessionId-timestamp-index y TTL), AnalysisCacheTable (DynamoDB on-demand con TTL)
    - Configurar eventos HTTP API: POST /analyze, GET /analyze/{analysisId}, GET /analyze (query sessionId)
    - Agregar políticas IAM: DynamoDBCrudPolicy para ambas tablas, bedrock:InvokeModel
    - Configurar variables de entorno: ANALYSES_TABLE, CACHE_TABLE, BEDROCK_MODEL_ID, BEDROCK_MAX_TOKENS, BEDROCK_TEMPERATURE, CACHE_TTL_MINUTES, ORCHESTRATOR_TIMEOUT_MS
    - Reutilizar la misma HttpApi existente (ScanHttpApi)
    - _Requirements: 5.1, 8.4, 12.1_

  - [ ] 8.2 Agregar dependencia npm de Bedrock Runtime
    - Agregar `@aws-sdk/client-bedrock-runtime` al package.json del proyecto
    - Verificar que `@aws-sdk/client-dynamodb` y `@aws-sdk/lib-dynamodb` ya existen o agregarlos
    - _Requirements: 5.1_

- [ ] 9. Implementar tests unitarios
  - [ ]* 9.1 Escribir tests del Risk Score
    - Crear `backend/tests/ai-engine/risk-score.test.ts`
    - Test: 3 findings "high" misma categoría → score = 45 (3×15), sin diversidad
    - Test: 2 critical + 3 high + 1 medium (categorías distintas) → score base + diversidad, tope 100
    - Test: arreglo vacío → score = 0, riskLevel = "minimal"
    - Test: determinismo — mismos findings en diferente orden → mismo score
    - _Requirements: 14.1_

  - [ ]* 9.2 Escribir tests del validador
    - Crear `backend/tests/ai-engine/validator.test.ts`
    - Test: Finding con severity "invalid" → rechazo con error indicando índice y razón
    - Test: 55 findings válidos → truncamiento a 50 por severidad, truncated=true, truncatedCount=5
    - Test: sessionId vacío → rechazo 400
    - Test: sanitización de caracteres de control en rawValue
    - _Requirements: 14.2_

  - [ ]* 9.3 Escribir tests de modo degradado
    - Crear `backend/tests/ai-engine/degraded-mode.test.ts`
    - Test: Mock de Bedrock que lanza error 3 veces → AnalysisResult con degraded=true, score correcto, fallback explanations
    - Test: Mock de Bedrock que retorna JSON parcial (solo explanations) → partial=true, recomendaciones genéricas
    - Usar mocks inyectados vía dependency injection
    - _Requirements: 14.3_

  - [ ]* 9.4 Escribir tests del hash de caché
    - Crear `backend/tests/ai-engine/cache-hash.test.ts`
    - Test: Dos arreglos con mismos 3 findings en orden distinto → hash SHA-256 idéntico
    - Test: Arreglos con findings distintos → hash diferente
    - _Requirements: 14.4_

  - [ ]* 9.5 Escribir tests de estructura de salida
    - Crear `backend/tests/ai-engine/output-structure.test.ts`
    - Test: AnalysisResult completo → JSON.stringify → JSON.parse → deepEqual al original
    - Test: Verificar campos obligatorios presentes en resultado completo y degradado
    - _Requirements: 14.5_

- [ ] 10. Checkpoint final - Verificar todo el módulo
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marcadas con `*` son opcionales y pueden saltarse para un MVP más rápido
- Cada task referencia requisitos específicos para trazabilidad
- Los checkpoints aseguran validación incremental
- El módulo usa Vitest exclusivamente para tests (sin fast-check ni property-based testing)
- La interfaz `Finding` se importa de `backend/services/scanner/modules/types.ts` — no se duplica
- El AI Engine se exporta como servicio importable (`analyzeFindings`) para invocación directa desde otros módulos
- Código en inglés, comentarios en español según convención del proyecto
- Modelo Bedrock por defecto: `amazon.nova-micro-v1:0` (menor costo en Bedrock)

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["2.1", "2.2", "2.3", "2.5", "2.6"] },
    { "id": 2, "tasks": ["2.4", "4.1", "4.2", "4.3"] },
    { "id": 3, "tasks": ["5.1"] },
    { "id": 4, "tasks": ["6.1", "8.1", "8.2"] },
    { "id": 5, "tasks": ["9.1", "9.2", "9.3", "9.4", "9.5"] }
  ]
}
```
