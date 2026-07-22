# Implementation Plan: Scanner Module (CentinelaIA)

## Overview

Plan de implementación incremental del módulo Scanner. Cada tarea construye sobre la anterior, empezando por la estructura del proyecto y tipos base, luego la lógica de negocio (validador → orquestador → módulos → store), y finalmente el handler Lambda que conecta todo. Los tests se incluyen como sub-tareas opcionales junto a cada componente.

## Tasks

- [x] 1. Scaffold del proyecto y configuración base
  - [x] 1.1 Crear estructura de directorios, package.json, tsconfig.json y vitest.config.ts
    - Crear `backend/` con subdirectorios: `handlers/`, `services/scanner/modules/`, `models/`, `tests/scanner/`
    - Crear `infra/` para la plantilla SAM
    - Inicializar `package.json` con dependencias: typescript, vitest, @types/node, @aws-sdk/lib-dynamodb, @aws-sdk/client-dynamodb, aws-lambda, @types/aws-lambda, uuid, @types/uuid
    - Configurar `tsconfig.json` con target ES2022, module NodeNext, strict mode
    - Configurar `vitest.config.ts` con globals: true, environment: node
    - _Requirements: 14.6_

  - [x] 1.2 Crear template.yaml de AWS SAM con Lambda, API Gateway HTTP y DynamoDB
    - Definir ScanFunction (nodejs20.x, 30s timeout, 256MB)
    - Definir ScanHttpApi con throttling (5 req/s, burst 10) en POST /scan
    - Definir ScansTable con PK scanId y GSI sessionId-timestamp-index
    - Configurar rutas: POST /scan, GET /scan/{scanId}, GET /scan
    - _Requirements: 11.1, 11.2, 11.7_

- [x] 2. Modelos de datos e interfaces comunes
  - [x] 2.1 Crear tipos e interfaces en `backend/services/scanner/modules/types.ts` y `backend/models/scan.ts`
    - Definir FindingCategory, FindingSeverity, Finding, ScanModuleInput, ScanModule en types.ts
    - Definir ScanStatus, ScanResult, ConsentEvidence, ScanRequestBody en scan.ts
    - Exportar todo desde `backend/services/scanner/index.ts`
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 12.1_

- [x] 3. Validador de entrada y prevención de SSRF
  - [x] 3.1 Implementar `backend/services/scanner/validator.ts`
    - Implementar `validateScanRequest(body)`: verificar campos requeridos (target, authorizationConfirmed, sessionId), formato JSON, authorization === true
    - Implementar `validateTarget(target)`: validar URL con esquema HTTP/HTTPS, dominio sin esquema (aplicar HTTPS por defecto), IP (IPv4/IPv6), longitud ≤ 2048, extraer dominio
    - Implementar `resolveAndCheckIp(targetDomain, targetIp)`: resolver DNS, verificar que ninguna IP pertenezca a rangos privados/loopback/link-local/reservados. **Exportar como función standalone reutilizable** para que los módulos que siguen redirecciones (Header Analyzer, Cookie Inspector) puedan invocarla en cada salto
    - Retornar ValidationResult con datos normalizados o error con código y mensaje específico
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 10.4_

  - [x]* 3.2 Escribir unit tests para el validador en `backend/tests/scanner/validator.test.ts`
    - Test: target válido (URL HTTPS) → accepted con datos normalizados
    - Test: target vacío → error 400 "Field 'target' is required"
    - Test: target > 2048 chars → error 400 longitud excedida
    - Test: esquema ftp:// → error 400 esquema no soportado
    - Test: authorizationConfirmed = false → error 403
    - Test: IP privada 192.168.1.1 → error 400 SSRF
    - Test: IP loopback 127.0.0.1 → error 400 SSRF
    - Test: dominio sin esquema → normaliza con HTTPS
    - Usar mocks para `dns.promises.resolve` (no conexiones reales)
    - _Requirements: 1.2, 2.2, 3.1, 14.6_

- [x] 4. Orquestador de escaneo
  - [x] 4.1 Implementar `backend/services/scanner/orchestrator.ts`
    - Implementar `executeScan(input, config)`: ejecutar módulos con `Promise.allSettled`
    - Implementar timeout individual por módulo (5s default) con AbortController
    - Implementar timeout global (25s safety margin) que cancela módulos pendientes
    - Capturar excepciones de módulos → generar Finding de error con severity "info"
    - Capturar timeouts de módulos → generar Finding con severity "low"
    - Determinar status: "complete" si todos OK, "partial" si alguno falló/timeout, "unreachable" si no hay conexión inicial
    - Generar ScanResult con scanId (uuid), timestamp, durationMs, totalFindings, findings
    - _Requirements: 12.2, 12.3, 12.4, 13.1, 13.2, 13.3, 13.4, 9.4, 9.5_

  - [x]* 4.2 Escribir unit tests para el orquestador en `backend/tests/scanner/orchestrator.test.ts`
    - Test: todos los módulos exitosos → status "complete", findings agregados
    - Test: un módulo lanza excepción → status "partial", Finding de error generado, otros módulos completan
    - Test: módulo excede timeout individual → Finding de timeout generado, otros módulos completan
    - Test: timeout global (25s) → módulos pendientes cancelados, status "partial"
    - Usar módulos mock que implementen ScanModule
    - _Requirements: 12.4, 13.1, 13.3, 13.4, 14.6_

- [x] 5. Checkpoint - Verificar base funcional
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. Módulos de verificación — Header Analyzer y Fingerprinter
  - [x] 6.1 Implementar `backend/services/scanner/modules/header-analyzer.ts`
    - Crear factory `createHeaderAnalyzer()` que retorna ScanModule
    - Hacer GET al targetUrl con redirecciones automáticas DESHABILITADAS (`redirect: 'manual'`)
    - Al recibir respuesta 3xx con header Location: extraer host/IP de destino, llamar a `resolveAndCheckIp()` para validar que no sea IP privada/reservada. Si la IP es válida, seguir la redirección manualmente. Si la IP es prohibida, abortar el seguimiento y generar Finding con severity "medium", categoría "http-headers", indicando que se bloqueó una redirección SSRF
    - Verificar 7 headers de seguridad: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy, X-XSS-Protection
    - Generar Finding por header ausente con severidad según config (high/medium/low)
    - Generar Finding por header con valor inseguro (severity "medium")
    - Generar Finding por header con valor seguro (severity "info")
    - _Requirements: 2.5, 4.1, 4.2, 4.3, 4.4, 4.6, 12.1_

  - [x] 6.2 Implementar `backend/services/scanner/modules/fingerprinter.ts`
    - Crear factory `createFingerprinter()` que retorna ScanModule
    - Hacer GET al targetUrl con redirecciones automáticas DESHABILITADAS (`redirect: 'manual'`)
    - Al recibir respuesta 3xx con header Location: extraer host/IP de destino, llamar a `resolveAndCheckIp()` para validar que no sea IP privada/reservada. Si la IP es válida, seguir la redirección manualmente. Si la IP es prohibida, abortar el seguimiento y generar Finding con severity "medium", categoría "server-fingerprint", indicando que se bloqueó una redirección SSRF
    - Examinar headers: Server, X-Powered-By, X-AspNet-Version, X-Generator
    - Generar Finding severity "low" por cada header con valor presente
    - Generar Finding severity "info" si ningún header divulga tecnología
    - Manejar error de conexión → Finding severity "info" con error
    - _Requirements: 2.5, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 12.1_

  - [ ]* 6.3 Escribir unit tests para Header Analyzer y Fingerprinter
    - Header Analyzer: test header presente+seguro → Finding "info"
    - Header Analyzer: test header ausente → Finding con severidad correcta (high/medium/low)
    - Header Analyzer: test header inseguro (CSP con unsafe-inline) → Finding "medium"
    - Header Analyzer: test redirección a IP privada (169.254.169.254) → Finding "medium" de bloqueo SSRF generado, escaneo continúa con headers de la respuesta previa
    - Fingerprinter: test Server + X-Powered-By presentes → Findings "low"
    - Fingerprinter: test sin headers de tecnología → Finding "info"
    - Fingerprinter: test redirección a IP privada (10.0.0.1) → Finding "medium" categoría "server-fingerprint" de bloqueo SSRF generado, escaneo continúa
    - Mockear `http.get` / `fetch` para respuestas simuladas (incluyendo 302 con Location a IP interna)
    - _Requirements: 2.5, 14.1, 14.5, 14.6_

- [x] 7. Módulos de verificación — TLS Checker y Cookie Inspector
  - [x] 7.1 Implementar `backend/services/scanner/modules/tls-checker.ts`
    - Crear factory `createTlsChecker()` que retorna ScanModule
    - Usar `tls.connect()` nativo para verificar versiones de protocolo (TLS 1.0-1.3)
    - Reportar SSLv2/SSLv3 como "info" (no testable directamente desde Node 20)
    - Analizar cipher suites via `socket.getCipher()` → Finding "high" para cifrados inseguros
    - Verificar certificado: expiración, cadena de confianza, coincidencia de dominio via `socket.getPeerCertificate()`
    - Manejar timeout de conexión → Finding "critical"
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9, 5.10, 5.11, 12.1_

  - [x] 7.2 Implementar `backend/services/scanner/modules/cookie-inspector.ts`
    - Crear factory `createCookieInspector()` que retorna ScanModule
    - Hacer GET al targetUrl con redirecciones automáticas DESHABILITADAS (`redirect: 'manual'`)
    - Seguir redirecciones manualmente hasta 5 saltos: al recibir 3xx con Location, extraer host/IP de destino, llamar a `resolveAndCheckIp()` para validar. Si la IP es válida, seguir. Si la IP es prohibida, abortar la cadena de redirecciones y generar Finding con severity "medium", categoría "cookies", indicando bloqueo SSRF; analizar cookies recolectadas hasta ese punto
    - Parsear headers Set-Cookie de todas las respuestas acumuladas (max 50 cookies)
    - Verificar flags: Secure, HttpOnly, SameSite por cada cookie
    - Generar Finding "medium" por cada flag ausente
    - Generar Finding "info" si no hay cookies
    - Generar Finding "low" si cookie malformada no se puede parsear
    - _Requirements: 2.5, 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 12.1_

  - [ ]* 7.3 Escribir unit tests para TLS Checker y Cookie Inspector
    - TLS: test protocolo obsoleto (TLS 1.0) → Finding "high"
    - TLS: test certificado expirado → Finding "critical"
    - TLS: test configuración válida → Finding "info"
    - Cookie: test cookie sin Secure/HttpOnly/SameSite → Findings "medium"
    - Cookie: test cookie con todos los flags → sin Findings superiores a "info"
    - Cookie: test redirección a IP privada (127.0.0.1) en segundo salto → Finding "medium" de bloqueo SSRF generado, cookies del primer salto analizadas normalmente
    - Mockear `tls.connect` y `http.get` (no conexiones reales); mockear `resolveAndCheckIp` para simular IP prohibida
    - _Requirements: 2.5, 14.2, 14.3, 14.6_

- [x] 8. Módulo de verificación — DNS Checker
  - [x] 8.1 Implementar `backend/services/scanner/modules/dns-checker.ts`
    - Crear factory `createDnsChecker()` que retorna ScanModule
    - Si `input.isIpAddress === true`, retornar Finding "info" indicando que DNS no aplica para IPs
    - Usar `dns.promises.resolveTxt(domain)` para buscar registro SPF (prefijo "v=spf1")
    - Consultar `_dmarc.<domain>` para DMARC (prefijo "v=DMARC1")
    - Verificar DKIM en selectores: "default", "google", "selector1", "selector2"
    - Usar AbortController con timeout de 5s por consulta
    - Generar Findings según severidad: sin SPF → "high", SPF +all → "high", sin DMARC → "high", DMARC p=none → "medium", DKIM encontrado → "info", DKIM no encontrado → "medium"
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8, 1.5, 12.1_

  - [ ]* 8.2 Escribir unit tests para DNS Checker
    - Test: dominio sin registro SPF → Finding "high"
    - Test: registro DMARC con p=none → Finding "medium"
    - Test: DKIM encontrado en selector "google" → Finding "info"
    - Mockear `dns.promises.resolveTxt` con respuestas simuladas
    - _Requirements: 14.4, 14.6_

- [x] 9. Checkpoint - Verificar módulos de escaneo
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 10. Store de DynamoDB
  - [ ] 10.1 Implementar `backend/services/scanner/store.ts`
    - Crear `createDynamoStore(tableName)` que retorna ScanStore
    - Implementar `put(result)`: PutItem con reintentos (max 2) y backoff exponencial (100ms → 400ms)
    - Implementar truncamiento si item > 390KB: recortar rawValue de Findings "info", agregar `truncated: true`
    - Implementar `get(scanId)`: GetItem por partition key
    - Implementar `listBySession(sessionId)`: Query en GSI sessionId-timestamp-index, ScanIndexForward=false, Limit=50
    - Retornar `{ persisted: false }` si falla tras reintentos (no lanzar excepción)
    - _Requirements: 10.1, 10.2, 10.3, 10.5, 10.6_

  - [ ]* 10.2 Escribir unit tests para el store en `backend/tests/scanner/store.test.ts`
    - Test: put exitoso → persisted: true
    - Test: put falla 3 veces (2 reintentos) → persisted: false
    - Test: get con scanId existente → retorna ScanResult
    - Test: get con scanId inexistente → retorna null
    - Test: listBySession → retorna array ordenado por timestamp desc
    - Mockear @aws-sdk/lib-dynamodb (DynamoDBDocumentClient)
    - _Requirements: 10.1, 10.5, 14.6_

- [ ] 11. Lambda Handler — Integración final
  - [ ] 11.1 Implementar `backend/handlers/scan-handler.ts`
    - Parsear APIGatewayProxyEvent: extraer method + path
    - Ruta POST /scan: parsear body JSON → validateScanRequest → resolveAndCheckIp → executeScan → store.put → responder 200
    - Ruta GET /scan/{scanId}: store.get → responder 200 o 404
    - Ruta GET /scan?sessionId=X: store.listBySession → responder 200
    - Construir ConsentEvidence al iniciar escaneo exitoso
    - Manejar errores: 400 (validación), 403 (authorization), 500 (inesperado)
    - Registrar módulos: createHeaderAnalyzer, createTlsChecker, createCookieInspector, createDnsChecker, createFingerprinter
    - Configurar OrchestratorConfig con moduleTimeoutMs=5000, globalTimeoutMs=25000
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7, 3.3, 3.4_

  - [ ]* 11.2 Escribir unit tests para el handler en `backend/tests/scanner/handler.test.ts`
    - Test: POST /scan con body válido → 200 con ScanResult
    - Test: POST /scan sin authorizationConfirmed → 403
    - Test: POST /scan con target inválido → 400
    - Test: GET /scan/{scanId} existente → 200
    - Test: GET /scan/{scanId} inexistente → 404
    - Mockear orchestrator y store para aislar handler
    - _Requirements: 11.1, 11.2, 11.3, 11.6, 14.6_

- [ ] 12. Checkpoint final - Verificar integración completa
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marcadas con `*` son opcionales y pueden saltarse para un MVP más rápido
- Cada tarea referencia requisitos específicos para trazabilidad
- Los checkpoints aseguran validación incremental
- No se incluyen property-based tests (decisión de diseño: PBT queda para post-hackathon)
- Unit tests usan mocks/fixtures — nunca conexiones reales de red (Req 14.6)
- Código en inglés, comentarios de alto nivel en español (steering tech.md)
- Stack: TypeScript + Vitest + AWS SAM + Node.js 20

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2"] },
    { "id": 1, "tasks": ["2.1"] },
    { "id": 2, "tasks": ["3.1", "4.1"] },
    { "id": 3, "tasks": ["3.2", "4.2"] },
    { "id": 4, "tasks": ["6.1", "6.2", "7.1", "7.2", "8.1"] },
    { "id": 5, "tasks": ["6.3", "7.3", "8.2", "10.1"] },
    { "id": 6, "tasks": ["10.2", "11.1"] },
    { "id": 7, "tasks": ["11.2"] }
  ]
}
```
