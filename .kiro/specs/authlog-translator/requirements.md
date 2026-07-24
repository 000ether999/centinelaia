# Requirements Document

## Introduction

Esta feature agrega un traductor de logs de autenticación (auth.log y fail2ban) a
CentinelaIA. El traductor convierte texto de log en un arreglo de `Finding[]` que
fluye por el motor de IA y la correlación exactamente igual que el parser de Nmap
existente. El patrón de referencia (contrato `Finding`, invocación del AI Engine,
fusión y correlación de hallazgos) ya está implementado en
`backend/services/log-translator/nmap-parser.ts` y
`backend/services/log-translator/merge-findings.ts`; esta feature lo **reutiliza**
y no lo re-especifica.

El objetivo es que el usuario pueda pegar un log de autenticación y obtener las
mismas explicaciones, priorización y score de riesgo que produce el flujo de Nmap,
detectando ataques de fuerza bruta por IP y reconociendo defensa activa (baneos de
fail2ban).

## Glossary

- **Auth_Log_Parser**: módulo `backend/services/log-translator/authlog-parser.ts`
  que expone la función `translateAuthLog(text: string): Finding[]`.
- **Finding**: contrato compartido definido en
  `backend/services/scanner/modules/types.ts` (category, severity, rawValue,
  description). No se re-especifica en este documento.
- **AI_Engine**: motor de IA compartido en `backend/services/ai-engine/` que
  consume `Finding[]` para generar explicaciones, priorización y score de riesgo.
- **Analyze_Handler**: handler liviano `backend/handlers/analyze-handler.ts` del
  endpoint POST /analyze.
- **Merge_Helper**: helper existente `backend/services/log-translator/merge-findings.ts`
  que fusiona findings directos con findings derivados de un log.
- **Log_Analysis_Category**: nueva categoría de hallazgo `'log-analysis'`.
- **Flujo_2**: sección del `frontend/` donde el usuario sube un log para análisis.
- **fail2ban**: servicio de defensa activa que banea IPs tras intentos fallidos.

## Requirements

### Requirement 1: Traducción de logs de autenticación a Finding[]

**User Story:** Como analista de seguridad, quiero convertir el texto de un log de
autenticación en hallazgos estructurados, para que el motor de IA los explique y
priorice igual que los hallazgos del scanner.

#### Acceptance Criteria

1. THE Auth_Log_Parser SHALL exponer la función `translateAuthLog(text: string): Finding[]`.
2. WHEN el texto contiene una línea de la forma "Failed password for [invalid user] X from &lt;IP&gt; port ...", THE Auth_Log_Parser SHALL registrar un intento fallido asociado a la IP de origen.
3. WHEN el texto contiene una línea de la forma "Invalid user X from &lt;IP&gt;", THE Auth_Log_Parser SHALL registrar un intento fallido asociado a la IP de origen.
4. THE Auth_Log_Parser SHALL agregar los intentos fallidos por IP de origen y emitir un Finding por IP con el conteo de intentos.
5. WHERE una IP acumula más de 100 intentos fallidos, THE Auth_Log_Parser SHALL asignar severity 'high' al Finding de esa IP.
6. WHERE una IP acumula entre 11 y 100 intentos fallidos, THE Auth_Log_Parser SHALL asignar severity 'medium' al Finding de esa IP.
7. WHERE una IP acumula entre 1 y 10 intentos fallidos, THE Auth_Log_Parser SHALL asignar severity 'low' al Finding de esa IP.
8. WHEN el texto contiene una línea de fail2ban de la forma "Ban &lt;IP&gt;", "Unban &lt;IP&gt;" o "already banned" para una IP, THE Auth_Log_Parser SHALL emitir un Finding de severity 'info' que indique defensa activa detectada para esa IP.
9. THE Auth_Log_Parser SHALL asignar category 'log-analysis' a todos los Finding que emite.
10. THE Auth_Log_Parser SHALL generar un campo description de entre 10 y 500 caracteres para cada Finding.
11. THE Auth_Log_Parser SHALL incluir en el campo rawValue la evidencia del hallazgo con la IP de origen y el conteo de intentos.
12. IF el texto no contiene ninguna línea reconocible de auth.log ni de fail2ban, THEN THE Auth_Log_Parser SHALL retornar un arreglo vacío.

### Requirement 2: Registro consistente de la categoría 'log-analysis'

**User Story:** Como desarrollador, quiero que la nueva categoría de hallazgo esté
registrada en todos los puntos donde el sistema la valida o la describe, para que
el build compile y el motor de IA no rechace los hallazgos del traductor.

#### Acceptance Criteria

1. THE FindingCategory (`backend/services/scanner/modules/types.ts`) SHALL incluir el valor 'log-analysis'.
2. THE VALID_CATEGORIES Set del validator (`backend/services/ai-engine/validator.ts`) SHALL incluir el valor 'log-analysis' para aceptar findings de esa categoría en tiempo de ejecución.
3. THE CATEGORY_DESCRIPTIONS Record (`backend/services/ai-engine/fallback-generator.ts`) SHALL incluir una entrada 'log-analysis' con el texto "eventos de seguridad en logs de autenticación".
4. THE CATEGORY_RECOMMENDATIONS Record (`backend/services/ai-engine/fallback-generator.ts`) SHALL incluir una entrada 'log-analysis' con una recomendación sobre endurecer el acceso SSH que mencione deshabilitar el login de root, usar llaves en lugar de contraseñas, fail2ban y limitar IPs.
5. WHEN se compila el proyecto con `npm run build`, THE build SHALL completarse sin errores de tipo por categorías faltantes en los Record<FindingCategory, string>.

### Requirement 3: Integración del traductor en POST /analyze

**User Story:** Como usuario del API, quiero enviar un log de autenticación en la
solicitud de análisis, para que el sistema lo traduzca y correlacione junto con el
resto de hallazgos usando el mismo motor de IA.

#### Acceptance Criteria

1. THE Analyze_Handler SHALL aceptar un campo opcional `authLog` de tipo string en el cuerpo de la solicitud POST /analyze, de forma análoga al campo `nmapOutput` existente.
2. WHEN el cuerpo de la solicitud incluye un campo `authLog` no vacío, THE Analyze_Handler SHALL traducirlo mediante `translateAuthLog` y fusionar los Finding resultantes usando el Merge_Helper.
3. WHEN se fusionan findings derivados de `authLog`, THE Merge_Helper SHALL actualizar el sourceContext para reflejar la fuente de log de autenticación.
4. THE Analyze_Handler SHALL producir un sourceContext de máximo 200 caracteres, respetando el límite validado por el AI_Engine.
5. WHERE el cuerpo de la solicitud no incluye `authLog` o el campo está vacío, THE Analyze_Handler SHALL mantener el comportamiento actual del flujo sin cambios.
6. THE Analyze_Handler SHALL delegar la traducción y la fusión al servicio correspondiente, manteniendo el handler liviano y sin lógica de negocio.

### Requirement 4: Selección de tipo de log en el frontend

**User Story:** Como usuario, quiero elegir el tipo de log que subo en el Flujo_2,
para poder analizar salidas de Nmap o de auth.log desde la misma interfaz.

#### Acceptance Criteria

1. THE Flujo_2 SHALL presentar un elemento `<select>` que permita elegir entre el tipo de log "Nmap" y el tipo "auth.log".
2. WHEN el usuario selecciona el tipo "Nmap" y envía el log, THE Flujo_2 SHALL enviar el contenido en el campo `nmapOutput` de la solicitud a /analyze.
3. WHEN el usuario selecciona el tipo "auth.log" y envía el log, THE Flujo_2 SHALL enviar el contenido en el campo `authLog` de la solicitud a /analyze.
4. THE Flujo_2 SHALL conservar el flujo de Nmap actual y el renderizado de resultados existente sin regresiones.

### Requirement 5: Verificación mediante pruebas y build

**User Story:** Como desarrollador, quiero pruebas y una verificación de build
reproducibles, para asegurar que el traductor y su integración funcionan sin
introducir dependencias nuevas.

#### Acceptance Criteria

1. THE conjunto de pruebas SHALL incluir casos con Vitest que cubran la traducción de líneas de auth.log, líneas de fail2ban, la asignación de severidad por volumen y el caso de texto sin líneas reconocibles.
2. THE conjunto de pruebas SHALL ejecutarse sin acceso a red real.
3. THE feature SHALL implementarse sin agregar dependencias nuevas al proyecto.
4. WHEN se ejecutan `npm run build` y `npm test`, THE proyecto SHALL completar ambos comandos sin errores.
