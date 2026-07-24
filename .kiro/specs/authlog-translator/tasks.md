# Implementation Plan: Traductor de auth.log

## Overview

Implementar el parser de logs de autenticación, registrar la categoría `'log-analysis'` en el sistema, integrar el traductor en el flujo de análisis existente, y agregar la selección de tipo de log en el frontend.

## Tasks

- [x] 1. Parser authlog-parser.ts + tests
  - [x] 1.1 Crear `backend/services/log-translator/authlog-parser.ts` con la función `translateAuthLog(text: string): Finding[]`
    - Implementar patrones regex para: "Failed password", "Invalid user", "Ban", "Unban", "already banned"
    - Agregar intentos fallidos por IP de origen
    - Asignar severity según volumen: >100 → high, 11-100 → medium, 1-10 → low
    - Emitir findings de fail2ban con severity 'info'
    - Retornar `[]` si el texto no contiene líneas reconocibles
    - Todos los findings con category `'log-analysis'`, description 10-500 chars, rawValue con IP y conteo
    - _Satisface: Requirement 1, Requirement 5_
  - [x] 1.2 Crear `backend/tests/log-translator/authlog-parser.test.ts` con Vitest
    - Test: líneas "Failed password" se agrupan por IP correctamente
    - Test: líneas "Invalid user" se registran como intentos fallidos
    - Test: severity por volumen (5 → low, 50 → medium, 150 → high)
    - Test: líneas fail2ban (Ban/Unban/already banned) → Finding severity 'info'
    - Test: texto sin líneas reconocibles → `[]`
    - Test: campos del Finding (category, description length, rawValue)
    - _Satisface: Requirement 1, Requirement 5_

- [x] 2. Registrar categoría 'log-analysis' en 3 puntos
  - [x] 2.1 Agregar `'log-analysis'` al type union `FindingCategory` en `backend/services/scanner/modules/types.ts`
    - _Satisface: Requirement 2, Requirement 5_
  - [x] 2.2 Agregar `'log-analysis'` al Set `VALID_CATEGORIES` en `backend/services/ai-engine/validator.ts`
    - _Satisface: Requirement 2, Requirement 5_
  - [x] 2.3 Agregar entradas `'log-analysis'` en `CATEGORY_DESCRIPTIONS` y `CATEGORY_RECOMMENDATIONS` en `backend/services/ai-engine/fallback-generator.ts`
    - CATEGORY_DESCRIPTIONS: `"eventos de seguridad en logs de autenticación"`
    - CATEGORY_RECOMMENDATIONS: texto sobre endurecer SSH (root, llaves, fail2ban, limitar IPs)
    - Verificar con `npm run build` que no hay errores de tipo
    - _Satisface: Requirement 2, Requirement 5_

- [x] 3. Integrar authLog en merge-findings.ts + analyze-handler.ts + test de integración
  - [x] 3.1 Extender `MergeInput` con campo opcional `authLog?: string`, llamar `translateAuthLog` en `mergeFindings()` y actualizar sourceContext (≤200 chars)
    - Importar `translateAuthLog` desde `authlog-parser.ts`
    - Concatenar findings de authLog al arreglo fusionado
    - Construir sourceContext reflejando la fuente "auth.log"
    - _Satisface: Requirement 3, Requirement 5_
  - [x] 3.2 Extender `analyze-handler.ts` para detectar campo `authLog` en el body y pasarlo a `mergeFindings`, análogo al bloque de `nmapOutput`
    - Eliminar `authLog` del body antes de pasar al validator
    - _Satisface: Requirement 3, Requirement 5_
  - [x] 3.3 Agregar/extender tests de integración en `backend/tests/log-translator/merge-findings.test.ts`
    - Test: mergeFindings con authLog que contiene intentos fallidos fusiona correctamente
    - Test: mergeFindings con authLog vacío no modifica el resultado
    - _Satisface: Requirement 3, Requirement 5_

- [x] 4. Frontend: `<select>` tipo de log en Flujo 2
  - [x] 4.1 Agregar un elemento `<select>` en la UI de Flujo 2 con opciones "Nmap" (default) y "auth.log"
    - Enviar contenido en `nmapOutput` si selecciona Nmap, en `authLog` si selecciona auth.log
    - No romper el flujo existente de Nmap ni el renderizado de resultados
    - _Satisface: Requirement 4_

- [x] 5. Checkpoint final
  - Ejecutar `npm run build` y `npm test`. Ambos pasan sin errores. ✅

## Notes

- Los tests son parte integral de cada tarea, no opcionales.
- No se agregan dependencias nuevas al proyecto.
- El parser sigue el mismo patrón de `nmap-parser.ts` para consistencia.
- Sin acceso a red en tests — todo con inputs mockeados.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2", "2.1", "2.2", "2.3"] },
    { "id": 1, "tasks": ["3.1", "3.2", "3.3"] },
    { "id": 2, "tasks": ["4.1"] }
  ]
}
```
