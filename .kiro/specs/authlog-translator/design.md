# Diseño — Traductor de auth.log

## Overview

Este módulo traduce texto de logs de autenticación (sshd / fail2ban) a `Finding[]`,
reutilizando el mismo patrón de `nmap-parser.ts` + `merge-findings.ts`. No se
re-inventa arquitectura: se agrega un parser hermano (`authlog-parser.ts`), se
extiende el `Merge_Helper` para aceptar `authLog`, y se registra la categoría
`'log-analysis'` en los 3 puntos donde el sistema la necesita.

## Architecture

```
┌─────────────┐       ┌──────────────────┐       ┌───────────────┐
│ Frontend    │──POST──│ analyze-handler  │──────▶│ AI Engine     │
│ (Flujo 2)  │        │  + mergeFindings │       │ (explicación) │
└─────────────┘        └──────────────────┘       └───────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼                               ▼
   translateNmapOutput()          translateAuthLog()
   (nmap-parser.ts)               (authlog-parser.ts)
```

Flujo idéntico al de Nmap: handler detecta campo → llama al traductor → fusiona → envía al AI Engine.

## Components and Interfaces

### 1. `authlog-parser.ts`

Archivo: `backend/services/log-translator/authlog-parser.ts`

```typescript
export function translateAuthLog(text: string): Finding[]
```

**Patrones regex reconocidos:**

| Patrón | Ejemplo de línea |
|--------|------------------|
| `Failed password for (invalid user )?(\S+) from (\S+) port` | `Failed password for invalid user admin from 192.168.1.5 port 22 ssh2` |
| `Invalid user (\S+) from (\S+)` | `Invalid user test from 10.0.0.1` |
| `Ban (\S+)` | `fail2ban.actions: ...Ban 192.168.1.5` |
| `Unban (\S+)` | `fail2ban.actions: ...Unban 192.168.1.5` |
| `already banned` (con IP extraída de contexto) | `192.168.1.5 already banned` |

**Lógica de agregación:**

1. Recorrer líneas del texto.
2. Para cada línea que hace match con los patrones de intento fallido, incrementar contador de la IP.
3. Para líneas de fail2ban (Ban/Unban/already banned), registrar la IP en un set de "IPs baneadas".
4. Emitir findings:
   - Un `Finding` por cada IP con intentos fallidos (severity según volumen).
   - Un `Finding` por cada IP baneada con severity `'info'` (defensa activa).

**Mapeo volumen → severity:**

| Intentos fallidos | Severity |
|-------------------|----------|
| > 100             | `'high'` |
| 11 – 100          | `'medium'` |
| 1 – 10            | `'low'` |
| IP baneada        | `'info'` |

**Campos del Finding emitido:**

- `category`: siempre `'log-analysis'`
- `severity`: según tabla anterior
- `description`: 10-500 chars, ej. `"Se detectaron 47 intentos fallidos de autenticación desde la IP 192.168.1.5, indicando un posible ataque de fuerza bruta."`
- `rawValue`: evidencia, ej. `"IP=192.168.1.5 failed_attempts=47"`

Si el texto no contiene ninguna línea reconocible, retorna `[]`.

### 2. Registro de la categoría `'log-analysis'`

Se agrega en exactamente 3 puntos:

**a) `backend/services/scanner/modules/types.ts`** — tipo unión:
```typescript
export type FindingCategory =
  | 'http-headers'
  | 'tls-ssl'
  | 'cookies'
  | 'dns-security'
  | 'server-fingerprint'
  | 'log-analysis';         // ← nuevo
```

**b) `backend/services/ai-engine/validator.ts`** — set de validación:
```typescript
const VALID_CATEGORIES: ReadonlySet<string> = new Set<FindingCategory>([
  // ...existentes...
  'log-analysis',           // ← nuevo
]);
```

**c) `backend/services/ai-engine/fallback-generator.ts`** — ambos Records:
```typescript
const CATEGORY_DESCRIPTIONS: Record<FindingCategory, string> = {
  // ...existentes...
  'log-analysis': 'eventos de seguridad en logs de autenticación',
};

const CATEGORY_RECOMMENDATIONS: Record<FindingCategory, string> = {
  // ...existentes...
  'log-analysis': 'Endurecer el acceso SSH: deshabilitar login de root, usar autenticación por llaves en lugar de contraseñas, configurar fail2ban para bloqueo automático y limitar las IPs que pueden conectarse al servicio.',
};
```

### 3. Extensión de `merge-findings.ts` y `analyze-handler.ts`

**`MergeInput`** se extiende con campo opcional:
```typescript
export interface MergeInput {
  findings: Finding[];
  nmapOutput?: string;
  authLog?: string;        // ← nuevo
  sourceContext?: string;
}
```

**`mergeFindings()`** procesa `authLog` igual que `nmapOutput`:
- Si `authLog` tiene contenido, llama `translateAuthLog(authLog)`.
- Concatena los findings resultantes al arreglo.
- Actualiza `sourceContext` reflejando la fuente (ej. `"Correlación: 3 hallazgos del scanner + 5 de auth.log."`).
- Respeta el límite de 200 caracteres.

**`analyze-handler.ts`** — bloque análogo al de `nmapOutput`:
- Detecta campo `authLog` en el body.
- Lo pasa a `mergeFindings` junto con `nmapOutput` (ambos pueden coexistir).
- Elimina `authLog` del body antes de pasar al validator.
- El handler NO contiene lógica de parsing — sólo delega.

## Data Models

No se crean tablas ni modelos nuevos. Se reutiliza `Finding` existente con la nueva categoría.

## Error Handling

- Líneas que no hacen match con ningún patrón → se ignoran silenciosamente (no se emite finding).
- Texto vacío o nulo → retorna `[]`.
- IPs malformadas en el regex → no hacen match, se descartan.
- El validator del AI Engine rechaza findings con description fuera de rango → el parser garantiza 10-500 chars.

## Cambio mínimo en Frontend

En `Flujo_2`, se agrega un `<select>` con dos opciones:
- **Nmap** (valor por defecto): envía el contenido del textarea en `nmapOutput`.
- **auth.log**: envía el contenido en `authLog`.

El resto del flujo (renderizado de resultados, score, explicaciones) no cambia.

## Correctness Properties

Las siguientes propiedades se verifican con tests de ejemplo (Vitest), no con PBT:

1. **Completitud de agregación**: para cualquier texto con N líneas de intento fallido de una misma IP, el Finding emitido para esa IP reporta exactamente N intentos.
2. **Monotonía de severidad**: si count(IP) > 100 → severity es 'high'; si 11 ≤ count ≤ 100 → 'medium'; si 1 ≤ count ≤ 10 → 'low'. No existe solapamiento.
3. **Independencia de fuentes**: findings de fail2ban (severity 'info') se emiten independientemente de los findings de fuerza bruta para la misma IP.
4. **Seguridad del arreglo vacío**: texto sin patrones reconocibles → `[]` (nunca undefined, nunca throw).
5. **Invariantes de campos**: todo Finding emitido tiene category `'log-analysis'`, description entre 10-500 chars, y rawValue no vacío.

## Testing Strategy

**PBT no aplica** para esta feature: el parser es lógica de pattern-matching con reglas de umbral fijo, no una función con espacio de entrada infinito donde propiedades universales revelarían bugs adicionales respecto a ejemplos bien elegidos. Los tests con ejemplos concretos cubren eficazmente todos los escenarios.

**Enfoque: Vitest con inputs mockeados, sin acceso a red.**

Tests a implementar (`backend/tests/log-translator/authlog-parser.test.ts`):

1. **Líneas de "Failed password"** — verifica que se agrupan por IP y se cuenta correctamente.
2. **Líneas de "Invalid user"** — verifica que se registran como intentos fallidos.
3. **Severity por volumen** — inputs con 5, 50 y 150 intentos para la misma IP → verifica `low`, `medium`, `high`.
4. **Líneas de fail2ban (Ban/Unban/already banned)** — verifica Finding con severity `'info'`.
5. **Texto sin líneas reconocibles** — retorna `[]`.
6. **Mezcla de fuentes** — texto con intentos fallidos + baneos → genera ambos tipos de finding.
7. **Campos del Finding** — verifica `category === 'log-analysis'`, description entre 10-500 chars, rawValue incluye IP y conteo.

Tests de integración ligera (`backend/tests/log-translator/merge-findings.test.ts` — extender):

8. **`mergeFindings` con `authLog`** — verifica que se fusionan los findings y sourceContext refleja la fuente.
9. **`mergeFindings` con `authLog` vacío** — comportamiento sin cambios.

Sin dependencias nuevas. Sin acceso a red.
