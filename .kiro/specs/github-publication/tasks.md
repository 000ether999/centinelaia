# Implementation Plan: Publicación segura en GitHub

## Overview

Flujo secuencial y fail-closed para preparar, revisar y publicar CentinelaIA. Cada tarea depende de la anterior; ninguna operación de commit o push se ejecuta sin su aprobación explícita correspondiente.

## Tasks

- [x] 1. Inspeccionar Git, remotos y política de exclusión
  - Informar rama, HEAD, estado staged/unstaged/untracked y nombre, URL y destino de cada remoto sin modificar Git.
  - Actualizar `.gitignore` con reglas faltantes para dependencias, `dist/`, `build/`, `.aws-sam/`, entornos, AWS local, claves, cobertura, cachés y logs.
  - _Requirements: 1.1, 1.5, 3.1, 3.2_

- [x] 2. Revisar secretos y archivos rastreados
  - Construir el conjunto candidato y escanear tanto archivos candidatos como rastreados; reportar solo ruta y categoría, con valores redactados.
  - Detectar rutas excluidas aún rastreadas y corregir archivos o configuración sensible; solicitar aprobación antes de retirar una ruta del índice conservando el archivo local.
  - Bloquear el flujo ante secretos, lecturas omitidas o análisis incompleto.
  - _Requirements: 1.2, 1.3, 1.4, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_

- [x] 3. Asegurar README y ejecutar la puerta de validación
  - Crear o completar el `README.md` raíz en español con propósito, preparación local, build, tests y despliegue AWS SAM, sin secretos.
  - Ejecutar en orden el build y los tests sin watch declarados en `package.json`; validar `infra/template.yaml` si AWS SAM CLI está disponible.
  - Bloquear ante fallos críticos; registrar SAM como `pending` únicamente si la CLI no está disponible.
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7_

- [x] 4. Preparar staging explícito y solicitar aprobación del commit
  - Añadir únicamente rutas aprobadas mediante staging por rutas explícitas; no usar staging global ni commit implícito.
  - Repetir el escaneo sobre el contenido indexado y verificar que HEAD, candidato e índice coincidan con el plan validado.
  - Reportar rutas staged, resumen del diff y diff redactado; detenerse para solicitar aprobación explícita del commit.
  - _Requirements: 5.1, 5.2, 5.5_

- [x] 5. Crear el commit aprobado con hooks habilitados
  - Confirmar la aprobación del commit y que HEAD, índice y conjunto candidato no cambiaron; si cambiaron, invalidar la aprobación y volver a la tarea 2.
  - Crear un commit nuevo y descriptivo sin `--amend`, `--no-verify` ni opciones destructivas; bloquear ante fallo de hooks.
  - Reportar el SHA local y detenerse para solicitar una aprobación explícita e independiente del push.
  - _Requirements: 5.3, 5.5_

- [x] 6. Publicar al remoto aprobado y verificar el resultado
  - Confirmar la aprobación del push y que nombre, URL y destino del remoto coincidan con el destino aprobado.
  - Actualizar referencias remotas sin alterar ramas de trabajo, comprobar fast-forward y ejecutar un push normal; usar `-u` solo para una rama nueva.
  - Ante divergencia o rechazo, conservar ambos historiales sin force, rebase automático ni reset; tras éxito, verificar el SHA remoto e informar URL pública y SHA.
  - _Requirements: 3.3, 3.4, 3.5, 5.4, 5.5, 5.6, 5.7_

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1"] },
    { "id": 1, "tasks": ["2"] },
    { "id": 2, "tasks": ["3"] },
    { "id": 3, "tasks": ["4"] },
    { "id": 4, "tasks": ["5"] },
    { "id": 5, "tasks": ["6"] }
  ]
}
```

## Notes

- Las aprobaciones de commit y push son independientes; su ausencia detiene el flujo.
- No se permiten staging global, bypass de hooks, force push ni reescritura automática del historial.
