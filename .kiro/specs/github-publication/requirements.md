# Requirements Document

## Introduction

Esta spec define la preparación y publicación segura de CentinelaIA, un proyecto Node.js, TypeScript y AWS SAM, en un repositorio público de GitHub. La fase actual solo documenta requisitos y no autoriza cambios operativos en Git ni GitHub.

## Glossary

- **Preparador_de_Publicación**: Sistema que revisa y prepara el repositorio para su publicación.
- **Conjunto_de_Publicación**: Archivos y cambios seleccionados para el commit de publicación.
- **Artefacto_Sensible**: Archivo local con secretos o configuración privada, como `.env`, variantes de `.env`, credenciales de AWS, configuración AWS local o claves privadas.
- **Secreto**: Credencial, token, contraseña, clave privada o valor que permite acceso no autorizado.
- **Puerta_de_Validación**: Comprobaciones de documentación, compilación, pruebas y plantilla AWS SAM.
- **Comprobación_Crítica**: Verificación de secretos, exclusiones rastreadas, README, compilación o pruebas cuyo fallo bloquea el commit y el push.
- **Comprobación_Opcional**: Validación AWS SAM que puede quedar pendiente cuando la herramienta AWS SAM no está disponible.
- **Commit_de_Publicación**: Commit creado exclusivamente con el Conjunto_de_Publicación validado.
- **Remoto_de_GitHub**: Repositorio público de GitHub configurado como destino.
- **Aprobación_de_Publicación**: Confirmación explícita del usuario posterior a la revisión del contenido preparado.
- **Proceso_Git_Seguro**: Flujo que conserva hooks, historial local y remoto, y archivos de trabajo.

## Requirements

### Requirement 1: Exclusiones seguras

**User Story:** Como responsable del proyecto, quiero excluir dependencias, salidas y archivos locales sensibles, para publicar solo contenido reproducible y seguro.

#### Acceptance Criteria

1. THE Preparador_de_Publicación SHALL mantener reglas de `.gitignore` para `node_modules/`, cualquier `dist/`, cualquier `build/`, `.aws-sam/`, `.env`, variantes de `.env`, credenciales y configuración AWS locales, claves privadas, cobertura, cachés y logs.
2. WHEN una ruta coincide con una regla de exclusión, THE Preparador_de_Publicación SHALL excluir la ruta del Conjunto_de_Publicación.
3. WHEN `.env.example` contiene únicamente nombres y valores de ejemplo no autenticables, THE Preparador_de_Publicación SHALL permitir `.env.example` en el Conjunto_de_Publicación.
4. IF una ruta excluida permanece rastreada por Git, THEN THE Preparador_de_Publicación SHALL bloquear la publicación.
5. IF falta una regla de exclusión requerida, THEN THE Preparador_de_Publicación SHALL informar la regla ausente.

### Requirement 2: Verificación de secretos

**User Story:** Como mantenedor, quiero verificar el contenido publicable y rastreado, para evitar exponer secretos en GitHub.

#### Acceptance Criteria

1. WHEN el Conjunto_de_Publicación está preparado, THE Preparador_de_Publicación SHALL analizar cada archivo del Conjunto_de_Publicación para detectar Secretos.
2. WHEN el repositorio contiene archivos rastreados, THE Preparador_de_Publicación SHALL analizar cada archivo rastreado para detectar Secretos.
3. IF el análisis detecta un Secreto aunque el análisis no se complete, THEN THE Preparador_de_Publicación SHALL bloquear el commit y el push.
4. IF el análisis detecta un Secreto aunque el análisis no se complete, THEN THE Preparador_de_Publicación SHALL informar la ruta y la categoría sin mostrar el valor detectado.
5. IF el análisis de secretos no puede completarse, THEN THE Preparador_de_Publicación SHALL bloquear el commit y el push.
6. IF el análisis de secretos no puede completarse, THEN THE Preparador_de_Publicación SHALL permitir continuar únicamente las actividades de preparación que no publiquen cambios.

### Requirement 3: Revisión del repositorio y del remoto

**User Story:** Como mantenedor, quiero revisar el estado local y el destino remoto, para conocer exactamente qué se publicará y dónde.

#### Acceptance Criteria

1. WHEN comienza la preparación, THE Preparador_de_Publicación SHALL informar la rama actual y los cambios staged, unstaged y untracked.
2. WHEN se revisan los remotos, THE Preparador_de_Publicación SHALL informar el nombre, la URL y el repositorio de destino de cada remoto configurado.
3. IF un Remoto_de_GitHub configurado apunta de forma confirmada a un destino distinto del aprobado, THEN THE Preparador_de_Publicación SHALL bloquear el push.
4. WHERE no existe un Remoto_de_GitHub configurado, THE Preparador_de_Publicación SHALL permitir ejecutar el intento de push.
5. IF la rama remota contiene cambios incompatibles con el Commit_de_Publicación, THEN THE Preparador_de_Publicación SHALL conservar ambos historiales para resolución manual.

### Requirement 4: Validación previa a la publicación

**User Story:** Como visitante de GitHub, quiero un proyecto documentado y verificable, para poder comprenderlo, compilarlo, probarlo y desplegarlo.

#### Acceptance Criteria

1. WHEN el Conjunto_de_Publicación está preparado, THE Preparador_de_Publicación SHALL verificar que el `README.md` raíz describa propósito, preparación local, compilación, pruebas y despliegue AWS SAM sin Secretos.
2. WHEN las dependencias están disponibles, THE Puerta_de_Validación SHALL ejecutar la compilación declarada en `package.json`.
3. WHEN la compilación termina correctamente, THE Puerta_de_Validación SHALL ejecutar las pruebas declaradas en `package.json` sin modo watch.
4. WHEN las pruebas terminan correctamente, THE Puerta_de_Validación SHALL validar `infra/template.yaml` con AWS SAM.
5. IF una Comprobación_Crítica falla, THEN THE Preparador_de_Publicación SHALL bloquear el commit y el push.
6. WHERE la herramienta AWS SAM no está disponible, THE Puerta_de_Validación SHALL registrar la Comprobación_Opcional como pendiente.
7. WHEN ninguna Comprobación_Crítica ha fallado, THE Preparador_de_Publicación SHALL permitir preparar el commit aunque existan comprobaciones pendientes.

### Requirement 5: Commit y push controlados

**User Story:** Como responsable del proyecto, quiero preparar un commit y publicarlo sin reescribir historial ni omitir controles, para mantener la integridad del repositorio.

#### Acceptance Criteria

1. WHEN todas las comprobaciones terminan correctamente, THE Preparador_de_Publicación SHALL añadir al índice únicamente el Conjunto_de_Publicación.
2. WHEN el índice está preparado, THE Preparador_de_Publicación SHALL presentar las rutas staged y el resumen del diff para revisión.
3. WHEN se concede la Aprobación_de_Publicación, THE Preparador_de_Publicación SHALL crear un Commit_de_Publicación descriptivo con los hooks habilitados.
4. WHEN el Commit_de_Publicación está listo, THE Preparador_de_Publicación SHALL publicar el commit mediante un push sin reescribir el historial remoto.
5. WHEN el Proceso_Git_Seguro ejecuta un comando, THE Proceso_Git_Seguro SHALL usar únicamente opciones no destructivas que conserven los hooks habilitados.
6. WHEN finaliza el push, THE Preparador_de_Publicación SHALL verificar que el Commit_de_Publicación sea alcanzable desde la rama remota publicada.
7. WHEN la verificación remota termina correctamente, THE Preparador_de_Publicación SHALL informar la URL pública y el identificador del commit.

### Requirement 6: Límite de la fase actual

**User Story:** Como usuario, quiero aprobar los requisitos antes de continuar, para evitar cambios prematuros en el proyecto o en GitHub.

#### Acceptance Criteria

1. WHILE la fase de requisitos permanece sin aprobación, THE Preparador_de_Publicación SHALL limitar las modificaciones al directorio `.kiro/specs/github-publication/`.
2. WHILE la fase de requisitos permanece sin aprobación, THE Preparador_de_Publicación SHALL conservar sin cambios el índice y el historial de Git.
3. WHILE la fase de requisitos permanece sin aprobación, THE Preparador_de_Publicación SHALL conservar sin cambios los remotos y repositorios de GitHub.