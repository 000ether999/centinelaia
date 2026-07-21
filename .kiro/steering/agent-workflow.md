---
inclusion: always
---

# CentinelaIA — Flujo de trabajo del agente y gestión de créditos

## Contexto
Este proyecto se desarrolla con un presupuesto fijo de 2000 créditos de Kiro en
5 días, para una sola persona sin experiencia previa en desarrollo de
aplicaciones web. La eficiencia en el uso de créditos es tan importante como la
calidad del código.

## Reglas de flujo de trabajo (specs)
- Sigue siempre el flujo completo: `requirements.md` → aprobación → `design.md`
  → aprobación → `tasks.md` → ejecución tarea por tarea.
- No generes o modifiques `design.md` o `tasks.md` sin aprobación explícita del
  paso anterior ("LGTM" o feedback concreto).
- Al ejecutar tareas, hazlo una por una. No asumas que puedes ejecutar varias
  tareas en cadena sin revisión intermedia.
- Cada tarea completada debe incluir una explicación breve (2-4 líneas) de qué
  se implementó y por qué, dirigida a alguien sin experiencia previa en
  desarrollo web.

## Reglas de gestión de créditos
- Usa el modelo **Auto** por defecto. Solo escala a un modelo más capaz cuando
  la tarea sea de diseño de arquitectura o lógica central del motor de IA (ver
  `tech.md`).
- No actives agent hooks (automatizaciones por evento) hasta que exista una
  base de código estable del primer spec (scanner). Activar hooks sobre código
  que cambia constantemente genera ejecuciones repetidas innecesarias.
- Si detectas que una tarea va a requerir significativamente más créditos de lo
  esperado (por ejemplo, por ambigüedad en los requisitos), detente y pregunta
  antes de continuar, en vez de iterar múltiples veces a ciegas.

## Presupuesto de referencia (5 días, ~2000 créditos)
- Día 1: steering + spec 1 completo (requirements → design → tasks) + inicio de
  ejecución del scanner. ~300-400 créditos.
- Día 2: finalizar scanner + spec 2 completo (motor de IA) + inicio de
  ejecución. ~400-500 créditos.
- Día 3: finalizar motor de IA + spec 3 (traductor de logs) + correlación.
  ~400-500 créditos.
- Día 4: integración end-to-end, despliegue en AWS, pruebas manuales.
  ~300-400 créditos.
- Día 5: ajustes finales, grabación de video de demo, README, colchón de
  reserva para imprevistos de último minuto. ~300-400 créditos.

## Reporte de progreso
Al final de cada día de trabajo (o cuando se te pida explícitamente), resume:
qué se completó, cuántos créditos se han consumido aproximadamente según el
dashboard de Kiro, y qué riesgo de scope existe para el día siguiente.
