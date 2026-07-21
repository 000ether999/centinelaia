---
inclusion: always
---

# CentinelaIA — Preferencias técnicas y guardarraíles de costo

## Filosofía
No hay una preferencia de framework predefinida. Tienes libertad para proponer
el stack que mejor balancee velocidad de desarrollo en 5 días, costo mínimo, y
mantenibilidad post-hackathon. Sin embargo, cualquier propuesta debe respetar
los guardarraíles de esta sección.

## Guardarraíles de costo (regla dura)
- Prioriza servicios de AWS dentro del **free tier** (Lambda, DynamoDB modo
  on-demand, S3, API Gateway, CloudFront). Evita servicios con costo fijo
  mensual (ej. instancias EC2 siempre encendidas, RDS provisionado) salvo que
  no exista alternativa serverless razonable.
- Para el motor de IA, prioriza **Amazon Bedrock** con el modelo de menor costo
  que cumpla la tarea razonablemente bien (por ejemplo, un modelo de la familia
  Haiku/Nova Micro-Lite antes que uno de gama alta), en vez de llamar a APIs
  externas de pago (OpenAI, Anthropic directo) que generarían cobros fuera del
  crédito ya asignado del hackathon.
- Si una tarea requiere mayor capacidad de razonamiento (ej. correlacionar
  hallazgos complejos, generar el score de riesgo), está permitido escalar a un
  modelo intermedio de Bedrock — pero justifica por qué el modelo económico no
  alcanza antes de escalar.
- Nunca propongas un servicio o arquitectura solo por ser "más impresionante"
  si un servicio más simple cumple el mismo objetivo con menor costo y menor
  tiempo de implementación.

## Arquitectura esperada (alto nivel, tú defines el detalle)
- Frontend: aplicación web simple, servida como estática (S3 + CloudFront o
  equivalente), sin frameworks pesados innecesarios para el alcance del MVP.
- Backend: funciones serverless (AWS Lambda) detrás de API Gateway. Handlers
  livianos: reciben la petición, llaman a servicios de dominio, arman la
  respuesta — la lógica de negocio vive en módulos separados, no en el handler.
- Persistencia: DynamoDB en modo on-demand para historial de escaneos.
- IA: Amazon Bedrock, invocado desde Lambda.

## Convenciones de código
- Idioma del código y nombres de variables: inglés (estándar de la industria).
- Comentarios y documentación (README, docstrings de alto nivel): español.
- Cada función/módulo nuevo debe incluir al menos una prueba básica antes de
  darse por completada (no es necesario TDD estricto dado el plazo de 5 días,
  pero cero pruebas no es aceptable para lógica de negocio central como el
  parser de headers o el cálculo del score de riesgo).

## Modelo de ejecución de agente
- Usa el modelo **Auto** de Kiro por defecto para: boilerplate, configuración
  de infraestructura, tests, documentación, y tareas de bajo riesgo.
- Reserva un modelo más capaz solo para: el diseño de la arquitectura inicial
  (`design.md` de cada spec) y la lógica del motor de análisis con IA, donde la
  calidad del razonamiento importa más que la velocidad.
