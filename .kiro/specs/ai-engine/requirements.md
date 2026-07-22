# Requirements Document

## Introduction

El módulo AI Engine es el motor de análisis por inteligencia artificial de CentinelaIA. Su responsabilidad es recibir un arreglo de Finding[] (hallazgos estructurados provenientes del scanner o del traductor de logs), invocar Amazon Bedrock para traducirlos a explicaciones en lenguaje natural comprensibles por usuarios no expertos, generar un score de riesgo compuesto (0-100), y retornar una lista priorizada de recomendaciones de remediación. Es un módulo compartido: lo consumen tanto el flujo del scanner como el flujo del traductor de logs, por lo que su interfaz de entrada es agnóstica al origen de los hallazgos. El diseño encapsula la estrategia de prompt engineering para permitir iteración rápida sobre los prompts sin modificar la estructura del módulo.

## Glossary

- **AI_Engine**: El sistema de análisis por IA de CentinelaIA, implementado como módulo de servicio invocado desde Lambda. Recibe Finding[] y produce Analysis_Result.
- **Finding**: Hallazgo individual de seguridad con estructura: category (FindingCategory), severity (FindingSeverity), rawValue (string | null), description (string, 10-500 caracteres). Contrato definido en el scanner (Spec 1).
- **FindingCategory**: Tipo de la categoría del hallazgo. Valores válidos: "http-headers", "tls-ssl", "cookies", "dns-security", "server-fingerprint".
- **FindingSeverity**: Nivel de severidad del hallazgo. Valores ordenados de mayor a menor impacto: "critical", "high", "medium", "low", "info".
- **Analysis_Result**: Estructura de salida del AI_Engine que contiene: explicaciones en lenguaje natural, score de riesgo compuesto, y recomendaciones priorizadas.
- **Risk_Score**: Puntuación numérica compuesta de 0 a 100 que representa el nivel de riesgo global del conjunto de hallazgos analizados. 0 indica ausencia de riesgo detectable; 100 indica riesgo máximo.
- **Explanation**: Texto en lenguaje natural que describe un hallazgo de seguridad de forma comprensible para un usuario sin experiencia en ciberseguridad.
- **Recommendation**: Acción concreta de remediación priorizada por impacto, asociada a uno o más Findings.
- **Prompt_Template**: Plantilla de texto que define la estructura y contexto enviado a Bedrock. Encapsula la estrategia de prompt engineering en archivos o constantes separadas de la lógica del módulo.
- **Bedrock_Client**: Componente que encapsula la comunicación con Amazon Bedrock, incluyendo invocación del modelo, manejo de errores y reintentos.
- **Analysis_Cache**: Componente que almacena Analysis_Results previamente generados para evitar invocaciones redundantes a Bedrock cuando los Finding[] de entrada son idénticos.
- **Session_ID**: Identificador único que agrupa análisis de un mismo usuario o proyecto.

## Requirements

### Requisito 1: Interfaz de entrada agnóstica al origen

**User Story:** Como módulo consumidor (scanner o traductor de logs), quiero invocar el AI_Engine pasándole un arreglo de Finding[] sin indicar su origen, para que el mismo motor de IA funcione con hallazgos de cualquier fuente.

#### Criterios de Aceptación

1. THE AI_Engine SHALL aceptar como entrada un objeto con los campos obligatorios: findings (arreglo de Finding[]), sessionId (string), y un campo opcional sourceContext (string, máximo 200 caracteres) que describe el origen de los hallazgos para enriquecer el contexto del análisis.
2. WHEN el AI_Engine recibe un arreglo de findings, SHALL validar que cada elemento del arreglo contenga los campos obligatorios (category, severity, rawValue, description) con valores dentro de los conjuntos definidos en el Glossary antes de procesar la solicitud.
3. IF el arreglo de findings está vacío, THEN THE AI_Engine SHALL retornar un Analysis_Result con Risk_Score igual a 0, un arreglo vacío de Explanations, y un arreglo vacío de Recommendations, sin invocar a Bedrock.
4. IF el arreglo de findings contiene más de 50 elementos, THEN THE AI_Engine SHALL procesar únicamente los primeros 50 hallazgos ordenados por severidad descendente (critical > high > medium > low > info), descartando los restantes e incluyendo en el Analysis_Result un campo truncated con valor true y truncatedCount con la cantidad de hallazgos descartados.
5. IF algún elemento del arreglo no cumple la validación del criterio 2 (campo faltante, category inválida, severity inválida, o description fuera del rango 10-500 caracteres), THEN THE AI_Engine SHALL rechazar la solicitud completa con un código de error 400 y un mensaje indicando el índice del elemento inválido y la razón del rechazo.
6. IF la solicitud no incluye el campo sessionId o el valor está vacío, THEN THE AI_Engine SHALL rechazar la solicitud con un código de error 400 y un mensaje indicando que sessionId es obligatorio.

---

### Requisito 2: Generación de explicaciones en lenguaje natural

**User Story:** Como usuario de CentinelaIA sin experiencia en ciberseguridad, quiero que los hallazgos técnicos del escaneo se traduzcan a explicaciones claras y comprensibles, para entender qué significa cada problema detectado sin necesitar conocimientos técnicos.

#### Criterios de Aceptación

1. WHEN el AI_Engine procesa un arreglo de Finding[], SHALL generar una Explanation en español para cada Finding, con un mínimo de 50 caracteres y un máximo de 500 caracteres por explicación.
2. THE AI_Engine SHALL generar cada Explanation conteniendo: una descripción del problema en lenguaje simple, el impacto potencial para el usuario o su sitio web, y el nivel de urgencia relativo al resto de hallazgos.
3. WHEN el AI_Engine genera explicaciones, SHALL asociar cada Explanation con el Finding original mediante el índice del hallazgo en el arreglo de entrada, permitiendo al consumidor correlacionar explicación con hallazgo.
4. THE AI_Engine SHALL generar explicaciones que no utilicen jerga técnica sin definirla previamente dentro de la misma explicación (ej. no usar "HSTS" sin indicar qué significa).
5. IF Bedrock retorna una respuesta que no contiene una explicación válida para uno o más Findings (respuesta truncada, formato inesperado, o contenido vacío para un hallazgo específico), THEN THE AI_Engine SHALL generar una explicación genérica por defecto basada en la severidad y categoría del Finding ("Se detectó un problema de seguridad de nivel [severidad] en la categoría [categoría]") y marcar esa explicación con un campo fallback en valor true.

---

### Requisito 3: Cálculo del score de riesgo compuesto

**User Story:** Como usuario de CentinelaIA, quiero ver un número único que represente el nivel de riesgo global de mi sitio, para tener una evaluación rápida sin leer todos los hallazgos.

#### Criterios de Aceptación

1. WHEN el AI_Engine procesa un arreglo de Finding[], SHALL calcular un Risk_Score como número entero en el rango 0 a 100, donde 0 representa ausencia de riesgo detectable y 100 representa riesgo máximo.
2. THE AI_Engine SHALL calcular el Risk_Score utilizando como base los pesos de severidad: critical = 25 puntos, high = 15 puntos, medium = 8 puntos, low = 3 puntos, info = 0 puntos. La fórmula es: Risk_Score_base = MIN(suma de (peso_severidad × cantidad_de_findings_con_esa_severidad) para todas las severidades, 100). Ejemplo ilustrativo: 2 findings critical (2×25=50) + 3 findings high (3×15=45) = 95 base; luego se aplica el factor de diversidad del criterio 3 si corresponde, con tope final en 100.
3. WHEN el AI_Engine calcula el Risk_Score, SHALL aplicar un factor de diversidad que incremente el score en un 10% adicional (sobre el score base) por cada categoría distinta de FindingCategory que contenga al menos un hallazgo de severidad "medium" o superior, con un incremento máximo de 50% (5 categorías).
4. THE AI_Engine SHALL retornar el Risk_Score junto con un campo riskLevel (string) que clasifique el score en: "critical" (81-100), "high" (61-80), "moderate" (41-60), "low" (21-40), "minimal" (0-20).
5. THE AI_Engine SHALL calcular el Risk_Score de forma determinista: para un mismo conjunto de Finding[] (mismas categorías, severidades y cantidades), el score resultante SHALL ser idéntico independientemente del orden de los hallazgos en el arreglo de entrada.
6. THE AI_Engine SHALL retornar siempre un Risk_Score como número entero entre 0 y 100 inclusive, para cualquier arreglo válido de Finding[] de entrada.

---

### Requisito 4: Priorización de recomendaciones de remediación

**User Story:** Como usuario de CentinelaIA, quiero saber qué arreglar primero, para enfocar mi tiempo y recursos en los problemas que más impactan la seguridad de mi sitio.

#### Criterios de Aceptación

1. WHEN el AI_Engine procesa un arreglo de Finding[], SHALL generar una lista ordenada de Recommendations, donde cada Recommendation contiene: título (máximo 100 caracteres), descripción de la acción correctiva (50-300 caracteres), prioridad (número entero de 1 a N donde 1 es máxima prioridad), y los índices de los Findings relacionados.
2. THE AI_Engine SHALL ordenar las Recommendations por prioridad utilizando los siguientes criterios en orden: primero severidad del hallazgo más grave asociado (critical > high > medium > low), segundo cantidad de hallazgos que resolvería la misma acción (agrupación por remediación común), tercero facilidad estimada de implementación (indicada por Bedrock en el análisis).
3. WHEN múltiples Findings pueden resolverse con una misma acción correctiva (ej. múltiples headers faltantes se resuelven configurando un middleware de headers), THE AI_Engine SHALL agrupar esos Findings en una sola Recommendation que referencie todos los índices de Findings relacionados.
4. THE AI_Engine SHALL generar un máximo de 10 Recommendations por análisis; si existen más de 10 acciones posibles, SHALL agrupar las de menor prioridad bajo una Recommendation final genérica titulada "Otras mejoras menores" con los Findings restantes.
5. WHEN el AI_Engine genera Recommendations, SHALL incluir en cada una un campo effort (string del conjunto: "quick-win", "moderate", "complex") que indique la complejidad estimada de implementar la corrección.
6. IF el arreglo de findings contiene únicamente hallazgos con severidad "info", THEN THE AI_Engine SHALL generar una sola Recommendation con prioridad 1 indicando que no se requieren acciones correctivas inmediatas y que la configuración actual es aceptable.

---

### Requisito 5: Invocación de Amazon Bedrock

**User Story:** Como desarrollador del proyecto, quiero que las llamadas a Bedrock estén encapsuladas en un componente dedicado, para poder cambiar de modelo o ajustar parámetros sin modificar la lógica de negocio del AI_Engine.

#### Criterios de Aceptación

1. THE Bedrock_Client SHALL invocar Amazon Bedrock utilizando un modelo de la familia económica (Nova Micro, Nova Lite, o Haiku) como modelo por defecto, configurable mediante variable de entorno (BEDROCK_MODEL_ID) sin cambios de código.
2. THE Bedrock_Client SHALL enviar las solicitudes a Bedrock con un timeout máximo de 30 segundos por invocación, y un límite de tokens de salida configurable mediante variable de entorno (BEDROCK_MAX_TOKENS, valor por defecto: 2048).
3. WHEN el Bedrock_Client invoca a Bedrock, SHALL incluir en la solicitud: el prompt construido a partir del Prompt_Template correspondiente, los parámetros del modelo (temperature configurable, valor por defecto: 0.3), y el límite de tokens de salida.
4. THE Bedrock_Client SHALL implementar reintentos con backoff exponencial (base 1 segundo, máximo 3 reintentos) exclusivamente para errores transitorios: ThrottlingException, ServiceUnavailableException, y errores de red (timeout, conexión rechazada).
5. IF Bedrock retorna un error no transitorio (ValidationException, AccessDeniedException, ModelNotReadyException) después de una invocación, THEN THE Bedrock_Client SHALL propagar el error al AI_Engine sin reintentos, con un mensaje descriptivo del tipo de error.
6. WHEN el Bedrock_Client recibe una respuesta exitosa de Bedrock, SHALL validar que la respuesta contenga texto no vacío antes de retornarla al AI_Engine; IF la respuesta está vacía o no contiene el campo de texto esperado, THEN SHALL tratar la situación como error transitorio y reintentar.

---

### Requisito 6: Encapsulación de prompt engineering

**User Story:** Como desarrollador del proyecto, quiero que los prompts enviados a Bedrock estén definidos en archivos o constantes separadas de la lógica del módulo, para poder iterar sobre la calidad de las respuestas sin modificar la estructura del código.

#### Criterios de Aceptación

1. THE AI_Engine SHALL almacenar cada Prompt_Template como constante de texto o archivo independiente, separado de la lógica de orquestación y del Bedrock_Client.
2. THE AI_Engine SHALL utilizar un Prompt_Template principal para generar explicaciones y recomendaciones a partir de los Findings. Prompts adicionales para otros propósitos podrán agregarse en fases futuras sin cambios en la lógica de orquestación.
3. WHEN el AI_Engine construye el prompt final para Bedrock, SHALL inyectar los Finding[] serializados como JSON dentro del Prompt_Template, junto con el sourceContext si fue proporcionado, sin modificar la estructura base del template.
4. THE AI_Engine SHALL incluir en cada Prompt_Template instrucciones explícitas sobre el formato de salida esperado (JSON con campos específicos), para que la respuesta de Bedrock sea parseable de forma determinista.
5. WHEN se modifica un Prompt_Template (texto del template), THE AI_Engine SHALL funcionar sin cambios en la lógica de orquestación, validación de entrada, o estructura de salida — solo el contenido enviado a Bedrock y la calidad de las respuestas deben verse afectados.

---

### Requisito 7: Protección contra prompt injection

**User Story:** Como operador de la plataforma, quiero que el AI_Engine mitigue la posibilidad de que un sitio malicioso manipule las explicaciones o el score mediante valores crafteados en headers, cookies o registros DNS que se inyectan como datos en el prompt, para preservar la fiabilidad del análisis.

#### Criterios de Aceptación

1. THE AI_Engine SHALL construir el Prompt_Template delimitando explícitamente el bloque de datos de Findings mediante tags XML (ej. `<findings_data>...</findings_data>`) y el bloque de sourceContext mediante tags equivalentes (ej. `<source_context>...</source_context>`) cuando esté presente, con una instrucción explícita al modelo indicando que todo el contenido dentro de esos bloques es dato a analizar y nunca debe interpretarse como instrucción, sin importar su contenido.
2. THE AI_Engine SHALL calcular el Risk_Score exclusivamente mediante la fórmula determinista del Requisito 3, sin permitir que ningún valor sugerido por Bedrock en su respuesta sobrescriba o influya el Risk_Score final — el impacto máximo de un prompt injection exitoso se limita a la manipulación de texto explicativo, nunca al score numérico.
3. IF el AI_Engine detecta en algún rawValue o description caracteres de control no imprimibles (códigos ASCII 0-31 excepto salto de línea y tabulación), THEN THE AI_Engine SHALL remover dichos caracteres antes de incluir el valor en el prompt enviado a Bedrock.
4. THE AI_Engine SHALL validar que la respuesta de Bedrock, una vez parseada, contenga únicamente los campos JSON esperados por el esquema de salida (Requisito 11); IF la respuesta incluye campos no declarados en el esquema o contenido fuera del formato JSON esperado, THEN THE AI_Engine SHALL descartar esos campos adicionales sin incluirlos en el Analysis_Result.

---

### Requisito 8: Caché de resultados de análisis

**User Story:** Como operador de la plataforma, quiero evitar llamadas redundantes a Bedrock cuando se analizan los mismos hallazgos, para reducir costos y latencia.

#### Criterios de Aceptación

1. WHEN el AI_Engine recibe una solicitud de análisis, SHALL calcular un hash determinista (SHA-256) del arreglo de findings serializado (ordenado por category, luego severity, luego description) para usar como clave de caché.
2. WHEN existe un Analysis_Result en el Analysis_Cache con el mismo hash y cuya antigüedad es menor a 1 hora (TTL configurable mediante variable de entorno CACHE_TTL_MINUTES, valor por defecto: 60), THE AI_Engine SHALL retornar el resultado cacheado sin invocar a Bedrock, incluyendo un campo cached con valor true en la respuesta.
3. WHEN el AI_Engine genera un Analysis_Result nuevo (no cacheado), SHALL almacenarlo en el Analysis_Cache asociado al hash calculado, con un TTL igual al configurado.
4. THE Analysis_Cache SHALL implementarse en DynamoDB con TTL nativo (atributo expiresAt), reutilizando la misma tabla o una tabla dedicada con modo on-demand para no incurrir en costos fijos.
5. IF la escritura o lectura del Analysis_Cache falla (error de DynamoDB), THEN THE AI_Engine SHALL continuar la operación normalmente: en caso de lectura fallida, proceder a invocar Bedrock; en caso de escritura fallida, retornar el resultado al cliente sin cachear y registrar el error en logs.
6. THE AI_Engine SHALL producir un hash idéntico para dos arreglos de findings que contengan los mismos valores de category, severity, rawValue y description, independientemente del orden original en el arreglo de entrada. Esta propiedad de determinismo se verifica con los casos de ejemplo del Requisito 14 criterio 4.

---

### Requisito 9: Manejo de errores y degradación graceful

**User Story:** Como usuario de CentinelaIA, quiero que si la IA no puede analizar mis hallazgos por problemas técnicos, aún reciba información útil basada en los datos crudos, para no quedarme sin respuesta alguna.

#### Criterios de Aceptación

1. IF Bedrock no está disponible después de agotar todos los reintentos (3 reintentos con backoff exponencial), THEN THE AI_Engine SHALL generar un Analysis_Result degradado que contenga: Risk_Score calculado exclusivamente con la fórmula determinista del Requisito 3 (sin enriquecimiento de IA), explicaciones genéricas basadas en severidad y categoría de cada Finding, y recomendaciones genéricas ordenadas por severidad, con un campo degraded en valor true.
2. IF Bedrock retorna una respuesta parcial (JSON incompleto o campos faltantes en la respuesta), THEN THE AI_Engine SHALL parsear los campos disponibles, completar los faltantes con valores por defecto (explicaciones genéricas, recomendaciones basadas en severidad), y marcar el Analysis_Result con un campo partial en valor true indicando qué campos fueron generados sin IA.
3. IF Bedrock retorna un error de ThrottlingException en todas las invocaciones (3 reintentos agotados por throttling), THEN THE AI_Engine SHALL aplicar el mismo comportamiento de degradación del criterio 1 y registrar un evento de rate limiting para monitoreo.
4. WHEN el AI_Engine genera un Analysis_Result (exitoso, degradado o parcial), SHALL incluir un campo metadata con: timestamp (ISO 8601), modelId utilizado (o "none" si degradado), latencyMs (duración total del análisis), cached (boolean), y status (string del conjunto: "complete", "degraded", "partial").
5. IF el AI_Engine encuentra un error inesperado no contemplado en los criterios anteriores (excepción no capturada), THEN THE AI_Engine SHALL retornar un código de error 500 con un objeto JSON conteniendo un campo error con descripción genérica ("Error interno del motor de análisis") y registrar el stack trace completo en los logs sin exponerlo al cliente.

---

### Requisito 10: Manejo de rate limiting de Bedrock

**User Story:** Como operador de la plataforma, quiero que el AI_Engine respete los límites de tasa de Bedrock y gestione el throttling de forma inteligente, para evitar degradación del servicio bajo carga.

#### Criterios de Aceptación

1. WHEN el Bedrock_Client recibe un ThrottlingException de Bedrock, SHALL esperar antes de reintentar utilizando backoff exponencial con jitter: primer reintento tras 1-2 segundos (aleatorio), segundo tras 2-4 segundos, tercero tras 4-8 segundos.
2. THE AI_Engine SHALL registrar en logs cada evento de throttling con: timestamp, número de reintento, tiempo de espera aplicado, y resultado final (éxito tras reintento o degradación), para permitir detección de patrones de saturación y ajuste futuro si se requiere un mecanismo de concurrencia más sofisticado post-hackathon.

---

### Requisito 11: Estructura de salida del Analysis_Result

**User Story:** Como consumidor de la API (frontend), quiero que la salida del AI_Engine tenga una estructura JSON consistente y predecible, para renderizar los resultados sin lógica condicional compleja.

#### Criterios de Aceptación

1. THE AI_Engine SHALL retornar el Analysis_Result como objeto JSON con los campos obligatorios: riskScore (number, 0-100), riskLevel (string), explanations (arreglo de objetos Explanation), recommendations (arreglo de objetos Recommendation), y metadata (objeto con campos del Requisito 9 criterio 4).
2. THE AI_Engine SHALL representar cada Explanation como objeto JSON con los campos: findingIndex (number, índice del Finding en el arreglo de entrada), text (string, 50-500 caracteres), y fallback (boolean, true si fue generada sin IA).
3. THE AI_Engine SHALL representar cada Recommendation como objeto JSON con los campos: priority (number, 1 a N), title (string, máximo 100 caracteres), description (string, 50-300 caracteres), effort (string del conjunto: "quick-win", "moderate", "complex"), y relatedFindings (arreglo de numbers representando índices de Findings).
4. THE AI_Engine SHALL garantizar que la cantidad de elementos en el arreglo explanations sea igual a la cantidad de findings procesados (respetando el límite de 50 del Requisito 1 criterio 4).
5. THE AI_Engine SHALL producir un Analysis_Result cuya serialización a JSON y posterior deserialización sea equivalente al objeto original, verificado mediante los casos de ejemplo del Requisito 14 criterio 5.
6. THE AI_Engine SHALL incluir los campos opcionales en el Analysis_Result cuando apliquen: cached (boolean), degraded (boolean), partial (boolean), truncated (boolean), truncatedCount (number), sin omitir los campos obligatorios.

---

### Requisito 12: Persistencia de resultados de análisis

**User Story:** Como usuario de CentinelaIA, quiero que los resultados del análisis de IA se guarden junto con el escaneo, para poder consultarlos después sin repetir el análisis.

#### Criterios de Aceptación

1. WHEN el AI_Engine genera un Analysis_Result exitoso (status "complete", "degraded" o "partial"), SHALL persistir el resultado en DynamoDB asociado a un analysisId (UUID v4) y al sessionId proporcionado en la solicitud.
2. THE AI_Engine SHALL persistir el Analysis_Result en DynamoDB en un máximo de 3 segundos tras la generación del resultado.
3. WHEN el AI_Engine persiste un Analysis_Result, SHALL almacenar como atributos de la tabla: analysisId (partition key), sessionId (clave de índice secundario), timestamp (ISO 8601), el Analysis_Result completo como documento JSON, y los findingsHash (para correlación con la caché).
4. IF la persistencia en DynamoDB falla tras un máximo de 2 reintentos con backoff exponencial, THEN THE AI_Engine SHALL retornar el Analysis_Result al cliente en la respuesta con un campo persisted en valor false y registrar el error en logs.
5. IF el Analysis_Result serializado excede 390 KB, THEN THE AI_Engine SHALL truncar el campo text de las Explanations de Findings con severidad "info" hasta que el ítem quepa dentro del límite de 400 KB de DynamoDB, y agregar un campo storageTruncated en valor true al resultado persistido.

---

### Requisito 13: API REST para análisis y consulta de resultados

**User Story:** Como consumidor de la API (frontend o flujo del scanner), quiero endpoints REST para solicitar análisis de hallazgos y consultar resultados previos, para integrar el AI_Engine con los demás componentes del sistema.

#### Criterios de Aceptación

1. WHEN un cliente envía una solicitud POST a /analyze con un body JSON válido (findings, sessionId, sourceContext opcional), THE AI_Engine SHALL procesar los hallazgos y retornar un código 200 con el Analysis_Result completo en formato application/json.
2. WHEN un cliente envía una solicitud GET a /analyze/{analysisId}, THE AI_Engine SHALL recuperar el Analysis_Result correspondiente de DynamoDB y retornarlo con código 200 en formato application/json.
3. WHEN un cliente envía una solicitud GET a /analyze/{analysisId} con un analysisId que no existe, THE AI_Engine SHALL retornar un código 404 con un objeto JSON que contenga un campo error indicando que el recurso no fue encontrado.
4. WHEN un cliente envía una solicitud GET a /analyze?sessionId={sessionId}, THE AI_Engine SHALL retornar un código 200 con un array JSON de Analysis_Results asociados a ese Session_ID, ordenados por timestamp descendente, con un máximo de 20 resultados por respuesta.
5. IF un cliente envía una solicitud POST a /analyze con un body que no es JSON válido o que no contiene los campos requeridos (findings, sessionId), THEN THE AI_Engine SHALL retornar un código 400 con un objeto JSON que contenga un campo error indicando los campos faltantes o el problema de formato.
6. IF el AI_Engine encuentra un error interno durante el análisis, THEN THE AI_Engine SHALL retornar un código 500 con un objeto JSON que contenga un campo error con descripción genérica sin exponer detalles internos.

---

### Requisito 14: Pruebas del módulo AI_Engine

**User Story:** Como desarrollador del proyecto, quiero que el módulo AI_Engine tenga pruebas básicas para su lógica de negocio central, para asegurar que el cálculo del score, la validación de entrada y el comportamiento de degradación funcionan correctamente sin depender de Bedrock real.

#### Criterios de Aceptación

1. THE AI_Engine SHALL incluir al menos 3 pruebas unitarias para el cálculo del Risk_Score que verifiquen: una con hallazgos de una sola severidad (ej. 3 findings "high" → score esperado según fórmula), una con hallazgos de múltiples severidades y categorías (verificando factor de diversidad), y una con arreglo vacío (score = 0).
2. THE AI_Engine SHALL incluir al menos 2 pruebas unitarias para la validación de entrada que verifiquen: una con un Finding inválido (campo faltante o severity no reconocida) que genere rechazo con código 400, y una con un arreglo de más de 50 findings que verifique el truncamiento correcto.
3. THE AI_Engine SHALL incluir al menos 2 pruebas unitarias para el comportamiento de degradación que verifiquen: una simulando Bedrock no disponible (mock que lanza error tras reintentos) que retorne Analysis_Result degradado con campo degraded en true, y una simulando respuesta parcial de Bedrock que complete los campos faltantes con valores por defecto.
4. THE AI_Engine SHALL incluir al menos 1 prueba unitaria para el cálculo del hash de caché que verifique la propiedad de determinismo: dos arreglos de findings con los mismos elementos en diferente orden deben producir el mismo hash.
5. THE AI_Engine SHALL incluir al menos 1 prueba unitaria para la serialización del Analysis_Result que verifique la propiedad round-trip: serializar a JSON y deserializar de vuelta produce un objeto equivalente al original.
6. THE AI_Engine SHALL ejecutar todas las pruebas utilizando mocks del Bedrock_Client (sin invocar Bedrock real), y todas las pruebas SHALL pasar exitosamente al ejecutar el comando de pruebas del proyecto.