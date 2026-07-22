# Requirements Document

## Introduction

El módulo Scanner es el motor de escaneo técnico de CentinelaIA. Su responsabilidad es recibir una URL o dominio objetivo, ejecutar una batería de verificaciones de seguridad (headers HTTP, TLS/SSL, cookies, DNS, fingerprinting), y devolver hallazgos estructurados en JSON. Los resultados se persisten en DynamoDB y se exponen mediante API Gateway para su consumo posterior por el motor de IA (Spec 2). El diseño debe ser extensible para incorporar nuevos tipos de verificación (ej. escaneo de puertos) en fases futuras sin refactorización mayor.

## Glossary

- **Scanner**: El sistema de escaneo de seguridad web de CentinelaIA, implementado como función Lambda detrás de API Gateway.
- **Target**: La URL o dominio proporcionado por el usuario como objetivo del escaneo.
- **Finding**: Un hallazgo individual de seguridad producido por el Scanner, representado como objeto JSON con categoría, severidad, valor crudo y descripción.
- **Scan_Result**: El conjunto completo de Findings generados por un escaneo, junto con metadatos (timestamp, target, estado).
- **Authorization_Confirmation**: Declaración explícita del usuario confirmando que posee autorización para escanear el Target.
- **Header_Analyzer**: Submódulo del Scanner responsable de verificar headers HTTP de seguridad.
- **TLS_Checker**: Submódulo del Scanner responsable de analizar la configuración TLS/SSL del Target.
- **Cookie_Inspector**: Submódulo del Scanner responsable de verificar flags de seguridad en cookies.
- **DNS_Checker**: Submódulo del Scanner responsable de verificar registros DNS de seguridad.
- **Fingerprinter**: Submódulo del Scanner responsable de identificar tecnología del servidor.
- **Scan_Store**: Componente de persistencia que almacena Scan_Results en DynamoDB.
- **Session_ID**: Identificador único que agrupa escaneos de un mismo usuario o proyecto.

## Requirements

### Requisito 1: Validación de entrada del Target

**User Story:** Como usuario de CentinelaIA, quiero proporcionar una URL o dominio como objetivo de escaneo, para que el sistema sepa qué analizar.

#### Criterios de Aceptación

1. WHEN el usuario envía una solicitud de escaneo con un Target válido (URL con esquema HTTP o HTTPS, o dominio registrable con TLD válido según la lista pública de sufijos IANA), THE Scanner SHALL aceptar la solicitud y comenzar el proceso de escaneo.
2. IF el usuario envía una solicitud de escaneo con un Target vacío, con longitud superior a 2048 caracteres, con esquema distinto de HTTP/HTTPS, o con formato que no corresponde a una URL válida ni a un dominio registrable, THEN THE Scanner SHALL rechazar la solicitud con un código de error 400 y un mensaje indicando la razón específica del rechazo (campo vacío, longitud excedida, esquema no soportado, o formato inválido).
3. WHEN el Target es una URL con esquema HTTP/HTTPS que incluye path, query o fragmento, THE Scanner SHALL extraer el dominio (host) para las verificaciones que operan a nivel de dominio (DNS, TLS) y utilizar la URL completa sin fragmento para las verificaciones HTTP.
4. WHEN el Target es un dominio sin esquema, THE Scanner SHALL utilizar HTTPS como esquema por defecto para las verificaciones que requieren conexión HTTP.
5. IF el Target es una dirección IP (IPv4 o IPv6) en lugar de un dominio, THEN THE Scanner SHALL aceptar la solicitud ejecutando únicamente las verificaciones aplicables a IP (TLS, headers HTTP, cookies, fingerprinting) y omitir las verificaciones que requieren dominio (DNS).

---

### Requisito 2: Prevención de SSRF (Server-Side Request Forgery)

**User Story:** Como operador de la plataforma, quiero que el scanner valide que la IP resuelta del target no sea una dirección interna o reservada, para evitar que un usuario malintencionado utilice la Lambda como proxy para acceder a recursos internos de AWS (ej. endpoint de metadata 169.254.169.254).

#### Criterios de Aceptación

1. WHEN el Target es un dominio, THE Scanner SHALL resolver su dirección IP mediante DNS antes de ejecutar cualquier módulo de verificación que realice conexiones de red.
2. IF la IP resuelta del dominio (o la IP proporcionada directamente como target) pertenece a alguno de los siguientes rangos: privados (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback (127.0.0.0/8, ::1), link-local (169.254.0.0/16, fe80::/10), o reservados (fc00::/7), THEN THE Scanner SHALL rechazar la solicitud con un código de error 400 y un mensaje indicando que el target no es escaneable por razones de seguridad, sin ejecutar ningún módulo de verificación.
3. THE Scanner SHALL ejecutar esta validación una sola vez en el validador, después de la validación de formato del target y antes de invocar al orquestador — no debe repetirse dentro de cada módulo individual.
4. IF el dominio resuelve a múltiples direcciones IP (round-robin DNS), THEN THE Scanner SHALL validar todas las IPs resueltas; si alguna de ellas pertenece a un rango prohibido, la solicitud completa se rechaza con código 400.
5. WHEN cualquier módulo de verificación que sigue redirecciones HTTP (Header_Analyzer, Cookie_Inspector) recibe una respuesta de redirección (3xx con header Location) durante su ejecución, THE módulo SHALL resolver la IP de destino de la URL indicada en el header Location y validarla contra las mismas reglas de rangos prohibidos del criterio 2 antes de seguir la redirección. IF la IP de destino pertenece a un rango prohibido, THEN THE módulo SHALL abortar el seguimiento de esa redirección, generar un Finding con severidad "medium" y categoría correspondiente al módulo indicando que se bloqueó una redirección a IP interna por protección SSRF, y continuar el escaneo normal sin interrumpir los demás módulos.

---

### Requisito 3: Confirmación de autorización

**User Story:** Como usuario de CentinelaIA, quiero confirmar que tengo autorización para escanear el objetivo, para que el sistema solo analice activos con permiso explícito del propietario.

#### Criterios de Aceptación

1. IF el usuario envía una solicitud de escaneo sin el campo Authorization_Confirmation o con Authorization_Confirmation en un valor distinto de boolean `true`, THEN THE Scanner SHALL rechazar la solicitud con un código de error 403 y un mensaje indicando que se requiere confirmación de autorización.
2. WHEN el usuario envía una solicitud de escaneo con Authorization_Confirmation en valor boolean `true`, THE Scanner SHALL proceder con el escaneo.
3. WHEN un escaneo se inicia tras confirmación de autorización, THE Scanner SHALL registrar como evidencia de consentimiento: el valor de Authorization_Confirmation, el Target confirmado, y el timestamp (ISO 8601) del momento de la confirmación, asociados al Scan_Result correspondiente.
4. IF el escaneo finaliza con estado parcial o fallido, THEN THE Scanner SHALL preservar la evidencia de consentimiento registrada en el criterio 3 sin modificarla ni eliminarla.

---

### Requisito 4: Análisis de headers HTTP de seguridad

**User Story:** Como usuario de CentinelaIA, quiero que el scanner verifique los headers HTTP de seguridad del objetivo, para identificar configuraciones faltantes o inseguras.

#### Criterios de Aceptación

1. WHEN el Scanner analiza el Target, THE Header_Analyzer SHALL verificar la presencia y valor de los siguientes headers: X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Content-Security-Policy, Referrer-Policy, Permissions-Policy, X-XSS-Protection.
2. WHEN un header de seguridad está ausente en la respuesta del Target, THE Header_Analyzer SHALL generar un Finding con la siguiente severidad según el header: "high" para Content-Security-Policy y Strict-Transport-Security ausentes; "medium" para X-Frame-Options, X-Content-Type-Options y Permissions-Policy ausentes; "low" para Referrer-Policy y X-XSS-Protection ausentes.
3. WHEN un header de seguridad está presente con un valor considerado inseguro (X-Frame-Options: ALLOW-FROM con origen no confiable; CSP con 'unsafe-inline' o 'unsafe-eval'; HSTS con max-age menor a 86400), THE Header_Analyzer SHALL generar un Finding con severidad "medium" indicando el valor actual y la configuración recomendada.
4. WHEN un header de seguridad está presente con un valor considerado seguro, THE Header_Analyzer SHALL generar un Finding con severidad "info" registrando la configuración correcta.
5. FOR ALL valid HTTP responses, parsing the headers then formatting them back to Findings then parsing again SHALL produce Findings equivalentes (propiedad round-trip del parser de headers).
6. WHEN el Header_Analyzer sigue redirecciones HTTP durante la obtención de la respuesta del Target, SHALL aplicar la validación anti-SSRF en cada salto de redirección conforme al Requisito 2 criterio 5.

---

### Requisito 5: Análisis de configuración TLS/SSL

**User Story:** Como usuario de CentinelaIA, quiero que el scanner verifique la configuración TLS/SSL del objetivo, para detectar protocolos obsoletos, cifrados débiles o certificados problemáticos.

#### Criterios de Aceptación

1. WHEN el Scanner analiza el Target, THE TLS_Checker SHALL intentar conexión con cada una de las siguientes versiones de protocolo: SSLv2, SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3, y generar un Finding por cada versión indicando si el servidor la soporta o no.
2. WHEN el servidor soporta SSLv2 o SSLv3, THE TLS_Checker SHALL generar un Finding con severidad "critical" indicando el uso de un protocolo con vulnerabilidades conocidas explotables.
3. WHEN el servidor soporta TLS 1.0 o TLS 1.1, THE TLS_Checker SHALL generar un Finding con severidad "high" indicando el uso de un protocolo obsoleto.
4. WHEN el Scanner analiza el Target, THE TLS_Checker SHALL verificar los cipher suites ofrecidos por el servidor y generar un Finding con severidad "high" por cada cipher suite que utilice algoritmos clasificados como inseguros (RC4, DES, 3DES, MD5, export-grade, NULL, o longitud de clave simétrica menor a 128 bits).
5. WHEN el Scanner analiza el Target, THE TLS_Checker SHALL verificar la validez del certificado SSL evaluando: fecha de expiración, cadena de confianza completa hasta una CA raíz reconocida, y coincidencia entre el dominio del Target y el CN o SAN del certificado.
6. WHEN el certificado del Target expira en menos de 30 días, THE TLS_Checker SHALL generar un Finding con severidad "medium" indicando la cantidad de días restantes hasta la expiración.
7. WHEN el certificado del Target ya ha expirado, THE TLS_Checker SHALL generar un Finding con severidad "critical" indicando que el certificado es inválido y la fecha en que expiró.
8. IF la cadena de confianza del certificado no puede ser verificada hasta una CA raíz reconocida (certificado autofirmado, CA intermedia faltante, o CA no confiable), THEN THE TLS_Checker SHALL generar un Finding con severidad "high" indicando el motivo específico del fallo de la cadena.
9. IF el dominio del Target no coincide con el CN ni con ningún valor del SAN del certificado, THEN THE TLS_Checker SHALL generar un Finding con severidad "high" indicando el dominio esperado y los dominios presentes en el certificado.
10. WHEN el servidor incluye el header Strict-Transport-Security con un valor de max-age igual o superior a 86400 segundos, THE TLS_Checker SHALL generar un Finding con severidad "info" confirmando que HSTS está habilitado e indicando el valor de max-age detectado.
11. IF el TLS_Checker no puede establecer una conexión TLS con el Target dentro del timeout configurado del módulo, THEN THE TLS_Checker SHALL generar un Finding con severidad "critical" indicando que no se pudo verificar TLS y registrar el error de conexión.

---

### Requisito 6: Verificación de seguridad de cookies

**User Story:** Como usuario de CentinelaIA, quiero que el scanner verifique los flags de seguridad de las cookies del objetivo, para identificar cookies que podrían ser vulnerables a robo o manipulación.

#### Criterios de Aceptación

1. WHEN el Target responde con headers Set-Cookie en cualquiera de las respuestas HTTP obtenidas durante el escaneo (incluyendo redirecciones hasta un máximo de 5 saltos), THE Cookie_Inspector SHALL verificar la presencia de los flags Secure, HttpOnly y SameSite en cada cookie, hasta un máximo de 50 cookies por escaneo. El seguimiento de redirecciones SHALL aplicar la validación anti-SSRF en cada salto conforme al Requisito 2 criterio 5.
2. WHEN una cookie carece del flag Secure, THE Cookie_Inspector SHALL generar un Finding con severidad "medium", categoría "cookies", y rawValue conteniendo el nombre de la cookie afectada, indicando que la cookie puede transmitirse por conexiones no cifradas.
3. WHEN una cookie carece del flag HttpOnly, THE Cookie_Inspector SHALL generar un Finding con severidad "medium", categoría "cookies", y rawValue conteniendo el nombre de la cookie afectada, indicando que la cookie es accesible desde JavaScript.
4. WHEN una cookie carece del flag SameSite o tiene el valor "None" sin el flag Secure, THE Cookie_Inspector SHALL generar un Finding con severidad "medium", categoría "cookies", y rawValue conteniendo el nombre de la cookie afectada, indicando vulnerabilidad a CSRF.
5. WHEN el Target no responde con cookies en ninguna de las respuestas HTTP obtenidas durante el escaneo, THE Cookie_Inspector SHALL generar un Finding con severidad "info" indicando que no se detectaron cookies para analizar.
6. IF un header Set-Cookie del Target contiene sintaxis malformada que impide extraer el nombre de la cookie o sus atributos, THEN THE Cookie_Inspector SHALL omitir esa cookie del análisis de flags y generar un Finding con severidad "low" indicando que se detectó una cookie con formato no parseable.

---

### Requisito 7: Verificación de registros DNS de seguridad

**User Story:** Como usuario de CentinelaIA, quiero que el scanner verifique los registros DNS de seguridad del objetivo, para identificar configuraciones de correo y dominio que permitan suplantación de identidad.

#### Criterios de Aceptación

1. WHEN el Scanner analiza el Target, THE DNS_Checker SHALL consultar el registro TXT del dominio para identificar la política SPF (prefijo "v=spf1"), consultar el registro TXT en el subdominio `_dmarc.<dominio>` para identificar la política DMARC (prefijo "v=DMARC1"), y verificar la presencia de registros DKIM en los selectores comunes ("default", "google", "selector1", "selector2") bajo `<selector>._domainkey.<dominio>`.
2. WHEN el dominio no tiene un registro SPF configurado, THE DNS_Checker SHALL generar un Finding con severidad "high" indicando que el dominio es vulnerable a email spoofing.
3. WHEN el dominio tiene un registro SPF que incluye el mecanismo "+all", THE DNS_Checker SHALL generar un Finding con severidad "high" indicando que la política SPF permite envío desde cualquier origen.
4. WHEN el dominio no tiene un registro DMARC configurado, THE DNS_Checker SHALL generar un Finding con severidad "high" indicando que no hay política de autenticación de correo definida.
5. WHEN el dominio tiene un registro DMARC con política "none" (p=none), THE DNS_Checker SHALL generar un Finding con severidad "medium" indicando que la política no rechaza correo no autenticado.
6. WHEN el DNS_Checker detecta un registro DKIM válido en al menos uno de los selectores consultados, THE DNS_Checker SHALL generar un Finding con severidad "info" confirmando la presencia de DKIM e indicando el selector encontrado.
7. WHEN el DNS_Checker no detecta registros DKIM en ninguno de los selectores consultados, THE DNS_Checker SHALL generar un Finding con severidad "medium" indicando que no se pudo confirmar la presencia de DKIM.
8. IF el DNS_Checker no recibe respuesta de los servidores DNS del Target dentro de 5 segundos por consulta, THEN THE DNS_Checker SHALL generar un Finding con severidad "low" indicando que no se pudieron consultar los registros DNS, registrar el error, y continuar con los demás módulos de verificación.

---

### Requisito 8: Fingerprinting de tecnología del servidor

**User Story:** Como usuario de CentinelaIA, quiero que el scanner identifique la tecnología del servidor objetivo, para que el motor de IA pueda correlacionar tecnología detectada con vulnerabilidades conocidas en fases futuras.

#### Criterios de Aceptación

1. WHEN el Scanner analiza el Target, THE Fingerprinter SHALL examinar los headers de respuesta HTTP (Server, X-Powered-By, X-AspNet-Version, X-Generator) para identificar tecnología del servidor.
2. WHEN el header Server está presente y contiene un valor no vacío, THE Fingerprinter SHALL generar un Finding con severidad "low" registrando el valor completo del header como tecnología detectada.
3. WHEN el header X-Powered-By está presente y contiene un valor no vacío, THE Fingerprinter SHALL generar un Finding con severidad "low" indicando la divulgación de tecnología backend y registrando el valor del header.
4. WHEN el header X-AspNet-Version o X-Generator está presente y contiene un valor no vacío, THE Fingerprinter SHALL generar un Finding con severidad "low" por cada header detectado, registrando el nombre del header y su valor.
5. WHEN ninguno de los headers examinados (Server, X-Powered-By, X-AspNet-Version, X-Generator) está presente o todos contienen valores vacíos, THE Fingerprinter SHALL generar un Finding con severidad "info" indicando que el servidor no divulga información de tecnología mediante headers HTTP.
6. IF el Fingerprinter no puede obtener una respuesta HTTP del Target para examinar los headers, THEN THE Fingerprinter SHALL generar un Finding con severidad "info" indicando que no se pudo realizar el fingerprinting y registrar el error de conexión.
7. WHEN el Fingerprinter sigue redirecciones HTTP durante la obtención de la respuesta del Target, SHALL aplicar la validación anti-SSRF en cada salto de redirección conforme al Requisito 2 criterio 5.

---

### Requisito 9: Estructura de hallazgos (Findings)

**User Story:** Como consumidor de la API (motor de IA), quiero que los hallazgos del scanner tengan una estructura JSON consistente, para poder procesarlos de forma automatizada y generar explicaciones.

#### Criterios de Aceptación

1. THE Scanner SHALL representar cada Finding como un objeto JSON con los campos obligatorios: category (string), severity (string), rawValue (string o null), y description (string, mínimo 10 caracteres, máximo 500 caracteres).
2. THE Scanner SHALL utilizar los valores de severity exclusivamente del conjunto: "critical", "high", "medium", "low", "info".
3. THE Scanner SHALL utilizar los valores de category exclusivamente del conjunto: "http-headers", "tls-ssl", "cookies", "dns-security", "server-fingerprint".
4. THE Scanner SHALL incluir en el Scan_Result un campo de metadatos con: scanId (string UUID v4), target (string), timestamp (ISO 8601), durationMs (number), totalFindings (number), y status (string del conjunto: "complete", "partial", "unreachable", "error").
5. THE Scanner SHALL incluir el arreglo de Findings en un campo llamado "findings" dentro del Scan_Result, y el valor de totalFindings en los metadatos SHALL ser igual a la longitud del arreglo findings.
6. FOR ALL valid Scan_Results, serializar a JSON y deserializar de vuelta SHALL producir un Scan_Result equivalente al original (propiedad round-trip de serialización).

---

### Requisito 10: Persistencia de resultados en DynamoDB

**User Story:** Como usuario de CentinelaIA, quiero que los resultados del escaneo se guarden para poder consultarlos después sin repetir el escaneo.

#### Criterios de Aceptación

1. WHEN un escaneo se completa con estado exitoso, THE Scan_Store SHALL persistir el Scan_Result completo en DynamoDB asociado al scanId correspondiente en un máximo de 3 segundos tras la finalización del escaneo.
2. WHEN un escaneo se completa con errores parciales, THE Scan_Store SHALL persistir los Findings obtenidos junto con un campo de status indicando "partial" y una lista de errores encontrados, utilizando la misma estructura JSON que un resultado exitoso.
3. WHEN el Scan_Store persiste un Scan_Result, THE Scan_Store SHALL asociarlo con el Session_ID proporcionado en la solicitud, utilizando Session_ID como clave de índice secundario para permitir consultar todos los escaneos de una misma sesión.
4. IF la solicitud de escaneo no incluye un Session_ID o el valor está vacío, THEN THE Scanner SHALL rechazar la solicitud con un código de error 400 y un mensaje indicando que Session_ID es obligatorio.
5. IF el Scan_Store no puede escribir en DynamoDB tras un máximo de 2 reintentos con backoff exponencial, THEN THE Scanner SHALL retornar los Findings al cliente en la respuesta HTTP con un campo adicional "persisted" en valor falso y registrar el error de persistencia en los logs.
6. IF el Scan_Result serializado excede 390 KB, THEN THE Scan_Store SHALL truncar el campo rawValue de los Findings de severidad "info" hasta que el ítem quepa dentro del límite de 400 KB de DynamoDB, y agregar un campo "truncated" en valor verdadero al Scan_Result persistido.

---

### Requisito 11: API REST para ejecución y consulta de escaneos

**User Story:** Como consumidor de la API (frontend o motor de IA), quiero endpoints REST para disparar escaneos y consultar resultados, para integrar el scanner con otros componentes del sistema.

#### Criterios de Aceptación

1. WHEN un cliente envía una solicitud POST a /scan con un body JSON válido (target, authorizationConfirmed, sessionId), THE Scanner SHALL iniciar el proceso de escaneo y retornar un código 200 con el Scan_Result completo en formato application/json.
2. WHEN un cliente envía una solicitud GET a /scan/{scanId}, THE Scanner SHALL recuperar el Scan_Result correspondiente de DynamoDB y retornarlo con código 200 en formato application/json.
3. WHEN un cliente envía una solicitud GET a /scan/{scanId} con un scanId que no existe, THE Scanner SHALL retornar un código 404 con un objeto JSON que contenga un campo error indicando que el recurso no fue encontrado.
4. IF el Scanner encuentra un error interno durante el escaneo, THEN THE Scanner SHALL retornar un código 500 con un objeto JSON que contenga un campo error con descripción del problema.
5. THE Scanner SHALL procesar las solicitudes POST /scan de forma síncrona, retornando los resultados completos en la misma respuesta HTTP.
6. IF un cliente envía una solicitud POST a /scan con un body que no es JSON válido o que no contiene todos los campos requeridos (target, authorizationConfirmed, sessionId), THEN THE Scanner SHALL retornar un código 400 con un objeto JSON que contenga un campo error indicando los campos faltantes o el problema de formato.
7. WHEN un cliente envía una solicitud GET a /scan?sessionId={sessionId}, THE Scanner SHALL retornar un código 200 con un array JSON de Scan_Results asociados a ese Session_ID, ordenados por timestamp descendente, con un máximo de 50 resultados por respuesta.

---

### Requisito 12: Extensibilidad del motor de escaneo

**User Story:** Como desarrollador del proyecto, quiero que el scanner sea fácil de extender con nuevos tipos de verificación, para incorporar funcionalidades futuras (ej. escaneo de puertos) sin refactorización mayor.

#### Criterios de Aceptación

1. THE Scanner SHALL organizar la lógica de cada tipo de verificación (headers, TLS, cookies, DNS, fingerprinting) en módulos de servicio independientes que implementen una interfaz común consistente en: una función que reciba como entrada un objeto con el Target y la configuración del escaneo, y retorne como salida un arreglo de objetos Finding según la estructura definida en el Requisito 8.
2. THE Scanner SHALL invocar cada módulo de verificación de forma que agregar un nuevo módulo requiera únicamente: crear el módulo implementando la interfaz definida en el criterio 1, y agregarlo a la lista de verificaciones activas, sin modificar el código de los módulos existentes ni la lógica de orquestación del Scanner.
3. THE Scanner SHALL permitir que cada módulo de verificación se ejecute y se pruebe de forma aislada, garantizando que ningún módulo importe ni referencie directamente a otro módulo de verificación, y que no compartan estado mutable entre sí.
4. IF un módulo de verificación registrado lanza una excepción durante su ejecución, THEN THE Scanner SHALL capturar el error, registrar un Finding con severidad "info" indicando la falla del módulo, y continuar ejecutando los módulos restantes sin interrumpir el escaneo.

---

### Requisito 13: Manejo de timeouts y objetivos no alcanzables

**User Story:** Como usuario de CentinelaIA, quiero que el scanner maneje graciosamente los casos en que el objetivo no responde o tarda demasiado, para obtener resultados parciales en vez de una falla total.

#### Criterios de Aceptación

1. WHEN un módulo de verificación no recibe respuesta del Target en un tiempo configurable (por defecto 5 segundos por módulo, rango válido: 1-10 segundos), THE Scanner SHALL cancelar la ejecución de ese módulo, generar un Finding con category correspondiente al módulo, severity "low", y description indicando timeout tras el tiempo configurado, y continuar con los demás módulos.
2. WHEN el primer intento de conexión HTTP al Target falla por error de resolución DNS o conexión rechazada antes de ejecutar cualquier módulo de verificación, THE Scanner SHALL retornar un Scan_Result con status "unreachable" y un Finding con category "http-headers", severity "critical", y description que incluya el tipo de error (DNS/conexión rechazada) y la dirección del Target.
3. IF la suma del tiempo transcurrido de ejecución del Scanner alcanza 25 segundos (margen de seguridad de 5 segundos respecto al límite máximo de Lambda de 30 segundos), THEN THE Scanner SHALL cancelar los módulos aún en ejecución, retornar un Scan_Result con status "partial" que incluya los Findings completados hasta ese momento, y un Finding adicional con severity "low" indicando qué módulos fueron cancelados por timeout global.
4. IF uno o más módulos finalizan con status "timeout" pero al menos un módulo completa exitosamente, THEN THE Scanner SHALL retornar el Scan_Result con status "partial" incluyendo tanto los Findings exitosos como los Findings de timeout generados por cada módulo cancelado.

---

### Requisito 14: Pruebas de módulos de escaneo

**User Story:** Como desarrollador del proyecto, quiero que cada módulo de escaneo tenga pruebas básicas, para asegurar que los parsers y checkers producen Findings correctos ante entradas conocidas.

#### Criterios de Aceptación

1. THE Header_Analyzer SHALL incluir al menos 3 pruebas unitarias que verifiquen la generación de Findings conforme al comportamiento definido en el Requisito 4: una para un header de seguridad presente con valor seguro, una para un header ausente, y una para un header con valor inseguro conocido, validando que el Finding resultante contenga la severidad y categoría esperadas según las reglas del Requisito 4.
2. THE TLS_Checker SHALL incluir al menos 3 pruebas unitarias que verifiquen: una para un protocolo obsoleto (TLS 1.0 o 1.1) que genere Finding con severidad "high", una para un certificado ya expirado que genere Finding con severidad "critical", y una para una configuración TLS válida que genere Finding con severidad "info", conforme al comportamiento definido en el Requisito 5.
3. THE Cookie_Inspector SHALL incluir al menos 2 pruebas unitarias que verifiquen: una para una cookie sin flags Secure/HttpOnly/SameSite que genere Findings con severidad "medium" por cada flag ausente, y una para una cookie con todos los flags presentes que no genere Findings de severidad superior a "info", conforme al comportamiento definido en el Requisito 6.
4. THE DNS_Checker SHALL incluir al menos 3 pruebas unitarias que verifiquen: una para un dominio sin registro SPF que genere Finding con severidad "high", una para un registro DMARC con política "none" que genere Finding con severidad "medium", y una para la presencia de DKIM que genere Finding con severidad "info", conforme al comportamiento definido en el Requisito 7.
5. THE Fingerprinter SHALL incluir al menos 2 pruebas unitarias que verifiquen: una para headers de respuesta que contengan Server y X-Powered-By que genere Findings con severidad "low" registrando la tecnología detectada, y una para headers sin información de tecnología que genere Finding con severidad "info", conforme al comportamiento definido en el Requisito 8.
6. THE Scanner SHALL ejecutar todas las pruebas de los módulos de escaneo utilizando datos de entrada fijos (fixtures o mocks) sin realizar conexiones de red reales, y todas las pruebas SHALL pasar exitosamente al ejecutar el comando de pruebas del proyecto.
