# CentinelaIA

CentinelaIA es un auditor de seguridad web serverless que inspecciona encabezados HTTP, TLS, cookies, DNS, CORS, métodos HTTP permitidos, security.txt y tecnologías expuestas. Sus hallazgos se guardan en DynamoDB y un motor compartido de IA los convierte en explicaciones claras, un score de riesgo con grado compuesto (A–F) y recomendaciones priorizadas. El mismo motor de IA también interpreta logs externos (Nmap y auth.log/fail2ban) subidos por el usuario, los enriquece con CVEs conocidos (NVD) y los correlaciona con los hallazgos del escáner. Úsalo únicamente sobre activos propios, laboratorios o sistemas para los que tengas autorización explícita.

## Qué hace

- **Escáner de seguridad web (10 checks):** headers HTTP de seguridad (incluyendo validación de HSTS ≥1 año + `includeSubDomains` y `nosniff` estricto), configuración TLS/SSL (con veredicto real de cadena de OpenSSL), cookies, registros DNS (SPF/DKIM/DMARC), fingerprinting de tecnología del servidor, verificación de CORS, métodos HTTP permitidos, presencia de security.txt, redirección HTTP→HTTPS, y exposición de rutas sensibles (`.git/HEAD`, `.env`, `phpinfo.php`).
- **Motor de IA compartido:** traduce los hallazgos técnicos a explicaciones en lenguaje simple, calcula un score de riesgo compuesto (0-100) con grado tipo SSL Labs (A–F) y prioriza qué corregir primero. El score pondera por categoría: CVEs por keyword (no verificados) cuentan al 50%; las correlaciones no duplican el conteo.
- **Traductor de logs:** parsea salidas de Nmap y logs de autenticación (auth.log/fail2ban) y los analiza con el mismo motor de IA.
- **Enriquecimiento CVE (NVD + CISA KEV):** cruza versiones de software detectadas con el NVD. Los CVEs presentes en el catálogo CISA KEV (explotación activa confirmada) se marcan con `[KEV - explotación activa]` y su severidad sube un escalón.
- **Correlación determinista (5 reglas):** combina hallazgos de múltiples fuentes en un solo análisis. Reglas activas: puerto HTTPS↔debilidad TLS, versión de servicio↔CVE, fuerza bruta SSH (auth.log)↔puerto SSH abierto (Nmap), CORS permisivo↔CSP débil, y problema de cadena TLS↔HSTS ausente. Funciona sin Bedrock — es por reglas puras y extensible (registry).
- **Grado A–F:** además del score numérico, el motor devuelve una letra fácil de leer (A = mínimo riesgo, F = crítico), visible de forma prominente en el frontend.
- **Historial navegable por sesión:** los escaneos y análisis se persisten en DynamoDB. El frontend permite reabrir cualquier resultado histórico desde el panel de historial (`GET /scan/{id}` y `GET /analyze/{id}`). La lista de análisis es liviana (sin findings/explanations); el detalle completo se carga bajo demanda.
- **Export de resultados:** el panel de resultados incluye botones para exportar el análisis como JSON descargable o PDF (vía `window.print()`), sin dependencias adicionales.
- **Frontend estático:** interfaz web ligera servida por CloudFront, con confirmación de autorización obligatoria antes de escanear.

## Naturaleza del escaneo (pasivo y semi-activo)

La mayoría de los checks son **pasivos**: leen lo que el objetivo ya publica en la
respuesta que se le pide (cabeceras HTTP, certificado y cifrado TLS, cookies,
registros DNS, tecnología expuesta). No prueban vulnerabilidades ni envían
cargas maliciosas.

El módulo de **exposición de recursos** (`security-exposure`) es la excepción:
realiza sondeo **semi-activo** de rutas que el objetivo no publica
(`/.git/HEAD`, `/.env`, `/phpinfo.php`) para comprobar si son accesibles. Son
peticiones GET normales, pero algunos WAF y sistemas de detección registran ese
patrón como intento de intrusión y pueden generar bloqueos o reportes de abuso
contra quien escanea. Por eso la herramienta exige confirmación explícita de
autorización antes de cualquier escaneo, y la registra como evidencia
(`ConsentEvidence`) junto al resultado.

Úsala únicamente sobre activos propios, laboratorios o sistemas para los que
tengas autorización expresa.

## Modo laboratorio (CLI)

La API pública **bloquea objetivos privados por diseño** (protección anti-SSRF en
tres capas: validación de entrada, lista de rangos reservados y validación en el
conector antes de abrir el socket). Eso es correcto para un servicio expuesto a
internet, pero impide auditar un laboratorio propio.

Para eso existe un CLI que ejecuta los 10 módulos del escáner **en tu máquina** y
envía los hallazgos al motor de análisis:

```bash
npm run lab -- --target http://127.0.0.1:8081 --authorize
```

Opciones:

- `--target <url|host[:port]>` — objetivo (obligatorio). En este modo se aceptan
  `localhost`, hosts sin TLD y `host:puerto`.
- `--authorize` — **obligatorio**. Equivale a la casilla de autorización del
  frontend y queda registrado en el resultado. Sin este flag el CLI no ejecuta.
- `--session-id <id>` — identificador de sesión para agrupar el historial.
- `--base-url <url>` — envía los hallazgos a un despliegue remoto en vez de
  procesarlos en el proceso local.
- `--out <ruta>` — guarda el resultado completo en JSON.

El modo se activa con la variable `CENTINELAIA_ALLOW_PRIVATE_TARGETS=true`, que el
propio CLI establece en su proceso. Esa variable **se ignora cuando el código corre
en AWS Lambda**: la protección del servicio público no puede desactivarse por una
variable de entorno mal configurada en el despliegue.

## Categorías de hallazgos

| Categoría | Fuente |
|---|---|
| `http-headers` | Escáner (headers, HSTS, CSP, redirect HTTP→HTTPS) |
| `tls-ssl` | Escáner |
| `cookies` | Escáner |
| `dns-security` | Escáner |
| `server-fingerprint` | Escáner (fingerprinting de tecnología) |
| `cors` | Escáner |
| `http-methods` | Escáner |
| `security-txt` | Escáner |
| `port-service` | Traductor de logs (filas de Nmap con puerto/servicio/versión estructurados) |
| `security-exposure` | Escáner (exposición de `.git`, `.env`, `phpinfo.php`) |
| `log-analysis` | Traductor de logs (auth.log / fail2ban) |
| `known-vulnerabilities` | Enriquecimiento CVE (NVD + CISA KEV) |
| `correlation` | Motor de correlación determinista (5 reglas) |

## Arquitectura

El backend está escrito en TypeScript y se ejecuta en AWS Lambda detrás de una API Gateway HTTP API. AWS SAM define las funciones, las tablas DynamoDB bajo demanda, los permisos mínimos para invocar Bedrock (parametrizados por región y partición del stack) y el frontend (S3 privado + CloudFront con Origin Access Control).

### Motor de IA: tres modos de ejecución

El motor de IA selecciona su proveedor con la variable de entorno `AI_ENGINE_MODE`:

- `bedrock` — invoca Amazon Bedrock con el modelo **Nova Micro** (menor costo). Requiere acceso al modelo y cuota disponible en la región del stack.
- `mock` — cliente simulado que devuelve el mismo esquema de respuesta que el modelo real, sin costo ni cuota. Útil para demos y pruebas de contrato.
- `fallback` — genera explicaciones y recomendaciones por reglas, sin invocar ningún modelo. Es el modo por defecto del despliegue: garantiza que el sistema nunca falle por cuota de Bedrock.

En cualquier modo, si el cliente de IA falla o se agota el tiempo, el motor degrada automáticamente al modo por reglas y marca el resultado con `degraded: true` y `metadata.executionMode`.

## API

Todos los endpoints comparten la misma HTTP API:

- `POST /scan` — ejecuta un escaneo (requiere `authorizationConfirmed: true`).
- `GET /scan/{scanId}` — obtiene un escaneo por ID.
- `GET /scan?sessionId=...` — lista escaneos de una sesión.
- `POST /analyze` — analiza findings con el motor de IA. Acepta campos opcionales `nmapOutput` (salida de Nmap) y `authLog` (auth.log/fail2ban) para traducir, enriquecer con CVEs y **correlacionar** logs con los findings enviados.
- `GET /analyze/{analysisId}` — obtiene un análisis por ID.
- `GET /analyze?sessionId=...` — lista análisis de una sesión.
- `POST /translate-log` — traduce logs a findings estructurados sin invocar IA. Acepta `nmapOutput` (salida de Nmap) y/o `authLog` (auth.log/fail2ban); requiere al menos uno de los dos campos.

### Autenticación

La API valida un header `x-api-key` contra el secreto pasado en el despliegue (parámetro `ApiSharedSecret`). Si no se configura secreto, la autenticación queda deshabilitada (útil para desarrollo local); en producción debes configurarlo siempre.

## Requisitos

- Node.js 22 y npm.
- Para despliegue o ejecución serverless local: AWS SAM CLI.
- Para desplegar: AWS CLI autenticada mediante un perfil o variables del entorno del sistema, permisos sobre CloudFormation, Lambda, API Gateway, DynamoDB, S3, CloudFront, IAM y Bedrock, y acceso al modelo configurado en la región elegida.
- Docker o Finch solo si se usa `sam local`.

No guardes credenciales, tokens ni archivos `.env` reales en este repositorio. La configuración de AWS debe permanecer fuera del proyecto.

## Preparación local

Desde la raíz del repositorio instala exactamente las dependencias bloqueadas:

```bash
npm ci
```

## Compilación

```bash
npm run build
```

TypeScript genera los artefactos de Lambda en `backend/dist/`.

## Pruebas

```bash
npm test
```

Este comando ejecuta Vitest una vez, sin modo watch. Para desarrollo interactivo existe `npm run test:watch`, pero no se usa en la puerta de validación.

## Ejecución local opcional

Después de compilar, construye la aplicación SAM e inicia la API local:

```bash
sam build --template-file infra/template.yaml
sam local start-api
```

Los escaneos deben incluir confirmación de autorización del objetivo.

## Frontend

El frontend estático vive en `frontend/` (HTML, CSS y JavaScript sin frameworks). Para ejecutarlo localmente:

1. Copia `frontend/config.example.js` a `frontend/config.js`.
2. Completa `API_BASE_URL` con la URL de tu API (output `ScanApiUrl` del stack) y `API_KEY` con el secreto configurado en el despliegue (o déjalo vacío si la auth está deshabilitada).
3. Sirve la carpeta con cualquier servidor estático (por ejemplo `npx serve frontend`).

`frontend/config.js` está en `.gitignore` para no publicar la URL ni el secreto de tu despliegue.

## Despliegue con AWS SAM

Valida, construye y despliega desde la raíz. El primer despliegue puede usar el asistente para revisar región, nombre del stack y capacidades; no escribas credenciales en `samconfig.toml`.

```bash
sam validate --lint --template-file infra/template.yaml
sam build --template-file infra/template.yaml
sam deploy --guided --parameter-overrides ApiSharedSecret=<tu-secreto-fuerte>
```

Los siguientes despliegues pueden usar `sam deploy`, que lee `samconfig.toml` (pasa de nuevo `--parameter-overrides ApiSharedSecret=...`). Al finalizar, SAM muestra en los outputs las URL de `/scan`, `/analyze` y del frontend en CloudFront. Sube los archivos del frontend al bucket con `aws s3 sync frontend/ s3://<FrontendBucketName>/` (usa el output `FrontendBucketName`).

Para usar el modelo real de IA, cambia `AI_ENGINE_MODE` a `bedrock` en el template (o vía override) una vez que tengas acceso y cuota de Nova Micro; de lo contrario deja `fallback` (o usa `mock` para demostrar el formato de salida sin costo).

El despliegue crea recursos que pueden generar costos en AWS; revisa el change set y elimina el stack cuando ya no sea necesario.
