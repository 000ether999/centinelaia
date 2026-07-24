# CentinelaIA

CentinelaIA es un auditor de seguridad web serverless que inspecciona encabezados HTTP, TLS, cookies, DNS y tecnologías expuestas. Sus hallazgos se guardan en DynamoDB y un motor compartido de IA en Amazon Bedrock los convierte en explicaciones y prioridades comprensibles. Úsalo únicamente sobre activos propios, laboratorios o sistemas para los que tengas autorización explícita.

## Arquitectura

El backend está escrito en TypeScript y se ejecuta en AWS Lambda detrás de API Gateway HTTP API. AWS SAM define las funciones, las tablas DynamoDB bajo demanda y los permisos mínimos para invocar Bedrock. El modelo predeterminado es Amazon Nova Micro para mantener bajo el costo.

## Requisitos

- Node.js 22 y npm.
- Para despliegue o ejecución serverless local: AWS SAM CLI.
- Para desplegar: AWS CLI autenticada mediante un perfil o variables del entorno del sistema, permisos sobre CloudFormation, Lambda, API Gateway, DynamoDB, S3, IAM y Bedrock, y acceso al modelo configurado en la región elegida.
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

La API expone `POST /scan`, `GET /scan/{scanId}`, `GET /scan?sessionId=...`, `POST /analyze`, `GET /analyze/{analysisId}` y `GET /analyze?sessionId=...`. Los escaneos deben incluir confirmación de autorización del objetivo.

## Despliegue con AWS SAM

Valida, construye y despliega desde la raíz. El primer despliegue puede usar el asistente para revisar región, nombre del stack y capacidades; no escribas credenciales en `samconfig.toml`.

```bash
sam validate --lint --template-file infra/template.yaml
sam build --template-file infra/template.yaml
sam deploy --guided
```

Los siguientes despliegues pueden usar `sam deploy`, que lee `samconfig.toml`. Al finalizar, SAM muestra las URL de `/scan` y `/analyze` en los outputs del stack. El despliegue crea recursos que pueden generar costos en AWS; revisa el change set y elimina el stack cuando ya no sea necesario.