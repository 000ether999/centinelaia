---
inclusion: always
---

# CentinelaIA — Estructura del proyecto

## Organización de carpetas esperada
Propone y respeta una estructura similar a esta (ajusta nombres si el stack
elegido lo justifica, pero mantén la separación de responsabilidades):

```
centinelaia/
├── frontend/              # Aplicación web (estática o SPA simple)
├── backend/
│   ├── handlers/          # Handlers livianos de Lambda (parsean evento, llaman a services)
│   ├── services/          # Lógica de negocio: scanner, motor de IA, correlación
│   ├── models/            # Definiciones de datos (hallazgos, reportes, score)
│   └── tests/
├── infra/                 # Definición de infraestructura como código (AWS CDK/SAM/Terraform)
├── .kiro/
│   ├── steering/          # Este archivo y los demás steering files
│   └── specs/             # Los 3 specs del proyecto (scanner, motor IA, logs)
└── README.md
```

## Reglas de organización
- Agrupa funciones Lambda por dominio (`backend/services/scanner/`,
  `backend/services/ai-engine/`, `backend/services/log-translator/`), no por
  tipo técnico.
- El motor de IA (`ai-engine`) debe ser un módulo **compartido**, invocado tanto
  por el flujo del scanner como por el flujo del traductor de logs — no
  dupliques la lógica de prompts o llamadas a Bedrock en dos lugares distintos.
- Los tres specs (`scanner`, `ai-engine`, `log-translator`) deben poder
  desarrollarse y probarse de forma independiente, incluso si comparten el
  módulo de IA.
- El README.md raíz debe explicar: qué hace el proyecto, cómo desplegarlo, y
  cómo correrlo localmente — esto es un entregable obligatorio del hackathon,
  no opcional.
