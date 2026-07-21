---
inclusion: fileMatch
fileMatchPattern: 'backend/services/scanner/**'
---

# CentinelaIA — Alcance funcional del motor de escaneo

## Checks a implementar (ordenados por prioridad para el MVP)

1. **Headers HTTP de seguridad**: Content-Security-Policy, Strict-Transport-Security,
   X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
   Para cada header ausente o mal configurado, registra severidad y una
   descripción técnica breve (la explicación en lenguaje simple la genera el
   motor de IA, no este módulo).
2. **TLS/SSL**: versión de protocolo soportada (marcar como hallazgo crítico si
   acepta TLS 1.0/1.1), fuerza de las cipher suites, validez y expiración del
   certificado, cadena de confianza.
3. **Cookies**: flags Secure, HttpOnly, SameSite en cualquier cookie detectada.
4. **DNS de seguridad**: presencia y validez de registros SPF, DKIM, DMARC.
5. **Fingerprinting de tecnología**: versión de servidor expuesta en headers
   (ej. `Server: nginx/1.18.0`), frameworks detectables vía headers o rutas
   comunes.

## Fuera del MVP, pero contempla el diseño para no bloquearlo después
- Escaneo de puertos comunes (top 100/1000) y detección de servicios/versiones
  expuestas — diseña el módulo de scanner de forma que agregar esta capacidad
  después no requiera reescribir la arquitectura base.
- Cruce de versiones de software detectadas contra la API pública de NVD/CVE
  para señalar vulnerabilidades conocidas específicas.

## Requisito de producto (no de alcance técnico)
Antes de ejecutar cualquier escaneo activo (no solo lectura de headers/DNS
pasivos), la interfaz debe pedir al usuario que confirme que tiene autorización
para escanear el objetivo ingresado. Esto es un patrón estándar en herramientas
de este tipo (similar a Qualys SSL Labs u OWASP ZAP) y forma parte del diseño
de producto, no una limitación de qué funcionalidades construir.

## Formato del resultado del scanner
El scanner debe devolver una estructura de datos consistente (lista de
hallazgos con: categoría, severidad, descripción técnica, evidencia cruda) que
el motor de IA (spec independiente) consume para generar explicaciones,
priorización y el score de riesgo compuesto. No mezcles la lógica de
explicación en lenguaje natural dentro del módulo de scanner — esa
responsabilidad es exclusiva del motor de IA.
