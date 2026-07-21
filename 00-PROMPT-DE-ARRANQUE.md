# Prompt de arranque — pegar en el chat de Specs de Kiro (una sola vez)

> Instrucciones de uso: primero copia los 5 archivos de la carpeta `.kiro/steering/`
> a tu repo (en esa misma ruta). Luego abre Kiro, cambia a **modo Specs**, y pega
> el siguiente prompt completo como tu primer mensaje. Kiro ya tendrá los steering
> files cargados como contexto permanente, así que este prompt no necesita repetir
> todo el detalle técnico — solo dispara el proceso de planificación.

---

Quiero construir **CentinelaIA**, un auditor de seguridad web potenciado por IA, como
proyecto de hackathon con entrega en 5 días. Ya tienes el contexto completo del
producto, el stack, la estructura y el alcance de seguridad en mis steering files —
úsalos como fuente de verdad antes de proponer nada.

Antes de escribir una sola línea de código, quiero que hagas lo siguiente, en este orden:

1. **Propón el stack técnico completo** (lenguaje backend, framework frontend si aplica,
   servicios AWS específicos) optimizando por: (a) mínimo costo — prioriza servicios
   dentro del free tier de AWS y evita llamadas a APIs externas de pago, (b) velocidad
   de desarrollo en 5 días para una sola persona sin experiencia previa en desarrollo
   web, y (c) que el resultado sea desplegable y con buena demo en vivo. Justifica
   brevemente cada elección.

2. **Divide el proyecto en 3 specs independientes**, en este orden de prioridad
   (cada uno debe poder demostrarse por sí solo si el tiempo se acaba):
   - Spec 1: Motor de escaneo (headers HTTP, TLS/SSL, cookies, DNS/SPF-DKIM-DMARC,
     fingerprinting de tecnología).
   - Spec 2: Motor de análisis con IA (traduce los hallazgos del scanner a
     explicaciones claras + prioriza qué arreglar primero + genera un score de
     riesgo compuesto).
   - Spec 3: Traductor de logs subidos por el usuario (Nmap, auth.log/fail2ban) que
     reutiliza el mismo motor de IA del Spec 2 y correlaciona hallazgos entre
     ambas fuentes.

3. Para el **Spec 1**, genera primero `requirements.md` en notación EARS con las
   historias de usuario, luego espera mi aprobación antes de generar `design.md`,
   y espera mi aprobación de `design.md` antes de generar `tasks.md`. No ejecutes
   ninguna tarea todavía.

4. Al proponer el diseño, ten en cuenta que **este proyecto debe seguir siendo
   desarrollable después del hackathon** — evita decisiones que solo funcionen como
   demo desechable; prioriza una base de código real, aunque el alcance del MVP
   sea acotado.

5. Antes de cerrar esta primera conversación, dime explícitamente:
   - Qué modelo(s) vas a usar por defecto para las tareas del Spec 1 (y por qué,
     en términos de costo/rendimiento).
   - Un presupuesto estimado de créditos para completar el Spec 1 completo.
   - Cualquier configuración adicional de MCP, hooks o permisos de AWS que
     necesites que yo habilite antes de que puedas empezar a ejecutar tareas.

Recuerda: soy nuevo desarrollando este tipo de aplicaciones, así que cuando generes
`design.md`, incluye breves explicaciones de por qué eliges cada patrón o servicio,
no solo qué vas a construir.
