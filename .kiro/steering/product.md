---
inclusion: always
---

# CentinelaIA — Visión de producto

## Qué es
CentinelaIA es un auditor de seguridad web potenciado por IA. Combina un motor de
escaneo técnico con un motor de análisis por IA que traduce hallazgos crudos
(propios y de logs externos subidos por el usuario) en explicaciones claras,
priorizadas por riesgo real, para gente que no necesariamente es experta en
ciberseguridad.

## Por qué existe (problema que resuelve)
Las herramientas de auditoría de seguridad existentes (Nmap, testssl.sh,
securityheaders.com, Qualys SSL Labs) entregan resultados técnicos crudos que
requieren experiencia para interpretar. CentinelaIA cierra esa brecha: un mismo
motor de IA explica, prioriza y correlaciona hallazgos de múltiples fuentes
(scanner propio + logs subidos), en vez de mostrar listas técnicas aisladas.

## Usuarios objetivo
- Estudiantes y profesionales de ciberseguridad en laboratorios de entrenamiento.
- Equipos de desarrollo/DevOps pequeños sin especialista en seguridad dedicado.
- Cualquier persona que administra un servidor o sitio propio y quiere una
  auditoría rápida y comprensible.

## Contexto de uso
Esta herramienta está diseñada para auditar activos propios o de laboratorio
(entornos de práctica, dominios propios, infraestructura propia). El diseño de
producto debe incluir un campo de confirmación de autorización antes de escanear
un objetivo (patrón estándar en herramientas de este tipo, como Qualys SSL Labs),
pero esto es una decisión de UX del producto, no una limitación de alcance técnico.

## Alcance por fases (MVP de hackathon vs roadmap post-hackathon)

### Fase 1 — MVP del hackathon (5 días, debe quedar 100% funcional)
- Motor de escaneo: headers HTTP de seguridad, configuración TLS/SSL, cookies,
  registros DNS de seguridad (SPF/DKIM/DMARC), fingerprinting básico de
  tecnología del servidor.
- CORS: detección de política de origen cruzado permisiva o ausente.
- Métodos HTTP: detección de métodos peligrosos habilitados (PUT, DELETE, TRACE, etc.).
- security.txt: verificación de existencia del archivo de divulgación responsable.
- Motor de IA: traduce los hallazgos del scanner a explicaciones + genera un
  score de riesgo compuesto + prioriza qué arreglar primero.
- Traductor de logs: soporta al menos un formato (salida de Nmap) subido como
  texto/archivo, analizado por el mismo motor de IA del punto anterior.
- Correlación simple entre hallazgos del scanner y hallazgos del log.
- Historial de escaneos persistido (sin necesidad de cuentas de usuario
  complejas — un identificador simple de sesión/proyecto es suficiente para el
  MVP).
- Integración con la API pública de NVD/CVE para cruzar versiones de software
  detectadas con vulnerabilidades conocidas.

### Fase 2 — Roadmap post-hackathon (no bloquea la entrega, pero el diseño de
Fase 1 no debe hacer imposible construir esto después)
- Escaneo de puertos comunes y detección de servicios expuestos.
- Soporte para más formatos de log (auth.log, fail2ban, Wireshark/pcap export).
- Autenticación real de usuarios y equipos, con historial por cuenta.
- Exportación de reportes en PDF.
- Escaneos programados/recurrentes con alertas de cambios.

## Criterios de éxito (alineados a la rúbrica del hackathon)
- Impacto tecnológico: la herramienta debe resolver un problema real de forma
  verificable, no ser un demo cosmético.
- Innovación: el diferenciador es el motor de IA **compartido** entre el
  scanner propio y los logs externos — no tratarlos como dos features
  separadas.
- Software funcional: repo público con README claro, demo desplegada, video
  de presentación.
- Uso de AWS: los servicios de AWS deben ejecutar la lógica central (no ser
  decorativos).
