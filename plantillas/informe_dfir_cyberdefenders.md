# Informe Forense - [Título del Caso]

## 1. Resumen Ejecutivo

Se realizó un análisis forense digital sobre [descripción del caso: tipo de incidente, sistemas afectados, contexto]. 

El análisis determinó que [conclusión principal del análisis].

---

## 2. Detalles del Caso

| Campo | Valor |
|---|---|
| Plataforma | CyberDefenders |
| Nombre del Lab | [Nombre del laboratorio] |
| Categoría | [Malware Analysis / Threat Hunting / Network Forensics / Memory Forensics / Disk Forensics] |
| Dificultad | [Easy / Medium / Hard] |
| Analista | Jorge Fernández Córcoles |
| Fecha | DD/MM/AAAA |

---

## 3. Evidencias Disponibles

| Evidencia | Tipo | Descripción |
|-----------|------|-------------|
| [archivo.vmem] | Volcado de memoria | [Descripción breve] |
| [imagen.E01] | Imagen de disco | [Descripción breve] |
| [captura.pcap] | Captura de red | [Descripción breve] |
| [logs/] | Logs del sistema | [Descripción breve] |

---

## 4. Entorno y Herramientas

| Herramienta | Versión | Uso |
|-------------|---------|-----|
| Volatility | [2/3] | Análisis de volcado de memoria |
| Autopsy / FTK Imager | | Análisis de imagen de disco |
| Wireshark | | Análisis de tráfico de red |
| CyberChef | | Decodificación y análisis de artefactos |
| [Otra herramienta] | | [Uso] |

---

## 5. Análisis

### 5.1 Análisis de Memoria
[Describe los hallazgos del volcado de memoria: procesos sospechosos, conexiones de red activas, artefactos en memoria, inyecciones, etc.]

```
# Comandos Volatility relevantes utilizados
vol.py -f archivo.vmem --profile=[perfil] [plugin]
```

### 5.2 Análisis de Disco
[Describe los hallazgos del análisis de la imagen de disco: archivos modificados, eliminados o sospechosos, rutas relevantes, artefactos del sistema de archivos, registro de Windows, prefetch, etc.]

### 5.3 Análisis de Red
[Describe el tráfico analizado: conexiones a C2, exfiltración de datos, protocolos usados, IPs y dominios implicados, patrones anómalos.]

### 5.4 Análisis de Logs
[Describe los logs revisados: eventos de Windows, logs de aplicación, autenticaciones, ejecuciones de procesos.]

### 5.5 Artefactos Identificados

| Artefacto | Tipo | Valor | Observaciones |
|-----------|------|-------|---------------|
| [nombre] | [Hash / IP / Dominio / Ruta] | [valor] | [descripción] |
| | | | |

---

## 6. Línea de Tiempo Forense

| Timestamp (UTC) | Fuente | Evento |
|-----------------|--------|--------|
| YYYY-MM-DD HH:MM:SS | [Log / Disco / Memoria / Red] | [Descripción del evento] |
| YYYY-MM-DD HH:MM:SS | | |

---

## 7. Hallazgos

- [Hallazgo 1 — qué se encontró y qué significa]
- [Hallazgo 2]
- [Hallazgo 3]

---

## 8. Mapeo MITRE ATT&CK

| Táctica | Técnica | Sub-técnica | Descripción |
|---|---|---|---|
| [Táctica] | [Txxxx] | [Txxxx.xxx] | [Explicación] |
| | | | |

---

## 9. Conclusión

| Campo | Valor |
|---|---|
| Tipo de incidente | [Malware / Intrusión / Exfiltración / Ransomware / ...] |
| Impacto | [Bajo / Medio / Alto / Crítico] |
| Sistemas afectados | [Lista de sistemas] |
| ¿Contenido? | [Sí / No / Parcialmente] |

[Descripción del alcance del compromiso y conclusión del análisis.]

---

## 10. Acciones Recomendadas

- [Acción 1 — remediación / contención]
- [Acción 2 — hardening]
- [Acción 3 — mejora de detección]

---
