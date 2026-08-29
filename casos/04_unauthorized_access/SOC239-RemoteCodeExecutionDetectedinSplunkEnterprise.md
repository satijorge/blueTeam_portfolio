# Informe de Incidente - Remote Code Execution Detected in Splunk Enterprise

## 1. Resumen Ejecutivo

Se investigó una alerta de seguridad relacionada con [descripción breve de la alerta].

La investigación determinó que se trata de un [Verdadero Positivo / Falso Positivo / Actividad Benigna / Inconcluso].

---

## 2. Detalles de la Alerta

| Campo | Valor |
|---|---|
| Plataforma | LetsDefend |
| ID del Caso |  SOC239 |
| Tipo de Alerta | Unauthorized Access |
| Severidad | Alta |
| Estado | Escalado |
| Analista | Jorge Fernández Córcoles |
| Fecha | 23/06/2026 |

---

## 3. Información Inicial de la Alerta

| Campo | Valor |
|---|---|
| Nombre de la alerta | Remote Code Execution Detected in Splunk Enterprise |
| IP origen | 180.101.88.240 |
| IP destino | 172.16.20.13 |
| Hostname | Splunk Enterprise |
| Usuario | |
| Hash del fichero |  |
| URL / Dominio | http://18[.]219[.]80[.]54:8000/en-US/splunkd/__upload/indexing/preview?output_mode=json&props.NO_BINARY_CHECK=1&input.path=shell.xsl |
| Timestamp | Nov, 21, 2023, 12:24 PM |

---

## 4. Pasos de la Investigación

### 4.1 Revisión de la Alerta
[Describe qué mostraba la alerta y por qué requirió investigación.]
La alerta mostraba una ejecución remota de código (RCE) detectada en Splunk Enterprise. El endpoint era 172.16.20.13    

### 4.2 Análisis de Logs
[Explica qué logs se revisaron y qué se encontró.]

### 4.3 Análisis de IOCs
[Resume IPs, dominios, hashes, URLs u otros artefactos sospechosos.]

### 4.4 Actividad del Usuario / Endpoint
[Describe la actividad relevante del usuario o del endpoint.]

### 4.5 Línea de Tiempo del Incidente

| Timestamp | Evento |
|---|---|
| HH:MM:SS | Primer evento detectado |
| HH:MM:SS | ... |
---

## 5. Hallazgos

- "session opened for user admin(uid=0) by (uid=0)" este log indicaba que el atacante inició sesión como usuario root, llamado admin. 
- [Hallazgo 1]
- Con "useradd -m analsyt" el atacante crea un usuario y con "passwd analsyt" establece una contraseña. 
- 

---

## 6. Mapeo MITRE ATT&CK

| Táctica | Técnica | Sub-técnica | Descripción |
|---|---|---|---|
| Acceso Inicial | [Txxxx] | [Txxxx.xxx] | [Explicación] |
| Ejecución | [Txxxx] | [Txxxx.xxx] | [Explicación] |
| Evasión de Defensas | [Txxxx] | [Txxxx.xxx] | [Explicación] |

---

## 7. Herramientas Utilizadas

| Herramienta | Uso |
|---|---|
| VirusTotal | [Para qué se usó] |
| AnyRun | [Para qué se usó] |
| [Otra herramienta] | [Para qué se usó] |

---

## 8. Conclusión

| Campo | Valor |
|---|---|
| Clasificación | [Verdadero Positivo / Falso Positivo / Benigno / Inconcluso] |
| Impacto | [Bajo / Medio / Alto] |

---

## 9. Acciones Recomendadas

- [Acción 1]
- [Acción 2]
- [Acción 3]

---
