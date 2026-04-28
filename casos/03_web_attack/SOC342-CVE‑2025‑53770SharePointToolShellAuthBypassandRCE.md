# Informe de Incidente - CVE‑2025‑53770 SharePoint ToolShell Auth Bypass and RCE

## 1. Resumen Ejecutivo

Se investigó una alerta de seguridad relacionada con un POST sospechoso apuntando a ToolPane.aspx con un payload
bastante largo, lo que nos podría dar indicaciones de una explotación CVE-2025-53770.

La investigación determinó que se trata de un Verdadero Positivo.

---

## 2. Detalles de la Alerta

| Campo | Valor |
|---|---|
| Plataforma | LetsDefend |
| ID del Caso | SOC342 |
| Tipo de Alerta | Web attack |
| Severidad | Crítica |
| Estado | Escalado |
| Analista | Jorge Fernández Córcoles |
| Fecha | 27/04/2026 |

---

## 3. Información Inicial de la Alerta

| Campo | Valor |
|---|---|
| Nombre de la alerta | CVE‑2025‑53770 SharePoint ToolShell Auth Bypass and RCE |
| IP origen | 107.191.58.76 |
| IP destino | 172.16.20.17 |
| Hostname | SharePoint01 |
| Usuario | |
| Hash del fichero | |
| URL / Dominio | /_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx |
| Timestamp | Jul, 22, 2025, 01:07 PM |

---

## 4. Pasos de la Investigación

### 4.1 Revisión de la Alerta
La alerta mostraba un posible ataque dirigido a una vulnerabilidad crítica de remote code execution causada por la deserialización
de datos no confiables en Microsoft SharePoint Server. 

### 4.2 Análisis de Logs
Se revisaron los logs y se encontró únicamente un POST a /_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx usando una cabecera Referer (/_layouts/SignOut.aspx) para que la consulta POST parezca legítima para el Servidor. Una vez dentro del endpoint, el atacante ya puede ejecutar el payload malicioso sin problema (Remote Code Execution).

### 4.3 Análisis de IOCs
Contamos con "/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx" como URL y como cabecera Referer "/_layouts/SignOut.aspx", lo que nos dice con exactitud que nos encontramos ante un ataque. 

### 4.4 Actividad del Usuario / Endpoint
El endpoint SharePoint Server on-premises ha sido afectado. PowerShell con contenido en base64, se compila un ejecutable payload.exe y el atacante crea spinstall0.aspx. 

---

## 5. Hallazgos

- Petición POST a ToolPane.aspx con cabecera SignOut.aspx, con la intención de entrar al endpoint sin necesitar autenticación al entender el servidor que la petición viene de un usuario que ha cerrado sesión.
- PowerShell con contenido en base64, buscando extraer las Keys de SharePoint. Decodificando el payload vemos que intenta extraer la ValidationKey y la DecryptionKey. Con estas claves el atacante puede falsificar los tokens de autenticación y entrar al endpoint sin necesitar explotar las vulnerabilidades de nuevo. 
- Se compila un ejecutable payload.exe. El atacante consigue copiar y compilar malware en la máquina víctima usando csc.exe.
- Creando spinstall0.aspx desde el CMD el atacante consigue persistencia. Además el atacante consigue descargar el payload desde su servidor 107.191.58.76. 

---

## 6. Mapeo MITRE ATT&CK

| Táctica | Técnica | Sub-técnica | Descripción |
|---|---|---|---|
| Acceso Inicial | [T1190] | | Explotación de una vulnerabilidad pública como es SharePoint ToolShell Exploitation, autenticación bypass |
| Ejecución | [T1059] | [T1059.001] | Remote code execution tras lograr la entrada al Server |
| Persistencia | [T1505] | [T1505.003] | Despliegue de web shell para mantener el acceso al servidor |

---

## 7. Herramientas Utilizadas

| Herramienta | Uso |
|---|---|
| Mitre Att&ck | Para buscar información sobre la vulnerabilidad pública CVE‑2025‑53770 |
| Claude | A modo de información y ayuda para el informe |

---

## 8. Conclusión

| Campo | Valor |
|---|---|
| Clasificación | Verdadero Positivo |
| Impacto | Alto |

---

## 9. Acciones Recomendadas

- Mitigar la opción de la autenticación bypass a través de esa vulnerabilidad de SharePoint, instalando siempre los parches de seguridad.
- Seguir revisando los logs periódicamente. 
- Rotar las Keys de SharePoint. 
- Aislar el servidor temporalmente. 

---
