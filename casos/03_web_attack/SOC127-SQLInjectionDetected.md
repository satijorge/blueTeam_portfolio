# Informe de Incidente - SQL Injection Detected

## 1. Resumen Ejecutivo

Se investigó una alerta de seguridad relacionada con inyecciones SQL al endpoint servidor web "WebServer1000". No es posible determinar con certeza la respuesta a estas consultas desde el log management, así que se la alerta va a escalar de nivel para ser nuevamente revisada. Sin embargo, el informe incluye información detallada de los sucesos. 

La investigación determinó que se trata de un Verdadero Positivo.

---

## 2. Detalles de la Alerta

| Campo | Valor |
|---|---|
| Plataforma | LetsDefend |
| ID del Caso | SOC127 |
| Tipo de Alerta | Web Attack |
| Severidad | Alta |
| Estado | Escalado |
| Analista | Jorge Fernández Córcoles |
| Fecha | 26/05/2026 |

---

## 3. Información Inicial de la Alerta

| Campo | Valor |
|---|---|
| Nombre de la alerta | SQL Injection Detected |
| IP origen | 118.194.247.28 |
| IP destino | 172.16.20.12 |
| Hostname | WebServer1000 |
| Usuario | |
| Hash del fichero | |
| URL / Dominio | |
| Timestamp | Mar, 07, 2024, 12:51 PM |

---

## 4. Pasos de la Investigación

### 4.1 Revisión de la Alerta
La alerta mostraba la detección de un ataque SQL injection en el endpoint WebServer1000 con IP 172.16.20.12. El payload mostraba indicios de XSS y de comand injection en la base de datos. EXEC xp_cmdshell('cat ../../../etc/passwd') intenta ejecutar en una cmdshell la lectura del fichero passwd. Con <script>alert("XSS")</script>, intenta ejecutar el script en el endpoint. Se decidió investigar porque los indicios son muy claros de inyección SQL.

### 4.2 Análisis de Logs
Los logs mostraron indicaciones de un ataque de inyección SQL desde la dirección IP 118.194.247.28 hacia el endpoint WebServer1000. El ataque comienza con un payload genérico de inyección SQL. Este payload incluye numerosos vectores de ataque distintos: (XSS, command execution, etc...). El código 200 indica que los payloads fueron procesados por el servidor y llegaron a la base de datos, aunque no es posible confirmar si fueron ejecutados con éxito. Después de este payload el atacante comienza a realizar consultas de reconocimiento: para saber cuál es la base de datos, para enumerar columnas, etc... 

### 4.3 Análisis de IOCs
118.194.247.28 es la IP desde donde se realizan las consultas SQL. En VirusTotal aparece marcada como maliciosa por 10/91 vendors (Fortinet y BitDefender, entre otros). 

### 4.4 Actividad del Usuario / Endpoint
No existe ningún índice de actividad en el endpoint ya que el EDR no lo incluye entre sus máquinas. Incluso filtrando por IP (172.16.20.12) y buscando el nombre del Hostname (WebServer1000).  

## 4.5 Línea de Tiempo del Incidente

| Timestamp | Evento |
|---|---|
| 12:51:45 | Primera consulta que incluye un payload de reconocimiento. |
| 12:53:07 | Consulta de reconocimiento (errores de sintaxis), el atacante comienza a realizar varias consultas para comprobar si está permitida la inyección SQL en el servidor. |
| ... | ... |
| 12:53:47 | Consulta de reconocimiento (numero de columnas), el atacante realiza su última query a la base de datos. |
---

## 5. Hallazgos

- (GET /?douj=3034 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert("XSS")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')# HTTP/1.1" 200 865), que incluye XSS e inyección de comandos. 
- GET /index.php?id=1);SELECT DBMS_PIPE.RECEIVE_MESSAGE('hamM',5) FROM DUAL--, con el que comprueba que hay inyección SQL e intenta conocer si motor de la BD es oracle. 
- GET /index.php?id=1 ORDER BY 8991-- eXLc HTTP/1.1" 200 865, para comprobar exactamente cuantas columnas tiene la query. 

---

## 6. Mapeo MITRE ATT&CK

| Táctica | Técnica | Sub-técnica | Descripción |
|---|---|---|---|
| Acceso Inicial | T1190 | | Explota una vulnerabilidad conocida como SQL injection contra una aplicación web pública. |
| Ejecución | T1059 | | El atacante intenta ejecutar comandos con xp_cmdshell('cat ../../../etc/passwd') |
| Evasión de Defensas | T1027 | | Codificación URL en los payloads de las consultas SQL como técnica de evasión. |
| Descubrimiento | T1082 | | Intento de lectura de passwd. |

---

## 7. Herramientas Utilizadas

| Herramienta | Uso |
|---|---|
| VirusTotal | Para comprobar la dirección IP origen del ataque. |
| Claude | Para la resolución de dudas y elaboración del informe.  |
| Mitre Att&ck | Para realizar el mapeo |

---

## 8. Conclusión

| Campo | Valor |
|---|---|
| Clasificación | Verdadero Positivo |
| Impacto | Alto |

---

## 9. Acciones Recomendadas

- Bloquear la IP del atacante 118.194.247.28 en el WAF y firewall. 
- Aislar el servidor si fuera posible. 
- Para comprobar que devolvió el servidor, analizar el cuerpo de las respuestas a las consultas SQL para ver si ha habido algún compromiso indebido. 
- Comprobar si hay persistencia. 
- Parchear la vulnerabilidad y establecer el mínimo privilegio al usuario no root de la base de datos. 

---
