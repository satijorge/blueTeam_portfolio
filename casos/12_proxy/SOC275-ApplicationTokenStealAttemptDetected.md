# Informe de Incidente - Application Token Steal Attempt Detected

## 1. Resumen Ejecutivo

Se investigó una alerta de seguridad relacionada con un robo de token de aplicación dirigido al endpoint Gloriana. El atacante utiliza un correo phishing como vector de acceso inicial y consigue que desde el endpoint se clique el enlace malicioso. Como resultado, el token de aplicación se exfiltra con exito hacia un servidor fraudulento.

La investigación determinó que se trata de un Verdadero Positivo.

---

## 2. Detalles de la Alerta

| Campo | Valor |
|---|---|
| Plataforma | LetsDefend |
| ID del Caso | SOC275 |
| Tipo de Alerta | Web Attack / Proxy / Phishing |
| Severidad | Alta |
| Estado | Escalado |
| Analista | Jorge Fernández Córcoles |
| Fecha | 08/05/2026 |

---

## 3. Información Inicial de la Alerta

| Campo | Valor |
|---|---|
| Nombre de la alerta | Application Token Steal Attempt Detected |
| IP origen | 23.82.12.29 |
| IP destino | 172.16.17.172 |
| Hostname | Gloriana |
| Usuario | gloriana@letsdefend.io |
| Hash del fichero | |
| URL / Dominio | http://homespottersf[.]com:8081/reset-password?token=123letsdefendisthebest123 |
| Timestamp | Apr, 19, 2024, 08:23 AM |

---

## 4. Pasos de la Investigación

### 4.1 Revisión de la Alerta
La alerta mostraba la detección un intento de robo de token de aplicación, por lo tanto se decidió investigarlo. Al usuario del Endpoint (gloriana@letsdefend.io) le llega un correo con dos url's maliciosas. "https://download[.]cyberlearn[.]academy/download/download?url=" y "http://homespottersf[.]com:8081/reset-password?token=123letsdefendisthebest123". Nos centraremos en la segunda de aquí en adelante, porque el POST y la exfiltración del token están vinculados a homespottersf[.]com, no al otro dominio.
 

### 4.2 Análisis de Logs
El usuario clica en el enlace y aquí es donde aparecen los dos siguientes logs: 
- GET /reset-password?email=gloriana@letsdefend.io. Este es el GET aparece cuando el usuario clica en enlace y le dirige a un sitio web: homespottersf[.]com. 
- POST /reset-password?token=123letsdefendisthebest123. Posteriormente se realiza un POST con el token de aplicación descrito anteriormente. Este POST es dirigido hacia un servidor marcado como malicioso en VirusTotal. 

### 4.3 Análisis de IOCs
23.82.12.29 es la direccion IP del sitio web "http://homespottersf[.]com:8081/reset-password", donde se realiza el POST con el token.
"https://download[.]cyberlearn[.]academy/download/download?url=" es un dominio malicioso (10/94 flags en VirusTotal). No fue posible determinar su rol con los datos disponibles.
"http://homespottersf[.]com:8081/reset-password?token=123letsdefendisthebest123" es la dirección del POST con el token ya incluído, listo para el atacante. 

### 4.4 Actividad del Usuario / Endpoint
En cuanto a la actividad del usuario conocemos que clica en el enlace, y contamos con dos solicitudes HTTP. El GET y después el POST. No tenemos ningún indicio de que el ataque continuara en la máquina Gloriana.  


## 4.5 Línea de Tiempo del Incidente

| Timestamp | Evento |
|---|---|
| 07:48:00 | Llega un correo que incluye las dos URL's maliciosas "https://download[.]cyberlearn[.]academy/download/download?url=" y "http://homespottersf[.]com:8081/reset-password?token=123letsdefendisthebest123" |
| 08:23:40 | GET /reset-password?email=gloriana@letsdefend.io HTTP/1.1 |
| 08:23:46 | POST token -> homespottersf[.]com ->  Respuesta 200 (exfiltración exitosa)  |

---

## 5. Hallazgos

- "https://download[.]cyberlearn[.]academy/download/download?url=" marcada en VirusTotal como malware y phishing. 10/94 vendors la flaguean. 
- "http://homespottersf[.]com:8081/reset-password?token=123letsdefendisthebest123"  sitio web malicioso según VirusTotal. 2/94 vendors la marcan. 
- 23.82.12.29 IP destino para exfiltración del token y marcada en VirusTotal como maliciosa por phishing (1/92). Con sede en Leaseweb USA.  

---

## 6. Mapeo MITRE ATT&CK

| Táctica | Técnica | Sub-técnica | Descripción |
|---|---|---|---|
| Acceso Inicial | T1566 | T1566.002 | El vector de entrada del atacante es el link del correo phishing |
| Acceso a credenciales | T1528 | | El atacante roba el token de aplicación a través del POST |

---

## 7. Herramientas Utilizadas

| Herramienta | Uso |
|---|---|
| VirusTotal | Para el análisis de las direcciones IP y las URL's sospechosas |
| AnyRun | Para tratar de entender la dirección "https://download[.]cyberlearn[.]academy/download/download?url=" y ver su importancia en el ataque |
| Claude | Para la revisión de la alerta y como método de aprendizaje |
| MITRE ATT&CK | Para el mapeo de tácticas y técnicas |

---

## 8. Conclusión

| Campo | Valor |
|---|---|
| Clasificación | Verdadero Positivo |
| Impacto | Alto |

---

## 9. Acciones Recomendadas

- Rotación del token de aplicación porque se ha visto comprometido.
- Contención parcial (aislamiento de red, restricción de acceso a recursos internos, etc...) de la máquina Gloriana hasta que se haya solucionado el ataque.
- Bloqueo de la cuenta de usuario gloriana@letsdefend.io y revisión por si ha mandado correos phishing desde ella. 
- Bloqueo de direcciones IP y URL's maliciosas para que no se pueda clicar el enlace desde ningún dispositivo en la red local. 

---
