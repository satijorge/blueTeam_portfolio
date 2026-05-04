# Informe de Incidente - Impersonating Domain MX Record Change Detected

## 1. Resumen Ejecutivo

Se investigó una alerta de seguridad relacionada con un cambio en el registro MX de un dominio sospechoso. 

La investigación determinó que se trata de un Verdadero Positivo.

---

## 2. Detalles de la Alerta

| Campo | Valor |
|---|---|
| Plataforma | LetsDefend |
| ID del Caso | SOC326 |
| Tipo de Alerta | Phishing / Threat Intel |
| Severidad | Alto |
| Estado | Escalado |
| Analista | Jorge Fernández Córcoles |
| Fecha | 04/05/2026 |

---

## 3. Información Inicial de la Alerta

| Campo | Valor |
|---|---|
| Nombre de la alerta | SOC326 - Impersonating Domain MX Record Change Detected |
| IP origen | Desconocida |
| IP destino | 172.16.17.162 |
| Hostname | Mateo |
| Usuario | LetsDefend |
| Hash del fichero | |
| URL / Dominio | letsdefwnd[.]io |
| Timestamp | Sep, 17, 2024, 12:05 PM |

---

## 4. Pasos de la Investigación

### 4.1 Revisión de la Alerta
Al usuario le llega una alerta de Threat Intel por correo el dia 17 de septiembre avisando de que se ha detectado un cambio en el registro MX del dominio letsdefwnd[.]io (dominio que intenta suplantar a letsdefend.io). Al día siguiente, al usuario Mateo le llega un correo desde una dirección que usa ese dominio malicioso, con un asunto de haber ganado un "Voucher" y pidiéndole que clique el enlace malicioso (http://letsdefwnd[.]io/). Por ahora no encontramos ningún indicio (vía letsdefend, anyrun, etc...) de que el dominio sea malicioso, aunque Threat Intel tiene preferencia sobre las demás herramientas mencionadas. Por lo tanto, lo marcaremos como malicioso. Por otro lado, el 22 de septiembre llega un correo al equipo SOC de letsdefend con remitente Threat Intel de nuevo, diciendo que "The compromised account is test@letsdefend.io". 


### 4.2 Análisis de Logs
Se revisaron los logs de correo, el EDR del endpoint Mateo y se analizó el dominio letsdefwnd[.]io en VirusTotal y Any.run. El correo de phishing llegó a mateo@letsdefend.io el 18 de septiembre y el enlace fue clicado desde el endpoint Mateo. No se encontró evidencia de ejecución de payload ni actividad maliciosa posterior en el endpoint. El dominio no fue detectado como malicioso en VirusTotal ni Any.run, sin embargo la alerta de Threat Intel tiene precedencia sobre estas herramientas al tratarse de inteligencia contextual específica sobre este dominio.


### 4.3 Análisis de IOCs
letsdefwnd[.]io es el dominio malicioso creado para suplantar el dominio de Letsdefend. 
http://letsdefwnd[.]io/ es la URL maligna adjuntada en el correo de phishing. 
mail‍.mailerhost‍.net es el dominio de registro MX descubierto.
voucher@letsdefwnd.io es la cuenta email del remitente del phishing.
172.16.17.162 es el endpoint Mateo. 

### 4.4 Actividad del Usuario / Endpoint
El usuario Mateo clicó el enlace malicioso desde el endpoint Mateo (172.16.17.162). No se encontró actividad posterior en el EDR — sin procesos maliciosos, descargas ni conexiones salientes sospechosas tras la visita al dominio. No es posible determinar con los logs disponibles si hubo exfiltración de credenciales, aunque el aviso posterior de CTI sobre la cuenta test@letsdefend.io comprometida sugiere que el ataque tuvo éxito en algún punto.

---

## 5. Hallazgos

- Dominio letsdefwnd[.]io creado para suplantar a letsdefwnd.io, con registro MX apuntando a mail.mailerhost[.]net — infraestructura preparada específicamente para envío de phishing.
- El usuario Mateo recibió y clicó un email fraudulento desde voucher@letsdefwnd[.]io un día después de que el SOC fuera avisado por CTI, sin que se hubiera bloqueado 
el dominio.
- La cuenta test@letsdefend.io aparece como comprometida en el aviso de CTI del 22 de septiembre, lo que sugiere que el ataque tuvo éxito.

---

## 6. Mapeo MITRE ATT&CK

| Táctica | Técnica | Sub-técnica | Descripción |
|---|---|---|---|
| Acceso Inicial | T1566 | T1566.002 | El atacante envía un correo phishing para conseguir entrar en el Endpoint |
| Ingeniería Social | T1684 | T1684.002 | El atacante busca falsificar el remitente del correo modificando los encabezados del correo electrónico |
| Ejecucion  | T1204 | T1204.001 | El atacante usa el enlace malicioso para intentar ejecutar código en el Endpoint |
| Desarrollo de Recursos | T1583 | T1583.001 | Registro del dominio letsdefwnd[.]io para suplantar a letsdefend.io |

---

## 7. Herramientas Utilizadas

| Herramienta | Uso |
|---|---|
| VirusTotal | Para identificar el riesgo de los dominios, IP's, URL's a priori maliciosas |
| AnyRun | Como alternativa a VirusTotal |
| Claude | Para busqueda de información y contrastar opiniones |
| MITRE ATT&CK | Para el mapeo |

---

## 8. Conclusión

| Campo | Valor |
|---|---|
| Clasificación | Verdadero Positivo |
| Impacto | Alto |

---

## 9. Acciones Recomendadas

- Tanto bloquear el dominio letsdefend[.]io e IPs asociadas en el perímetro de red, como concienciar a los trabajadores de LetsDefend para no caer en estos intentos de ataques de phishing. 
- Definir un SLA de respuesta para alertas de CTI. 
- Bloquear el Endpoint para evitar cualquier tipo de acción posterior por parte del atacante. Además, resetear las credenciales de test@letsdefend[.]io y activar MFA, si no estuviera ya activado.

---