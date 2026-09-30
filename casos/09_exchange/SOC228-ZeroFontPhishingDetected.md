# Informe de Incidente - ZeroFont Phishing Detected

## 1. Resumen Ejecutivo

Se investigó una alerta de seguridad generada el 13/10/2023 a las 07:02:24 por un correo de phishing enviado desde noreply@googleone.com, un dominio que imita el servicio Google One, a elliot@letsdefend.io. El correo superó el filtro de seguridad de correo y, con el pretexto de que el buzón se había quedado sin espacio, incluía un enlace a un archivo ZIP alojado en AWS S3.

El usuario descargó el archivo y abrió el documento que contenía. Como consecuencia, `WINWORD.EXE` lanzó en el equipo Elliot el ejecutable `Order Specification.exe`, identificado por varios motores antivirus como `RisePro Stealer`, un malware diseñado para robar información del equipo.

La investigación determinó que se trata de un Verdadero Positivo.

---

## 2. Detalles de la Alerta

| Campo | Valor |
|---|---|
| Plataforma | LetsDefend |
| ID del Caso | SOC228 |
| Tipo de Alerta | Phishing / Malware |
| Severidad | Alta |
| Estado | Escalado |
| Analista | Jorge Fernández Córcoles |
| Fecha | 29/09/2026 |

---

## 3. Información Inicial de la Alerta

| Campo | Valor |
|---|---|
| Nombre de la alerta | ZeroFont Phishing Detected |
| Dirección remitente | noreply@googleone.com |
| Dirección destinataria | elliot@letsdefend.io |
| IP origen | 206.189.190.128 |
| IP destino | 172.16.17.241 |
| Hostname | Elliot |
| Usuario | LetsDefend |
| Hash del fichero | 800ec98e34adc24608860bd0b95d38db3ee3c8a4798127aa426f6b2ae030a72e |
| URL / Dominio | https://files-ld[.]s3[.]us-east-2[.]amazonaws[.]com/static/Order_Specification.zip |
| Timestamp | 2023-10-13 07:02:24 |

---

## 4. Pasos de la Investigación

### 4.1 Revisión de la Alerta
La alerta describe la detección de un correo phishing con dirección de destino `elliot@letsdefend.io`. El analista SOC L1 indica que el correo parece que bypasseó el email security product. Al tratarse de una amenaza hacia una cuenta de correo corporativa se decidió investigar más a fondo.

### 4.2 Análisis de Logs
Los logs de correo simplemente mostraron el clic en el enlace malicioso del correo proveniente de `noreply@googleone.com`, que intenta suplantar a un servicio legítimo de Google (GoogleOne) a través de un dominio parecido al de Google: `googleone.com`. El acceso inicial es phishing. 

### 4.3 Análisis de IOCs
- `206.189.190.128` es el servidor SMTP desde donde proviene el correo. En VirusTotal queda marcado como malicioso por varios proveedores, específicamente 6/91. 
- `https://files-ld[.]s3[.]us-east-2[.]amazonaws[.]com/static/Order_Specification.zip` es el sitio de descarga malicioso marcado en VirusTotal por 9/95 vendors de seguridad. 
- `Order_Specification.doc` es el archivo resultado de la extracción del zip malicioso.
- `Order Specification.exe` es el proceso que se crea al abrir el archivo `Order_Specification.doc` con `WINWORD.EXE`. Con el ejecutable, no hay mucha duda de que sea ilegítimo puesto que 40/63 proveedores de seguridad lo marcan como malicioso según VirusTotal. Además, la etiqueta común que le proporcionan varios de estos proveedores es `riseprostealer`. Un tipo de `infostealer` diseñado para infiltrarse en los sistemas operativos Windows y robar sigilosamente información personal y confidencial. El filehash del archivo es `800ec98e34adc24608860bd0b95d38db3ee3c8a4798127aa426f6b2ae030a72e`. 

### 4.4 Actividad del Usuario / Endpoint
Los primeros bytes (50 4B 03 04, firma ZIP) indican que es un documento Office moderno (OOXML), no un .doc clásico (OLE2), pese a su extensión .doc. Al clicar el usuario en el enlace, `Order_Specification.zip` se descarga en la ruta `C:\Users\LetsDefend\Downloads`. Una vez descargado, el usuario ejecuta el documento .doc para ver el contenido y se crea un proceso con PID 4200 (hijo de PID 1676: WINWORD.EXE) llamado `Order Specification.exe`. No se ha encontrado actividad posterior en el endpoint `Elliot`.

### 4.5 Línea de Tiempo del Incidente

| Timestamp | Evento |
|---|---|
| 07:02:00 | Email enviado por `noreply@googleone.com` y recibido por `elliot@letsdefend.io`, con el asunto `You're Out of Storage And May Not Receive New mails!` y un link de descarga de `https://files-ld[.]s3[.]us-east-2[.]amazonaws[.]com/static/Order_Specification.zip` |
| 07:22:00 | El usuario LetsDefend accede al sitio web de descarga del archivo malicioso `https://files-ld[.]s3[.]us-east-2[.]amazonaws[.]com/static/Order_Specification.zip` el atacante consigue superar la fase de entrega |
| 07:25:33 | El usuario desde el endpoint ejecuta el .doc a través de `WINWORD.EXE`. Este proceso crea un proceso hijo llamado `Order Specification.exe` que se lanza desde la siguiente ruta temporal `C:\Users\LetsDefend\AppData\Local\Temp\1\` |

---

## 5. Hallazgos

- El correo de phishing llegó al buzón del usuario superando el filtro de seguridad de correo. El remitente usaba un dominio que imita a Google One y un asunto de urgencia (almacenamiento lleno).
- El malware se alojó en un servicio legítimo (un bucket S3 de AWS), lo que dificulta su bloqueo por reputación.
- El usuario hizo clic en el enlace y descargó `Order_Spesification.zip` en `C:\Users\LetsDefend\Downloads`. 
- La apertura del documento con WINWORD.EXE generó el proceso hijo Order Specification.exe (PID 4200), ejecutado desde AppData\Local\Temp\1\. Que Word lance un ejecutable es un indicador claro de actividad maliciosa.
- El ejecutable (hash 800ec98e...) está marcado como malicioso por 40/63 motores en VirusTotal y varios lo identifican como RisePro, un infostealer.
- No se ha encontrado actividad posterior en el EDR, log manager, ni email security. No se ha encontrado robo de credenciales, por lo que el caso se escala. 

---

## 6. Mapeo MITRE ATT&CK

| Táctica | Técnica | Sub-técnica | Descripción |
|---|---|---|---|
| Acceso Inicial | T1566 | T1566.002 | El adversario envía un correo que contiene un link malicioso para ganar acceso al sistema |
| Ejecución | T1204 | T1204.001 | Antes de abrir el fichero, el usuario hace clic en el enlace |
| Ejecución | T1204 | T1204.002 | El atacante consigue la ejecución de malware a través de la ejecución de un archivo .doc |
| Sigilo | T1027 | - | El atacante utiliza la técnica `ZeroFont` para bypassear la seguridad de correo. Consiste en escribir secciones del correo con letra de tamaño 0 para que no sean detectados |

---

## 7. Herramientas Utilizadas

| Herramienta | Uso |
|---|---|
| VirusTotal | Para comprobar la reputación de las direcciones IP y sitios web asociados al ataque. Además de los hashes como el del ejecutable |
| Máquina Elliot y PowerShell | Para extraer el hash del ejecutable |
| MITRE ATT&CK | Para la búsqueda de TTPs del atacante y el mapeo |
| Gemini | Buscar información acerca de los `RisePro Stealer` y `ZeroFont` |

---

## 8. Conclusión

| Campo | Valor |
|---|---|
| Clasificación | Verdadero Positivo |
| Impacto | Alto |

---

## 9. Acciones Recomendadas

- Contención de la máquina `Elliot` para evitar posible actividad futura. 
- Bloquear la dirección IP del SMTP server del firewall perimetral: `206.189.190.128`. 
- Pendiente de realizar el análisis forense por si hay actividad posterior en el endpoint a pesar de no haberla visualizado, con especial hincapié en el análisis de malware del documento.  
- Bloquear la URL `https://files-ld[.]s3[.]us-east-2[.]amazonaws[.]com/static/Order_Specification.zip` en el proxy para evitar que otro usuario que caiga en el Phishing descargue el malware.  
- Bloquear el hash `800ec98e34adc24608860bd0b95d38db3ee3c8a4798127aa426f6b2ae030a72e`
- Bloquear el remitente o dominio en la pasarela de correo.
- Resetear las credenciales de la cuenta local LetsDefend en el endpoint `Elliot`. Es lo primero que se debe hacer ante un InfoStealer. 

---
