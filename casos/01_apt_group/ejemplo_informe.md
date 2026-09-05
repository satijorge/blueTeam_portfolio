# Informe de Incidente - Lazarus Phishing Campaign Detected (APT38)

## 1. Resumen Ejecutivo

Se investigó una alerta de seguridad relacionada con una campaña de phishing Lazarus detectada. La alerta era tipo APT Group así que es muy importante actuar cuanto antes. 

La investigación determinó que se trata de un Verdadero Positivo.

---

## 2. Detalles de la Alerta

| Campo | Valor |
|---|---|
| Plataforma | LetsDefend |
| ID del Caso | SOC337 |
| Tipo de Alerta | Phishing |
| Severidad | Alta |
| Estado | Escalado |
| Analista | Jorge Fernández Córcoles |
| Fecha | 05/09/2026 |

---

## 3. Información Inicial de la Alerta

| Campo | Valor |
|---|---|
| Nombre de la alerta | Lazarus Phishing Campaign Detected (APT38) |
| IP origen | 152.89.61.96 |
| IP destino | 172.16.20.3 |
| Dirección de origen | trevorgreer9312@gmail.com |
| Dirección de destino| Ellen@letsdefend.io |
| Hostname | Ellen |
| Usuario | LetsDefend |
| Hash del fichero | Por determinar |
| URL / Dominio | https://blockchainjobhub[.]com/invite/E3fM8yF7 |
| Timestamp | 2025-03-06 05:15:00 |

---

## 4. Pasos de la Investigación

### 4.1 Revisión de la Alerta
La alerta mostraba una campaña de phishing dirigida a nuestra organización por parte de un grupo de Amenazas Persistentes Avanzadas (APT). La alerta nos dio una dirección origen del correo y una destino. Así que decidimos empezar a investigar por ahí. 

### 4.2 Análisis de Logs
La cuenta de correo con dirección destino `Ellen@letsdefend.io` mostraba en su bandeja de entrada un único correo sospechoso con dirección origen `trevorgreer9312@gmail.com`. Este correo mostraba unos requisitos para una contratación de trader de criptomonedas, seguido de un botón de continuar sospechoso. Este botón por debajo tenía un "href" al siguiente sitio web: `https://blockchainjobhub[.]com/invite/E3fM8yF7`. Analizando este sitio web con inteligencia de amenazas detectamos era de un grupo APT: **Lazarus**. 

### 4.3 Análisis de IOCs
`https://blockchainjobhub[.]com/invite/E3fM8yF7` es la dirección de enlace a donde te redirigía el email si clicabas en el botón. 
`152.89.61.96` el servidor SMTP desde donde procede el email de `trevorgreer9312@gmail.com`. 
`trevorgreer9312@gmail.com` es la dirección de correo desde la cual se manda el email. 
`nvidiaupdate.zip` es el archivo descargado desde el sitio web `https://blockchainjobhub[.]com/invite/E3fM8yF7`
, cuando el usuario clica el enlace. 
`update.vbs` es el archivo resultante de la extracción del zip `nvidiaupdate.zip`.

### 4.4 Actividad del Usuario / Endpoint
En el endpoint monitoring filtré por Ellen para localizar el endpoint afectado. Efectivamente, desde la máquina Ellen se accedió al sitio malicioso y justo 4 min después, desde `explorer.exe` se abre PowerShell y descomprime un zip: `nvidiaupdate.zip`. Aproximadamente 30 segundos después se ejecuta un archivo localizado en esa ruta `C:\Users\LetsDefend\nvidiadrive\update.vbs`. Todo indica a que se trata de malware pero queda pendiente de investigación posibles movimientos laterales en la red, C2, creación de persistencia, etc...

### 4.5 Línea de Tiempo del Incidente

| Timestamp | Evento |
|---|---|
| 05:15:00 | El correo malicioso llega al endpoint Ellen |
| 00:21:35 | El día siguiente, desde el endpoint Ellen clican el enlace y se accede al sitio web: `https://blockchainjobhub[.]com/invite/E3fM8yF7` |
| 00:25:27 | Se descomprime desde PowerShell un archivo llamado `nvidiaupdate.zip` justo después de acceder al sitio web y el parent process es `explorer.exe`, lo cual no es común, es preocupante |
| 00:25:55 | Se realiza la ejecución del archivo `C:\Users\LetsDefend\nvidiadrive\update.vbs` |

---

## 5. Hallazgos

- `152.89.61.96` es el servidor SMTP desde donde proviene el correo malicioso. Marcada en VirusTotal como phishing: 7/90 proveedores de seguridad la marcan como maliciosa. En AbuseIPDB aparece con un 9% de confianza de compromiso.  
- `trevorgreer9312@gmail.com` es la cuenta de gmail que envió el correo phishing. 
- `https://blockchainjobhub[.]com/invite/E3fM8yF7` es el sitio web de descarga del archivo. 
- `"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -Command "Expand-Archive -Force -Path 'C:\Users\LetsDefend\nvidiaupdate.zip' -DestinationPath 'C:\Users\LetsDefend\nvidiadrive'"`, es el comando de descompresión post-descarga en el endpoint Ellen y establece `C:\Users\LetsDefend\nvidiadrive` como ruta destino de la extracción. 
- `"C:\Windows\system32\wscript.exe" "C:\Users\LetsDefend\nvidiadrive\update.vbs"` confirma la ejecución del archivo extraido de `nvidiaupdate.zip`. Se realiza desde `wscript.exe` que es legítimo de Windows. Es posible que el EDR no detectara esta técnica de Living Of the Land por eso mismo. 

---

## 6. Mapeo MITRE ATT&CK

| Táctica | Técnica | Sub-técnica | Descripción |
|---|---|---|---|
| Acceso Inicial | T1566 | T1566.002 | Los atacantes abusan de ingeniería social (envío de correos phishing) para conseguir acceso al endpoint Ellen |
| Ejecución | T1059 | T1059.001 | Los atacantes consiguen descomprmir el archivo descargado a través de PowerShell |
| Ejecución | T1059 | T1059.005 | Los atacantes se aprovechan de VB (Visual Basic) para ejecutar comandos maliciosos | 
| Ejecución | T1204 | T1204.001 | El usuario clica el enlace malicioso y consigue ejecución de código en el endpoint |
| Sigilo | T1036 | T1036.005 | Masquerading: el atacante manipula el nombre del archivo descargado para que parezca legítimo. En este caso el zip parece ser una actualización de Nvidia |

---

## 7. Herramientas Utilizadas

| Herramienta | Uso |
|---|---|
| VirusTotal y AbuseIPDB | Para el escaneo de la dirección SMTP asociada con el envío del correo |
| Threat Intel de LetsDefend | Realmente fue quien determinó que `blockchainjobhub[.]com` era un dominio de Lazarus |
| MITRE ATT&CK | Para buscar información del APT group y para el mapeo de TTPs |

---

## 8. Conclusión

| Campo | Valor |
|---|---|
| Clasificación | Verdadero Positivo |
| Impacto | Alto |

---

## 9. Acciones Recomendadas

- Bloquear en nuestros firewalls, IDSs/IPSs, EDRs, tanto la dirección de correo `trevorgreer9312@gmail.com`, como la dirección IP `152.89.61.96`, como el dominio de Lazarus `blockchainjobhub[.]com`. 
- Contención del endpoint Ellen. 
- Investigación forense de la descarga y ejecución de `update.vbs`. 
- Investigar TTPs de Lazarus para saber cuál es su siguiente paso en el ataque. 
- Talleres de concienciación para evitar que nuestros empleados caigan en estas campañas de phishing. 

---
