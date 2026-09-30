# Informe de Incidente - Possible VM Detection Attempt

## 1. Resumen Ejecutivo

Se investigó la alerta SOC317 `Possible VM Detection Attempt`, generada el 29/08/2024 a las 11:32:15 al ejecutarse en el equipo Anemon (172.16.17.118) un script de PowerShell que consulta WMI para averiguar si el sistema es una máquina virtual.

La investigación reveló que, minutos antes, la IP externa 37.19.205.203 había realizado 14 intentos de conexión RDP contra el equipo en unos 3 minutos. El último tuvo éxito y dio acceso a la cuenta local LetsDefend. Inmediatamente después se ejecutaron varios comandos de reconocimiento del sistema, usuarios, privilegios y procesos, además del script de detección de virtualización.

La investigación determinó que se trata de un Verdadero Positivo.

---

## 2. Detalles de la Alerta

| Campo | Valor |
|---|---|
| Plataforma | LetsDefend |
| ID del Caso | SOC317 |
| Tipo de Alerta | Acceso no autorizado / Fuerza Bruta / Descubrimiento |
| Severidad | Media |
| Estado | Escalado |
| Analista | Jorge Fernández Córcoles |
| Fecha | 30/09/2026 |

---

## 3. Información Inicial de la Alerta

| Campo | Valor |
|---|---|
| Nombre de la alerta | Possible VM Detection Attempt |
| IP origen | 37.19.205.203 |
| IP destino | 172.16.17.118 |
| Hostname | Anemon |
| Usuario | LetsDefend |
| Hash del fichero | - |
| URL / Dominio | - |
| Timestamp | 2024-08-29 11:32:15 |

---

## 4. Pasos de la Investigación

### 4.1 Revisión de la Alerta
La alerta mostraba un posible intento de detección de máquina virtual en el endpoint `Anemon`. El analista SOC L1 no pudo determinar que el comando que causó la alerta lo escribiera el atacante pero sí que vio numerosos intentos de conexión vía RDP hacia la máquina `Anemon` con dirección IP `172.16.17.118` desde la dirección `37.19.205.203`. Se decidió investigar al ver el comando de descubrimiento que hizo saltar la alerta: `Get-WmiObject Win32_ComputerSystem`.

### 4.2 Análisis de Logs
Los logs mostraron 14 intentos de conexión entrantes desde `37.19.205.203` hacia `172.16.17.118` vía RDP (puerto 3389) en un intervalo de 3 min, y solo una fue exitosa a las 11:30:31. Esto nos hace pensar que estamos ante un intento de acceso inicial por fuerza bruta. Con el adversario ya dentro de la máquina, este ejecuta un script de PowerShell de descubrimiento donde intenta conocer si el sistema es una máquina virtual. Y si lo es, cuál es el software de virtualización específico. Este comprueba si es uno de esta lista: `VirtualBox`, `VMware`, `KVM`, `Hyper-V`, `Xen`. Esto lo realiza a través de `Get-WmiObject Win32_ComputerSystem`,el comando que hace saltar la alerta. Este comando le proporciona información acerca del hardware del equipo (fabricante, modelo, dominio), aunque consulta únicamente una sola propiedad: `Model`. 

### 4.3 Análisis de IOCs
- `37.19.205.203` es la dirección IP origen del ataque. Marcada en VirusTotal como no maliciosa pero en AbuseIPDB como posiblemente comprometida. Un 39% nos hace dudar de que sea legítima al 100%, además de numerosos reportes por fuerza bruta en las últimas semanas. 
- `$error.clear() $vmCheck = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue if ($vmCheck) { if ($vmCheck.Model -match "VirtualBox" -or $vmCheck.Model -match "VMware" -or $vmCheck.Model -match "KVM" -or $vmCheck.Model -match "Hyper-V" -or $vmCheck.Model -match "Xen") { echo "Virtualization environment detected: $($vmCheck.Model)" } else { echo "Virtualization environment not detected." } } else { echo "The WMI query failed." }` es el Script de PowerShell que devuelve si la máquina es un entorno de virtualización y qué software específico es el que usa. 


### 4.4 Actividad del Usuario / Endpoint
Se han encontrado algunos comandos de descubrimiento, al igual que el del script. Estos son: `whoami /priv`, `net user`, `net localgroup administrators`, `systeminfo` y `tasklist /v`. Con estos muestra los privilegios de la cuenta actual `LetsDefend`, lista detalladamente los procesos activos, recoge información del sistema, etc...
Pero no encontramos ningún indicio más de compromiso en el log monitoring y EDR: movimientos laterales, exfiltración... Está pendiente de seguir investigando pero en los logs no se recoge actividad posterior. 

### 4.5 Línea de Tiempo del Incidente

| Timestamp | Evento |
|---|---|
| 11:27:15 | Primer intento de conexión desde `37.19.205.203`, con EID 4625 |
| 11:30:31 | Loggeo exitoso desde `37.19.205.203` en la cuenta LetsDefend, con EID 4624 |
| 11:31:47 | Inicio de comandos de descubrimiento: `whoami /priv`, `net user`, `net localgroup administrators`, `systeminfo` y `tasklist /v` |
| 11:32:03 | Comando de descubrimiento `Get-WmiObject Win32_ComputerSystem` |

---

## 5. Hallazgos
- El puerto 3389 está expuesto a internet: un servicio remoto (como lo es RDP) no debería estar expuesto a internet.  
- Se puede decir con firmeza que el atacante realiza un acceso inicial al endpoint `Anemon` por fuerza bruta tras 14 intentos en un intervalo en torno a los 3 minutos. Y que la dirección IP es sospechosa gracias a los reportes en inteligencia de amenazas visualizados en las últimas semanas. 
- También podemos afirmar la existencia de comandos y script de descubrimiento del sistema, poco después de que el atacante lograse entrar a la máquina. 
- Al ejecutar el comando `net localgroup administrators` en la máquina podemos ver que la cuenta LetsDefend se trata de una cuenta del grupo con máximos privilegios, lo que aumenta el impacto del incidente a "Alto".
- Lo que no podemos determinar con exactitud es la falta de actividad posterior en el endpoint `Anemon`. Los logs no muestran nada de lo que seguir tirando. Aun así, se recomienda escalar para continuar con la investigación al tratarse de una cuenta del grupo de administradores. 

---

## 6. Mapeo MITRE ATT&CK

| Táctica | Técnica | Sub-técnica | Descripción |
|---|---|---|---|
| Acceso con credenciales | T1110 | T1110.001 | El atacante realiza un ataque de fuerza bruta al sistema para conseguir la contraseña de inicio de sesión de la cuenta `LetsDefend` |
| Acceso inicial | T1078 | T1078.003 | El adversario abusa de las credenciales de una cuenta local `LetsDefend` para conseguir acceso inicial al endpoint `Anemon` |
| Acceso inicial | T1133| - | El atacante entra vía RDP, un servicio remoto externo, que no debería estar expuesto a internet |
| Ejecución | T1059 | T1059.001 | El atacante ejecuta Scripts y comandos de descubrimiento abusando de la herramienta PowerShell |
| Ejecución | T1047 | - | El atacante abusa de la Instrumentalización de administración de Windows (WMI) para ejecutar comandos y cargas útiles maliciosas. En nuestro caso, el atacante lo hace a modo de descubrimiento |
| Descubrimiento | T1497 | T1497.001 | El atacante intenta obtener información detallada sobre el sistema operativo para detectar y evitar entornos de virtualización |
| Descubrimiento | T1069 | T1069.001 | El adversario intenta encontrar grupos del sistema local y la configuración de permisos, como sucede con `net localgroup administrators` |
| Descubrimiento | T1057 | - | El atacante intenta obtener información sobre los procesos en ejecución en el sistema con `tasklist /v` |
| Descubrimiento | T1033 | - | El atacante busca obtener información acerca de los privilegios del usuario actual `whoami /priv` |
| Descubrimiento | T1087 | T1087.001 | El atacante busca obtener información acerca de la cuenta de usuario actual con `net user` |
| Descubrimiento | T1082| - | El atacante busca obtener información acerca del sistema operativo en sí con `systeminfo`|

---

## 7. Herramientas Utilizadas

| Herramienta | Uso |
|---|---|
| VirusTotal | Comprobar reputación de la dirección IP |
| AbuseIPDB | Igual que VirusTotal |
| MITRE ATT&CK | Para realizar el mapeo |

---

## 8. Conclusión

| Campo | Valor |
|---|---|
| Clasificación | Verdadero Positivo |
| Impacto | Alto |

---

## 9. Acciones Recomendadas

- Aislar la máquina `Anemon` hasta que se realice una análisis más profundo del incidente y se determine como limpia. 
- Bloquear la dirección IP `37.19.205.203` del firewall perimetral.
- Rotar las contraseñas de la cuenta local `LetsDefend` en la máquina `Anemon`. 
- Establecer una política de bloqueo de cuenta, para conseguir bloquear una cuenta tras numerosos inicios de sesión fallidos. 
- Crear una regla de correlación en el SIEM que alerte si existen más de 10 intentos de conexión fallidos en un intervalo de 1h, por ejemplo. 
- Cerrar la exposición del RDP, dar acceso solo por VPN con MFA. 
- Buscar la IP 37.19.205.203 en los logs de otros equipos, por si atacó más máquinas.

---
