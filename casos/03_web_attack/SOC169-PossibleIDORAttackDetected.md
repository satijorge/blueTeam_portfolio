# Informe de Incidente - Possible IDOR Attack Detected

## 1. Resumen Ejecutivo

Se investigó una alerta de seguridad relacionada con el servidor web WebServer1005. Nos encontramos ante un ataque 
de referencia directa insegura a objetos (IDOR). En nuestro caso, un ataque dirigido a la información de 5 usuarios.
Posteriormente comentaremos todo acerca de lo ocurrido.

La investigación determinó que se trata de un Verdadero Positivo.

---

## 2. Detalles de la Alerta

| Campo | Valor |
|---|---|
| Plataforma | LetsDefend |
| ID del Caso | SOC169 |
| Tipo de Alerta | Web attack |
| Severidad | Media |
| Estado | Escalado |
| Analista | Jorge Fernández Córcoles |
| Fecha | 26/04/2026 |

---

## 3. Información Inicial de la Alerta

| Campo | Valor |
|---|---|
| Nombre de la alerta | Possible IDOR Attack Detected |
| IP origen | 134.209.118.137 |
| IP destino | 172.16.17.15 |
| Hostname | WebServer1005 |
| Usuario | |
| Hash del fichero | |
| URL / Dominio | https://172.16.17.15/get_user_info/ |
| Timestamp | Feb, 04, 2026, 02:59 AM |

---

## 4. Pasos de la Investigación

### 4.1 Revisión de la Alerta
La alerta mostraba un posible ataque IDOR a un servidor web Windows llamado Webserver1005.

### 4.2 Análisis de Logs
Los logs mostraron con firmeza que se trataba efectivamente de un ataque IDOR. El atacante realizó
varios POST hacia el servidor solicitando un objeto (al parecer la información de usuarios) y estos
fueron exitosos ya que el tamaño de bytes de respuesta cambia dependiendo del usuario. 


### 4.3 Análisis de IOCs
Los POST se realizaron de la siguiente forma: https://172.16.17.15/get_user_info/?user_id=X ; 
siendo X el número de usuario que buscaba el atacante. 
Posteriormente el atacante usa una herramienta conocida para la exfiltración de los datos recopilados: Invoke-DNSExfiltrator.ps1 
Además, el atacante desactiva después el antivirus de microsoft para posteriormente poder realizar las consultas DNS: 
Microsoft Defender Antivirus Real-time Protection scanning for malware and other potentially unwanted software was disabled


### 4.4 Actividad del Usuario / Endpoint
Creación del script "Invoke-DNSExfiltrator.ps1" dentro de la siguiente ruta C:\Users\LetsDefend\Documents\


---

## 5. Hallazgos

- Consultas POST aparentemente IDOR
- Desactivación de Microsoft Defender Antivirus
- Consultas DNS de dominios previamente generados con la herramienta Invoke-DNSExfiltrator.ps1

---

## 6. Mapeo MITRE ATT&CK

| Táctica | Técnica | Sub-técnica | Descripción |
|---|---|---|---|
| Acceso Inicial | [T1190] | [] | [ Explotación de la vulnerabilidad IDOR en la aplicación web ] |
| Recolección | [T1213] | [] | [ Recolección de datos de usuarios mediante las peticiones POST ] |
| Evasión de Defensas | [T1562] | [T1562.001] | [Desactivación de Microsoft Defender] |
| Exfiltración | [T1048] | [T1048.003] | [Exfiltración de datos mediante consultas DNS con Invoke-DNSExfiltrator.ps1] |

---

## 7. Herramientas Utilizadas

| Herramienta | Uso |
|---|---|
| [ Google ] | [ Para consultar acerca de la herramienta Invoke-DNSExfiltrator.ps1 ] |
| [ Claude ] | [ Resolución de dudas ] |

---

## 8. Conclusión

| Campo | Valor |
|---|---|
| Clasificación | Verdadero Positivo |
| Impacto | Medio |

---

## 9. Acciones Recomendadas

- Lo primero sería corregir la vulnerabilidad IDOR. La información del usuario no debería ser accesible.
- Configurar WAF para que bloquear direcciones IP que actuen de forma anómala con recurrencia.  
- Colocar también un rate limiting, que limite la velocidad con la que se hacen consultas al servidor web
 desde una misma dirección IP. 
- Monitorización de DNS, implementar inspección del tráfico DNS para detectar consultas anómalas. 
- Por último proteger Microsoft Defender, debería validar siempre las credenciales del adminnistrador para
evitar situaciones como esta. 

---
