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
  Select-String -Path C:\Logs\* -Pattern "timeout" -Recurse

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
  Get-Service | Select-Object Name, Status,
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

