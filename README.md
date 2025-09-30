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

---

## Monitorización y troubleshooting rápidos
- `taskmgr` — Administrador de tareas (procesos, rendimiento, inicio).
- `perfmon` / `resmon` / `msinfo32` para diagnóstico avanzado.
- `eventvwr.msc` — Visor de eventos (Application, System, Security): revisar errores y eventos relevantes.
[21~- `services.msc` — gestionar servicios (start/stop/startup type).
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

**Nota:** PowerShell es extremadamente poderoso y el vector preferido para scripting administrativo y post-explotación; auditar scripts y restricciones de ejecución es buena práctica.

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
