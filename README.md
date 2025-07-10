# Tabla Comparativa: Comandos Bash (Linux) vs PowerShell (Windows)

Esta tabla basica está diseñada para administradores de sistemas, profesionales de redes, ciberseguridad y usuarios avanzados que trabajan entre entornos Linux y windows.

Archivos y Directorios

| Bash (Linux)                          | PowerShell (Windows)                               | Descripción                                   |
|----------------------------------------|----------------------------------------------------|-----------------------------------------------|
| `ls -l`                                | `Get-ChildItem -Force`                             | Listar archivos detalladamente               |
| `ls -la /ruta`                         | `Get-ChildItem -Path /ruta -Force`                 | Ver todo en un directorio                    |
| `cd /ruta`                             | `Set-Location /ruta`                               | Cambiar directorio                           |
| `pwd`                                  | `Get-Location`                                     | Ver ruta actual                              |
| `mkdir nueva_carpeta`                  | `New-Item -ItemType Directory nueva_carpeta`       | Crear carpeta                                |
| `rmdir carpeta`                        | `Remove-Item carpeta -Recurse`                     | Eliminar carpeta                             |
| `cp archivo1 archivo2`                 | `Copy-Item archivo1 archivo2`                      | Copiar archivos                              |
| `mv archivo1 carpeta/`                 | `Move-Item archivo1 carpeta`                       | Mover o renombrar archivos                   |
| `rm archivo`                           | `Remove-Item archivo`                              | Eliminar archivo                             |
| `rm -rf carpeta`                       | `Remove-Item carpeta -Recurse -Force`              | Eliminar carpeta con contenido               |
| `touch archivo.txt`                    | `New-Item archivo.txt`                             | Crear archivo vacío                         |
| `cat archivo.txt`                      | `Get-Content archivo.txt`                          | Ver contenido de archivo                     |
| `nano archivo.txt`                     | `notepad archivo.txt`                              | Editar archivo de texto                      |
| `find /ruta -name "*.log"`             | `Get-ChildItem /ruta -Recurse -Filter *.log`       | Buscar archivos                              |
| `grep 'cadena' archivo`                | `Select-String -Path archivo -Pattern 'cadena'`    | Buscar texto en archivo                      |
| `stat archivo`                         | `(Get-Item archivo).LastWriteTime`                 | Ver información de archivo                   |
| `basename /ruta/archivo`               | `(Split-Path /ruta/archivo -Leaf)`                 | Nombre del archivo                          |
| `dirname /ruta/archivo`                | `(Split-Path /ruta/archivo -Parent)`               | Carpeta contenedora                          |

---

Procesos y Sistema

| Bash (Linux)                          | PowerShell (Windows)                               | Descripción                                   |
|----------------------------------------|----------------------------------------------------|-----------------------------------------------|
| `ps aux`                               | `Get-Process`                                       | Ver procesos activos                         |
| `top`                                  | `Get-Process | Sort-Object CPU -Descending`         | Procesos ordenados por CPU                   |
| `htop`                                 | `[Process Explorer]`                                | Vista gráfica de procesos                    |
| `kill PID`                             | `Stop-Process -Id PID`                              | Matar proceso                                |
| `killall nombre`                       | `Stop-Process -Name nombre`                         | Matar por nombre                             |
| `df -h`                                | `Get-PSDrive`                                       | Espacio en disco                             |
| `du -sh carpeta`                       | `(Get-ChildItem carpeta -Recurse | Measure-Object -Property Length -Sum).Sum` | Tamaño carpeta |
| `free -h`                              | `Get-CimInstance`                                   | Ver uso de memoria                          |
| `uptime`                               | `(Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime` | Tiempo encendido        |
| `uname -a`                             | `Get-ComputerInfo | Select OsName, OsArchitecture`  | Info sistema                                |
| `hostname`                             | `$env:COMPUTERNAME`                                 | Nombre de host                               |
| `whoami`                               | `$env:USERNAME`                                     | Usuario actual                              |
| `id usuario`                           | `whoami /all`                                       | Info de usuario                             |
| `last`                                 | `Get-EventLog -LogName Security -InstanceId 4624`   | Últimos logins                              |
| `shutdown now`                         | `Stop-Computer`                                     | Apagar                                       |
| `reboot`                               | `Restart-Computer`                                  | Reiniciar                                    |
| `crontab -e`                           | `schtasks /create`                                  | Tareas programadas                          |

---

Redes

| Bash (Linux)                          | PowerShell (Windows)                               | Descripción                                   |
|----------------------------------------|----------------------------------------------------|-----------------------------------------------|
| `ip a`                                 | `Get-NetIPAddress`                                  | Ver interfaces e IP                         |
| `ifconfig`                             | `ipconfig /all`                                     | Configuración IP                            |
| `ping 8.8.8.8`                        | `Test-Connection 8.8.8.8`                          | Ping                                         |
| `traceroute dominio`                   | `tracert dominio`                                   | Trazado ruta                                |
| `nslookup dominio`                     | `Resolve-DnsName dominio`                          | Resolver DNS                                |
| `dig dominio`                          | `Resolve-DnsName dominio`                          | Consultar DNS                               |
| `curl http://sitio`                    | `Invoke-WebRequest http://sitio`                   | Descargar web                               |
| `wget http://sitio`                    | `Invoke-WebRequest`                                 | Descargar web                               |
| `netstat -tulnp`                       | `netstat -ano`                                      | Puertos y conexiones                        |
| `ss -tulnp`                            | `Get-NetTCPConnection`                              | Conexiones activas                          |
| `arp -a`                               | `arp -a`                                            | Tabla ARP                                   |
| `ip route`                             | `Get-NetRoute`                                      | Tabla de rutas                              |
| `nmap -sS 192.168.1.1`                 | `[Nmap en Windows]`                                 | Escaneo de red                              |
| `tcpdump -i eth0`                      | `[tshark o Wireshark]`                              | Análisis de tráfico                         |

---

Logs y Diagnóstico

| Bash (Linux)                          | PowerShell (Windows)                               | Descripción                                   |
|----------------------------------------|----------------------------------------------------|-----------------------------------------------|
| `journalctl -xe`                       | `Get-WinEvent -LogName System -MaxEvents 20`        | Ver logs críticos                           |
| `tail -f /var/log/syslog`              | `Get-Content -Path C:\Ruta\Log -Tail 10 -Wait`    | Seguir logs en tiempo real                  |
| `dmesg | less`                         | `Get-WinEvent -LogName System`                     | Mensajes del sistema                        |
| `who`                                  | `query user`                                        | Usuarios conectados                         |

---

Seguridad

| Bash (Linux)                          | PowerShell (Windows)                               | Descripción                                   |
|----------------------------------------|----------------------------------------------------|-----------------------------------------------|
| `chmod 755 archivo`                    | `icacls` o GUI NTFS                                 | Permisos de archivo                         |
| `chown usuario:grupo archivo`          | `Set-Acl`                                           | Cambiar propietario                         |
| `passwd usuario`                       | `net user usuario *`                                | Cambiar contraseña                          |
| `sudo comando`                         | `[PowerShell elevado]`                              | Ejecutar como administrador                 |
| `iptables -L`                          | `Get-NetFirewallRule`                               | Ver firewall                                |
| `fail2ban-client status`               | `[No equivalente nativo]`                           | Protección anti fuerza bruta                |

---

