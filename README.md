# NashexGuard

Escáner defensivo de malware y auditoría de seguridad para Windows. **Solo biblioteca estándar de Python:
no hay nada que instalar con `pip`**, así que no agrega riesgo de cadena de suministro a tu PC.

## Qué hace

| Comando | Qué revisa |
|---|---|
| `scan [rutas]` | Hashes de malware conocido (tu lista), archivo de prueba EICAR, ejecutables disfrazados (`foto.jpg` que es un `.exe`), dobles extensiones (`factura.pdf.exe`), carácter RTLO, scripts con patrones de ataque (PowerShell codificado, `certutil`, `mshta`, borrado de copias de sombra…), ejecutables PE sospechosos (secciones RWX, código cifrado/empaquetado, punto de entrada anómalo), ZIP con contraseña con ejecutables, macros de Office |
| `persistence` | Claves Run/RunOnce, carpetas de inicio, tareas programadas, servicios automáticos |
| `processes` | Procesos con líneas de comando maliciosas, Word/Excel lanzando `cmd`/PowerShell, `svchost.exe` falso |
| `audit` | Defender (tiempo real, firmas), firewall, UAC, RDP, sesión administradora, archivo `hosts`, puertos abiertos a la red |
| `checkup` | Todo lo anterior + análisis rápido de Descargas, Escritorio, Temp, Inicio y Public |
| `watch [rutas]` | Vigila carpetas y analiza cada archivo nuevo cuando termina de descargarse |
| `quarantine list/add/restore` | Cuarentena reversible |

## Garantías de seguridad

- **Solo lectura.** Nunca borra, nunca modifica el registro, nunca cambia configuración.
- **La única acción es mover a cuarentena**, y solo si la pedís (`quarantine add` o `scan --quarantine` con confirmación por archivo). El archivo queda renombrado `.quar`, de solo lectura, con un `.json` que dice de dónde vino, y se restaura con `quarantine restore`.
- **Se niega a mover** archivos de `C:\Windows` y `Program Files`, para no romper el sistema.
- **No usa la red.** No sube archivos ni consulta servicios externos.
- **No ejecuta ninguno de los archivos que analiza.** Solo los lee.
- Los únicos comandos externos son scripts de PowerShell fijos y de lectura (`Get-ScheduledTask`, `Get-CimInstance`, `Get-MpComputerStatus`, `Get-NetFirewallProfile`, `Get-NetTCPConnection`, `Get-AuthenticodeSignature`). Están en `nashex_guard/system.py` y `scanner.py`.

## Instalación (Windows)

1. Instalá Python 3.10+ **desde python.org o la Microsoft Store** (no desde otros sitios).
2. Descargá este repositorio (`git clone` o ZIP desde GitHub).
3. Abrí PowerShell en la carpeta y ejecutá:

```powershell
python -m nashex_guard checkup
```

Para ver tareas, servicios y configuración completos, abrí PowerShell **como administrador** (sigue siendo solo lectura).

### Uso

```powershell
python -m nashex_guard scan C:\Users\TuUsuario\Downloads
python -m nashex_guard scan --quarantine            # ofrece cuarentena para lo MALICIOSO / MUY SOSPECHOSO
python -m nashex_guard scan -v --json informe.json  # incluye hallazgos menores y guarda JSON
python -m nashex_guard watch                         # vigilancia continua
python -m nashex_guard quarantine list
python -m nashex_guard quarantine restore 20261029-181800_ab12cd34ef567890.quar
```

### Hashes de malware conocido (opcional)

Descargá vos mismo una lista de SHA-256 (por ejemplo, las exportaciones de MalwareBazaar de abuse.ch) en un `.txt`
con un hash por línea, y usala con `--hashlist lista.txt`. El programa no la descarga por vos.

### Reglas YARA (opcional)

Solo si querés: `pip install yara-python` y `--yara-rules carpeta_con_reglas`. No está probado en este repositorio.

## Qué NO es

Es un complemento heurístico, **no un reemplazo de Defender/Bitdefender**: no tiene driver en el kernel, no bloquea
la ejecución en tiempo real, no emula código ni tiene base de firmas propia ni telemetría en la nube. Un malware
nuevo y bien hecho puede pasar; una alerta puede ser un falso positivo (revisá el motivo antes de actuar).
Mantené Defender (o Bitdefender) activo y usá esto como segunda opinión.

## Tests

```
python -m unittest discover -s tests -v
```

Los tests cubren el escáner, el parser PE (con ejecutables sintéticos), la cuarentena y la vigilancia.
Las partes que dependen de Windows (`system.py`: registro, tareas, servicios, procesos, auditoría) se probaron con
respuestas simuladas de PowerShell; **no se ejecutaron en un Windows real**.
