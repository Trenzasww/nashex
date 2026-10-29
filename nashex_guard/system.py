"""Revisión de persistencia, procesos y endurecimiento de Windows. Todo es de solo lectura."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .rules import analyze_command, norm
from .util import Finding, is_windows, json_list, run_powershell


@dataclass
class Item:
    source: str
    name: str
    detail: str
    findings: list[Finding] = field(default_factory=list)


# ---------------------------------------------------------------- persistencia
def _registry_run() -> list[Item]:
    import winreg

    items = []
    roots = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    keys = [r"Software\Microsoft\Windows\CurrentVersion\Run", r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"]
    for rname, root in roots.items():
        for key in keys:
            try:
                with winreg.OpenKey(root, key) as k:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(k, i)
                        except OSError:
                            break
                        i += 1
                        items.append(Item(f"Registro {rname}\\{key.split(chr(92))[-1]}", name, str(value),
                                          analyze_command(str(value))))
            except OSError:
                continue
    return items


def _startup_folders() -> list[Item]:
    items = []
    dirs = [Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup",
            Path(os.environ.get("PROGRAMDATA", "")) / "Microsoft/Windows/Start Menu/Programs/StartUp"]
    for d in dirs:
        if d.is_dir():
            for f in d.iterdir():
                fnd = [Finding("low", "startup_item", "Archivo en carpeta de inicio")]
                if f.suffix.lower() in {".bat", ".cmd", ".vbs", ".js", ".ps1", ".hta", ".exe", ".scr"}:
                    fnd.append(Finding("medium", "startup_exec", f"Ejecutable/script directo en inicio ({f.suffix})"))
                items.append(Item("Carpeta de inicio", f.name, str(f), fnd))
    return items


def _tasks() -> list[Item]:
    script = ("Get-ScheduledTask | ForEach-Object { $t=$_; $t.Actions | ForEach-Object { [pscustomobject]@{"
              "Task=($t.TaskPath+$t.TaskName); Exec=$_.Execute; Args=$_.Arguments} } } | ConvertTo-Json -Compress")
    items = []
    for row in json_list(run_powershell(script)):
        task, exe, args = row.get("Task") or "", row.get("Exec") or "", row.get("Args") or ""
        cmd = f"{exe} {args}".strip()
        trusted = task.lower().startswith("\\microsoft\\windows\\")
        items.append(Item("Tarea programada", task, cmd, analyze_command(cmd, trusted_task=trusted)))
    return items


def _services() -> list[Item]:
    script = ("Get-CimInstance Win32_Service | Where-Object {$_.StartMode -eq 'Auto'} | "
              "Select-Object Name,PathName | ConvertTo-Json -Compress")
    items = []
    for row in json_list(run_powershell(script)):
        path = row.get("PathName") or ""
        fnd = analyze_command(path, trusted_task=True)
        if path and not path.startswith('"') and re.match(r"^[A-Za-z]:\\.*\s.*\.exe", path, re.I) \
                and " " in path.lower().split(".exe")[0]:
            fnd.append(Finding("low", "unquoted_service", "Ruta de servicio sin comillas (posible escalada de privilegios)"))
        items.append(Item("Servicio automático", row.get("Name") or "?", path, fnd))
    return items


def persistence() -> list[Item]:
    if not is_windows():
        return []
    return _registry_run() + _startup_folders() + _tasks() + _services()


# -------------------------------------------------------------------- procesos
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
SYSTEM_BINARIES = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "wininit.exe", "spoolsv.exe"}


def processes() -> list[Item]:
    if not is_windows():
        return []
    script = ("Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine "
              "| ConvertTo-Json -Compress")
    rows = json_list(run_powershell(script, 120))
    by_pid = {r.get("ProcessId"): r for r in rows}
    sysroot = norm(os.environ.get("SystemRoot", "C:\\Windows"))
    items = []
    for r in rows:
        name = (r.get("Name") or "").lower()
        exe = r.get("ExecutablePath") or ""
        cmd = r.get("CommandLine") or ""
        fnd = analyze_command(cmd or exe)
        if name in SYSTEM_BINARIES and exe and not norm(exe).startswith(sysroot + "/system32"):
            fnd.append(Finding("high", "masquerade", f"{name} corriendo fuera de System32 (suplantación de proceso del sistema)"))
        parent = by_pid.get(r.get("ParentProcessId"))
        if parent and (parent.get("Name") or "").lower() in OFFICE and name in SHELLS:
            fnd.append(Finding("high", "office_spawn", f"{parent.get('Name')} lanzó {name} (típico de macros maliciosas)"))
        items.append(Item("Proceso", f"{r.get('Name')} (PID {r.get('ProcessId')})", cmd or exe, fnd))
    return items


# --------------------------------------------------------------- endurecimiento
def _reg_value(root: str, key: str, name: str):
    import winreg

    try:
        with winreg.OpenKey(getattr(winreg, root), key) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def audit() -> list[Item]:
    if not is_windows():
        return []
    items: list[Item] = []

    def add(name, detail, sev=None, rule="audit", msg=""):
        items.append(Item("Configuración", name, detail, [Finding(sev, rule, msg)] if sev else []))

    mp = json_list(run_powershell("Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,"
                                  "AntivirusSignatureAge,IsTamperProtected | ConvertTo-Json -Compress"))
    if mp:
        m = mp[0]
        add("Antivirus (Defender)", f"tiempo real={m.get('RealTimeProtectionEnabled')} firmas={m.get('AntivirusSignatureAge')} días "
            f"anti-manipulación={m.get('IsTamperProtected')}")
        if m.get("RealTimeProtectionEnabled") is False:
            add("Protección en tiempo real", "desactivada", "high", "av_off",
                "Sin protección en tiempo real (válido solo si usás otro antivirus activo)")
        age = m.get("AntivirusSignatureAge")
        if isinstance(age, int) and age > 7:
            add("Firmas de Defender", f"{age} días de antigüedad", "medium", "av_stale", "Firmas desactualizadas")
    else:
        add("Antivirus (Defender)", "no se pudo consultar (puede haber otro antivirus instalado)")

    for p in json_list(run_powershell("Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress")):
        if p.get("Enabled") in (False, 0):
            add(f"Firewall perfil {p.get('Name')}", "desactivado", "high", "fw_off", "Firewall de Windows desactivado")
    if _reg_value("HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA") == 0:
        add("Control de cuentas (UAC)", "desactivado", "high", "uac_off", "UAC desactivado")
    if _reg_value("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections") == 0:
        add("Escritorio remoto (RDP)", "habilitado", "medium", "rdp_on", "RDP habilitado: desactivalo si no lo usás")

    admin = run_powershell("([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())"
                           ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")
    if admin and admin.strip().lower() == "true":
        add("Sesión actual", "administrador", "low", "admin_session", "Usás una cuenta administradora a diario; conviene una estándar")

    hosts = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32/drivers/etc/hosts"
    try:
        for line in hosts.read_text(errors="ignore").splitlines():
            s = line.strip()
            if s and not s.startswith("#") and not re.match(r"^(127\.0\.0\.1|::1|0\.0\.0\.0)\s+(localhost|.*)$", s):
                add("Archivo hosts", s, "medium", "hosts_redirect", "Entrada en hosts que redirige un dominio a otra IP")
    except OSError:
        pass

    listen = json_list(run_powershell(
        "Get-NetTCPConnection -State Listen | Where-Object {$_.LocalAddress -notin '127.0.0.1','::1'} | "
        "ForEach-Object { [pscustomobject]@{Port=$_.LocalPort;Proc=(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName} }"
        " | ConvertTo-Json -Compress"))
    seen = set()
    for row in listen:
        key = (row.get("Port"), row.get("Proc"))
        if key not in seen:
            seen.add(key)
            add("Puerto abierto a la red", f"{row.get('Port')} ← {row.get('Proc')}")
    return items
