"""Reglas heurísticas compartidas por el escáner, la persistencia y los procesos."""
from __future__ import annotations

import os
import re

from .util import Finding

# (regex, severidad, id, descripción). Se aplican por línea, sin distinguir mayúsculas.
_RAW_PATTERNS = [
    (r"powershell(\.exe)?\b.*\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", "high", "ps_encoded",
     "PowerShell con comando codificado en Base64"),
    (r"\b(iex|invoke-expression)\b.*(downloadstring|downloadfile|webclient|invoke-webrequest|\biwr\b)", "high",
     "ps_download_exec", "Descarga y ejecuta código remoto"),
    (r"downloadstring\s*\(", "medium", "ps_downloadstring", "Descarga de texto remoto desde PowerShell"),
    (r"-w(indowstyle)?\s+hidden", "medium", "ps_hidden", "Ejecución oculta de PowerShell"),
    (r"frombase64string\s*\(", "medium", "b64_decode", "Decodificación Base64 en script"),
    (r"\bamsiutils\b|amsiinitfailed", "high", "amsi_bypass", "Intento de desactivar AMSI"),
    (r"set-mppreference\b.*-disable(realtimemonitoring|ioavprotection|behaviormonitoring)", "high",
     "defender_off", "Intenta desactivar Windows Defender"),
    (r"add-mppreference\b.*-exclusion(path|process|extension)", "medium", "defender_exclusion",
     "Agrega exclusiones a Windows Defender"),
    (r"certutil(\.exe)?\b.*-(urlcache|decode)", "high", "certutil_abuse", "certutil usado para descargar/decodificar"),
    (r"bitsadmin(\.exe)?\b.*/transfer", "medium", "bitsadmin_transfer", "bitsadmin usado para descargar"),
    (r"mshta(\.exe)?\s+(https?:|vbscript:|javascript:)", "high", "mshta_remote", "mshta ejecutando contenido remoto/script"),
    (r"regsvr32(\.exe)?\b.*(/i:|scrobj\.dll).*https?:", "high", "regsvr32_squiblydoo", "regsvr32 cargando script remoto"),
    (r"rundll32(\.exe)?\b.*(javascript:|mshtml)", "high", "rundll32_script", "rundll32 ejecutando script"),
    (r"vssadmin(\.exe)?\s+delete\s+shadows", "critical", "ransom_shadow", "Borra copias de sombra (típico de ransomware)"),
    (r"wbadmin(\.exe)?\s+delete\s+(catalog|backup|systemstatebackup)", "critical", "ransom_backup",
     "Borra copias de seguridad (típico de ransomware)"),
    (r"bcdedit(\.exe)?\b.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)", "high",
     "bcdedit_recovery", "Desactiva la recuperación de Windows"),
    (r"net(1)?\s+user\s+\S+\s+\S+\s+/add", "high", "net_user_add", "Crea una cuenta de usuario local"),
    (r"reg(\.exe)?\s+add\b.*\\currentversion\\run", "medium", "reg_run", "Se agrega al inicio de Windows"),
    (r"schtasks(\.exe)?\s+/create", "low", "schtasks_create", "Crea una tarea programada"),
    (r"createobject\(\s*[\"']wscript\.shell[\"']\s*\)", "medium", "wscript_shell", "Ejecución de comandos con WScript.Shell"),
]
SCRIPT_PATTERNS = [(re.compile(p, re.I), sev, rid, msg) for p, sev, rid, msg in _RAW_PATTERNS]

# Carpetas donde un ejecutable no suele vivir legítimamente.
WRITABLE_MARKERS = [
    ("/appdata/local/temp/", "medium"),
    ("/windows/temp/", "medium"),
    ("/users/public/", "medium"),
    ("/$recycle.bin/", "medium"),
    ("/programdata/", "low"),
    ("/downloads/", "low"),
    ("/appdata/roaming/", "low"),
    ("/appdata/local/", "low"),
]

LOLBINS_MEDIUM = {"mshta.exe", "wscript.exe", "cscript.exe"}
LOLBINS_LOW = {"powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}

DOUBLE_EXT = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp[34]|zip|rar)\s*\.(exe|scr|bat|cmd|com|pif|js|jse|vbs|vbe|wsf|hta|lnk|ps1)$",
    re.I,
)

NON_EXEC_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".pdf", ".txt", ".doc", ".docx", ".xls", ".xlsx",
                 ".ppt", ".pptx", ".mp3", ".mp4", ".rtf", ".csv", ".ico", ".webp", ".mkv", ".avi"}
SCRIPT_EXTS = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta"}
ARCHIVE_DANGEROUS = {".exe", ".scr", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".lnk", ".ps1", ".com", ".pif"}


def norm(path: str) -> str:
    return path.replace("\\", "/").lower()


def writable_location(path: str) -> tuple[str, str] | None:
    p = norm(path)
    for marker, sev in WRITABLE_MARKERS:
        if marker in p:
            return marker, sev
    return None


def scan_text(text: str) -> list[Finding]:
    """Busca patrones peligrosos línea por línea (líneas truncadas para acotar el costo)."""
    found: dict[str, Finding] = {}
    for line in text.splitlines():
        line = line[:8000]
        for rx, sev, rid, msg in SCRIPT_PATTERNS:
            if rid not in found and rx.search(line):
                found[rid] = Finding(sev, rid, msg)
    return list(found.values())


def extract_exe(cmd: str) -> str:
    cmd = cmd.strip()
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return cmd[1:end] if end > 0 else cmd[1:]
    m = re.match(r"(.+?\.(?:exe|com|scr|bat|cmd|ps1|vbs|js|dll))(\s|$)", cmd, re.I)
    return m.group(1) if m else cmd.split(" ")[0]


def analyze_command(cmd: str, trusted_task: bool = False) -> list[Finding]:
    """Analiza una línea de comando (inicio, tarea, servicio o proceso)."""
    if not cmd:
        return []
    cmd = os.path.expandvars(cmd)
    findings = scan_text(cmd)
    exe = extract_exe(cmd)
    where = writable_location(exe)
    if where:
        findings.append(Finding(where[1], "exe_in_user_dir", f"Ejecutable en carpeta de usuario/temporal: {exe}"))
    name = os.path.basename(norm(exe))
    if not trusted_task:
        if name in LOLBINS_MEDIUM:
            findings.append(Finding("medium", "lolbin", f"Usa {name}, común en malware basado en scripts"))
        elif name in LOLBINS_LOW:
            findings.append(Finding("low", "lolbin", f"Usa {name} (revisar argumentos)"))
    return findings
