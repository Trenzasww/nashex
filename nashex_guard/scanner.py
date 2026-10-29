"""Escáner de archivos: hashes conocidos, EICAR, ejecutables disfrazados, scripts y PE sospechosos."""
from __future__ import annotations

import os
import re
import sys
import zipfile
from dataclasses import dataclass, field

from . import pe
from .rules import (ARCHIVE_DANGEROUS, DOUBLE_EXT, NON_EXEC_EXTS, SCRIPT_EXTS, scan_text, writable_location)
from .util import Finding, is_windows, json_list, run_powershell, score, sha256_file, verdict

# La firma EICAR (archivo de prueba inofensivo estándar) se arma por partes para que este
# código fuente no sea detectado como malware por otros antivirus.
EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-" + "TEST-FILE!$H+H*").encode()

SKIP_DIRS = {"system volume information", "$recycle.bin.keep", "windowsapps"}
SIGNATURE_SENSITIVE = {"pe_user_writable", "pe_packer", "pe_high_entropy_exec", "pe_rwx", "pe_entry_nonexec", "pe_entry_outside"}


@dataclass
class FileResult:
    path: str
    size: int
    sha256: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        return verdict(self.findings)

    @property
    def score(self) -> int:
        return score(self.findings)

    def to_dict(self) -> dict:
        return {"path": self.path, "size": self.size, "sha256": self.sha256, "verdict": self.verdict,
                "score": self.score, "findings": [f.to_dict() for f in self.findings]}


def load_hashlist(path: str) -> set[str]:
    hashes = set()
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            token = line.strip().split()[0].lower() if line.strip() and not line.startswith("#") else ""
            if re.fullmatch(r"[0-9a-f]{64}", token):
                hashes.add(token)
    return hashes


_sig_cache: dict[str, tuple[str, str] | None] = {}


def verify_signature(path: str) -> tuple[str, str] | None:
    """(estado, firmante) vía Get-AuthenticodeSignature; solo Windows. Solo lectura."""
    if path in _sig_cache:
        return _sig_cache[path]
    result = None
    if is_windows():
        escaped = path.replace("'", "''")
        out = run_powershell(
            f"$s=Get-AuthenticodeSignature -LiteralPath '{escaped}';"
            "[pscustomobject]@{S=[string]$s.Status;N=$s.SignerCertificate.Subject}|ConvertTo-Json -Compress", 30)
        rows = json_list(out)
        if rows:
            result = (rows[0].get("S") or "", rows[0].get("N") or "")
    _sig_cache[path] = result
    return result


def _check_name(name: str) -> list[Finding]:
    out = []
    if DOUBLE_EXT.search(name):
        out.append(Finding("high", "double_ext", f"Doble extensión engañosa: {name}"))
    if "\u202e" in name:
        out.append(Finding("high", "rtlo", "El nombre usa un carácter que invierte el texto (RTLO) para ocultar la extensión real"))
    return out


def _check_zip(path: str) -> list[Finding]:
    out = []
    try:
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()[:5000]
            names = [i.filename for i in infos]
            encrypted_danger = [i.filename for i in infos
                                if i.flag_bits & 1 and os.path.splitext(i.filename.lower())[1] in ARCHIVE_DANGEROUS]
            if encrypted_danger:
                out.append(Finding("medium", "zip_encrypted_exec",
                                   "ZIP con contraseña que contiene ejecutables/scripts (técnica común para evadir antivirus)"))
            if any("vbaproject.bin" in n.lower() for n in names):
                out.append(Finding("medium", "office_macros", "Documento Office con macros VBA"))
            for n in names:
                if DOUBLE_EXT.search(n):
                    out.append(Finding("high", "double_ext", f"Doble extensión engañosa dentro del archivo: {n}"))
                    break
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError):
        pass
    return out


def scan_file(path: str, hashes: set[str] | frozenset[str] = frozenset(), max_size: int = 200 << 20,
              yara_scan=None) -> FileResult | None:
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return None
    if not os.path.isfile(path) or os.path.islink(path):
        return None
    name = os.path.basename(path)
    ext = os.path.splitext(name)[1].lower()
    res = FileResult(path, st.st_size, "")
    res.findings += _check_name(name)
    if st.st_size > max_size:
        res.findings.append(Finding("info", "too_big", f"Archivo mayor a {max_size >> 20} MB: no se analizó el contenido"))
        return res
    try:
        res.sha256 = sha256_file(path)
        with open(path, "rb") as f:
            head = f.read(4096)
    except OSError:
        return None

    if res.sha256 in hashes:
        res.findings.append(Finding("critical", "hash_match", "El hash coincide con malware conocido de tu lista"))
    if EICAR in head:
        res.findings.append(Finding("critical", "eicar", "Archivo de prueba EICAR (inofensivo, detectado correctamente)"))

    signed_present = False
    if pe.is_pe(head):
        pe_findings, info = pe.analyze_pe(path, st.st_size)
        res.findings += pe_findings
        signed_present = info.get("signed_present", False)
        if ext in NON_EXEC_EXTS:
            res.findings.append(Finding("high", "disguised_exec", f"Es un ejecutable disfrazado de {ext}"))
        loc = writable_location(path)
        if loc and not signed_present:
            res.findings.append(Finding(loc[1], "pe_user_writable", f"Ejecutable sin firma en {loc[0]}"))
    elif ext in SCRIPT_EXTS:
        try:
            with open(path, "rb") as f:
                text = f.read(2 << 20).decode("utf-8", errors="ignore")
            res.findings += scan_text(text)
        except OSError:
            pass
    elif head[:2] == b"PK" and ext in {".zip", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".jar"}:
        res.findings += _check_zip(path)
    elif head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" and ext in {".doc", ".xls", ".ppt"}:
        try:
            with open(path, "rb") as f:
                blob = f.read(4 << 20)
            if b"VBA" in blob and re.search(rb"(AutoOpen|Auto_Open|Document_Open|Workbook_Open)", blob):
                res.findings.append(Finding("medium", "office_macros", "Documento Office con macros de ejecución automática"))
        except OSError:
            pass

    if yara_scan:
        res.findings += yara_scan(path)

    # Si Windows confirma una firma Authenticode válida, se descartan las pistas débiles de contexto.
    if signed_present and score(res.findings) and not any(f.severity in ("high", "critical") for f in res.findings):
        sig = verify_signature(path)
        if sig and sig[0] == "Valid":
            res.findings = [f for f in res.findings if f.rule not in SIGNATURE_SENSITIVE]
            res.findings.append(Finding("info", "signed_valid", f"Firma digital válida: {sig[1][:80]}"))
    return res


def iter_files(paths: list[str], stats: dict):
    for root_path in paths:
        if os.path.isfile(root_path):
            yield root_path
            continue
        for root, dirs, files in os.walk(root_path, followlinks=False, onerror=lambda e: stats.__setitem__("errors", stats["errors"] + 1)):
            dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
            for fn in files:
                yield os.path.join(root, fn)


def scan_paths(paths: list[str], hashes=frozenset(), max_size: int = 200 << 20, yara_scan=None, progress: bool = True):
    stats = {"files": 0, "errors": 0, "bytes": 0}
    results: list[FileResult] = []
    for p in iter_files(paths, stats):
        r = scan_file(p, hashes, max_size, yara_scan)
        if r is None:
            stats["errors"] += 1
            continue
        stats["files"] += 1
        stats["bytes"] += r.size
        if r.findings:
            results.append(r)
        if progress and stats["files"] % 500 == 0:
            print(f"  ... {stats['files']} archivos analizados", file=sys.stderr)
    return results, stats
