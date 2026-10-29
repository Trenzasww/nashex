"""Cuarentena reversible: mueve el archivo, lo vuelve inerte y guarda cómo restaurarlo. Nunca borra."""
from __future__ import annotations

import json
import os
import shutil
import stat
import time
from pathlib import Path

from .rules import norm
from .util import is_windows, sha256_file

PROTECTED = ["c:/windows", "c:/program files", "c:/program files (x86)", "/usr", "/bin", "/sbin", "/etc", "/boot", "/lib"]


def default_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") if is_windows() else None
    return Path(base or Path.home()) / ("NashexGuard" if base else ".nashex_guard") / "quarantine"


def _protected(path: str) -> bool:
    p = norm(os.path.abspath(path))
    return any(p == d or p.startswith(d + "/") for d in PROTECTED)


def add(path: str, reason: str = "", qdir: Path | None = None, allow_protected: bool = False) -> Path:
    qdir = qdir or default_dir()
    src = os.path.abspath(path)
    if not os.path.isfile(src) or os.path.islink(src):
        raise ValueError(f"No es un archivo regular: {src}")
    if _protected(src) and not allow_protected:
        raise PermissionError(f"Ruta protegida del sistema, no se mueve para no dañar tu PC: {src}")
    qdir.mkdir(parents=True, exist_ok=True)
    digest = sha256_file(src)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = qdir / f"{stamp}_{digest[:16]}.quar"
    shutil.move(src, dest)
    os.chmod(dest, stat.S_IREAD)
    meta = {"original_path": src, "sha256": digest, "time": stamp, "reason": reason}
    (qdir / (dest.name + ".json")).write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return dest


def list_items(qdir: Path | None = None) -> list[dict]:
    qdir = qdir or default_dir()
    items = []
    for meta in sorted(qdir.glob("*.quar.json")) if qdir.exists() else []:
        data = json.loads(meta.read_text(encoding="utf-8"))
        data["id"] = meta.name[: -len(".json")]
        items.append(data)
    return items


def restore(item_id: str, qdir: Path | None = None) -> str:
    qdir = qdir or default_dir()
    f = qdir / item_id
    meta = qdir / (item_id + ".json")
    if not f.is_file() or not meta.is_file():
        raise FileNotFoundError(f"No existe en cuarentena: {item_id}")
    data = json.loads(meta.read_text(encoding="utf-8"))
    target = Path(data["original_path"])
    if target.exists():
        raise FileExistsError(f"Ya existe un archivo en {target}; no se sobrescribe.")
    target.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(f, stat.S_IREAD | stat.S_IWRITE)
    shutil.move(f, target)
    meta.unlink()
    return str(target)
