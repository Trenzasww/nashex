"""Soporte opcional de reglas YARA. Solo se activa si instalás 'yara-python' vos mismo."""
from __future__ import annotations

from pathlib import Path

from .util import Finding


def build(rules_dir: str):
    try:
        import yara  # type: ignore
    except ImportError:
        raise SystemExit("YARA no está instalado. Es opcional: pip install yara-python (solo si querés usar reglas YARA).")
    files = {p.stem: str(p) for p in Path(rules_dir).rglob("*") if p.suffix.lower() in {".yar", ".yara"}}
    if not files:
        raise SystemExit(f"No hay archivos .yar/.yara en {rules_dir}")
    rules = yara.compile(filepaths=files)

    def scan(path: str) -> list[Finding]:
        try:
            return [Finding("high", "yara_match", f"Regla YARA: {m.rule}") for m in rules.match(path, timeout=20)]
        except yara.Error:
            return []

    return scan
