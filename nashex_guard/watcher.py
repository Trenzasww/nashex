"""Vigilancia periódica de carpetas: analiza archivos nuevos o modificados."""
from __future__ import annotations

import os
import time

from .scanner import FileResult, iter_files, scan_file


def snapshot(paths: list[str]) -> dict[str, tuple[float, int]]:
    snap = {}
    for p in iter_files(paths, {"errors": 0}):
        try:
            st = os.stat(p, follow_symlinks=False)
        except OSError:
            continue
        snap[p] = (st.st_mtime, st.st_size)
    return snap


def watch(paths: list[str], on_result, hashes=frozenset(), interval: float = 3.0, max_size: int = 200 << 20,
          cycles: int | None = None, yara_scan=None) -> None:
    """Llama on_result(FileResult) por cada archivo nuevo/cambiado con hallazgos.

    Un archivo se analiza cuando su tamaño y fecha dejan de cambiar entre dos ciclos,
    para no leerlo a medio descargar.
    """
    known = snapshot(paths)
    pending: dict[str, tuple[float, int]] = {}
    n = 0
    while cycles is None or n < cycles:
        time.sleep(interval)
        n += 1
        current = snapshot(paths)
        for p, sig in current.items():
            if known.get(p) == sig:
                continue
            if pending.get(p) == sig:
                known[p] = sig
                pending.pop(p, None)
                r: FileResult | None = scan_file(p, hashes, max_size, yara_scan)
                if r and r.findings:
                    on_result(r)
            else:
                pending[p] = sig
        for p in list(known):
            if p not in current:
                known.pop(p)
