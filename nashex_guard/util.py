from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections import Counter
from dataclasses import dataclass

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEV_WEIGHT = {"info": 0, "low": 1, "medium": 3, "high": 7, "critical": 15}


@dataclass
class Finding:
    severity: str
    rule: str
    message: str

    def to_dict(self) -> dict:
        return {"severity": self.severity, "rule": self.rule, "message": self.message}


def score(findings: list[Finding]) -> int:
    return sum(SEV_WEIGHT[f.severity] for f in findings)


def verdict(findings: list[Finding]) -> str:
    if any(f.severity == "critical" or f.rule in ("hash_match", "eicar") for f in findings):
        return "MALICIOSO"
    total = score(findings)
    if total >= 7:
        return "MUY SOSPECHOSO"
    if total >= 3:
        return "SOSPECHOSO"
    if total >= 1:
        return "REVISAR"
    return "LIMPIO"


def is_windows() -> bool:
    return os.name == "nt"


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math

    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def run_powershell(script: str, timeout: int = 90) -> str | None:
    """Ejecuta un script de PowerShell de solo lectura definido en este código."""
    if not is_windows():
        return None
    prefix = "[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ProgressPreference='SilentlyContinue';"
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", prefix + script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 else None


def json_list(text: str | None) -> list[dict]:
    if not text or not text.strip():
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if isinstance(data, dict):
        return [data]
    return [d for d in data if isinstance(d, dict)]
