from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from . import __version__, quarantine, system
from .scanner import load_hashlist, scan_paths
from .util import SEV_ORDER, Finding, verdict
from .watcher import watch

MARK = {"info": "[i]", "low": "[.]", "medium": "[!]", "high": "[!!]", "critical": "[!!!]"}


def _default_paths(quick: bool = True) -> list[str]:
    home = Path.home()
    cands = [home / "Downloads", home / "Desktop", Path(tempfile.gettempdir()),
             Path(os.environ.get("APPDATA", home / "AppData/Roaming")) / "Microsoft/Windows/Start Menu/Programs/Startup",
             Path(os.environ.get("PUBLIC", "C:/Users/Public"))]
    return [str(p) for p in cands if p.exists()]


def _print_findings(findings: list[Finding], indent: str = "    ") -> None:
    for f in sorted(findings, key=lambda x: -SEV_ORDER[x.severity]):
        print(f"{indent}{MARK[f.severity]} {f.message}  ({f.rule})")


def _print_items(items: list[system.Item], show_all: bool) -> int:
    flagged = 0
    for it in items:
        if it.findings:
            flagged += 1
        elif not show_all:
            continue
        print(f"- {it.source}: {it.name}\n    {it.detail[:200]}")
        _print_findings(it.findings)
    return flagged


def _load_hashes(args) -> set[str]:
    hashes: set[str] = set()
    for p in getattr(args, "hashlist", None) or []:
        hashes |= load_hashlist(p)
    return hashes


def _yara(args):
    if getattr(args, "yara_rules", None):
        from .yara_support import build

        return build(args.yara_rules)
    return None


def _confirm(msg: str) -> bool:
    try:
        return input(f"{msg} [s/N]: ").strip().lower() in {"s", "si", "sí", "y", "yes"}
    except EOFError:
        return False


def cmd_scan(args) -> int:
    paths = args.paths or _default_paths()
    print(f"Analizando: {', '.join(paths)}")
    results, stats = scan_paths(paths, _load_hashes(args), args.max_size << 20, _yara(args))
    results.sort(key=lambda r: -r.score)
    shown = 0
    for r in results:
        v = r.verdict
        if v == "LIMPIO" or (v == "REVISAR" and not args.verbose):
            continue
        shown += 1
        print(f"\n{v}: {r.path}\n    sha256: {r.sha256}")
        _print_findings(r.findings)
        if args.quarantine and v in ("MALICIOSO", "MUY SOSPECHOSO") and _confirm("    ¿Mover a cuarentena?"):
            try:
                dest = quarantine.add(r.path, "; ".join(f.rule for f in r.findings))
                print(f"    -> en cuarentena: {dest}")
            except (OSError, ValueError) as e:
                print(f"    No se pudo: {e}")
    print(f"\n{stats['files']} archivos analizados, {shown} con hallazgos relevantes, {stats['errors']} no accesibles.")
    if args.json:
        Path(args.json).write_text(json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Informe JSON: {args.json}")
    return 1 if any(r.verdict in ("MALICIOSO", "MUY SOSPECHOSO") for r in results) else 0


def _system_cmd(fn, title):
    def run(args) -> int:
        if os.name != "nt":
            print(f"{title}: solo disponible en Windows.")
            return 0
        items = fn()
        print(f"{title}: {len(items)} elementos revisados")
        flagged = _print_items(items, args.all)
        print(f"\n{flagged} con observaciones.")
        return 1 if any(f.severity in ("high", "critical") for it in items for f in it.findings) else 0
    return run


def cmd_checkup(args) -> int:
    code = 0
    for fn, title in ((system.audit, "Configuración de seguridad"), (system.persistence, "Persistencia"),
                      (system.processes, "Procesos")):
        print(f"\n===== {title} =====")
        code |= _system_cmd(fn, title)(args)
    print("\n===== Archivos (análisis rápido) =====")
    args.paths = []
    return code | cmd_scan(args)


def cmd_watch(args) -> int:
    paths = args.paths or _default_paths()
    print(f"Vigilando cada {args.interval}s: {', '.join(paths)}  (Ctrl+C para salir)")

    def alert(r):
        print(f"\n{r.verdict}: {r.path}")
        _print_findings(r.findings)

    try:
        watch(paths, alert, _load_hashes(args), args.interval, args.max_size << 20, yara_scan=_yara(args))
    except KeyboardInterrupt:
        print("\nVigilancia detenida.")
    return 0


def cmd_quarantine(args) -> int:
    if args.action == "list":
        for it in quarantine.list_items():
            print(f"{it['id']}\n    origen: {it['original_path']}\n    motivo: {it['reason']}")
        return 0
    if args.action == "add":
        for p in args.targets:
            try:
                print(f"{p} -> {quarantine.add(p, 'manual')}")
            except (OSError, ValueError) as e:
                print(f"{p}: {e}")
        return 0
    for item in args.targets:
        try:
            print(f"Restaurado en {quarantine.restore(item)}")
        except (OSError, ValueError) as e:
            print(f"{item}: {e}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nashex_guard", description="Escáner defensivo de malware y auditoría de seguridad.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    def scan_opts(sp):
        sp.add_argument("--hashlist", action="append", help="archivo con SHA-256 de malware conocido (uno por línea)")
        sp.add_argument("--yara-rules", help="carpeta con reglas .yar (requiere yara-python)")
        sp.add_argument("--max-size", type=int, default=200, help="MB máximo por archivo (200)")

    s = sub.add_parser("scan", help="analizar archivos/carpetas (sin argumentos: carpetas de riesgo)")
    s.add_argument("paths", nargs="*")
    s.add_argument("--quarantine", action="store_true", help="ofrece mover a cuarentena lo muy sospechoso (pide confirmación)")
    s.add_argument("--json", help="guardar informe JSON")
    s.add_argument("-v", "--verbose", action="store_true", help="incluir hallazgos de bajo riesgo")
    scan_opts(s)
    s.set_defaults(func=cmd_scan)

    for name, fn, title in (("persistence", system.persistence, "Persistencia"), ("processes", system.processes, "Procesos"),
                            ("audit", system.audit, "Configuración de seguridad")):
        sp = sub.add_parser(name, help=f"{title} (solo Windows, solo lectura)")
        sp.add_argument("--all", action="store_true", help="mostrar también lo que no tiene observaciones")
        sp.set_defaults(func=_system_cmd(fn, title))

    c = sub.add_parser("checkup", help="auditoría + persistencia + procesos + análisis rápido")
    c.add_argument("--all", action="store_true")
    c.add_argument("--quarantine", action="store_true")
    c.add_argument("--json")
    c.add_argument("-v", "--verbose", action="store_true")
    scan_opts(c)
    c.set_defaults(func=cmd_checkup)

    w = sub.add_parser("watch", help="vigilar carpetas y analizar archivos nuevos")
    w.add_argument("paths", nargs="*")
    w.add_argument("--interval", type=float, default=3.0)
    scan_opts(w)
    w.set_defaults(func=cmd_watch)

    q = sub.add_parser("quarantine", help="gestionar la cuarentena (nunca borra)")
    q.add_argument("action", choices=["list", "add", "restore"])
    q.add_argument("targets", nargs="*")
    q.set_defaults(func=cmd_quarantine)
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrumpido.")
        return 130
