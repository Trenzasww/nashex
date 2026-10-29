"""Análisis estático mínimo de ejecutables PE (solo lectura, sin ejecutar nada)."""
from __future__ import annotations

import struct

from .util import Finding, shannon_entropy

EXEC = 0x20000000
WRITE = 0x80000000
PACKERS_LOW = {"upx0", "upx1", "upx2", ".upx0", ".upx1"}
PACKERS_MED = {".aspack", ".adata", "aspack", ".themida", "themida", ".vmp0", ".vmp1", ".vmp2", ".petite",
               ".mpress1", ".mpress2", "nsp0", "nsp1", ".enigma1", ".enigma2"}


def is_pe(head: bytes) -> bool:
    return head[:2] == b"MZ"


def analyze_pe(path: str, size: int) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    info: dict = {"signed_present": False}
    with open(path, "rb") as f:
        dos = f.read(64)
        if len(dos) < 64 or dos[:2] != b"MZ":
            return findings, info
        e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
        if e_lfanew < 64 or e_lfanew > size - 24:
            return [Finding("low", "pe_malformed", "Cabecera MZ sin estructura PE válida")], info
        f.seek(e_lfanew)
        if f.read(4) != b"PE\0\0":
            return findings, info
        coff = f.read(20)
        if len(coff) < 20:
            return findings, info
        _, nsec, _, _, _, optsize, _ = struct.unpack("<HHIIIHH", coff)
        if nsec == 0 or nsec > 96 or optsize < 96:
            return [Finding("medium", "pe_malformed", "Cabecera PE inconsistente (secciones/opt header)")], info
        opt = f.read(optsize)
        magic = struct.unpack_from("<H", opt, 0)[0]
        entry_rva = struct.unpack_from("<I", opt, 16)[0]
        dd_off = {0x10B: 96, 0x20B: 112}.get(magic)
        if dd_off is not None and len(opt) >= dd_off + 5 * 8:
            _, sec_size = struct.unpack_from("<II", opt, dd_off + 4 * 8)
            info["signed_present"] = sec_size > 0

        sections = []
        for _ in range(nsec):
            hdr = f.read(40)
            if len(hdr) < 40:
                break
            name = hdr[:8].rstrip(b"\0").decode("latin1")
            vsize, vaddr, rsize, rptr, _, _, _, _, ch = struct.unpack_from("<IIIIIIHHI", hdr, 8)
            sections.append((name, vsize, vaddr, rsize, rptr, ch))
        info["sections"] = [s[0] for s in sections]

        for name, vsize, vaddr, rsize, rptr, ch in sections:
            low = name.lower()
            if ch & EXEC and ch & WRITE:
                findings.append(Finding("medium", "pe_rwx", f"Sección {name} ejecutable y escribible (RWX)"))
            if low in PACKERS_LOW:
                findings.append(Finding("low", "pe_packer", f"Empaquetado con UPX o similar ({name})"))
            elif low in PACKERS_MED:
                findings.append(Finding("medium", "pe_packer", f"Protector/empaquetador conocido ({name})"))
            if ch & EXEC and rsize > 0x1000 and rptr + 1 <= size:
                f.seek(rptr)
                sample = f.read(min(rsize, 1 << 20))
                ent = shannon_entropy(sample)
                if ent > 7.2:
                    findings.append(Finding("medium", "pe_high_entropy_exec",
                                            f"Código cifrado/comprimido en {name} (entropía {ent:.2f})"))

        if entry_rva:
            holder = next((s for s in sections if s[2] <= entry_rva < s[2] + max(s[1], s[3])), None)
            if holder is None:
                findings.append(Finding("medium", "pe_entry_outside", "Punto de entrada fuera de todas las secciones"))
            elif not holder[5] & EXEC:
                findings.append(Finding("medium", "pe_entry_nonexec", f"Punto de entrada en sección no ejecutable ({holder[0]})"))
    return findings, info
