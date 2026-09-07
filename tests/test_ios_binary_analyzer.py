#!/usr/bin/env python3
"""Deterministic offline tests for MO2 — iOS binary analyzer."""

import json
import os
import plistlib
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ios_binary_analyzer as mo2


FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures")


class TestMachOParser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = os.path.join(FIXTURE_DIR, "sample_macho.bin")
        if not os.path.exists(cls.fixture):
            mo2.create_sample_binary(cls.fixture)
        cls.macho = mo2.MachOAnalyzer(cls.fixture)
        cls.macho.analyze()

    def test_header_parsed(self):
        self.assertTrue(self.macho.is_64bit)
        self.assertEqual(self.macho.cpu_type, "arm64")
        self.assertEqual(self.macho.file_type, mo2.MachOAnalyzer.MH_EXECUTE)

    def test_load_commands_count(self):
        self.assertTrue(len(self.macho.load_commands) >= 4)

    def test_segments_found(self):
        names = {s["name"] for s in self.macho.segments}
        self.assertIn("__TEXT", names)

    def test_libraries_parsed(self):
        self.assertIn("/usr/lib/libSystem.B.dylib", self.macho.libraries)

    def test_uuid_and_signature(self):
        self.assertIsNotNone(self.macho.uuid)
        self.assertTrue(self.macho.has_code_signature)

    def test_pie_flag(self):
        self.assertIn("MH_PIE", self.macho.flags)

    def test_32bit_header_detected(self):
        # Build a minimal 32-bit header
        data = bytearray(28)
        struct.pack_into("<I", data, 0, mo2.MachOAnalyzer.MAGIC_32)
        struct.pack_into("<I", data, 4, 0x0000000C)  # arm
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(bytes(data))
            name = f.name
        try:
            m = mo2.MachOAnalyzer(name)
            m.analyze()
            self.assertFalse(m.is_64bit)
            self.assertEqual(m.cpu_type, "arm")
        finally:
            os.unlink(name)


class TestStringsAndEntropy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = os.path.join(FIXTURE_DIR, "sample_macho.bin")
        if not os.path.exists(cls.fixture):
            mo2.create_sample_binary(cls.fixture)
        with open(cls.fixture, "rb") as f:
            cls.raw = f.read()

    def test_string_extraction(self):
        strings = mo2.extract_ascii_strings(self.raw)
        values = [s["value"] for s in strings]
        self.assertIn("kSecClassGenericPassword", values)
        self.assertIn("/usr/lib/libSystem.B.dylib", values)
        self.assertTrue(all(8 <= s["length"] for s in strings if "libSystem" in s["value"]))

    def test_interesting_strings(self):
        strings = mo2.extract_ascii_strings(self.raw)
        hits = mo2.scan_interesting_strings(strings)
        joined = " ".join(h["value"] for h in hits)
        self.assertIn("password", joined)
        self.assertIn("AKIA", joined)

    def test_entropy_analysis(self):
        ent = mo2.shannon_entropy(self.raw)
        self.assertGreaterEqual(ent["overall"], 0.0)
        self.assertGreater(len(ent["blocks"]), 0)
        # Deterministic
        ent2 = mo2.shannon_entropy(self.raw)
        self.assertEqual(ent["overall"], ent2["overall"])
        self.assertTrue(all(0.0 <= b["entropy"] <= 8.0 for b in ent["blocks"]))


class TestKeychainScanner(unittest.TestCase):
    def test_scan_finds_keychain_refs(self):
        fixture = os.path.join(FIXTURE_DIR, "sample_macho.bin")
        if not os.path.exists(fixture):
            mo2.create_sample_binary(fixture)
        with open(fixture, "rb") as f:
            raw = f.read()
        kc = mo2.KeychainAnalyzer()
        kc.scan_binary(raw)
        patterns = {r["pattern"] for r in kc.keychain_refs}
        self.assertTrue(patterns)


class TestPlist(unittest.TestCase):
    def test_binary_and_xml_plist_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            xml_path = os.path.join(tmp, "Info.plist")
            with open(xml_path, "wb") as f:
                plistlib.dump({"CFBundleIdentifier": "com.lab.app",
                               "NSAllowsArbitraryLoads": True,
                               "keychain-access-groups": ["*"]}, f)
            pl = mo2.PlistAnalyzer(xml_path)
            self.assertTrue(pl.analyze())
            self.assertEqual(pl.format, "xml")
            self.assertIn("CFBundleIdentifier", pl.keys)

            bin_path = os.path.join(tmp, "bin.plist")
            with open(bin_path, "wb") as f:
                plistlib.dump({"nested": {"a": 1}, "list": [1, 2]}, f, fmt=plistlib.FMT_BINARY)
            pb = mo2.PlistAnalyzer(bin_path)
            self.assertTrue(pb.analyze())
            self.assertEqual(pb.format, "binary")


class TestDemo(unittest.TestCase):
    def test_demo_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = mo2.run_demo(os.path.join(tmp, "reports"))
            self.assertEqual(rc, 0)
            report = os.path.join(tmp, "reports", "mo2_demo_report.json")
            self.assertTrue(os.path.exists(report))
            with open(report) as f:
                data = json.load(f)
            self.assertEqual(data["cpu_type"], "arm64")
            self.assertGreater(data["keychain_refs"], 0)


if __name__ == "__main__":
    unittest.main()