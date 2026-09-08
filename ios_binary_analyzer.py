#!/usr/bin/env python3
"""MO2 — iOS Binary Analyzer

Analyzes Mach-O binaries, extracts entitlements, parses plist files,
and detects keychain item access patterns.
Uses only standard library modules.
"""

import struct
import plistlib
import xml.etree.ElementTree as ET
import os
import sys
import json
import re
import base64
import math
import argparse
from collections import defaultdict


class MachOAnalyzer:
    """Mach-O binary format constants and parser."""

    # Mach-O magic numbers
    MAGIC_32 = 0xFEEDFACE
    MAGIC_64 = 0xFEEDFACF
    FAT_MAGIC = 0xCAFEBABE
    FAT_MAGIC_64 = 0xCAFEBABF

    # CPU types
    CPU_TYPES = {
        0x00000007: 'x86',
        0x01000007: 'x86_64',
        0x0000000C: 'arm',
        0x0100000C: 'arm64',
        0x0200000C: 'arm64_32',
    }

    # File types
    MH_EXECUTE = 0x2
    MH_DYLIB = 0x6
    MH_BUNDLE = 0x8
    MH_DYLINKER = 0x7
    MH_KEXT_BUNDLE = 0xB

    MH_FILETYPES = {
        0x1: 'MH_OBJECT',
        0x2: 'MH_EXECUTE',
        0x6: 'MH_DYLIB',
        0x7: 'MH_DYLINKER',
        0x8: 'MH_BUNDLE',
        0xA: 'MH_PRELOAD',
        0xB: 'MH_KEXT_BUNDLE',
    }

    # Load commands
    LC_REQ_DYLD = 0x80000000
    LC_SEGMENT = 0x1
    LC_SEGMENT_64 = 0x19
    LC_DYLD_INFO_ONLY = 0x22 | LC_REQ_DYLD
    LC_SYMTAB = 0x02
    LC_UUID = 0x1B
    LC_CODE_SIGNATURE = 0x1D
    LC_ENCRYPTION_INFO = 0x21
    LC_ENCRYPTION_INFO_64 = 0x2C
    LC_LOAD_DYLIB = 0x0C
    LC_LOAD_WEAK_DYLIB = 0x80000028
    LC_MAIN = 0x80000018
    LC_RPATH = 0x80000034

    LC_NAMES = {
        0x01: 'LC_SEGMENT',
        0x02: 'LC_SYMTAB',
        0x05: 'LC_DYSYMTAB',
        0x0C: 'LC_LOAD_DYLIB',
        0x0D: 'LC_ID_DYLIB',
        0x0E: 'LC_LOAD_DYLINKER',
        0x19: 'LC_SEGMENT_64',
        0x1B: 'LC_UUID',
        0x1D: 'LC_CODE_SIGNATURE',
        0x21: 'LC_ENCRYPTION_INFO',
        0x22: 'LC_DYLD_INFO',
        0x2C: 'LC_ENCRYPTION_INFO_64',
        0x80000018: 'LC_MAIN',
        0x80000022: 'LC_DYLD_INFO_ONLY',
        0x80000028: 'LC_LOAD_WEAK_DYLIB',
        0x80000033: 'LC_UUID',
        0x80000034: 'LC_RPATH',
    }

    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.binary_name = os.path.basename(binary_path)
        self.data = None
        self.is_fat = False
        self.is_64bit = False
        self.cpu_type = None
        self.file_type = None
        self.flags = []
        self.load_commands = []
        self.segments = []
        self.libraries = []
        self.uuid = None
        self.has_code_signature = False
        self.is_encrypted = False
        self.entry_point = None

    def analyze(self):
        """Run full Mach-O analysis."""
        print(f"[*] Analyzing: {self.binary_name}")
        print(f"[*] File size: {os.path.getsize(self.binary_path)} bytes")
        print()

        with open(self.binary_path, 'rb') as f:
            self.data = f.read()

        if len(self.data) < 4:
            print("[!] File too small to be a Mach-O binary")
            return False

        magic = struct.unpack_from('<I', self.data, 0)[0]

        if magic == self.FAT_MAGIC or magic == self.FAT_MAGIC_64:
            self.is_fat = True
            return self._parse_fat_binary()
        elif magic == self.MAGIC_32 or magic == self.MAGIC_64:
            return self._parse_mach_header()
        else:
            print(f"[!] Not a recognized Mach-O binary (magic: 0x{magic:08X})")
            return False

    def _parse_fat_binary(self):
        """Parse FAT/Universal binary header."""
        magic = struct.unpack_from('<I', self.data, 0)[0]
        nfat = struct.unpack_from('>I', self.data, 4)[0]

        print(f"[*] FAT Binary detected with {nfat} architecture(s)")

        offset = 8
        archs = []
        for i in range(nfat):
            if offset + 20 > len(self.data):
                break
            cpu_type = struct.unpack_from('>I', self.data, offset)[0]
            cpu_subtype = struct.unpack_from('>I', self.data, offset + 4)[0]
            offset_val = struct.unpack_from('>I', self.data, offset + 8)[0]
            size = struct.unpack_from('>I', self.data, offset + 12)[0]
            align = struct.unpack_from('>I', self.data, offset + 16)[0]

            archs.append({
                'cpu_type': self.CPU_TYPES.get(cpu_type, f'unknown(0x{cpu_type:X})'),
                'offset': offset_val,
                'size': size,
                'align': 2 ** align,
            })
            offset += 20

        for arch in archs:
            print(f"  Architecture: {arch['cpu_type']} (offset: {arch['offset']}, size: {arch['size']})")

        # Parse first architecture
        if archs:
            first_arch = archs[0]
            saved_data = self.data
            self.data = self.data[first_arch['offset']:first_arch['offset'] + first_arch['size']]
            result = self._parse_mach_header()
            self.data = saved_data
            return result

        return False

    def _parse_mach_header(self):
        """Parse Mach-O header."""
        if len(self.data) < 28:
            print("[!] Data too small for Mach-O header")
            return False

        magic = struct.unpack_from('<I', self.data, 0)[0]

        if magic == self.MAGIC_64:
            self.is_64bit = True
            header_size = 32
            if len(self.data) < header_size:
                return False
            cpu_type = struct.unpack_from('<I', self.data, 4)[0]
            cpu_subtype = struct.unpack_from('<I', self.data, 8)[0]
            self.file_type = struct.unpack_from('<I', self.data, 12)[0]
            ncmds = struct.unpack_from('<I', self.data, 16)[0]
            sizeofcmds = struct.unpack_from('<I', self.data, 20)[0]
            flags = struct.unpack_from('<I', self.data, 24)[0]
        elif magic == self.MAGIC_32:
            self.is_64bit = False
            header_size = 28
            if len(self.data) < header_size:
                return False
            cpu_type = struct.unpack_from('<I', self.data, 4)[0]
            cpu_subtype = struct.unpack_from('<I', self.data, 8)[0]
            self.file_type = struct.unpack_from('<I', self.data, 12)[0]
            ncmds = struct.unpack_from('<I', self.data, 16)[0]
            sizeofcmds = struct.unpack_from('<I', self.data, 20)[0]
            flags = struct.unpack_from('<I', self.data, 24)[0]
        else:
            return False

        self.cpu_type = self.CPU_TYPES.get(cpu_type, f'unknown(0x{cpu_type:X})')

        # Decode flags
        flag_defs = [
            (0x00000001, 'MH_NOUNDEFS'),
            (0x00000002, 'MH_INCR_LINK'),
            (0x00000004, 'MH_DYLDLINK'),
            (0x00000008, 'MH_BIND_AT_LOAD'),
            (0x00000010, 'MH_PREBOUND'),
            (0x00000020, 'MH_SPLIT_SEGS'),
            (0x00000040, 'MH_TWOLEVEL'),
            (0x00000080, 'MH_FORCE_FLAT'),
            (0x00000100, 'MH_NO_MULTI_DEFS'),
            (0x00000200, 'MH_NOFIXPREBINDING'),
            (0x00000400, 'MH_PIE'),
            (0x00000800, 'MH_DEAD_STRIPPABLE_DYLIB'),
            (0x01000000, 'MH_ROOT_SAFE'),
            (0x02000000, 'MH_SETUID_SAFE'),
            (0x04000000, 'MH_NO_REEXPORTED_DYLIBS'),
            (0x08000000, 'MH_PIE'),
            (0x10000000, 'MH_ALLOW_STACK_EXECUTION'),
            (0x20000000, 'MH_ROOT_SAFE'),
            (0x40000000, 'MH_ALLOW_DYLD_INFO_ONLY'),
        ]

        self.flags = []
        for bit, name in flag_defs:
            if flags & bit and name not in self.flags:
                self.flags.append(name)

        print(f"[*] Mach-O Header Parsed:")
        print(f"    CPU Type: {self.cpu_type}")
        print(f"    64-bit: {self.is_64bit}")
        print(f"    File Type: {self.MH_FILETYPES.get(self.file_type, f'unknown(0x{self.file_type:X})')}")
        print(f"    Commands: {ncmds}")
        print(f"    Flags: {', '.join(self.flags) if self.flags else 'none'}")
        print()

        # Parse load commands
        self._parse_load_commands(header_size, ncmds)
        return True

    def _parse_load_commands(self, header_size, ncmds):
        """Parse all load commands."""
        offset = header_size

        for _ in range(ncmds):
            if offset + 8 > len(self.data):
                break

            cmd = struct.unpack_from('<I', self.data, offset)[0]
            cmdsize = struct.unpack_from('<I', self.data, offset + 4)[0]

            if cmdsize < 8 or offset + cmdsize > len(self.data):
                break

            cmd_name = self.LC_NAMES.get(cmd, f'LC_UNKNOWN(0x{cmd:X})')

            cmd_info = {'type': cmd, 'name': cmd_name, 'offset': offset, 'size': cmdsize}

            # Parse specific commands
            if cmd == self.LC_SEGMENT and not self.is_64bit:
                self._parse_segment_command(offset, cmdsize, is64=False)
            elif cmd == self.LC_SEGMENT_64 and self.is_64bit:
                self._parse_segment_command(offset, cmdsize, is64=True)
            elif cmd in (self.LC_LOAD_DYLIB, self.LC_LOAD_WEAK_DYLIB):
                self._parse_dylib_command(offset, cmdsize)
            elif cmd == self.LC_UUID:
                self._parse_uuid_command(offset)
            elif cmd == self.LC_CODE_SIGNATURE:
                self.has_code_signature = True
            elif cmd in (self.LC_ENCRYPTION_INFO, self.LC_ENCRYPTION_INFO_64):
                self._parse_encryption_info(offset)
            elif cmd in (0x80000018,):  # LC_MAIN
                self._parse_main_command(offset)

            self.load_commands.append(cmd_info)
            offset += cmdsize

    def _parse_segment_command(self, offset, cmdsize, is64):
        """Parse segment load command."""
        if is64:
            segname_offset = 0
            segname = self.data[offset + 8:offset + 24].split(b'\x00')[0].decode('ascii', errors='replace')
            vmaddr = struct.unpack_from('<Q', self.data, offset + 24)[0]
            vmsize = struct.unpack_from('<Q', self.data, offset + 32)[0]
            fileoff = struct.unpack_from('<Q', self.data, offset + 40)[0]
            filesize = struct.unpack_from('<Q', self.data, offset + 48)[0]
            nsects = struct.unpack_from('<I', self.data, offset + 56)[0]
        else:
            segname = self.data[offset + 8:offset + 24].split(b'\x00')[0].decode('ascii', errors='replace')
            vmaddr = struct.unpack_from('<I', self.data, offset + 24)[0]
            vmsize = struct.unpack_from('<I', self.data, offset + 28)[0]
            fileoff = struct.unpack_from('<I', self.data, offset + 32)[0]
            filesize = struct.unpack_from('<I', self.data, offset + 36)[0]
            nsects = struct.unpack_from('<I', self.data, offset + 40)[0]

        seg = {
            'name': segname,
            'vmaddr': vmaddr,
            'vmsize': vmsize,
            'fileoff': fileoff,
            'filesize': filesize,
            'nsects': nsects,
        }
        self.segments.append(seg)

    def _parse_dylib_command(self, offset, cmdsize):
        """Parse dylib load command to extract library name."""
        name_offset = struct.unpack_from('<I', self.data, offset + 8)[0]
        if offset + name_offset < len(self.data):
            name_data = self.data[offset + name_offset:offset + cmdsize]
            name = name_data.split(b'\x00')[0].decode('utf-8', errors='replace')
            if name:
                self.libraries.append(name)

    def _parse_uuid_command(self, offset):
        """Parse UUID command."""
        if offset + 16 <= len(self.data):
            uuid_bytes = self.data[offset + 8:offset + 16]
            self.uuid = '-'.join(f'{b:02X}' for b in uuid_bytes)

    def _parse_encryption_info(self, offset):
        """Parse encryption info command."""
        if self.is_64bit:
            crypt_offset = struct.unpack_from('<I', self.data, offset + 16)[0]
            crypt_size = struct.unpack_from('<I', self.data, offset + 20)[0]
            crypt_id = struct.unpack_from('<I', self.data, offset + 24)[0]
        else:
            crypt_offset = struct.unpack_from('<I', self.data, offset + 8)[0]
            crypt_size = struct.unpack_from('<I', self.data, offset + 12)[0]
            crypt_id = struct.unpack_from('<I', self.data, offset + 16)[0]

        if crypt_id != 0:
            self.is_encrypted = True

    def _parse_main_command(self, offset):
        """Parse LC_MAIN command for entry point."""
        entry_offset = struct.unpack_from('<Q', self.data, offset + 8)[0]
        stack_size = struct.unpack_from('<Q', self.data, offset + 16)[0]
        self.entry_point = entry_offset

    def print_report(self):
        """Print Mach-O analysis report."""
        print("=" * 60)
        print("  MO2 — iOS Binary Analyzer Report")
        print("=" * 60)

        print(f"\n  Binary: {self.binary_name}")
        print(f"  Size: {os.path.getsize(self.binary_path)} bytes")
        print(f"  Type: {'FAT/Universal' if self.is_fat else 'Mach-O'}")

        print(f"\n{'='*60}")
        print("  MACH-O HEADER")
        print(f"{'='*60}")
        print(f"  CPU Type: {self.cpu_type}")
        print(f"  64-bit: {self.is_64bit}")
        print(f"  File Type: {self.MH_FILETYPES.get(self.file_type, 'unknown')}")
        print(f"  UUID: {self.uuid or 'not found'}")
        print(f"  Flags: {', '.join(self.flags) if self.flags else 'none'}")

        if self.entry_point is not None:
            print(f"  Entry Point: 0x{self.entry_point:X}")

        print(f"\n{'='*60}")
        print("  SEGMENTS")
        print(f"{'='*60}")
        print(f"  {'Name':<16} {'VM Addr':<12} {'VM Size':<12} {'File Off':<12} {'File Size':<12}")
        print(f"  {'-'*64}")
        for seg in self.segments:
            name = seg['name'][:16]
            print(f"  {name:<16} 0x{seg['vmaddr']:<10X} 0x{seg['vmsize']:<10X} 0x{seg['fileoff']:<10X} 0x{seg['filesize']:<10X}")

        print(f"\n{'='*60}")
        print(f"  LOAD COMMANDS ({len(self.load_commands)} total)")
        print(f"{'='*60}")
        cmd_counts = defaultdict(int)
        for cmd in self.load_commands:
            cmd_counts[cmd['name']] += 1
        for name, count in sorted(cmd_counts.items()):
            print(f"  {name}: {count}")

        if self.libraries:
            print(f"\n{'='*60}")
            print(f"  LINKED LIBRARIES ({len(self.libraries)})")
            print(f"{'='*60}")
            for lib in sorted(self.libraries):
                print(f"  - {lib}")

        print(f"\n{'='*60}")
        print("  SECURITY FEATURES")
        print(f"{'='*60}")
        print(f"  Code Signature: {'Yes' if self.has_code_signature else 'No'}")
        print(f"  Encrypted: {'Yes' if self.is_encrypted else 'No'}")
        print(f"  PIE: {'Yes' if 'MH_PIE' in self.flags else 'No'}")

        if self.is_encrypted:
            print("  [!] Binary is encrypted (FairPlay DRM)")

        if not self.has_code_signature:
            print("  [!] No code signature - potential security issue")

        print(f"\n{'='*60}")
        print("  Analysis Complete")
        print(f"{'='*60}\n")


class PlistAnalyzer:
    """Analyze property list files."""

    def __init__(self, plist_path):
        self.plist_path = plist_path
        self.plist_name = os.path.basename(plist_path)
        self.data = None
        self.format = None
        self.keys = []

    def analyze(self):
        """Analyze plist file."""
        print(f"\n[*] Analyzing plist: {self.plist_name}")

        with open(self.plist_path, 'rb') as f:
            self.data = f.read()

        # Detect format
        if self.data[:6] == b'bplist':
            self.format = 'binary'
            return self._parse_binary_plist()
        elif b'<?xml' in self.data[:100]:
            self.format = 'xml'
            return self._parse_xml_plist()
        else:
            print("[!] Unknown plist format")
            return False

    def _parse_binary_plist(self):
        """Parse binary plist."""
        try:
            self.data_parsed = plistlib.loads(self.data)
            self._extract_keys(self.data_parsed, '')
            return True
        except Exception as e:
            print(f"[!] Error parsing binary plist: {e}")
            return False

    def _parse_xml_plist(self):
        """Parse XML plist."""
        try:
            self.data_parsed = plistlib.loads(self.data)
            self._extract_keys(self.data_parsed, '')
            return True
        except Exception as e:
            print(f"[!] Error parsing XML plist: {e}")
            return False

    def _extract_keys(self, data, prefix):
        """Recursively extract all keys from plist data."""
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                self.keys.append(full_key)
                self._extract_keys(value, full_key)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                self._extract_keys(item, f"{prefix}[{i}]")

    def print_report(self):
        """Print plist analysis report."""
        print(f"\n  Plist: {self.plist_name}")
        print(f"  Format: {self.format}")
        print(f"  Size: {len(self.data)} bytes")
        print(f"  Keys found: {len(self.keys)}")

        if self.keys:
            print(f"\n  Key Structure:")
            for key in sorted(self.keys)[:50]:
                print(f"    - {key}")
            if len(self.keys) > 50:
                print(f"    ... and {len(self.keys) - 50} more")


class EntitlementsExtractor:
    """Extract and analyze entitlements from plist files."""

    # Common entitlements and their security implications
    ENTITLEMENT_RISKS = {
        'com.apple.security.app-sandbox': 'App Sandbox',
        'com.apple.security.cs.allow-unsigned-executable-memory': 'Allow Unsigned Memory',
        'com.apple.security.cs.disable-library-validation': 'Disable Library Validation',
        'com.apple.security.get-user-allow': 'Get User Allow',
        'com.apple.security.network.client': 'Network Client',
        'com.apple.security.network.server': 'Network Server',
        'com.apple.security.device.camera': 'Camera Access',
        'com.apple.security.device.microphone': 'Microphone Access',
        'com.apple.security.device.usb': 'USB Access',
        'com.apple.security.files.user-selected.read-only': 'User Selected Files Read',
        'com.apple.security.files.user-selected.read-write': 'User Selected Files Read/Write',
        'com.apple.security.files.downloads.read-only': 'Downloads Read',
        'com.apple.security.files.downloads.read-write': 'Downloads Read/Write',
        'com.apple.security.files.documents.read-only': 'Documents Read',
        'com.apple.security.files.documents.read-write': 'Documents Read/Write',
        'com.apple.security.personal-information.location': 'Location Access',
        'com.apple.security.personal-information.addressbook': 'Contacts Access',
        'com.apple.security.personal-information.calendars': 'Calendar Access',
        'com.apple.security.print': 'Print Access',
    }

    def __init__(self):
        self.entitlements = []

    def extract_from_plist(self, plist_data):
        """Extract entitlements from parsed plist data."""
        if isinstance(plist_data, dict):
            # Check for entitlements key
            if 'Entitlements' in plist_data:
                self.entitlements = plist_data['Entitlements']
            else:
                self.entitlements = plist_data

    def extract_from_xml(self, plist_path):
        """Extract entitlements from XML plist file."""
        try:
            tree = ET.parse(plist_path)
            root = tree.getroot()
            # Find dict elements
            for dict_elem in root.findall('.//dict'):
                keys = dict_elem.findall('key')
                for key in keys:
                    self.entitlements[key.text] = True
        except ET.ParseError:
            pass

    def analyze(self):
        """Analyze extracted entitlements."""
        print(f"\n{'='*60}")
        print("  ENTITLEMENTS ANALYSIS")
        print(f"{'='*60}")

        if not self.entitlements:
            print("  No entitlements found")
            return

        print(f"\n  Total Entitlements: {len(self.entitlements)}")

        high_risk = []
        medium_risk = []

        for key, value in self.entitlements.items():
            risk_level = self._assess_risk(key, value)
            if risk_level == 'HIGH':
                high_risk.append((key, value))
            elif risk_level == 'MEDIUM':
                medium_risk.append((key, value))

        if high_risk:
            print(f"\n  [!] HIGH RISK ENTITLEMENTS ({len(high_risk)}):")
            for key, value in high_risk:
                print(f"      {key}: {value}")

        if medium_risk:
            print(f"\n  [i] MEDIUM RISK ENTITLEMENTS ({len(medium_risk)}):")
            for key, value in medium_risk:
                print(f"      {key}: {value}")

        print(f"\n  All Entitlements:")
        for key, value in sorted(self.entitlements.items()):
            desc = self.ENTITLEMENT_RISKS.get(key, '')
            if desc:
                print(f"    - {key} ({desc}): {value}")
            else:
                print(f"    - {key}: {value}")

    def _assess_risk(self, key, value):
        """Assess risk level of an entitlement."""
        if value is False or value == 'false':
            return 'LOW'

        high_risk_keys = [
            'com.apple.security.cs.allow-unsigned-executable-memory',
            'com.apple.security.cs.disable-library-validation',
        ]

        medium_risk_keys = [
            'com.apple.security.network.server',
            'com.apple.security.device.camera',
            'com.apple.security.device.microphone',
            'com.apple.security.personal-information.location',
        ]

        if key in high_risk_keys:
            return 'HIGH'
        elif key in medium_risk_keys:
            return 'MEDIUM'
        return 'LOW'


class KeychainAnalyzer:
    """Detect keychain access patterns in binary."""

    # Keychain access class strings
    KEYCHAIN_CLASSES = {
        'kSecClassGenericPassword': 'Generic Password',
        'kSecClassInternetPassword': 'Internet Password',
        'kSecClassCertificate': 'Certificate',
        'kSecClassKey': 'Crypto Key',
        'kSecClassIdentity': 'Identity',
    }

    # Common keychain access groups
    ACCESS_GROUPS = {
        'apple': 'Apple Default',
        'keychain-access-groups': 'Custom Access Group',
    }

    def __init__(self):
        self.keychain_refs = []
        self.access_groups = []

    def scan_binary(self, data):
        """Scan binary data for keychain references."""
        # Search for keychain-related strings
        keychain_patterns = [
            b'kSecClass',
            b'kSecAttr',
            b'kSecReturn',
            b'kSecMatch',
            b'SecItemAdd',
            b'SecItemCopyMatching',
            b'SecItemUpdate',
            b'SecItemDelete',
            b'kSecClassGenericPassword',
            b'kSecClassInternetPassword',
            b'kSecClassCertificate',
            b'kSecClassKey',
            b'kSecClassIdentity',
        ]

        for pattern in keychain_patterns:
            offset = 0
            while True:
                pos = data.find(pattern, offset)
                if pos == -1:
                    break
                # Extract surrounding string
                start = max(0, pos - 20)
                end = min(len(data), pos + len(pattern) + 50)
                context = data[start:end]
                # Clean up
                try:
                    context_str = context.decode('utf-8', errors='replace')
                    context_str = ''.join(c if c.isprintable() else ' ' for c in context_str)
                    self.keychain_refs.append({
                        'pattern': pattern.decode('utf-8', errors='replace'),
                        'offset': pos,
                        'context': context_str.strip()
                    })
                except Exception:
                    pass
                offset = pos + 1

    def analyze(self):
        """Print keychain analysis report."""
        print(f"\n{'='*60}")
        print("  KEYCHAIN ACCESS PATTERNS")
        print(f"{'='*60}")

        if not self.keychain_refs:
            print("  No keychain access patterns detected")
            return

        print(f"\n  References found: {len(self.keychain_refs)}")

        # Group by pattern type
        by_pattern = defaultdict(list)
        for ref in self.keychain_refs:
            by_pattern[ref['pattern']].append(ref)

        for pattern, refs in by_pattern.items():
            print(f"\n  Pattern: {pattern}")
            for ref in refs[:5]:
                print(f"    Offset: 0x{ref['offset']:X}")
                print(f"    Context: {ref['context'][:80]}")
            if len(refs) > 5:
                print(f"    ... and {len(refs) - 5} more")


def extract_ascii_strings(data, min_length=6):
    """Extract printable ASCII strings with their file offsets."""
    strings = []
    current = []
    start = 0
    for i, b in enumerate(data):
        if 32 <= b <= 126:
            if not current:
                start = i
            current.append(b)
        else:
            if len(current) >= min_length:
                strings.append({"offset": start, "length": len(current),
                                "value": bytes(current).decode("ascii", errors="replace")})
            current = []
    if len(current) >= min_length:
        strings.append({"offset": start, "length": len(current),
                        "value": bytes(current).decode("ascii", errors="replace")})
    return strings


def shannon_entropy(data, block=4096):
    """Compute overall and per-block Shannon entropy."""
    if not data:
        return {"overall": 0.0, "blocks": []}
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    overall = -sum(c / n * math.log2(c / n) for c in freq.values() if c)

    blocks = []
    for off in range(0, len(data), block):
        chunk = data[off:off + block]
        if not chunk:
            break
        f2 = {}
        for b in chunk:
            f2[b] = f2.get(b, 0) + 1
        m = len(chunk)
        e = -sum(c / m * math.log2(c / m) for c in f2.values() if c)
        blocks.append({"offset": off, "length": len(chunk), "entropy": round(e, 4)})
    return {"overall": round(overall, 4), "blocks": blocks}


def create_sample_binary(path):
    """Create a crafted, deterministic Mach-O 64-bit sample binary."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    data = bytearray(4096)

    struct.pack_into('<I', data, 0, MachOAnalyzer.MAGIC_64)
    struct.pack_into('<I', data, 4, 0x0100000C)
    struct.pack_into('<I', data, 8, 0x00000000)
    struct.pack_into('<I', data, 12, MachOAnalyzer.MH_EXECUTE)
    struct.pack_into('<I', data, 16, 4)
    struct.pack_into('<I', data, 20, 256)
    struct.pack_into('<I', data, 24, 0x00000485)  # NOUNDEFS|DYLDLINK|TWOLEVEL|PIE

    offset = 32
    struct.pack_into('<I', data, offset, MachOAnalyzer.LC_UUID)
    struct.pack_into('<I', data, offset + 4, 24)
    data[offset + 8:offset + 24] = bytes(range(16))

    offset = 56
    struct.pack_into('<I', data, offset, MachOAnalyzer.LC_CODE_SIGNATURE)
    struct.pack_into('<I', data, offset + 4, 16)
    struct.pack_into('<I', data, offset + 8, 0)
    struct.pack_into('<I', data, offset + 12, 0)

    offset = 72
    struct.pack_into('<I', data, offset, MachOAnalyzer.LC_SEGMENT_64)
    struct.pack_into('<I', data, offset + 4, 72)
    segname = b'__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    data[offset + 8:offset + 24] = segname[:16]
    struct.pack_into('<Q', data, offset + 24, 0x100000000)
    struct.pack_into('<Q', data, offset + 32, 0x1000)
    struct.pack_into('<Q', data, offset + 40, 0)
    struct.pack_into('<Q', data, offset + 48, 0x1000)
    struct.pack_into('<I', data, offset + 56, 0)

    offset = 144
    lib_cmd_size = (24 + len(b'/usr/lib/libSystem.B.dylib\x00') + 7) & ~7
    struct.pack_into('<I', data, offset, MachOAnalyzer.LC_LOAD_DYLIB)
    struct.pack_into('<I', data, offset + 4, lib_cmd_size)
    struct.pack_into('<I', data, offset + 8, 24)
    struct.pack_into('<I', data, offset + 12, 0)
    struct.pack_into('<I', data, offset + 16, 0)
    struct.pack_into('<I', data, offset + 20, 0)
    data[offset + 24:offset + 24 + len(b'/usr/lib/libSystem.B.dylib\x00')] = b'/usr/lib/libSystem.B.dylib\x00'

    data.extend(b'\x00' * (4096 - len(data)))

    markers = [
        b'kSecClassGenericPassword', b'SecItemAdd', b'kSecAttrService',
        b'NSAllowsArbitraryLoads', b'AWS_SECRET=' + b'AKIA' + b'IOSFODNN7EXAMPLE',
        b'com.apple.security.cs.disable-library-validation',
        b'http://192.0.2.40/beacon', b'password=hunter2_lab',
    ]
    for s in markers:
        data.extend(s + b'\x00')

    with open(path, 'wb') as f:
        f.write(bytes(data))
    return path


def scan_interesting_strings(strings, keywords=("http", "password", "secret", "aws", "key")):
    hits = []
    for s in strings:
        low = s["value"].lower()
        if any(k in low for k in keywords):
            hits.append(s)
    return hits


def run_demo(report_dir="reports"):
    """Offline demo: craft fixture, analyze, write JSON. Returns exit code."""
    os.makedirs(report_dir, exist_ok=True)
    fixture = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "fixtures", "sample_macho.bin")
    if not os.path.exists(fixture):
        create_sample_binary(fixture)
    binary_path = fixture

    macho = MachOAnalyzer(binary_path)
    if not macho.analyze():
        return 1
    with open(binary_path, 'rb') as f:
        raw = f.read()
    strings = extract_ascii_strings(raw)
    entropy = shannon_entropy(raw)
    keychain = KeychainAnalyzer()
    keychain.scan_binary(raw)
    interesting = scan_interesting_strings(strings)

    report = {
        "binary": macho.binary_name,
        "magic": "FAT" if macho.is_fat else "MACH-O",
        "cpu_type": macho.cpu_type,
        "is_64bit": macho.is_64bit,
        "file_type": macho.MH_FILETYPES.get(macho.file_type, "unknown"),
        "uuid": macho.uuid,
        "flags": macho.flags,
        "segments": [s["name"] for s in macho.segments],
        "libraries": sorted(macho.libraries),
        "has_code_signature": macho.has_code_signature,
        "is_encrypted": macho.is_encrypted,
        "entry_point": macho.entry_point,
        "strings_count": len(strings),
        "interesting_strings": [{k: s[k] for k in ("offset", "value")} for s in interesting[:40]],
        "keychain_refs": len(keychain.keychain_refs),
        "entropy": entropy["overall"],
    }
    out = os.path.join(report_dir, "mo2_demo_report.json")
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] JSON report: {out}")
    print(f"[*] CPU: {macho.cpu_type}  64-bit: {macho.is_64bit}  UUID: {macho.uuid}")
    print(f"[*] Strings: {len(strings)}  Keychain refs: {len(keychain.keychain_refs)}  Entropy: {entropy['overall']}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="ios_binary_analyzer",
        description="MO2 — iOS binary analyzer (Mach-O, Info.plist, entitlements, strings).")
    parser.add_argument("binary", nargs="?", help="Mach-O binary to analyze (omit for offline demo)")
    parser.add_argument("--plist", help="Info.plist (XML or binary) to analyze")
    parser.add_argument("--entitlements", help="entitlements plist file to analyze")
    parser.add_argument("--json", action="store_true", help="write JSON report to reports/")
    parser.add_argument("--report-dir", default="reports", help="report dir (default: reports)")
    parser.add_argument("--make-fixture", action="store_true", help="build the crafted Mach-O fixture")
    args = parser.parse_args()

    if args.make_fixture:
        fixture = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "fixtures", "sample_macho.bin")
        create_sample_binary(fixture)
        print(f"[*] Fixture written: {fixture}")
        return 0

    if not args.binary:
        return run_demo(args.report_dir)

    if not os.path.exists(args.binary):
        print(f"[!] File not found: {args.binary}")
        return 2

    macho = MachOAnalyzer(args.binary)
    if macho.analyze():
        macho.print_report()
        with open(args.binary, 'rb') as f:
            raw = f.read()
        keychain = KeychainAnalyzer()
        keychain.scan_binary(raw)
        keychain.analyze()
        strings = extract_ascii_strings(raw)
        entropy = shannon_entropy(raw)
        print(f"\n[*] Strings: {len(strings)}  Entropy(overall): {entropy['overall']}")

        if args.json:
            os.makedirs(args.report_dir, exist_ok=True)
            report = {
                "binary": macho.binary_name,
                "cpu_type": macho.cpu_type,
                "is_64bit": macho.is_64bit,
                "file_type": macho.MH_FILETYPES.get(macho.file_type, "unknown"),
                "uuid": macho.uuid,
                "flags": macho.flags,
                "segments": [s["name"] for s in macho.segments],
                "libraries": sorted(macho.libraries),
                "has_code_signature": macho.has_code_signature,
                "is_encrypted": macho.is_encrypted,
                "strings_count": len(strings),
                "keychain_refs": len(keychain.keychain_refs),
                "entropy": entropy["overall"],
            }
            out = os.path.join(args.report_dir, os.path.basename(args.binary) + ".json")
            with open(out, "w") as f:
                json.dump(report, f, indent=2)
            print(f"[*] JSON report: {out}")

    if args.plist:
        if not os.path.exists(args.plist):
            print(f"[!] plist not found: {args.plist}")
            return 2
        pl = PlistAnalyzer(args.plist)
        if pl.analyze():
            pl.print_report()

    if args.entitlements:
        if not os.path.exists(args.entitlements):
            print(f"[!] entitlements not found: {args.entitlements}")
            return 2
        extractor = EntitlementsExtractor()
        extractor.extract_from_xml(args.entitlements)
        extractor.analyze()

    return 0
