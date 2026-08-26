# MO2 — iOS Binary Analyzer

Analyzes Mach-O binaries, extracts entitlements, parses plist files, and detects keychain item access patterns.

## Overview

This tool performs static analysis of iOS/macOS binaries to identify:
- Mach-O header structure and metadata
- CPU architecture and binary type
- Load commands and linked libraries
- Security features (code signing, encryption, PIE)
- Entitlements and their risk levels
- Keychain access patterns

## Features

- **Mach-O Header Parsing**: Extract CPU type, file type, flags
- **FAT Binary Support**: Parse universal binaries with multiple architectures
- **Entitlement Extraction**: Analyze app entitlements for security implications
- **Plist Analysis**: Parse binary and XML property list files
- **Keychain Detection**: Find keychain access patterns in binaries
- **Security Assessment**: Evaluate encryption, code signing, PIE protection

## Installation

```bash
# No external dependencies required - uses standard library only
python3 ios_binary_analyzer.py <binary_file>
```

## Usage

```bash
# Analyze a Mach-O binary
python3 ios_binary_analyzer.py /path/to/binary

# Generate and analyze sample binary
python3 ios_binary_analyzer.py
```

## Example Output

```
[*] Analyzing: sample_macho.bin
[*] File size: 4096 bytes
[*] Mach-O Header Parsed:
    CPU Type: arm64
    64-bit: True
    File Type: MH_EXECUTE
    Commands: 4
    Flags: MH_DYLDLINK, MH_PIE

============================================================
  MO2 — iOS Binary Analyzer Report
============================================================

  Binary: sample_macho.bin
  Type: Mach-O

============================================================
  MACH-O HEADER
============================================================
  CPU Type: arm64
  64-bit: True
  File Type: MH_EXECUTE
  UUID: 01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10
  Flags: MH_DYLDLINK, MH_PIE

============================================================
  SEGMENTS
============================================================
  Name             VM Addr     VM Size     File Off    File Size
  __TEXT           0x100000000 0x1000       0x0         0x1000

============================================================
  SECURITY FEATURES
============================================================
  Code Signature: Yes
  Encrypted: No
  PIE: Yes
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
