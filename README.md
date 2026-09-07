# MO2 — iOS Binary Analyzer

Hand-rolled Mach-O parser plus plist / entitlements / strings / entropy analysis.
Standard-library only.

## What the engine genuinely does

- **Mach-O header parsing, by hand** — 32-bit (`MH_MAGIC`) and 64-bit
  (`MH_MAGIC_64`) headers, plus FAT/universal binaries; CPU type, file type,
  flag bits (PIE, etc.).
- **Load-command walker** — `LC_SEGMENT_64`, `LC_LOAD_DYLIB`, `LC_UUID`,
  `LC_CODE_SIGNATURE`, `LC_ENCRYPTION_INFO`, `LC_MAIN` extracted with real
  `struct` offsets.
- **Plist parsing** — XML and binary (`plistlib`) Info.plist with full key-tree
  enumeration.
- **Entitlements analysis** — XML entitlements load + risk-tiered assessment.
- **Keychain reference scan** — `kSec*` / `SecItem*` offsets and context.
- **Binary strings & entropy** — printable-ASCII string extraction with offsets,
  per-block Shannon entropy.

## Quick start

```bash
# Offline demo (crafts fixtures/sample_macho.bin, writes reports/, exit 0)
python3 ios_binary_analyzer.py

# Analyze a real Mach-O binary
python3 ios_binary_analyzer.py path/to/binary

# With plist + entitlements
python3 ios_binary_analyzer.py app_binary --plist Info.plist --entitlements app.entitlements

# JSON report
python3 ios_binary_analyzer.py path/to/binary --json --report-dir reports

# Rebuild fixture
python3 ios_binary_analyzer.py --make-fixture

# Tests
python3 -m unittest discover -s tests
```

## CLI

```
python3 ios_binary_analyzer.py [-h] [--plist PLIST] [--entitlements ENTITLEMENTS]
                               [--json] [--report-dir REPORT_DIR] [--make-fixture] [binary]
```

- `binary` — Mach-O binary to analyze. Omitted → offline demo (exit 0).
- `--plist` / `--entitlements` — additional plist inputs to analyze.
- `--json` — write JSON to `reports/<name>.json` (gitignored).
- `--make-fixture` — regenerate `fixtures/sample_macho.bin`.

Exit codes: `0` success (incl. demo), `2` usage/input error.

## Live Lab Test Plan

Prerequisites: a jailbroken or dev-signed device you own, or a decrypted
`Mach-O` you are authorized to analyze (the fixture stands in offline).

1. **Baseline**: `python3 ios_binary_analyzer.py fixtures/sample_macho.bin --json`
   — confirm arm64, 4+ load commands, `__TEXT` segment, keychain refs > 0.
2. **Real binary**: point it at a payload you have rights to (extract IPA,
   target the main `Mach-O`). Cross-check CPU/CPU64 and UUID against `otool -l`.
3. **Plist/entitlements**: `--plist Info.plist --entitlements app.entitlements`
   and compare entitlement risk flags with `codesign -d --entitlements - <app>`.
4. **Strings/entropy**: confirm entropy spikes at encrypted/FairPlay regions and
   that string offsets line up with the `__TEXT` section map from `otool`.
5. **Regression**: re-run `python3 -m unittest discover -s tests`.

## Metrics

| Metric                          | Value |
|---------------------------------|-------|
| Standard-library only           | Yes   |
| Third-party deps                | none  |
| Deterministic offline tests     | 13    |
| Fixture                         | `fixtures/sample_macho.bin` |
| Offline demo exit               | 0     |
| Report output                   | `reports/*.json` (gitignored) |
| Inputs                          | Mach-O / FAT, XML+binary plist, entitlements |

## IMPORTANT: Read before use.

Educational, authorization-required tooling. See `LICENSE` for the full shield —
Authorization, CFAA / computer-crime statutes, Acceptable Use, Prohibited Use,
No Warranty, and Responsible Disclosure. Only analyze binaries you own or are
explicitly authorized to assess.

## License

MIT — full legal shield in `LICENSE`.