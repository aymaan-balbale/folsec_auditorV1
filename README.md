# folsec-auditor

**NTFS / ACL Risk Auditor — Point-in-Time Gap Analyzer for Enterprise File Servers**

A single, statically linked `.exe` written in Rust. Scans NTFS directory trees at high speed, extracts Windows ACLs via direct Win32 API calls, and produces a self-contained HTML report exposing over-permissive entries, inheritance breaks, orphaned SIDs, and SIEM visibility gaps.

Built as an open-source lead-generation tool for [FolSec](https://folsec.com) — a platform providing continuous NTFS governance, real-time audit visibility, and anomaly detection. This tool gives IT administrators a point-in-time "what's broken right now" picture. FolSec tells you the moment it changes.

---

## What It Finds

| Risk | Severity | Description |
|------|----------|-------------|
| Over-permissive ACE | HIGH / MEDIUM | `Everyone`, `Authenticated Users`, or `BUILTIN\Users` with write / modify / full control |
| Inheritance break | MEDIUM | Folder explicitly blocks inherited permissions, creating a hidden permission island |
| Orphaned SID | LOW | ACE references a SID that cannot be resolved — typically a deleted AD account |
| Null DACL | CRITICAL | No DACL present = implicit allow-all for every user on the system |
| Anomaly simulated | CRITICAL | Rapid ACL cycling went undetected — SIEM has no real-time NTFS visibility |

---

## Output

1. **Self-contained HTML report** — single file, no server required, works air-gapped. Embed as email attachment or share via USB.
2. **Dry-run PowerShell script** (`remediate_dry_run.ps1`) — documents every remediation action with `Write-Host "Would remove..."`. Zero changes made; designed for change-management review.

---

## Quick Start

```powershell
# Scan a share and generate the HTML report
folsec-auditor.exe scan --root "\\fileserver01\HR" --output report.html

# Also generate the dry-run remediation script
folsec-auditor.exe scan --root "C:\DataFiles" --output report.html --remediation fix.ps1

# Limit depth for a fast triage pass
folsec-auditor.exe scan --root "D:\Projects" --output report.html --max-depth 4

# Run the anomaly simulator (see Anomaly Simulator section below)
folsec-auditor.exe scan --root "C:\DataFiles" --output report.html --simulate-anomaly

# Restrict CPU usage on production servers
folsec-auditor.exe scan --root "\\nas\share" --output report.html --threads 4
```

---

## CLI Reference

```
folsec-auditor.exe scan [OPTIONS]

Options:
  -r, --root <PATH>           Root path to scan (local or UNC)
  -o, --output <FILE>         HTML report output path [default: folsec_report.html]
      --remediation <FILE>    Dry-run PowerShell script output path (optional)
      --max-depth <N>         Max recursion depth; 0 = unlimited [default: 0]
      --follow-symlinks       Follow symbolic links (caution on SMB shares with junction points)
      --skip-access-denied    Silently skip denied paths instead of logging them
      --simulate-anomaly      Run the ransomware ACL cycling simulator
      --threads <N>           Rayon worker threads; 0 = all logical CPUs [default: 0]
  -h, --help                  Print help
  -V, --version               Print version
```

---

## Building from Source

**Requirements:** Rust stable toolchain, Windows host or cross-compilation target.

```powershell
# Clone
git clone https://github.com/aymaan-balbale/folsec_auditorV1.git
cd folsec_auditorV1

# Release build — single statically linked .exe, no runtime dependencies
$env:RUSTFLAGS="-C target-feature=+crt-static"
cargo build --release --target x86_64-pc-windows-msvc

# Binary location
.\target\x86_64-pc-windows-msvc\release\folsec-auditor.exe
```

> `cargo check` will run cleanly on Linux/macOS for CI purposes. ACL scanning is Windows-only; the binary on non-Windows produces an empty-findings report.

---

## Architecture

```
src/
├── main.rs              # CLI entry point (clap)
├── errors/mod.rs        # Typed error hierarchy — no panics in production
├── scanner/
│   ├── mod.rs           # Parallel traversal engine (walkdir + rayon)
│   ├── acl.rs           # Win32 DACL extraction (GetNamedSecurityInfoW)
│   ├── sid.rs           # SID → account name (LookupAccountSidW)
│   └── risk.rs          # Data model: RiskFinding, Severity, AuditSummary
├── simulator/mod.rs     # Ransomware ACL cycling simulator
├── reporter/mod.rs      # Self-contained HTML report generator
└── remediation/mod.rs   # Dry-run PowerShell .ps1 generator
```

**Parallelism:** `walkdir` streams directory entries lazily (no full-tree RAM load), `rayon::par_bridge()` distributes them across all CPU cores, and `dashmap` accumulates findings without a global lock. On a 16-core server, throughput is 8–12× faster than single-threaded scanning.

**Memory safety:** All Win32 security descriptor pointers are wrapped in a `SecurityDescriptorGuard` RAII type that calls `LocalFree` on drop — even when an error short-circuits traversal mid-ACE.

---

## Anomaly Simulator (`--simulate-anomaly`)

The simulator proves whether your SIEM has real-time NTFS audit visibility.

**What it does:**
1. Creates a hidden temporary directory (`.tmp_folsec_audit`) under the scan root.
2. Generates 50 dummy files inside it.
3. Cycles each file's ACL 50 times in rapid succession — **2,500 permission-change events in under 2 seconds** — mimicking the ACL manipulation pattern used by ransomware during encryption.
4. Deletes the directory.
5. Asks: *did your SIEM alert?*

A correctly configured environment (Windows Security Event Log → SIEM, with detection rules on Event IDs 4656 / 4663 / 4670) will fire during step 3. If it doesn't, you have a blind spot.

> ⚠ **Authorized use only.** Run this only on systems you own or have explicit written permission to test. The simulator creates and deletes only its own temp files — no production data is touched.

---

## The Dry-Run Remediation Script

Every finding in the report maps to a commented block in the generated `.ps1`:

```powershell
# Finding #1: [HIGH] \\fileserver01\HR\Payroll
# Risk: Trustee 'Everyone' has over-permissive access (Full Control)...

# LIVE COMMAND (review before use):
# icacls '\\fileserver01\HR\Payroll' /remove:g 'Everyone'

$ActionCount++
Write-Host "[DRY-RUN] #1: Would REMOVE ACE for 'Everyone' (Full Control) on path:" -ForegroundColor Yellow
Write-Host "  >> '\\fileserver01\HR\Payroll'" -ForegroundColor Yellow
```

The script never calls `Set-Acl` or `icacls` with side effects. It is designed to be handed to a change management team for approval before any live remediation is executed.

---

## Core Dependencies

| Crate | Purpose |
|-------|---------|
| `windows 0.58` | Win32 API bindings: `GetNamedSecurityInfoW`, `GetSecurityDescriptorDacl`, `LookupAccountSidW` |
| `walkdir` | Lazy, depth-first directory traversal with graceful error handling |
| `rayon` | Work-stealing thread pool for parallel ACL extraction |
| `clap` (derive) | Typed CLI argument parsing with auto-generated `--help` |
| `serde` + `serde_json` | Serializes findings into the report's embedded JSON data island |
| `dashmap` | Lock-minimizing concurrent HashMap for cross-thread finding accumulation |
| `thiserror` | Boilerplate-free typed error enum — every failure mode is named and handled |
| `indicatif` | Live progress spinner during long scans |
| `chrono` | Report timestamps |

---

## Why Not Just Use `icacls` / `Get-Acl`?

| | `icacls` / `Get-Acl` | folsec-auditor |
|---|---|---|
| Speed on 500k+ dirs | Minutes to hours (single-threaded) | Seconds to minutes (all cores) |
| Risk classification | None — raw output only | Automatic severity scoring |
| Orphaned SID detection | Manual cross-reference required | Built-in via `LookupAccountSidW` |
| Inheritance break detection | Requires custom scripting | Automatic via SD control flags |
| Report output | Terminal text / CSV | Interactive HTML with filters |
| Remediation script | Manual authoring | Auto-generated dry-run `.ps1` |
| SIEM gap detection | Not possible | Anomaly simulator built-in |

---

## Limitations (V1)

- **Windows only.** NTFS ACL scanning requires Win32 APIs.
- **Directories only.** Files inherit from their parent folder; scanning every file would multiply API calls with minimal additional signal.
- **No SACL / owner analysis.** DACL-only in V1.
- **Anomaly simulator uses `icacls` child processes.** V2 will use `SetNamedSecurityInfoW` directly for lower latency.
- **No Active Directory connectivity.** Orphaned SID detection is local — the tool cannot confirm whether a SID belongs to a disabled (vs. deleted) account without LDAP access.

---

## Contributing

Issues and pull requests are welcome. For significant changes, open an issue first to discuss the approach.

```bash
# Run checks (works on Linux/macOS for non-Windows modules)
cargo check
cargo clippy -- -D warnings
cargo test
```

---

## License

MIT — see [LICENSE](LICENSE).

---

*folsec-auditor surfaces what exists right now. [FolSec](https://folsec.com) tells you the moment anything changes.*
