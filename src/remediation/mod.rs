//! Safe PowerShell remediation script generator.
//!
//! This module produces a `.ps1` file that is:
//!   - 100% DRY-RUN: every action writes `Write-Host "Would ..."` instead
//!     of actually modifying any ACL.
//!   - Self-documenting: each block explains WHY it would make the change.
//!   - Safe to run: the script won't modify anything; it's a review artifact.
//!
//! The generated script is designed to be handed to an AD team lead or reviewed
//! in a change management process before any actual remediation is performed.

use std::{fmt::Write as FmtWrite, path::Path};

use crate::{
    errors::{AuditorError, Result},
    scanner::risk::{RiskFinding, RiskKind},
};

/// Generate and write the dry-run PowerShell remediation script.
///
/// `output_path` should be a `.ps1` file path. The function overwrites
/// any existing file at that path.
pub fn generate_remediation_script(
    findings: &[RiskFinding],
    scan_root: &str,
    output_path: &Path,
) -> Result<()> {
    let mut script = String::new();

    // ── Script Header ────────────────────────────────────────────────────────
    writeln!(script, "# ╔══════════════════════════════════════════════════════════════════╗").unwrap();
    writeln!(script, "# ║         FolSec NTFS Audit — DRY RUN Remediation Script          ║").unwrap();
    writeln!(script, "# ║                                                                  ║").unwrap();
    writeln!(script, "# ║  ⚠  THIS SCRIPT MAKES NO CHANGES. It prints what WOULD happen.  ║").unwrap();
    writeln!(script, "# ║     Review each action, get approval, then convert to real ACL   ║").unwrap();
    writeln!(script, "# ║     operations using Set-Acl or icacls.                          ║").unwrap();
    writeln!(script, "# ╚══════════════════════════════════════════════════════════════════╝").unwrap();
    writeln!(script, "#").unwrap();
    writeln!(script, "# Scan root:   {}", scan_root).unwrap();
    writeln!(script, "# Findings:    {}", findings.len()).unwrap();
    writeln!(
        script,
        "# Generated:  {}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
    ).unwrap();
    writeln!(script, "#").unwrap();
    writeln!(script, "# To convert to LIVE remediation, replace each Write-Host block with").unwrap();
    writeln!(script, "# the icacls or Set-Acl command shown in the comment above it.").unwrap();
    writeln!(script, "").unwrap();
    writeln!(script, "param(").unwrap();
    writeln!(script, "    # Set -WhatIf:$false and -Confirm:$false to enable LIVE mode (future V2 feature).").unwrap();
    writeln!(script, "    [switch]$WhatIf = $true").unwrap();
    writeln!(script, ")").unwrap();
    writeln!(script, "").unwrap();
    writeln!(script, "Write-Host \"\" ").unwrap();
    writeln!(script, "Write-Host \"FolSec Dry-Run Remediation Script\" -ForegroundColor Cyan").unwrap();
    writeln!(script, "Write-Host \"Scan Root: {}\" -ForegroundColor Gray", scan_root).unwrap();
    writeln!(script, "Write-Host \"Total actions: {}\" -ForegroundColor Gray", findings.len()).unwrap();
    writeln!(script, "Write-Host \"\" ").unwrap();
    writeln!(script, "$ErrorCount = 0").unwrap();
    writeln!(script, "$ActionCount = 0").unwrap();
    writeln!(script, "").unwrap();

    // ── Per-finding remediation blocks ───────────────────────────────────────
    for (i, finding) in findings.iter().enumerate() {
        let escaped_path = finding.path.replace('\'', "''");

        writeln!(script, "# ──────────────────────────────────────────────────────────────────").unwrap();
        writeln!(script, "# Finding #{}: [{:?}] {}", i + 1, finding.severity, finding.path).unwrap();
        writeln!(script, "# Risk: {}", &finding.description[..finding.description.len().min(200)]).unwrap();
        writeln!(script, "").unwrap();

        match &finding.risk {
            RiskKind::OverPermissiveAce { trustee, access_mask, access_mask_human } => {
                writeln!(script, "# LIVE COMMAND (review before use):").unwrap();
                writeln!(script, "# icacls '{}' /remove:g '{}'", escaped_path, trustee).unwrap();
                writeln!(script, "# Or with Set-Acl:").unwrap();
                writeln!(script, "# $acl = Get-Acl -Path '{}'", escaped_path).unwrap();
                writeln!(script, "# $ace = $acl.Access | Where-Object {{ $_.IdentityReference -eq '{}' }}", trustee).unwrap();
                writeln!(script, "# $acl.RemoveAccessRule($ace)").unwrap();
                writeln!(script, "# Set-Acl -Path '{}' -AclObject $acl", escaped_path).unwrap();
                writeln!(script, "").unwrap();
                writeln!(script, "$ActionCount++").unwrap();
                writeln!(
                    script,
                    "Write-Host \"[DRY-RUN] #{}: Would REMOVE ACE for '{}' (AccessMask: {} = 0x{:08X}) on path:\" -ForegroundColor Yellow",
                    i + 1, trustee, access_mask_human, access_mask
                ).unwrap();
                writeln!(
                    script,
                    "Write-Host \"  >> '{}'\" -ForegroundColor Yellow",
                    escaped_path
                ).unwrap();
            }

            RiskKind::InheritanceBreak { had_protected_copy } => {
                writeln!(script, "# LIVE COMMAND (review before use):").unwrap();
                writeln!(script, "# icacls '{}' /inheritance:e", escaped_path).unwrap();
                writeln!(script, "# Note: /inheritance:e re-enables inheritance without removing existing ACEs.").unwrap();
                writeln!(script, "# Use /inheritance:r to remove explicit ACEs after re-enabling (CAUTION).").unwrap();
                writeln!(script, "").unwrap();
                writeln!(script, "$ActionCount++").unwrap();
                writeln!(
                    script,
                    "Write-Host \"[DRY-RUN] #{}: Would RE-ENABLE inheritance on (had_protected_copy={}) :\" -ForegroundColor Magenta",
                    i + 1, had_protected_copy
                ).unwrap();
                writeln!(
                    script,
                    "Write-Host \"  >> '{}'\" -ForegroundColor Magenta",
                    escaped_path
                ).unwrap();
            }

            RiskKind::OrphanedSid { raw_sid } => {
                writeln!(script, "# LIVE COMMAND (review before use):").unwrap();
                writeln!(script, "# First verify SID is truly orphaned:").unwrap();
                writeln!(script, "# Get-ADObject -Filter {{objectSid -eq '{}'}} -ErrorAction SilentlyContinue", raw_sid).unwrap();
                writeln!(script, "# If the above returns nothing, then:").unwrap();
                writeln!(script, "# icacls '{}' /remove '{}'", escaped_path, raw_sid).unwrap();
                writeln!(script, "").unwrap();
                writeln!(script, "$ActionCount++").unwrap();
                writeln!(
                    script,
                    "Write-Host \"[DRY-RUN] #{}: Would REMOVE orphaned SID '{}' ACE from:\" -ForegroundColor DarkYellow",
                    i + 1, raw_sid
                ).unwrap();
                writeln!(
                    script,
                    "Write-Host \"  >> '{}'\" -ForegroundColor DarkYellow",
                    escaped_path
                ).unwrap();
            }

            RiskKind::NullDacl => {
                writeln!(script, "# LIVE COMMAND (review before use):").unwrap();
                writeln!(script, "# icacls '{}' /reset  # Resets to inherited permissions", escaped_path).unwrap();
                writeln!(script, "# Then explicitly grant access to appropriate groups.").unwrap();
                writeln!(script, "").unwrap();
                writeln!(script, "$ActionCount++").unwrap();
                writeln!(
                    script,
                    "Write-Host \"[DRY-RUN] #{}: CRITICAL — Would apply restrictive DACL to NULL-DACL path:\" -ForegroundColor Red",
                    i + 1
                ).unwrap();
                writeln!(
                    script,
                    "Write-Host \"  >> '{}'\" -ForegroundColor Red",
                    escaped_path
                ).unwrap();
            }

            RiskKind::AnomalySimulated { cycles_in_ms } => {
                writeln!(script, "# Anomaly simulation finding — no ACL remediation needed.").unwrap();
                writeln!(script, "# Action: Configure SIEM to alert on rapid ACL cycling.").unwrap();
                writeln!(script, "").unwrap();
                writeln!(
                    script,
                    "Write-Host \"[DRY-RUN] #{}: SIEM VISIBILITY GAP — {} ACL cycles went undetected in {}ms\" -ForegroundColor Red",
                    i + 1,
                    crate::scanner::risk::AuditSummary::default().critical_count, // placeholder
                    cycles_in_ms
                ).unwrap();
            }
        }

        writeln!(script, "").unwrap();
    }

    // ── Summary Footer ───────────────────────────────────────────────────────
    writeln!(script, "# ──────────────────────────────────────────────────────────────────").unwrap();
    writeln!(script, "Write-Host \"\" ").unwrap();
    writeln!(script, "Write-Host \"Dry-run complete. $ActionCount actions would be taken.\" -ForegroundColor Cyan").unwrap();
    writeln!(script, "Write-Host \"Errors during this script: $ErrorCount\" -ForegroundColor $(if ($ErrorCount -gt 0) {{ 'Red' }} else {{ 'Green' }})").unwrap();
    writeln!(script, "Write-Host \"\" ").unwrap();
    writeln!(script, "Write-Host \"Next step: Review each action above, obtain change approval,\" -ForegroundColor Gray").unwrap();
    writeln!(script, "Write-Host \"then execute with FolSec's guided remediation workflow.\" -ForegroundColor Gray").unwrap();
    writeln!(script, "Write-Host \"Contact: https://folsec.com/remediation\" -ForegroundColor Gray").unwrap();

    // ── Write to disk ────────────────────────────────────────────────────────
    std::fs::write(output_path, script).map_err(|e| AuditorError::Io {
        path: output_path.to_string_lossy().to_string(),
        source: e,
    })?;

    Ok(())
}
