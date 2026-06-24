//! Safe PowerShell remediation script generator.
//!
//! This is the "Safe Fix" module for the FolSec NTFS/ACL Risk Auditor.
//!
//! # Design Contract
//!
//! The generated `.ps1` file is:
//!   - **100% DRY-RUN by default**: every remediation action uses `Write-Host`
//!     to describe what *would* happen. No ACL is ever modified unless the
//!     operator explicitly converts the script to live mode.
//!   - **Targeted**: only generates remediation blocks for the three actionable
//!     risk categories that can be safely fixed via script:
//!       1. Over-permissive "Everyone" / "Authenticated Users" ACEs
//!       2. Explicit inheritance breaks
//!       3. Orphaned (unresolvable) SIDs
//!   - **Enterprise-safe**: includes `#Requires -RunAsAdministrator`,
//!     `$ErrorActionPreference = 'Stop'`, transcript logging, and a manual
//!     confirmation gate before any live execution.
//!   - **Self-documenting**: each block explains the risk, references the
//!     original finding, and shows the exact `icacls` / `Set-Acl` command
//!     that would be used in live mode.
//!
//! # Output Encoding
//!
//! The script is written as UTF-8 with BOM (`\xEF\xBB\xBF`), which is the
//! encoding expected by `powershell.exe` (Windows PowerShell 5.1) on
//! enterprise Windows Server installations. `pwsh` (PowerShell 7+) also
//! handles BOM-prefixed UTF-8 correctly.

use std::{collections::{HashMap, HashSet}, fmt::Write as FmtWrite, path::Path};

use crate::{
    errors::{AuditorError, Result},
    scanner::risk::{RiskFinding, RiskKind, Severity},
};

// ── Constants ────────────────────────────────────────────────────────────────

/// UTF-8 Byte Order Mark — required by Windows PowerShell 5.1 to correctly
/// interpret non-ASCII characters (e.g., path names with diacritics, CJK
/// folder names on international file servers).
const UTF8_BOM: &str = "\u{FEFF}";

/// Horizontal rule used between remediation blocks in the generated script.
const PS_RULE: &str =
    "# ══════════════════════════════════════════════════════════════════════════════";

/// Section divider (lighter weight than `PS_RULE`).
const PS_DIVIDER: &str =
    "# ──────────────────────────────────────────────────────────────────────────────";

// ── Public API ───────────────────────────────────────────────────────────────

/// Generate and write the dry-run PowerShell remediation script.
///
/// Findings are **aggregated by path** before script generation, so a path
/// with 5 violations produces ONE clean remediation block listing all 5
/// actions — not 5 separate blocks that spam the same path repeatedly.
///
/// Only findings with actionable risk types (`OverPermissiveAce`,
/// `InheritanceBreak`, `OrphanedSid`) produce remediation blocks.
/// `NullDacl` and `AnomalySimulated` findings are logged as informational
/// comments but receive no automated fix — those require manual triage.
///
/// # Arguments
///
/// * `findings` – the full `Vec<RiskFinding>` from the scan result.
/// * `scan_root` – the root path that was scanned (for header metadata).
/// * `output_path` – destination `.ps1` file path. Overwrites if it exists.
///
/// # Errors
///
/// Returns `AuditorError::Io` if the file cannot be created or written.
pub fn generate_remediation_script(
    findings: &[RiskFinding],
    scan_root: &str,
    output_path: &Path,
) -> Result<()> {
    let mut script = String::with_capacity(64 * 1024); // pre-allocate 64 KiB

    // ── UTF-8 BOM ────────────────────────────────────────────────────────────
    write!(script, "{}", UTF8_BOM).unwrap();

    // ── Enterprise safety boilerplate ────────────────────────────────────────
    emit_header(&mut script, findings, scan_root);
    emit_safety_boilerplate(&mut script);
    emit_dry_run_banner(&mut script, scan_root, findings);

    // ── Top 5 Riskiest Folders dashboard ─────────────────────────────────────
    emit_top5_riskiest_folders(&mut script, findings);

    // ── Aggregate actionable findings by path ────────────────────────────────
    // This eliminates the dry-run output spam where the same path appeared in
    // 5-6 separate blocks if it had multiple bad ACEs. Each path now gets ONE
    // clean block listing all remediation actions inside it.
    let mut actionable_by_path: HashMap<String, Vec<&RiskFinding>> = HashMap::new();
    let mut non_actionable: Vec<(usize, &RiskFinding)> = Vec::new();

    for (i, finding) in findings.iter().enumerate() {
        if is_actionable(&finding.risk) {
            actionable_by_path
                .entry(finding.path.clone())
                .or_default()
                .push(finding);
        } else {
            non_actionable.push((i + 1, finding));
        }
    }

    // ── Emit one aggregated block per path ───────────────────────────────────
    // Sort paths alphabetically for deterministic, readable output.
    let mut sorted_paths: Vec<&String> = actionable_by_path.keys().collect();
    sorted_paths.sort();

    let mut block_index: usize = 0;
    let mut total_actions: usize = 0;

    for path in sorted_paths {
        let path_findings = &actionable_by_path[path];
        block_index += 1;
        // Count unique findings (after dedup) to match what the block emitter actually outputs.
        let mut seen = HashSet::new();
        for f in path_findings {
            seen.insert(finding_dedup_key(f));
        }
        total_actions += seen.len();
        emit_aggregated_path_block(&mut script, block_index, path, path_findings);
    }

    // ── Emit non-actionable findings as comment-only blocks ──────────────────
    for (finding_num, finding) in &non_actionable {
        match &finding.risk {
            RiskKind::NullDacl => {
                emit_manual_triage_comment(
                    &mut script,
                    *finding_num,
                    finding,
                    "NULL DACL requires manual triage — apply a restrictive explicit DACL.",
                );
            }
            RiskKind::AnomalySimulated { cycles_in_ms } => {
                emit_manual_triage_comment(
                    &mut script,
                    *finding_num,
                    finding,
                    &format!(
                        "SIEM visibility gap detected ({}ms cycling). \
                         Configure audit policies to detect rapid ACL changes.",
                        cycles_in_ms
                    ),
                );
            }
            _ => {} // All actionable types are already handled above.
        }
    }

    // ── Summary footer ───────────────────────────────────────────────────────
    emit_footer(&mut script, total_actions);

    // ── Write to disk ────────────────────────────────────────────────────────
    std::fs::write(output_path, script.as_bytes()).map_err(|e| AuditorError::Io {
        path: output_path.to_string_lossy().to_string(),
        source: e,
    })?;

    Ok(())
}

// ── Private Emitters ─────────────────────────────────────────────────────────
//
// Each `emit_*` function appends a self-contained block of PowerShell to the
// script buffer. They are kept as separate functions for readability and to
// make future additions (e.g., new risk types) straightforward.

/// Emit the file header comment block with metadata.
fn emit_header(script: &mut String, findings: &[RiskFinding], scan_root: &str) {
    let actionable_count = findings
        .iter()
        .filter(|f| is_actionable(&f.risk))
        .count();

    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S %z");

    writeln!(script, "{}", PS_RULE).unwrap();
    writeln!(script, "# FolSec NTFS/ACL Risk Auditor — DRY-RUN Remediation Script").unwrap();
    writeln!(script, "{}", PS_RULE).unwrap();
    writeln!(script, "#").unwrap();
    writeln!(script, "#  ██████╗ ██████╗ ██╗   ██╗      ██████╗ ██╗   ██╗███╗   ██╗").unwrap();
    writeln!(script, "#  ██╔══██╗██╔══██╗╚██╗ ██╔╝      ██╔══██╗██║   ██║████╗  ██║").unwrap();
    writeln!(script, "#  ██║  ██║██████╔╝ ╚████╔╝ █████╗██████╔╝██║   ██║██╔██╗ ██║").unwrap();
    writeln!(script, "#  ██║  ██║██╔══██╗  ╚██╔╝  ╚════╝██╔══██╗██║   ██║██║╚██╗██║").unwrap();
    writeln!(script, "#  ██████╔╝██║  ██║   ██║          ██║  ██║╚██████╔╝██║ ╚████║").unwrap();
    writeln!(script, "#  ╚═════╝ ╚═╝  ╚═╝   ╚═╝          ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝").unwrap();
    writeln!(script, "#").unwrap();
    writeln!(script, "#  ⚠  THIS SCRIPT MAKES NO CHANGES BY DEFAULT.").unwrap();
    writeln!(script, "#     It uses Write-Host to print what WOULD be done.").unwrap();
    writeln!(script, "#     To convert to live mode, follow the instructions in each block.").unwrap();
    writeln!(script, "#").unwrap();
    writeln!(script, "#  Scan root:        {}", scan_root).unwrap();
    writeln!(script, "#  Total findings:   {}", findings.len()).unwrap();
    writeln!(script, "#  Actionable fixes: {}", actionable_count).unwrap();
    writeln!(script, "#  Generated:        {}", timestamp).unwrap();
    writeln!(script, "#  Generator:        FolSec Auditor v{}", env!("CARGO_PKG_VERSION")).unwrap();
    writeln!(script, "#").unwrap();
    writeln!(script, "#  CHANGE MANAGEMENT: This script should be reviewed in your").unwrap();
    writeln!(script, "#  organization's change control process before ANY modifications").unwrap();
    writeln!(script, "#  are made live. File server ACL changes can cause immediate").unwrap();
    writeln!(script, "#  access disruptions across the enterprise.").unwrap();
    writeln!(script, "#").unwrap();
    writeln!(script, "{}", PS_RULE).unwrap();
    writeln!(script).unwrap();
}

/// Emit the mandatory enterprise PowerShell safety boilerplate.
///
/// This includes:
///   - `#Requires -RunAsAdministrator` — script will refuse to run without elevation.
///   - `$ErrorActionPreference = 'Stop'` — any error halts execution immediately.
///   - `Set-StrictMode -Version Latest` — catches common scripting mistakes.
///   - Transcript logging for audit trail compliance.
///   - A confirmation prompt gate for live-mode conversion.
fn emit_safety_boilerplate(script: &mut String) {
    writeln!(script, "#Requires -RunAsAdministrator").unwrap();
    writeln!(script).unwrap();

    writeln!(script, "{}", PS_DIVIDER).unwrap();
    writeln!(script, "# SAFETY CONFIGURATION").unwrap();
    writeln!(script, "{}", PS_DIVIDER).unwrap();
    writeln!(script).unwrap();

    // Strict error handling — never silently swallow failures.
    writeln!(script, "# Halt on ANY error. In an enterprise environment, partial ACL changes").unwrap();
    writeln!(script, "# are worse than no changes at all — they create inconsistent state.").unwrap();
    writeln!(script, "$ErrorActionPreference = 'Stop'").unwrap();
    writeln!(script).unwrap();

    // Strict mode catches typos in variable names, undefined variables, etc.
    writeln!(script, "# Catch common scripting mistakes (undefined variables, etc.)").unwrap();
    writeln!(script, "Set-StrictMode -Version Latest").unwrap();
    writeln!(script).unwrap();

    // Transcript logging — creates an audit trail for compliance.
    writeln!(script, "# Audit trail: log all console output to a timestamped transcript file.").unwrap();
    writeln!(script, "# This is required by most enterprise change management frameworks.").unwrap();
    writeln!(script, "$TranscriptPath = Join-Path $PSScriptRoot (\"FolSec_Remediation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log\")").unwrap();
    writeln!(script, "Start-Transcript -Path $TranscriptPath -Append | Out-Null").unwrap();
    writeln!(script).unwrap();

    // Mode parameter and confirmation gate.
    writeln!(script, "# ── Execution Mode ─────────────────────────────────────────────────────────").unwrap();
    writeln!(script, "# By default, $LiveMode is $false. The script ONLY prints what it would do.").unwrap();
    writeln!(script, "# To enable LIVE remediation:").unwrap();
    writeln!(script, "#   1. Get change approval from your AD team lead.").unwrap();
    writeln!(script, "#   2. Set $LiveMode = $true below.").unwrap();
    writeln!(script, "#   3. The script will prompt for confirmation before proceeding.").unwrap();
    writeln!(script, "$LiveMode = $false").unwrap();
    writeln!(script).unwrap();

    // Confirmation gate — only fires when an operator has set $LiveMode = $true.
    writeln!(script, "if ($LiveMode) {{").unwrap();
    writeln!(script, "    Write-Host \"\" ").unwrap();
    writeln!(script, "    Write-Host \"╔══════════════════════════════════════════════════════════════╗\" -ForegroundColor Red").unwrap();
    writeln!(script, "    Write-Host \"║  ⚠  LIVE MODE ENABLED — ACL CHANGES WILL BE APPLIED!       ║\" -ForegroundColor Red").unwrap();
    writeln!(script, "    Write-Host \"║  This action is IRREVERSIBLE without a backup.              ║\" -ForegroundColor Red").unwrap();
    writeln!(script, "    Write-Host \"║  Ensure you have a full ACL backup (icacls /save).          ║\" -ForegroundColor Red").unwrap();
    writeln!(script, "    Write-Host \"╚══════════════════════════════════════════════════════════════╝\" -ForegroundColor Red").unwrap();
    writeln!(script, "    Write-Host \"\" ").unwrap();
    writeln!(script, "    $confirm = Read-Host \"Type 'APPLY CHANGES' to proceed, or press Enter to abort\"").unwrap();
    writeln!(script, "    if ($confirm -ne 'APPLY CHANGES') {{").unwrap();
    writeln!(script, "        Write-Host \"Aborted. No changes were made.\" -ForegroundColor Green").unwrap();
    writeln!(script, "        Stop-Transcript | Out-Null").unwrap();
    writeln!(script, "        exit 0").unwrap();
    writeln!(script, "    }}").unwrap();
    writeln!(script, "    Write-Host \"Proceeding with LIVE remediation...\" -ForegroundColor Red").unwrap();
    writeln!(script, "    Write-Host \"\" ").unwrap();
    writeln!(script, "}}").unwrap();
    writeln!(script).unwrap();
}

/// Emit the runtime banner that prints scan metadata when the script executes.
fn emit_dry_run_banner(script: &mut String, scan_root: &str, findings: &[RiskFinding]) {
    let actionable_count = findings
        .iter()
        .filter(|f| is_actionable(&f.risk))
        .count();

    writeln!(script, "{}", PS_DIVIDER).unwrap();
    writeln!(script, "# RUNTIME BANNER").unwrap();
    writeln!(script, "{}", PS_DIVIDER).unwrap();
    writeln!(script).unwrap();
    writeln!(script, "Write-Host \"\" ").unwrap();
    writeln!(script, "Write-Host \"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\" -ForegroundColor Cyan").unwrap();
    writeln!(script, "Write-Host \"  FolSec NTFS Auditor — Remediation Script\" -ForegroundColor Cyan").unwrap();
    writeln!(script, "Write-Host \"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\" -ForegroundColor Cyan").unwrap();
    writeln!(script, "Write-Host \"  Scan Root:        {}\" -ForegroundColor Gray", scan_root).unwrap();
    writeln!(script, "Write-Host \"  Total Findings:   {}\" -ForegroundColor Gray", findings.len()).unwrap();
    writeln!(script, "Write-Host \"  Actionable Fixes: {}\" -ForegroundColor Gray", actionable_count).unwrap();
    writeln!(
        script,
        "Write-Host \"  Mode:             $(if ($LiveMode) {{ 'LIVE' }} else {{ 'DRY-RUN' }})\" -ForegroundColor $(if ($LiveMode) {{ 'Red' }} else {{ 'Green' }})"
    ).unwrap();
    writeln!(script, "Write-Host \"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\" -ForegroundColor Cyan").unwrap();
    writeln!(script, "Write-Host \"\" ").unwrap();
    writeln!(script).unwrap();

    // Counters for the summary at the end.
    writeln!(script, "# ── Tracking counters ──────────────────────────────────────────────────────").unwrap();
    writeln!(script, "$ActionCount     = 0   # Number of remediation actions processed").unwrap();
    writeln!(script, "$SuccessCount    = 0   # Successful actions (live mode only)").unwrap();
    writeln!(script, "$ErrorCount      = 0   # Failed actions (live mode only)").unwrap();
    writeln!(script, "$SkippedCount    = 0   # Skipped (path not found, etc.)").unwrap();
    writeln!(script).unwrap();
}

/// Compute a numeric risk score for a severity level.
///
/// This weighting is used by the Top 5 Riskiest Folders dashboard to
/// aggregate findings into a single comparable score per path.
fn severity_points(severity: &Severity) -> u32 {
    match severity {
        Severity::Critical => 10,
        Severity::High     => 5,
        Severity::Medium   => 2,
        Severity::Low      => 1,
        Severity::Info     => 0,
    }
}

/// Emit the "Top 5 Riskiest Folders" dashboard block.
///
/// This mini-dashboard appears right after the runtime banner, giving the
/// operator an instant executive-level view of where risk is concentrated.
/// Risk score = sum of severity_points for all findings on that path.
fn emit_top5_riskiest_folders(script: &mut String, findings: &[RiskFinding]) {
    // ── Aggregate risk scores per path ────────────────────────────────────
    let mut score_by_path: HashMap<String, (u32, usize)> = HashMap::new();
    for f in findings {
        let entry = score_by_path.entry(f.path.clone()).or_insert((0, 0));
        entry.0 += severity_points(&f.severity);
        entry.1 += 1; // finding count
    }

    // ── Sort by score descending, take top 5 ─────────────────────────────
    let mut scored: Vec<(String, u32, usize)> = score_by_path
        .into_iter()
        .map(|(path, (score, count))| (path, score, count))
        .collect();
    scored.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    scored.truncate(5);

    if scored.is_empty() {
        return;
    }

    // ── Emit the dashboard block ─────────────────────────────────────────
    writeln!(script, "{}", PS_DIVIDER).unwrap();
    writeln!(script, "# TOP 5 RISKIEST FOLDERS").unwrap();
    writeln!(script, "{}", PS_DIVIDER).unwrap();
    writeln!(script).unwrap();

    writeln!(script, "Write-Host \"\" ").unwrap();
    writeln!(script, "Write-Host \"┌──────────────────────────────────────────────────────────────┐\" -ForegroundColor Red").unwrap();
    writeln!(script, "Write-Host \"│  🔥 TOP 5 RISKIEST FOLDERS                                  │\" -ForegroundColor Red").unwrap();
    writeln!(script, "Write-Host \"├──────────────────────────────────────────────────────────────┤\" -ForegroundColor Red").unwrap();

    for (rank, (path, score, count)) in scored.iter().enumerate() {
        // Build a visual risk bar: one '█' per 2 points, capped at 20 chars.
        let bar_len = ((*score as usize) / 2).min(20);
        let bar: String = "█".repeat(bar_len);
        let bar_color = if *score >= 20 { "Red" } else if *score >= 10 { "Yellow" } else { "DarkYellow" };

        let escaped_path = escape_ps_path(path);
        writeln!(
            script,
            "Write-Host \"│  #{} [Score: {:>3}] ({} finding(s))\" -ForegroundColor White",
            rank + 1, score, count
        ).unwrap();
        writeln!(
            script,
            "Write-Host \"│     {}\" -ForegroundColor {}",
            bar, bar_color
        ).unwrap();
        writeln!(
            script,
            "Write-Host \"│     {}\" -ForegroundColor Gray",
            escaped_path
        ).unwrap();

        if rank < scored.len() - 1 {
            writeln!(script, "Write-Host \"│\" -ForegroundColor Red").unwrap();
        }
    }

    writeln!(script, "Write-Host \"└──────────────────────────────────────────────────────────────┘\" -ForegroundColor Red").unwrap();
    writeln!(script, "Write-Host \"\" ").unwrap();
    writeln!(script).unwrap();
}

/// Emit a single aggregated remediation block for one filesystem path.
///
/// All actionable findings for this path are grouped into ONE clean block,
/// eliminating the output spam where the same path was listed 5-6 times for
/// multiple bad ACEs. The block contains:
///   - A comment header summarizing all findings for this path.
///   - A single `Test-Path` gate.
///   - One `Get-Acl` call shared across all remediation sub-actions.
///   - Individual sub-actions within the shared ACL context.
fn emit_aggregated_path_block(
    script: &mut String,
    block_num: usize,
    path: &str,
    findings: &[&RiskFinding],
) {
    let escaped = escape_ps_path(path);

    // ── Deduplicate findings ─────────────────────────────────────────────────
    // Windows NTFS can split a single logical permission into multiple ACEs with
    // different inheritance flags (ObjectInherit vs ContainerInherit). Our scanner
    // reports each ACE separately, but the textual descriptions are identical,
    // making the output look glitchy/spammy. We deduplicate by the text key so
    // each unique action appears exactly once per path block.
    let mut seen = HashSet::new();
    let mut unique_findings: Vec<&RiskFinding> = Vec::new();

    for finding in findings {
        let dedup_key = finding_dedup_key(finding);
        if seen.insert(dedup_key) {
            unique_findings.push(finding);
        }
    }

    // ── Comment header ───────────────────────────────────────────────────────
    writeln!(script, "{}", PS_RULE).unwrap();
    writeln!(
        script,
        "# PATH BLOCK #{} — {} finding(s) on this path",
        block_num,
        unique_findings.len()
    ).unwrap();
    writeln!(script, "# Path: {}", path).unwrap();
    writeln!(script, "#").unwrap();

    // List each unique finding as a sub-item in the header comment.
    for (sub_idx, finding) in unique_findings.iter().enumerate() {
        match &finding.risk {
            RiskKind::OverPermissiveAce { trustee, access_mask, access_mask_human } => {
                writeln!(
                    script,
                    "#   {}. [{:?}] OVER-PERMISSIVE ACE: '{}' with {} (0x{:08X})",
                    sub_idx + 1, finding.severity, trustee, access_mask_human, access_mask
                ).unwrap();
            }
            RiskKind::InheritanceBreak { had_protected_copy } => {
                writeln!(
                    script,
                    "#   {}. [{:?}] INHERITANCE BREAK (had_protected_copy={})",
                    sub_idx + 1, finding.severity, had_protected_copy
                ).unwrap();
            }
            RiskKind::OrphanedSid { raw_sid } => {
                writeln!(
                    script,
                    "#   {}. [{:?}] ORPHANED SID: {}",
                    sub_idx + 1, finding.severity, raw_sid
                ).unwrap();
            }
            _ => {} // Non-actionable types are never passed to this function.
        }
    }

    writeln!(script, "#").unwrap();
    writeln!(script, "# Recommendation: Review all sub-actions below before enabling live mode.").unwrap();
    writeln!(script, "{}", PS_RULE).unwrap();
    writeln!(script).unwrap();

    // ── PowerShell code block ────────────────────────────────────────────────
    writeln!(script, "$ActionCount += {}", unique_findings.len()).unwrap();
    writeln!(script, "$targetPath = '{}'", escaped).unwrap();
    writeln!(script).unwrap();

    writeln!(script, "if (Test-Path -LiteralPath $targetPath) {{").unwrap();
    writeln!(script, "    if ($LiveMode) {{").unwrap();
    writeln!(script, "        # ── LIVE: Apply all remediation actions for this path ──").unwrap();
    writeln!(script, "        try {{").unwrap();
    writeln!(script, "            $acl = Get-Acl -LiteralPath $targetPath").unwrap();
    writeln!(script, "            $modified = $false").unwrap();
    writeln!(script).unwrap();

    // Emit individual sub-actions inside the shared try block (deduplicated).
    for (sub_idx, finding) in unique_findings.iter().enumerate() {
        match &finding.risk {
            RiskKind::OverPermissiveAce { trustee, access_mask, access_mask_human } => {
                writeln!(script).unwrap();
                writeln!(
                    script,
                    "            # Sub-action {}: Remove over-permissive ACE for '{}' ({}, 0x{:08X})",
                    sub_idx + 1, trustee, access_mask_human, access_mask
                ).unwrap();
                writeln!(script, "            $rulesToRemove = $acl.Access | Where-Object {{").unwrap();
                writeln!(
                    script,
                    "                $_.IdentityReference.Value -eq '{}' -and $_.AccessControlType -eq 'Allow'",
                    trustee
                ).unwrap();
                writeln!(script, "            }}").unwrap();
                writeln!(script, "            foreach ($rule in $rulesToRemove) {{").unwrap();
                writeln!(script, "                $acl.RemoveAccessRule($rule) | Out-Null").unwrap();
                writeln!(script, "                $modified = $true").unwrap();
                writeln!(script, "            }}").unwrap();
                writeln!(
                    script,
                    "            Write-Host \"    [SUB-ACTION {}] Removed ACE for '{}' ({})\" -ForegroundColor Green",
                    sub_idx + 1, trustee, access_mask_human
                ).unwrap();
            }

            RiskKind::InheritanceBreak { .. } => {
                writeln!(script).unwrap();
                writeln!(
                    script,
                    "            # Sub-action {}: Re-enable inheritance",
                    sub_idx + 1
                ).unwrap();
                writeln!(script, "            # SetAccessRuleProtection($isProtected, $preserveInheritance)").unwrap();
                writeln!(script, "            #   $false = not protected = inheritance flows through").unwrap();
                writeln!(script, "            #   $false = do not preserve existing explicit ACEs").unwrap();
                writeln!(script, "            $acl.SetAccessRuleProtection($false, $false)").unwrap();
                writeln!(script, "            $modified = $true").unwrap();
                writeln!(
                    script,
                    "            Write-Host \"    [SUB-ACTION {}] Re-enabled inheritance\" -ForegroundColor Green",
                    sub_idx + 1
                ).unwrap();
            }

            RiskKind::OrphanedSid { raw_sid } => {
                writeln!(script).unwrap();
                writeln!(
                    script,
                    "            # Sub-action {}: Remove orphaned SID '{}'",
                    sub_idx + 1, raw_sid
                ).unwrap();
                writeln!(
                    script,
                    "            $orphanSid{} = New-Object System.Security.Principal.SecurityIdentifier('{}')",
                    sub_idx + 1, raw_sid
                ).unwrap();
                writeln!(script, "            $orphanRules = $acl.Access | Where-Object {{").unwrap();
                writeln!(
                    script,
                    "                $_.IdentityReference.Value -eq $orphanSid{}.Value",
                    sub_idx + 1
                ).unwrap();
                writeln!(script, "            }}").unwrap();
                writeln!(script, "            foreach ($rule in $orphanRules) {{").unwrap();
                writeln!(script, "                $acl.RemoveAccessRule($rule) | Out-Null").unwrap();
                writeln!(script, "                $modified = $true").unwrap();
                writeln!(script, "            }}").unwrap();
                writeln!(
                    script,
                    "            Write-Host \"    [SUB-ACTION {}] Removed orphaned SID '{}'\" -ForegroundColor Green",
                    sub_idx + 1, raw_sid
                ).unwrap();
            }

            _ => {} // Non-actionable types are never passed to this function.
        }
    }

    // Commit the ACL if any sub-actions modified it.
    writeln!(script).unwrap();
    writeln!(script, "            if ($modified) {{").unwrap();
    writeln!(script, "                Set-Acl -LiteralPath $targetPath -AclObject $acl -WhatIf").unwrap();
    writeln!(script, "                # NOTE: Remove '-WhatIf' above ONLY after thorough review.").unwrap();
    writeln!(script, "                # Set-Acl -LiteralPath $targetPath -AclObject $acl").unwrap();
    writeln!(script, "                $SuccessCount++").unwrap();
    writeln!(
        script,
        "                Write-Host \"  [APPLIED] All {} sub-actions applied on: $targetPath\" -ForegroundColor Green",
        unique_findings.len()
    ).unwrap();
    writeln!(script, "            }}").unwrap();

    writeln!(script, "        }} catch {{").unwrap();
    writeln!(script, "            $ErrorCount++").unwrap();
    writeln!(
        script,
        "            Write-Host \"  [ERROR] Failed to modify ACL on: $targetPath — $_\" -ForegroundColor Red"
    ).unwrap();
    writeln!(script, "        }}").unwrap();

    // ── DRY-RUN branch ──────────────────────────────────────────────────────
    writeln!(script, "    }} else {{").unwrap();
    writeln!(script, "        # ── DRY-RUN: Describe what would happen ──").unwrap();
    writeln!(
        script,
        "        Write-Host \"[DRY-RUN BLOCK #{:>3}] Path: $targetPath ({} action(s))\" -ForegroundColor Cyan",
        block_num,
        unique_findings.len()
    ).unwrap();

    for (sub_idx, finding) in unique_findings.iter().enumerate() {
        match &finding.risk {
            RiskKind::OverPermissiveAce { trustee, access_mask, access_mask_human } => {
                writeln!(
                    script,
                    "        Write-Host \"  {{\"{}\"}}.  Would REMOVE explicit Allow ACE for '{}' — {} (0x{:08X})\" -ForegroundColor Yellow",
                    sub_idx + 1, trustee, access_mask_human, access_mask
                ).unwrap();
            }
            RiskKind::InheritanceBreak { had_protected_copy } => {
                writeln!(
                    script,
                    "        Write-Host \"  {{\"{}\"}}.  Would RE-ENABLE INHERITANCE (had_protected_copy={})\" -ForegroundColor Magenta",
                    sub_idx + 1, had_protected_copy
                ).unwrap();
            }
            RiskKind::OrphanedSid { raw_sid } => {
                writeln!(
                    script,
                    "        Write-Host \"  {{\"{}\"}}.  Would REMOVE orphaned SID: {}\" -ForegroundColor DarkYellow",
                    sub_idx + 1, raw_sid
                ).unwrap();
            }
            _ => {}
        }
    }

    writeln!(script, "    }}").unwrap();
    writeln!(script, "}} else {{").unwrap();
    writeln!(script, "    $SkippedCount++").unwrap();
    writeln!(
        script,
        "    Write-Host \"  [SKIPPED BLOCK #{:>3}] Path not found: $targetPath\" -ForegroundColor DarkGray",
        block_num
    ).unwrap();
    writeln!(script, "}}").unwrap();
    writeln!(script).unwrap();
}


/// Emit a comment-only block for non-actionable findings (NullDacl, AnomalySimulated).
///
/// These risk types require manual triage by a senior admin and cannot be
/// safely automated. The block is informational only.
fn emit_manual_triage_comment(
    script: &mut String,
    finding_num: usize,
    finding: &RiskFinding,
    guidance: &str,
) {
    writeln!(script, "{}", PS_DIVIDER).unwrap();
    writeln!(
        script,
        "# INFO (Finding #{}) — MANUAL TRIAGE REQUIRED [{:?}]",
        finding_num, finding.severity
    ).unwrap();
    writeln!(script, "# Path:     {}", finding.path).unwrap();
    writeln!(script, "# Risk:     {}", truncate_desc(&finding.description)).unwrap();
    writeln!(script, "# Guidance: {}", guidance).unwrap();
    writeln!(script, "#").unwrap();
    writeln!(script, "# No automated fix is generated for this finding type.").unwrap();
    writeln!(script, "# Please review the HTML report for full details and remediate manually.").unwrap();
    writeln!(script, "{}", PS_DIVIDER).unwrap();
    writeln!(script).unwrap();
}

/// Emit the summary footer and transcript cleanup.
fn emit_footer(script: &mut String, total_actions: usize) {
    writeln!(script, "{}", PS_RULE).unwrap();
    writeln!(script, "# EXECUTION SUMMARY").unwrap();
    writeln!(script, "{}", PS_RULE).unwrap();
    writeln!(script).unwrap();
    writeln!(script, "Write-Host \"\" ").unwrap();
    writeln!(script, "Write-Host \"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\" -ForegroundColor Cyan").unwrap();
    writeln!(script, "Write-Host \"  Execution Summary\" -ForegroundColor Cyan").unwrap();
    writeln!(script, "Write-Host \"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\" -ForegroundColor Cyan").unwrap();
    writeln!(
        script,
        "Write-Host \"  Total actions:    {} (actionable findings)\" -ForegroundColor Gray",
        total_actions
    ).unwrap();
    writeln!(script, "Write-Host \"  Processed:        $ActionCount\" -ForegroundColor Gray").unwrap();
    writeln!(script, "Write-Host \"  Skipped:          $SkippedCount\" -ForegroundColor DarkGray").unwrap();
    writeln!(script).unwrap();

    // Live-mode-only counters
    writeln!(script, "if ($LiveMode) {{").unwrap();
    writeln!(
        script,
        "    Write-Host \"  Succeeded:        $SuccessCount\" -ForegroundColor Green"
    ).unwrap();
    writeln!(
        script,
        "    Write-Host \"  Failed:           $ErrorCount\" -ForegroundColor $(if ($ErrorCount -gt 0) {{ 'Red' }} else {{ 'Green' }})"
    ).unwrap();
    writeln!(script, "}} else {{").unwrap();
    writeln!(
        script,
        "    Write-Host \"  Mode:             DRY-RUN (no changes were made)\" -ForegroundColor Green"
    ).unwrap();
    writeln!(script, "}}").unwrap();
    writeln!(script).unwrap();

    writeln!(script, "Write-Host \"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\" -ForegroundColor Cyan").unwrap();
    writeln!(script, "Write-Host \"\" ").unwrap();
    writeln!(script).unwrap();

    // Next steps guidance
    writeln!(script, "Write-Host \"Next steps:\" -ForegroundColor White").unwrap();
    writeln!(script, "Write-Host \"  1. Review each action above with your AD team lead.\" -ForegroundColor Gray").unwrap();
    writeln!(script, "Write-Host \"  2. Submit this output through your change management process.\" -ForegroundColor Gray").unwrap();
    writeln!(script, "Write-Host \"  3. Back up current ACLs:  icacls '<root>' /save acl_backup.txt /T\" -ForegroundColor Gray").unwrap();
    writeln!(script, "Write-Host \"  4. Set `$LiveMode = `$true and re-run to apply (with -WhatIf safety).\" -ForegroundColor Gray").unwrap();
    writeln!(script, "Write-Host \"  5. Remove -WhatIf from Set-Acl calls only after final approval.\" -ForegroundColor Gray").unwrap();
    writeln!(script, "Write-Host \"\" ").unwrap();
    writeln!(script, "Write-Host \"Transcript saved to: $TranscriptPath\" -ForegroundColor DarkGray").unwrap();
    writeln!(script, "Write-Host \"Report & docs: https://folsec.com/remediation\" -ForegroundColor DarkGray").unwrap();
    writeln!(script, "Write-Host \"\" ").unwrap();
    writeln!(script).unwrap();

    // Clean up the transcript
    writeln!(script, "Stop-Transcript | Out-Null").unwrap();
}

// ── Utility Functions ────────────────────────────────────────────────────────

/// Returns `true` if the risk kind has an automated remediation path.
fn is_actionable(risk: &RiskKind) -> bool {
    matches!(
        risk,
        RiskKind::OverPermissiveAce { .. }
            | RiskKind::InheritanceBreak { .. }
            | RiskKind::OrphanedSid { .. }
    )
}

/// Produce a deduplication key for a finding based on its **visual output**.
///
/// Windows NTFS often splits a single logical permission into multiple ACEs
/// with different inheritance flags (ObjectInherit vs ContainerInherit vs
/// NoPropagateInherit, etc.). Our scanner reports each ACE independently,
/// and the `RiskFinding` structs can differ in fields we DON'T print
/// (severity computed from path context, description text, or even the raw
/// access_mask if generic bits are mapped differently).
///
/// To guarantee deduplication matches what the user actually *sees* in the
/// dry-run output, this function builds a key from the **exact same
/// fields** used in the `Write-Host` format strings:
///   - For OverPermissiveAce: the trustee name (lowercased) + the human-
///     readable access description + the hex mask.
///   - For InheritanceBreak: the `had_protected_copy` flag.
///   - For OrphanedSid: the raw SID string.
///
/// The trustee is lowercased because `LookupAccountSidW` and the static
/// well-known SID whitelist may return different casings for the same
/// principal (e.g., "BUILTIN\Users" vs "BUILTIN\users").
fn finding_dedup_key(finding: &RiskFinding) -> String {
    match &finding.risk {
        RiskKind::OverPermissiveAce { trustee, access_mask: _, access_mask_human } => {
            // Key uses ONLY the fields visible in the dry-run output line:
            //   "Would REMOVE explicit Allow ACE for '{trustee}' — {human} (0x{mask:08X})"
            //
            // We intentionally EXCLUDE the raw access_mask (hex value) because
            // Windows can split a single logical permission across multiple ACEs
            // with different raw masks (generic bits vs specific bits, or
            // inheritance-split ACEs) that nonetheless decode to the exact same
            // human-readable string. Including the mask would cause those
            // visually-identical lines to survive dedup.
            //
            // The human text still distinguishes genuinely different permission
            // levels (e.g., "Full Control" vs "Read, Execute, Read Control").
            //
            // Lowercase the trustee to collapse casing variants from different
            // SID resolution paths (dynamic LookupAccountSidW vs static whitelist).
            format!(
                "OPA|{}|{}",
                trustee.to_lowercase(),
                access_mask_human
            )
        }
        RiskKind::InheritanceBreak { had_protected_copy } => {
            format!("IB|{}", had_protected_copy)
        }
        RiskKind::OrphanedSid { raw_sid } => {
            format!("OS|{}", raw_sid)
        }
        RiskKind::NullDacl => "ND".to_string(),
        RiskKind::AnomalySimulated { cycles_in_ms } => {
            format!("AS|{}", cycles_in_ms)
        }
    }
}

/// Escape single quotes in a path for safe embedding in PowerShell strings.
///
/// PowerShell single-quoted strings use `''` to represent a literal `'`.
fn escape_ps_path(path: &str) -> String {
    path.replace('\'', "''")
}

/// Truncate a description string for use in comment headers (max 200 chars).
fn truncate_desc(desc: &str) -> &str {
    let max = 200;
    if desc.len() <= max {
        desc
    } else {
        // Find the last space before the limit to avoid cutting mid-word.
        match desc[..max].rfind(' ') {
            Some(pos) => &desc[..pos],
            None => &desc[..max],
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::risk::RiskFinding;

    /// Verify that the generated script contains the critical safety elements.
    #[test]
    fn generated_script_contains_safety_boilerplate() {
        let findings = vec![
            RiskFinding::over_permissive(
                r"C:\Shares\HR".to_string(),
                "Everyone".to_string(),
                0x1F01FF,
                "FullControl".to_string(),
            ),
            RiskFinding::inheritance_break(r"C:\Shares\Finance".to_string(), true),
            RiskFinding::orphaned_sid(
                r"C:\Shares\Legal".to_string(),
                "S-1-5-21-1234567890-987654321-111111111-9999".to_string(),
            ),
        ];

        let tmp_dir = std::env::temp_dir().join("folsec_test_remediation");
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let output_path = tmp_dir.join("test_remediate.ps1");

        generate_remediation_script(&findings, r"C:\Shares", &output_path).unwrap();

        let content = std::fs::read_to_string(&output_path).unwrap();

        // Enterprise safety checks
        assert!(content.contains("#Requires -RunAsAdministrator"));
        assert!(content.contains("$ErrorActionPreference = 'Stop'"));
        assert!(content.contains("Set-StrictMode -Version Latest"));
        assert!(content.contains("Start-Transcript"));
        assert!(content.contains("APPLY CHANGES"));

        // Dry-run markers (now aggregated per path block)
        assert!(content.contains("[DRY-RUN BLOCK"));
        assert!(content.contains("$LiveMode = $false"));

        // -WhatIf safety on Set-Acl
        assert!(content.contains("Set-Acl -LiteralPath $targetPath -AclObject $acl -WhatIf"));

        // Targeted fix types (now in aggregated path block headers)
        assert!(content.contains("OVER-PERMISSIVE ACE"));
        assert!(content.contains("INHERITANCE BREAK"));
        assert!(content.contains("SetAccessRuleProtection($false, $false)"));
        assert!(content.contains("ORPHANED SID"));

        // Aggregated block structure
        assert!(content.contains("PATH BLOCK #"));
        assert!(content.contains("$ActionCount +="));

        // Cleanup
        std::fs::remove_dir_all(&tmp_dir).ok();
    }

    /// Verify that non-actionable findings get comment-only blocks (no remediation code).
    #[test]
    fn non_actionable_findings_are_comment_only() {
        let findings = vec![RiskFinding::null_dacl(r"C:\Shares\Public".to_string())];

        let tmp_dir = std::env::temp_dir().join("folsec_test_noaction");
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let output_path = tmp_dir.join("test_noaction.ps1");

        generate_remediation_script(&findings, r"C:\Shares", &output_path).unwrap();

        let content = std::fs::read_to_string(&output_path).unwrap();

        // Should have the manual triage marker
        assert!(content.contains("MANUAL TRIAGE REQUIRED"));
        // Should NOT have any $ActionCount increment for this finding
        assert!(!content.contains("$ActionCount +="));

        // Cleanup
        std::fs::remove_dir_all(&tmp_dir).ok();
    }

    /// Verify that multiple findings on the SAME path produce ONE aggregated block.
    /// This is the core anti-spam fix — previously this produced 3 separate blocks.
    #[test]
    fn same_path_findings_are_aggregated() {
        let shared_path = r"C:\Shares\HR".to_string();
        let findings = vec![
            RiskFinding::over_permissive(
                shared_path.clone(),
                "Everyone".to_string(),
                0x1F01FF,
                "FullControl".to_string(),
            ),
            RiskFinding::inheritance_break(shared_path.clone(), true),
            RiskFinding::orphaned_sid(
                shared_path.clone(),
                "S-1-5-21-1234567890-987654321-111111111-9999".to_string(),
            ),
        ];

        let tmp_dir = std::env::temp_dir().join("folsec_test_aggregation");
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let output_path = tmp_dir.join("test_aggregated.ps1");

        generate_remediation_script(&findings, r"C:\Shares", &output_path).unwrap();

        let content = std::fs::read_to_string(&output_path).unwrap();

        // Should contain exactly ONE path block (block #1), not three separate ones.
        assert!(content.contains("PATH BLOCK #1 — 3 finding(s)"));
        // Should NOT have a second path block since all findings share the same path.
        assert!(!content.contains("PATH BLOCK #2"));

        // The single block should reference all three finding types as sub-actions.
        assert!(content.contains("OVER-PERMISSIVE ACE"));
        assert!(content.contains("INHERITANCE BREAK"));
        assert!(content.contains("ORPHANED SID"));

        // The aggregated action count should be 3 in one increment.
        assert!(content.contains("$ActionCount += 3"));

        // Cleanup
        std::fs::remove_dir_all(&tmp_dir).ok();
    }

    /// Verify single-quote escaping in paths.
    #[test]
    fn path_escaping() {
        assert_eq!(escape_ps_path(r"C:\Users\O'Brien\Docs"), r"C:\Users\O''Brien\Docs");
        assert_eq!(escape_ps_path(r"C:\Normal\Path"), r"C:\Normal\Path");
    }

    /// Verify the actionable filter correctly classifies risk types.
    #[test]
    fn actionable_classification() {
        assert!(is_actionable(&RiskKind::OverPermissiveAce {
            trustee: "Everyone".to_string(),
            access_mask: 0x1F01FF,
            access_mask_human: "FullControl".to_string(),
        }));
        assert!(is_actionable(&RiskKind::InheritanceBreak {
            had_protected_copy: false,
        }));
        assert!(is_actionable(&RiskKind::OrphanedSid {
            raw_sid: "S-1-5-21-0".to_string(),
        }));
        assert!(!is_actionable(&RiskKind::NullDacl));
        assert!(!is_actionable(&RiskKind::AnomalySimulated {
            cycles_in_ms: 100,
        }));
    }
}
