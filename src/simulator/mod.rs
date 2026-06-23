//! Ransomware behavior anomaly simulator (stealth execution via Win32 APIs).
//!
//! Purpose: Prove to the IT admin that their SIEM/EDR lacks real-time NTFS
//! audit visibility by:
//!   1. Creating a hidden temp directory under the scanned root.
//!   2. Generating 50 dummy files inside it.
//!   3. Cycling each file's DACL via `SetNamedSecurityInfoW` — NO child
//!      processes are spawned (unlike the V1 `icacls` approach, which an
//!      EDR would flag from the process tree alone).
//!   4. Cleaning up the directory.
//!   5. Asking the admin: "Did your SIEM alert on any of this?"
//!
//! This is 100% safe — no data is encrypted, no real files are modified.
//! The temporary directory is created only under the user-specified root.
//!
//! # Stealth Design (V2 improvement over V1)
//!
//! V1 spawned `icacls.exe` 2,500 times in a loop. Any EDR monitoring the
//! process tree would flag this immediately — defeating the purpose of the
//! simulation (which is to test *ACL audit* visibility, not process-spawn
//! visibility).
//!
//! V2 uses `SetNamedSecurityInfoW` directly. This is the same API that
//! Explorer's "Security" tab, `icacls.exe`, and real ransomware all call
//! under the hood. The difference: we make the calls in-process, producing
//! ONLY Windows Security Event Log entries (4670 / 4663) — exactly what a
//! properly configured SIEM should be monitoring.
//!
//! # Ethical Note
//! This simulator requires explicit `--simulate-anomaly` opt-in and prints
//! a warning banner before executing. It should only be run with prior
//! authorization from the server owner.

use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::errors::{AuditorError, Result};
use crate::scanner::risk::{RiskFinding, RiskKind, Severity};

/// Hidden directory name used for the simulation artifacts.
/// The leading dot makes it hidden on Unix; we set FILE_ATTRIBUTE_HIDDEN on Windows.
const TEMP_DIR_NAME: &str = ".tmp_folsec_audit";

/// Number of dummy files to create.
const FILE_COUNT: u32 = 50;

/// Number of ACL cycles per file.
const ACL_CYCLES: u32 = 50;

/// Result of the anomaly simulation.
pub struct SimulationResult {
    /// Total elapsed time for the entire simulation (create → cycle → cleanup).
    pub elapsed: Duration,
    /// Elapsed time specifically for the ACL cycling phase.
    pub cycling_elapsed_ms: u64,
    /// The RiskFinding to add to the final report.
    pub finding: RiskFinding,
    /// Whether cleanup succeeded (temp dir was removed).
    pub cleaned_up: bool,
}

/// Run the anomaly simulation under `root_path`.
///
/// Returns `Ok(SimulationResult)` on success or partial success (cleanup failure
/// is non-fatal and logged in the result). Returns `Err` only if the simulation
/// setup itself fails (e.g., cannot create temp directory).
pub fn run_simulation(root_path: &str) -> Result<SimulationResult> {
    let root = Path::new(root_path);
    let temp_dir = root.join(TEMP_DIR_NAME);

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  ⚠  FOLSEC ANOMALY SIMULATOR — AUTHORIZED USE ONLY          ║");
    println!("║     Simulating ransomware ACL cycling behavior...            ║");
    println!("║     Mode: Direct Win32 API (stealth — no child processes)    ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    let total_start = Instant::now();

    // ── Phase 1: Create hidden temp directory ────────────────────────────────
    create_hidden_directory(&temp_dir)?;
    eprintln!("[SIM] Created temp dir: {}", temp_dir.display());

    // ── Phase 2: Create dummy files ──────────────────────────────────────────
    let mut file_paths: Vec<PathBuf> = Vec::with_capacity(FILE_COUNT as usize);
    for i in 0..FILE_COUNT {
        let file_path = temp_dir.join(format!("folsec_dummy_{:03}.tmp", i));
        std::fs::write(&file_path, b"FolSec ACL Audit Simulation").map_err(|e| {
            AuditorError::Io {
                path: file_path.to_string_lossy().to_string(),
                source: e,
            }
        })?;
        file_paths.push(file_path);
    }
    eprintln!("[SIM] Created {} dummy files.", FILE_COUNT);

    // ── Phase 3: Rapid ACL cycling via Win32 API ─────────────────────────────
    // This is the "smoking gun" phase. We alternate between two DACL states
    // on each file using SetNamedSecurityInfoW directly — no child processes.
    // A real SIEM with Windows Security Event Log forwarding (Event IDs
    // 4670: Permissions on object changed) would fire
    // FILE_COUNT × ACL_CYCLES = 2,500 events in < 2 seconds.
    let cycling_start = Instant::now();
    cycle_acls_on_files(&file_paths)?;
    let cycling_elapsed_ms = cycling_start.elapsed().as_millis() as u64;

    eprintln!(
        "[SIM] Cycled ACLs {} times per file in {}ms total ({} total API calls).",
        ACL_CYCLES, cycling_elapsed_ms, ACL_CYCLES * FILE_COUNT
    );

    // ── Phase 4: Cleanup ─────────────────────────────────────────────────────
    let cleaned_up = cleanup(&temp_dir);
    if cleaned_up {
        eprintln!("[SIM] Temp directory cleaned up successfully.");
    } else {
        eprintln!(
            "[WARN] Cleanup failed — manual deletion required: {}",
            temp_dir.display()
        );
    }

    let total_elapsed = total_start.elapsed();

    let finding = RiskFinding {
        path: temp_dir.to_string_lossy().to_string(),
        severity: Severity::Critical,
        risk: RiskKind::AnomalySimulated { cycles_in_ms: cycling_elapsed_ms },
        description: format!(
            "FolSec Anomaly Simulator executed {} ACL cycles across {} files in {}ms \
             using direct Win32 SetNamedSecurityInfoW calls (zero child processes). \
             If your SIEM/EDR did NOT alert during this window, you lack real-time \
             NTFS audit visibility. A real ransomware attack would look identical.",
            ACL_CYCLES * FILE_COUNT,
            FILE_COUNT,
            cycling_elapsed_ms
        ),
        remediation_hint: "Enable Windows Security Audit Policy → 'Audit Object Access' \
             and forward Event IDs 4656/4660/4663/4670 to your SIEM. \
             FolSec provides out-of-the-box detection rules for this pattern."
            .to_string(),
    };

    println!("\n[SIM] Total simulation time: {:?}", total_elapsed);
    println!(
        "[SIM] {} ACL changes in {}ms — did your SIEM alert?\n",
        ACL_CYCLES * FILE_COUNT,
        cycling_elapsed_ms
    );

    Ok(SimulationResult {
        elapsed: total_elapsed,
        cycling_elapsed_ms,
        finding,
        cleaned_up,
    })
}

/// Create a directory and mark it as hidden on Windows.
fn create_hidden_directory(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).map_err(|e| AuditorError::Io {
        path: path.to_string_lossy().to_string(),
        source: e,
    })?;

    // Set FILE_ATTRIBUTE_HIDDEN on Windows so the dir doesn't visually
    // alarm the admin while the simulation is running.
    #[cfg(target_os = "windows")]
    set_hidden_attribute(path)?;

    Ok(())
}

/// Apply FILE_ATTRIBUTE_HIDDEN to a path via SetFileAttributesW.
#[cfg(target_os = "windows")]
fn set_hidden_attribute(path: &Path) -> Result<()> {
    use windows::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN};
    use windows::core::PCWSTR;

    let wide: Vec<u16> = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: wide is a valid null-terminated UTF-16 path.
    let ok = unsafe { SetFileAttributesW(PCWSTR(wide.as_ptr()), FILE_ATTRIBUTE_HIDDEN) };

    ok.map_err(|e| {
        AuditorError::SimulatorSetup(format!(
            "SetFileAttributesW failed on '{}': {:?}",
            path.display(),
            e
        ))
    })
}

/// Cycle ACLs on a list of files to simulate rapid permission manipulation.
///
/// Uses direct Win32 `SetNamedSecurityInfoW` calls — NO child processes are
/// spawned. This is critical for stealth: an EDR watching process trees would
/// immediately flag 2,500 `icacls.exe` invocations, but in-process API calls
/// produce ONLY the DACL-change audit events we want to test for.
///
/// Strategy: We alternate between two DACL states per cycle:
///   - Even cycles: Apply a restrictive DACL (only SYSTEM has access).
///     This simulates a ransomware "lockout" — stripping all user permissions.
///   - Odd cycles: Apply a permissive DACL (Everyone: Full Control).
///     This simulates the "restore" to keep the toggle generating events.
///
/// Each call to `SetNamedSecurityInfoW` should produce a Windows Security
/// Event ID 4670 ("Permissions on an object were changed") if the audit
/// policy is correctly configured.
fn cycle_acls_on_files(files: &[PathBuf]) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        return cycle_acls_on_files_win32(files);
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = files;
        Err(AuditorError::SimulatorSetup(
            "ACL cycling requires Windows (SetNamedSecurityInfoW is Win32-only)".to_string(),
        ))
    }
}

/// Windows implementation of ACL cycling using SetNamedSecurityInfoW.
///
/// # DACL Construction
///
/// We build two ACLs from scratch using `InitializeAcl` + `AddAccessAllowedAce`:
///
/// 1. **Restrictive ACL**: Single ACE granting `FILE_ALL_ACCESS` to `SYSTEM`
///    (S-1-5-18). All other principals are implicitly denied.
///
/// 2. **Permissive ACL**: Single ACE granting `FILE_ALL_ACCESS` to `Everyone`
///    (S-1-1-0). This is the worst-case over-permissive state.
///
/// We pre-build both ACLs once, then rapidly toggle between them for each
/// file × cycle. This keeps memory allocation out of the hot loop.
#[cfg(target_os = "windows")]
fn cycle_acls_on_files_win32(files: &[PathBuf]) -> Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::WIN32_ERROR;
    use windows::Win32::Security::{
        AddAccessAllowedAce, AllocateAndInitializeSid, FreeSid,
        InitializeAcl, ACL as WIN32_ACL, ACL_REVISION,
        DACL_SECURITY_INFORMATION, PSID, SID_IDENTIFIER_AUTHORITY,
    };
    use windows::Win32::Security::Authorization::{
        SetNamedSecurityInfoW, SE_FILE_OBJECT,
    };

    // ── Build the two well-known SIDs ────────────────────────────────────────
    // We use AllocateAndInitializeSid for maximum compatibility — this works
    // on all Windows versions from XP onward and doesn't require string parsing.

    // SID_IDENTIFIER_AUTHORITY for NT Authority (S-1-5-*).
    let sia_nt = SID_IDENTIFIER_AUTHORITY { Value: [0, 0, 0, 0, 0, 5] };
    // SID_IDENTIFIER_AUTHORITY for World Authority (S-1-1-*).
    let sia_world = SID_IDENTIFIER_AUTHORITY { Value: [0, 0, 0, 0, 0, 1] };

    let mut psid_system = PSID::default();
    let mut psid_everyone = PSID::default();

    // SAFETY: All parameters are valid. AllocateAndInitializeSid allocates
    // a SID that must be freed with FreeSid.
    unsafe {
        // S-1-5-18 = Local System
        AllocateAndInitializeSid(
            &sia_nt, 1, // 1 sub-authority
            18, 0, 0, 0, 0, 0, 0, 0,
            &mut psid_system,
        ).map_err(|e| AuditorError::SimulatorSetup(format!(
            "AllocateAndInitializeSid (SYSTEM) failed: {:?}", e
        )))?;

        // S-1-1-0 = Everyone
        AllocateAndInitializeSid(
            &sia_world, 1, // 1 sub-authority
            0, 0, 0, 0, 0, 0, 0, 0,
            &mut psid_everyone,
        ).map_err(|e| {
            // Free the system SID since we're bailing out.
            FreeSid(psid_system);
            AuditorError::SimulatorSetup(format!(
                "AllocateAndInitializeSid (Everyone) failed: {:?}", e
            ))
        })?;
    }

    // RAII cleanup: ensure FreeSid is called on both SIDs even on early return.
    // We use a simple Drop wrapper to guarantee this.
    struct SidCleanup(PSID);
    impl Drop for SidCleanup {
        fn drop(&mut self) {
            if !self.0 .0.is_null() {
                // SAFETY: SID was allocated by AllocateAndInitializeSid.
                unsafe { FreeSid(self.0); }
            }
        }
    }
    let _guard_system = SidCleanup(psid_system);
    let _guard_everyone = SidCleanup(psid_everyone);

    // ── Pre-build the two DACLs ──────────────────────────────────────────────
    // ACL buffer size = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) - sizeof(u32)
    //                   + SID length. We use a generous fixed buffer.
    //
    // sizeof(ACL) = 8, sizeof(ACCESS_ALLOWED_ACE) = 12, typical SID = 12–28 bytes.
    // We allocate 256 bytes — more than enough for a single-ACE ACL.
    const ACL_BUF_SIZE: usize = 256;

    let mut acl_restrictive_buf = vec![0u8; ACL_BUF_SIZE];
    let mut acl_permissive_buf = vec![0u8; ACL_BUF_SIZE];

    let acl_restrictive_ptr = acl_restrictive_buf.as_mut_ptr().cast::<WIN32_ACL>();
    let acl_permissive_ptr = acl_permissive_buf.as_mut_ptr().cast::<WIN32_ACL>();

    // SAFETY: Buffers are properly sized and zero-initialized.
    // InitializeAcl validates the buffer size and sets up the ACL header.
    unsafe {
        InitializeAcl(acl_restrictive_ptr, ACL_BUF_SIZE as u32, ACL_REVISION)
            .map_err(|e| AuditorError::SimulatorSetup(format!(
                "InitializeAcl (restrictive) failed: {:?}", e
            )))?;

        InitializeAcl(acl_permissive_ptr, ACL_BUF_SIZE as u32, ACL_REVISION)
            .map_err(|e| AuditorError::SimulatorSetup(format!(
                "InitializeAcl (permissive) failed: {:?}", e
            )))?;
    }

    // FILE_ALL_ACCESS = 0x001F01FF — the specific composite for full file rights.
    const FILE_ALL_ACCESS: u32 = 0x001F_01FF;

    // SAFETY: acl pointers were initialized, SID pointers are valid.
    unsafe {
        AddAccessAllowedAce(acl_restrictive_ptr, ACL_REVISION, FILE_ALL_ACCESS, psid_system)
            .map_err(|e| AuditorError::SimulatorSetup(format!(
                "AddAccessAllowedAce (SYSTEM) failed: {:?}", e
            )))?;

        AddAccessAllowedAce(acl_permissive_ptr, ACL_REVISION, FILE_ALL_ACCESS, psid_everyone)
            .map_err(|e| AuditorError::SimulatorSetup(format!(
                "AddAccessAllowedAce (Everyone) failed: {:?}", e
            )))?;
    }

    // ── Hot loop: toggle DACLs on all files ──────────────────────────────────
    // SetNamedSecurityInfoW is an in-process call — no child process spawning.
    // Each call produces a single Windows Security Event (4670) if audit policy
    // is configured. Total events: FILE_COUNT × ACL_CYCLES = 2,500.
    let mut errors_tolerated: u32 = 0;

    for file in files {
        let wide_path: Vec<u16> = file
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        for cycle in 0..ACL_CYCLES {
            // Alternate between restrictive (SYSTEM only) and permissive (Everyone).
            let dacl_ptr = if cycle % 2 == 0 {
                acl_restrictive_ptr
            } else {
                acl_permissive_ptr
            };

            // SAFETY:
            // - wide_path is a valid null-terminated UTF-16 string.
            // - dacl_ptr points to a valid, initialized ACL with one ACE.
            // - SE_FILE_OBJECT tells the API to interpret the name as a filesystem path.
            // - DACL_SECURITY_INFORMATION tells it to replace only the DACL.
            // - PSID::default() (null) for owner/group = "don't change".
            let result: WIN32_ERROR = unsafe {
                SetNamedSecurityInfoW(
                    PCWSTR(wide_path.as_ptr()),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    PSID::default(),  // ppsidOwner: don't change owner
                    PSID::default(),  // ppsidGroup: don't change group
                    Some(dacl_ptr as *const WIN32_ACL), // pDacl: our toggled DACL
                    None,             // pSacl: don't change SACL
                )
            };

            // ERROR_SUCCESS = 0. Any non-zero value is an error code.
            if result.0 != 0 {
                // Not fatal — the goal is event generation, not perfect ACL state.
                // We tolerate partial failures (e.g., if the file was locked).
                errors_tolerated += 1;
                if errors_tolerated == 1 {
                    // Log only the first error to avoid flooding stderr.
                    eprintln!(
                        "[SIM] SetNamedSecurityInfoW error {} on '{}' cycle {} (tolerated).",
                        result.0,
                        file.display(),
                        cycle + 1
                    );
                }
            }
        }
    }

    if errors_tolerated > 0 {
        eprintln!(
            "[SIM] {} API calls returned errors (all tolerated — simulation continued).",
            errors_tolerated
        );
    }

    // SidCleanup guards drop here, calling FreeSid on each allocated SID.
    Ok(())
}

/// Remove the temp directory and all its contents.
/// Returns true if removal succeeded, false otherwise (non-fatal).
fn cleanup(path: &Path) -> bool {
    // On Windows, files may still have restrictive DACLs from the simulation.
    // We attempt to reset permissions before deleting. If this fails, we still
    // try remove_dir_all — the OS may allow deletion if we're the owner.
    #[cfg(target_os = "windows")]
    reset_permissions_for_cleanup(path);

    std::fs::remove_dir_all(path).is_ok()
}

/// Best-effort: re-grant Everyone Full Control on all files in the temp dir
/// before attempting deletion. This handles the case where the last ACL cycle
/// left a restrictive DACL (SYSTEM-only), which would cause remove_dir_all
/// to fail with ACCESS_DENIED.
#[cfg(target_os = "windows")]
fn reset_permissions_for_cleanup(dir: &Path) {
    use windows::core::PCWSTR;
    use windows::Win32::Security::{
        AddAccessAllowedAce, AllocateAndInitializeSid, FreeSid,
        InitializeAcl, ACL as WIN32_ACL, ACL_REVISION,
        DACL_SECURITY_INFORMATION, PSID, SID_IDENTIFIER_AUTHORITY,
    };
    use windows::Win32::Security::Authorization::{
        SetNamedSecurityInfoW, SE_FILE_OBJECT,
    };

    // Build Everyone SID for cleanup.
    let sia_world = SID_IDENTIFIER_AUTHORITY { Value: [0, 0, 0, 0, 0, 1] };
    let mut psid_everyone = PSID::default();

    // SAFETY: All parameters are valid.
    unsafe {
        if AllocateAndInitializeSid(
            &sia_world, 1, 0, 0, 0, 0, 0, 0, 0, 0, &mut psid_everyone,
        ).is_err() {
            return; // Best-effort; if this fails, cleanup may still work.
        }
    }

    // Build a permissive ACL.
    const ACL_BUF_SIZE: usize = 256;
    let mut acl_buf = vec![0u8; ACL_BUF_SIZE];
    let acl_ptr = acl_buf.as_mut_ptr().cast::<WIN32_ACL>();

    // SAFETY: Buffer is valid and sized, SID is valid.
    let ok = unsafe {
        InitializeAcl(acl_ptr, ACL_BUF_SIZE as u32, ACL_REVISION).is_ok()
            && AddAccessAllowedAce(acl_ptr, ACL_REVISION, 0x001F_01FF, psid_everyone).is_ok()
    };

    if !ok {
        // SAFETY: SID was allocated, must be freed.
        unsafe { FreeSid(psid_everyone); }
        return;
    }

    // Walk the directory and reset each file's DACL.
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let wide: Vec<u16> = path
                .to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            // SAFETY: wide is valid UTF-16, acl_ptr and psid are valid.
            unsafe {
                let _ = SetNamedSecurityInfoW(
                    PCWSTR(wide.as_ptr()),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    PSID::default(),
                    PSID::default(),
                    Some(acl_ptr as *const WIN32_ACL),
                    None,
                );
            }
        }
    }

    // Also reset the directory itself.
    let wide_dir: Vec<u16> = dir
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: wide_dir is valid UTF-16, acl_ptr is valid.
    unsafe {
        let _ = SetNamedSecurityInfoW(
            PCWSTR(wide_dir.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            PSID::default(),
            PSID::default(),
            Some(acl_ptr as *const WIN32_ACL),
            None,
        );

        // Free the SID we allocated.
        FreeSid(psid_everyone);
    }
}
