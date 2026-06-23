//! ACL extraction from filesystem paths using Win32 security APIs.
//!
//! This is the most security-critical module in the entire codebase.
//! Every raw pointer interaction with Win32 security descriptors is wrapped
//! in a RAII guard (`SecurityDescriptorGuard`) to ensure `LocalFree` is
//! always called, even if we early-return on an error partway through.
//!
//! # Win32 Security Descriptor Model (Primer for code reviewers)
//!
//! A security descriptor (SD) is the root structure. It contains:
//!   - DACL (Discretionary ACL): Who can DO what → what we audit.
//!   - SACL (System ACL): What to LOG → not our concern here.
//!   - Owner SID / Group SID → future work.
//!
//! A DACL contains zero or more ACEs (Access Control Entries).
//! Each ACE has:
//!   - Header: ACE type (Allow/Deny), flags (inheritance bits), size.
//!   - AccessMask: bitmask of specific rights (Read=0x120089, Full=0x1F01FF, etc.)
//!   - SidStart: The beginning of the SID that the ACE applies to.
//!
//! We iterate ACEs via `GetAce(dacl, ace_index, &ace_ptr)` starting at index 0.

#[cfg(target_os = "windows")]
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{LocalFree, HLOCAL},
        Security::{
            Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT},
            GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
            IsValidSecurityDescriptor, ACE_HEADER, ACCESS_ALLOWED_ACE,
            ACL as WIN32_ACL, GetAce, DACL_SECURITY_INFORMATION,
            OWNER_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
            ACCESS_DENIED_ACE, PSID,
        },
    },
};

use crate::{
    errors::{AuditorError, Result},
    scanner::{
        risk::{RiskFinding, RiskKind},
        sid::{resolve_sid, ResolvedSid},
    },
};

// ── Well-Known Trustee Names That Indicate Over-Permissiveness ──────────────
/// These strings (lowercased) indicate broad, over-permissive trustees.
/// "Everyone" = S-1-1-0, grants access to literally every process/user.
/// "Authenticated Users" = S-1-5-11, excludes only truly anonymous sessions.
/// "BUILTIN\Users" = S-1-5-32-545, grants access to all local user accounts.
const OVERPERMISSIVE_TRUSTEES: &[&str] = &[
    "everyone",
    "authenticated users",
    "users",     // catches BUILTIN\Users after domain stripping
    "anonymous logon",
    "creator owner", // dangerous as inherited owner — not always, but flag it
];

// ── Access Mask Flag Decoding ────────────────────────────────────────────────
// These are the access mask bits we care about for "write-class" risk.
// Full Control = 0x1F01FF, Modify = includes WRITE_DAC, WRITE_OWNER, DELETE.
const WRITE_ACCESS_MASK: u32 =
    0x00000002  // FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x00000004  // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x00040000  // WRITE_DAC
    | 0x00080000  // WRITE_OWNER
    | 0x00010000  // DELETE
    | 0x001F01FF; // GENERIC_ALL / FILE_ALL_ACCESS

/// RAII wrapper around a Win32 security descriptor.
///
/// When this guard is dropped, `LocalFree` is called on the descriptor pointer.
/// This prevents leaks even if `extract_dacl_findings` returns early via `?`.
#[cfg(target_os = "windows")]
struct SecurityDescriptorGuard(PSECURITY_DESCRIPTOR);

#[cfg(target_os = "windows")]
impl Drop for SecurityDescriptorGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: The pointer was returned by GetNamedSecurityInfoW and has
            // not been freed yet. MSDN mandates LocalFree for this pointer.
            unsafe {
                LocalFree(HLOCAL(self.0 .0));
            }
        }
    }
}

/// Extract all ACL-based risk findings for a single directory path.
///
/// Returns a `Vec<RiskFinding>` (may be empty if the path is clean) or
/// an `Err` if the security descriptor itself could not be read.
///
/// Per-ACE resolution errors (orphaned SID lookup failures) are non-fatal:
/// they produce an `OrphanedSid` finding rather than aborting the scan.
#[cfg(target_os = "windows")]
pub fn extract_dacl_findings(path: &str) -> Result<Vec<RiskFinding>> {
    // ── Encode path as null-terminated UTF-16 ────────────────────────────────
    // Win32 "W" (wide) functions require UTF-16LE with a null terminator.
    let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    // ── Call GetNamedSecurityInfoW ───────────────────────────────────────────
    // We request DACL_SECURITY_INFORMATION | OWNER... | GROUP... so we get
    // the full SD. We only use the DACL portion in V1.
    let mut sd_ptr = PSECURITY_DESCRIPTOR::default();

    // Output pointers for owner, group, dacl — we keep dacl; others are freed
    // when sd_ptr is freed (they point INTO the SD buffer, not separate allocs).
    let mut owner_sid = PSID::default();
    let mut group_sid = PSID::default();
    let mut dacl_ptr: *mut WIN32_ACL = std::ptr::null_mut();
    let mut dacl_present = windows::Win32::Foundation::BOOL(0);
    let mut dacl_defaulted = windows::Win32::Foundation::BOOL(0);

    // SAFETY: wide_path is a valid null-terminated UTF-16 string.
    // GetNamedSecurityInfoW allocates sd_ptr on our behalf via LocalAlloc.
    // We MUST free it with LocalFree — the RAII guard below handles this.
    let err_code = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(wide_path.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
            Some(&mut owner_sid),
            Some(&mut group_sid),
            Some(&mut dacl_ptr),
            None, // We don't need SACL
            &mut sd_ptr,
        )
    };

    // GetNamedSecurityInfoW returns WIN32_ERROR (0 = ERROR_SUCCESS).
    if err_code.0 != 0 {
        return Err(AuditorError::SecurityDescriptorRead {
            path: path.to_string(),
            code: err_code.0,
        });
    }

    // Wrap in RAII guard immediately — any `?` from here onwards is safe.
    let _guard = SecurityDescriptorGuard(sd_ptr);

    // ── Validate the security descriptor ────────────────────────────────────
    // Belt-and-suspenders: IsValidSecurityDescriptor is a cheap sanity check.
    // SAFETY: sd_ptr is valid (GetNamedSecurityInfoW succeeded above).
    let valid = unsafe { IsValidSecurityDescriptor(sd_ptr) };
    if !valid.as_bool() {
        // Corrupted SD — log as critical, skip ACE iteration.
        return Ok(vec![RiskFinding {
            path: path.to_string(),
            severity: crate::scanner::risk::Severity::Critical,
            risk: RiskKind::NullDacl, // closest enum variant for "unreadable"
            description: format!("Security descriptor on '{}' is invalid/corrupt.", path),
            remediation_hint: "Run 'icacls \"{}\" /reset' and re-apply permissions.".to_string(),
        }]);
    }

    // ── Check SD control flags for inheritance break ─────────────────────
    // GetSecurityDescriptorControl takes *mut u16 for pcontrol in windows 0.58.
    let mut sd_control_raw: u16 = 0;
    let mut sd_revision: u32 = 0;

    // SAFETY: sd_ptr is valid. GetSecurityDescriptorControl reads the control word.
    unsafe {
        let _ = GetSecurityDescriptorControl(sd_ptr, &mut sd_control_raw, &mut sd_revision);
    }

    // SE_DACL_PROTECTED = 0x1000: the DACL is NOT inherited from parent.
    // This is the "inheritance break" indicator.
    let is_inheritance_broken = (sd_control_raw & (SE_DACL_PROTECTED.0 as u16)) != 0;

    // ── Extract the DACL ─────────────────────────────────────────────────────
    // GetSecurityDescriptorDacl populates our dacl_ptr and dacl_present flag.
    // SAFETY: sd_ptr is valid, all out-pointers are valid stack locations.
    unsafe {
        let _ = GetSecurityDescriptorDacl(
            sd_ptr,
            &mut dacl_present,
            &mut dacl_ptr,
            &mut dacl_defaulted,
        );
    }

    let mut findings: Vec<RiskFinding> = Vec::new();

    // ── No DACL present: implicit allow-all (CRITICAL) ───────────────────────
    if !dacl_present.as_bool() {
        findings.push(RiskFinding::null_dacl(path.to_string()));
        return Ok(findings);
    }

    // ── Inheritance Break finding ─────────────────────────────────────────────
    if is_inheritance_broken {
        findings.push(RiskFinding::inheritance_break(
            path.to_string(),
            // SE_DACL_PRESENT means there ARE explicit ACEs (copied or new).
            dacl_present.as_bool(),
        ));
    }

    // ── Null DACL pointer despite dacl_present = TRUE ────────────────────────
    // This shouldn't happen after a valid GetNamedSecurityInfoW, but handle it.
    if dacl_ptr.is_null() {
        findings.push(RiskFinding::null_dacl(path.to_string()));
        return Ok(findings);
    }

    // ── Iterate ACEs ─────────────────────────────────────────────────────────
    // SAFETY: dacl_ptr is non-null and was populated by GetSecurityDescriptorDacl.
    let ace_count = unsafe { (*dacl_ptr).AceCount };

    for ace_idx in 0..ace_count {
        let mut ace_ptr: *mut std::ffi::c_void = std::ptr::null_mut();

        // SAFETY: dacl_ptr is valid, ace_idx is within AceCount bounds.
        let got_ace = unsafe { GetAce(dacl_ptr, ace_idx as u32, &mut ace_ptr) };

        if got_ace.is_err() || ace_ptr.is_null() {
            // Skip this ACE — log via eprintln! for now; hook into tracing in V2.
            eprintln!(
                "[WARN] GetAce failed for index {} on '{}' — skipping ACE.",
                ace_idx, path
            );
            continue;
        }

        // ── Parse the ACE header to determine type ────────────────────────
        // SAFETY: ace_ptr is non-null and correctly aligned (guaranteed by Win32).
        let ace_header = unsafe { &*(ace_ptr as *const ACE_HEADER) };

        match ace_header.AceType {
            // ACCESS_ALLOWED_ACE_TYPE = 0x00
            0x00 => {
                let ace = unsafe { &*(ace_ptr as *const ACCESS_ALLOWED_ACE) };
                // SidStart is a u32 that is the FIRST DWORD of the SID.
                // We get a PSID by taking its address. This is the documented
                // pattern in Win32 SDK samples and Raymond Chen's blog.
                let psid = PSID(&ace.SidStart as *const u32 as *mut _);
                analyze_ace(path, psid, ace.Mask, false, &mut findings);
            }
            // ACCESS_DENIED_ACE_TYPE = 0x01
            0x01 => {
                let ace = unsafe { &*(ace_ptr as *const ACCESS_DENIED_ACE) };
                let psid = PSID(&ace.SidStart as *const u32 as *mut _);
                // Deny ACEs are generally GOOD (defense-in-depth).
                // We still check for orphaned SIDs in deny ACEs.
                match resolve_sid(psid) {
                    Ok(ResolvedSid::Orphaned { raw_sid }) => {
                        findings.push(RiskFinding::orphaned_sid(path.to_string(), raw_sid));
                    }
                    _ => {} // Deny ACE with valid SID = fine, skip
                }
            }
            // Other ACE types (object ACEs, audit ACEs) — not relevant for V1.
            _ => {}
        }
    }

    Ok(findings)
}

/// Analyze a single Allow ACE for risk and append findings as needed.
#[cfg(target_os = "windows")]
fn analyze_ace(
    path: &str,
    psid: PSID,
    access_mask: u32,
    _is_deny: bool,
    findings: &mut Vec<RiskFinding>,
) {
    // Resolve the SID to a human-readable name.
    let resolved = match resolve_sid(psid) {
        Ok(r) => r,
        Err(_) => {
            // Resolution failure where we didn't even get an orphaned SID result.
            // Treat as orphaned rather than silently skipping.
            findings.push(RiskFinding::orphaned_sid(
                path.to_string(),
                crate::scanner::sid::sid_to_string(psid),
            ));
            return;
        }
    };

    // ── Orphaned SID check ────────────────────────────────────────────────
    if let ResolvedSid::Orphaned { ref raw_sid } = resolved {
        findings.push(RiskFinding::orphaned_sid(path.to_string(), raw_sid.clone()));
        return;
    }

    let trustee = resolved.display().to_string();
    let trustee_lower = trustee.to_lowercase();

    // ── Over-permissive trustee check ─────────────────────────────────────
    let is_overpermissive_trustee = OVERPERMISSIVE_TRUSTEES
        .iter()
        .any(|&known| trustee_lower.contains(known));

    if is_overpermissive_trustee {
        // Check if the access mask includes any write-class permissions.
        if access_mask & WRITE_ACCESS_MASK != 0 {
            let access_human = decode_access_mask(access_mask);
            findings.push(RiskFinding::over_permissive(
                path.to_string(),
                trustee,
                access_mask,
                access_human,
            ));
        }
    }
}

/// Decode common Win32 access mask bits into a human-readable string.
/// Not exhaustive — covers the rights most relevant to ransomware/data exfil risk.
fn decode_access_mask(mask: u32) -> String {
    // Check for common composite masks first (most specific wins).
    if mask & 0x001F01FF == 0x001F01FF {
        return "Full Control".to_string();
    }

    let mut parts: Vec<&str> = Vec::new();

    if mask & 0x00000001 != 0 { parts.push("Read"); }
    if mask & 0x00000002 != 0 { parts.push("Write Data"); }
    if mask & 0x00000004 != 0 { parts.push("Append Data"); }
    if mask & 0x00000020 != 0 { parts.push("Execute"); }
    if mask & 0x00010000 != 0 { parts.push("Delete"); }
    if mask & 0x00020000 != 0 { parts.push("Read Control"); }
    if mask & 0x00040000 != 0 { parts.push("Write DAC"); }
    if mask & 0x00080000 != 0 { parts.push("Write Owner"); }

    if parts.is_empty() {
        format!("0x{:08X}", mask)
    } else {
        parts.join(", ")
    }
}

/// Non-Windows stub — always errors.
#[cfg(not(target_os = "windows"))]
pub fn extract_dacl_findings(_path: &str) -> Result<Vec<RiskFinding>> {
    Err(AuditorError::NonWindowsPlatform)
}
