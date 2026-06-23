//! SID → human-readable account name resolution.
//!
//! This module wraps `LookupAccountSidW` with careful buffer management and
//! explicit handling of the "orphaned SID" case (ERROR_NONE_MAPPED).
//!
//! Key Win32 nuance: `LookupAccountSidW` requires TWO calls:
//!   1. Pass NULL buffers to get required buffer sizes.
//!   2. Allocate those sizes and call again to get the actual strings.
//! Skipping the first call and guessing a buffer size is a common source of
//! silent truncation bugs — we do NOT do that here.

#[cfg(target_os = "windows")]
use windows::{
    core::PWSTR,
    Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NONE_MAPPED, WIN32_ERROR},
        Security::{LookupAccountSidW, PSID},
    },
};

use crate::errors::{AuditorError, Result};

/// The resolved identity of a SID.
#[derive(Debug, Clone)]
pub enum ResolvedSid {
    /// Successfully resolved to a domain\account name.
    Account {
        account_name: String,
        domain_name: String,
        /// Full display form: "DOMAIN\account"
        display: String,
    },
    /// SID could not be resolved — likely an orphaned/deleted AD principal.
    Orphaned {
        raw_sid: String,
    },
}

impl ResolvedSid {
    /// Returns the display string regardless of resolution status.
    pub fn display(&self) -> &str {
        match self {
            ResolvedSid::Account { display, .. } => display,
            ResolvedSid::Orphaned { raw_sid } => raw_sid,
        }
    }

    pub fn is_orphaned(&self) -> bool {
        matches!(self, ResolvedSid::Orphaned { .. })
    }
}

/// Attempt to resolve a SID pointer to an account name.
///
/// # Safety
/// `psid` MUST be a valid, non-null pointer to a properly formed SID obtained
/// from a Windows security descriptor. Callers get such a pointer from
/// `GetAce` → `KNOWN_ACE.SidStart`. We validate non-null in `acl.rs`.
///
/// On non-Windows platforms this function always returns `Err(NonWindowsPlatform)`.
#[cfg(target_os = "windows")]
pub fn resolve_sid(psid: PSID) -> Result<ResolvedSid> {
    use std::mem::MaybeUninit;

    // ── Step 1: Size Discovery ──────────────────────────────────────────────
    // Pass zero-length buffers and mutable size variables. The API will fail
    // with ERROR_INSUFFICIENT_BUFFER and populate the sizes we need.
    let mut name_len: u32 = 0;
    let mut domain_len: u32 = 0;
    // SID_NAME_USE enum output — we capture it but don't strictly need it for
    // risk assessment (we care about the name, not whether it's a user vs. group).
    let mut sid_name_use = MaybeUninit::uninit();

    // SAFETY: We're calling with null-equivalent PWSTR (None) and zero lengths
    // to probe the required buffer size. This is the documented Win32 pattern.
    let probe_result = unsafe {
        LookupAccountSidW(
            None,                        // lpSystemName: NULL = local system
            psid,
            PWSTR::null(),               // lpName: null probe
            &mut name_len,
            PWSTR::null(),               // lpReferencedDomainName: null probe
            &mut domain_len,
            sid_name_use.as_mut_ptr(),
        )
    };

    // The probe call MUST fail with ERROR_INSUFFICIENT_BUFFER.
    // If it succeeds (very unusual) or fails with a different code, handle both.
    if let Err(e) = probe_result {
        let win32_err = WIN32_ERROR(e.code().0 as u32);

        // ERROR_NONE_MAPPED: SID exists but has no associated account.
        // This IS the orphaned SID case — convert to raw string and return.
        if win32_err == ERROR_NONE_MAPPED {
            return Ok(ResolvedSid::Orphaned {
                raw_sid: sid_to_string(psid),
            });
        }

        // Any error other than INSUFFICIENT_BUFFER here is unexpected.
        if win32_err != ERROR_INSUFFICIENT_BUFFER {
            return Err(AuditorError::SidResolution {
                sid_string: sid_to_string(psid),
                code: win32_err.0,
            });
        }
    }

    // ── Step 2: Actual Resolution with properly sized buffers ───────────────
    // Allocate Vec<u16> buffers of the sizes the API told us we need.
    // The lengths include the null terminator, so the Vec capacity is exact.
    let mut name_buf: Vec<u16> = vec![0u16; name_len as usize];
    let mut domain_buf: Vec<u16> = vec![0u16; domain_len as usize];

    // SAFETY: We're passing valid, non-null, correctly sized mutable buffers.
    // `PWSTR` wraps a *mut u16 pointing at the start of each Vec.
    let result = unsafe {
        LookupAccountSidW(
            None,
            psid,
            PWSTR(name_buf.as_mut_ptr()),
            &mut name_len,
            PWSTR(domain_buf.as_mut_ptr()),
            &mut domain_len,
            sid_name_use.as_mut_ptr(),
        )
    };

    if let Err(e) = result {
        let win32_err = WIN32_ERROR(e.code().0 as u32);
        if win32_err == ERROR_NONE_MAPPED {
            return Ok(ResolvedSid::Orphaned {
                raw_sid: sid_to_string(psid),
            });
        }
        return Err(AuditorError::SidResolution {
            sid_string: sid_to_string(psid),
            code: win32_err.0,
        });
    }

    // ── Step 3: UTF-16 → Rust String conversion ─────────────────────────────
    // Trim at the null terminator (name_len on success = chars WITHOUT null).
    let account_name = String::from_utf16(&name_buf[..name_len as usize]).map_err(|e| {
        AuditorError::Utf16Decode {
            path: "<SID name buffer>".to_string(),
            source: e,
        }
    })?;

    let domain_name =
        String::from_utf16(&domain_buf[..domain_len as usize]).map_err(|e| {
            AuditorError::Utf16Decode {
                path: "<SID domain buffer>".to_string(),
                source: e,
            }
        })?;

    let display = if domain_name.is_empty() {
        account_name.clone()
    } else {
        format!("{}\\{}", domain_name, account_name)
    };

    Ok(ResolvedSid::Account {
        account_name,
        domain_name,
        display,
    })
}

/// Stub for non-Windows compilation targets (CI, cross-check).
#[cfg(not(target_os = "windows"))]
pub fn resolve_sid(_psid: *mut std::ffi::c_void) -> Result<ResolvedSid> {
    Err(crate::errors::AuditorError::NonWindowsPlatform)
}

/// Convert a PSID to its canonical string form (e.g., "S-1-5-32-544").
///
/// Uses `ConvertSidToStringSidW` under the hood. This is used as a fallback
/// display name for orphaned SIDs and in error messages.
#[cfg(target_os = "windows")]
pub fn sid_to_string(psid: PSID) -> String {
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;

    let mut sid_string_ptr = PWSTR::null();

    // SAFETY: psid is assumed valid (checked by caller), sid_string_ptr
    // receives a LocalAlloc'd buffer that we must free with LocalFree.
    let ok = unsafe { ConvertSidToStringSidW(psid, &mut sid_string_ptr) };

    if ok.is_err() {
        return "<unreadable SID>".to_string();
    }

    // SAFETY: On success, sid_string_ptr points to a valid null-terminated
    // UTF-16 string allocated by LocalAlloc.
    let result = unsafe {
        // Find null terminator to determine length
        let mut len = 0usize;
        while *sid_string_ptr.0.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(sid_string_ptr.0, len);
        String::from_utf16_lossy(slice)
    };

    // SAFETY: We must free the LocalAlloc'd buffer. Failure to do so leaks
    // memory. On a scan of 500k directories this adds up fast.
    unsafe {
        windows::Win32::Foundation::LocalFree(
            windows::Win32::Foundation::HLOCAL(sid_string_ptr.0 as *mut _),
        );
    }

    result
}

#[cfg(not(target_os = "windows"))]
pub fn sid_to_string(_psid: *mut std::ffi::c_void) -> String {
    "<non-windows>".to_string()
}
