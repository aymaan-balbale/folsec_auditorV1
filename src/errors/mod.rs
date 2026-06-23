//! Central error hierarchy for folsec-auditor.
//!
//! Design principle: NEVER panic on an enterprise file server. Every failure
//! mode is a typed variant here, so callers can decide whether to skip a path,
//! log a warning, or abort the entire scan. Most callers will `log & continue`.

use thiserror::Error;

/// Top-level error type for all auditor operations.
#[derive(Debug, Error)]
pub enum AuditorError {
    // ── Scanner Errors ──────────────────────────────────────────────────────
    /// Returned when `GetNamedSecurityInfoW` fails for a given path.
    #[error("Failed to read security descriptor for '{path}': Win32 error {code:#010x}")]
    SecurityDescriptorRead { path: String, code: u32 },

    /// Returned when `GetSecurityDescriptorDacl` reports an absent DACL.
    /// This is unusual but valid on some objects (e.g., kernel objects with
    /// no DACL = implicit allow-all, a critical finding in itself).
    #[error("No DACL present on '{path}' (implicit allow-all — critical risk)")]
    NoDacl { path: String },

    /// Returned when SID→account name resolution fails via `LookupAccountSidW`.
    /// Common cause: SID references a deleted AD account (orphaned SID).
    #[error("SID resolution failed for '{sid_string}': Win32 error {code:#010x}")]
    SidResolution { sid_string: String, code: u32 },

    /// The Win32 API returned a buffer that could not be decoded as valid UTF-16.
    #[error("Invalid UTF-16 in Win32 buffer for path '{path}': {source}")]
    Utf16Decode {
        path: String,
        #[source]
        source: std::string::FromUtf16Error,
    },

    // ── I/O / Traversal Errors ──────────────────────────────────────────────
    /// Wraps `walkdir::Error` for directory traversal failures.
    #[error("Directory traversal error: {0}")]
    Traversal(#[from] walkdir::Error),

    /// Generic I/O error (file creation, writing reports, etc.)
    #[error("I/O error on '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    // ── Report / Output Errors ──────────────────────────────────────────────
    /// JSON serialization failure (should be unreachable for our data types).
    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    // ── Simulator Errors ────────────────────────────────────────────────────
    /// The anomaly simulator failed to set up its temporary directory.
    #[error("Anomaly simulator setup failed: {0}")]
    SimulatorSetup(String),

    // ── Platform Guard ──────────────────────────────────────────────────────
    /// Returned on non-Windows platforms. The ACL scanner is Windows-only.
    #[error("This tool requires Windows (NTFS ACL scanning is Win32-only)")]
    NonWindowsPlatform,
}

/// Convenience alias used throughout the codebase.
pub type Result<T> = std::result::Result<T, AuditorError>;

/// A per-path error that is collected during scanning rather than aborting.
/// The scan continues; these are surfaced in the final report's "Errors" section.
#[derive(Debug, serde::Serialize)]
pub struct ScanError {
    pub path: String,
    pub message: String,
}

impl ScanError {
    pub fn new(path: impl Into<String>, err: &AuditorError) -> Self {
        Self {
            path: path.into(),
            message: err.to_string(),
        }
    }
}
