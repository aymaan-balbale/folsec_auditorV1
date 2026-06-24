//! Risk classification types.
//!
//! These structs are the canonical data model for all ACL findings.
//! They derive `Serialize` so they flow directly into the HTML report's
//! embedded JSON data island without any transformation layer.
//!
//! ## Context-Aware Severity (v1.2)
//!
//! Severity is now a function of BOTH the trustee and the file path:
//!   - **Sensitive paths** (HR, Finance, Legal, Top_Secret, Confidential, Admin)
//!     escalate severity by one or two levels.
//!   - **Public paths** (Public, Drop, Common, Temp) de-escalate since broad
//!     access is often intentional on shared drop folders.
//!   - **General paths** use the baseline severity matrix.

use serde::Serialize;

// ── Path Context Classification ─────────────────────────────────────────────

/// Substrings that indicate a path contains sensitive organizational data.
/// Case-insensitive matching is applied against the full path string.
const SENSITIVE_KEYWORDS: &[&str] = &[
    "HR", "Finance", "Legal", "Top_Secret", "Confidential", "Admin",
];

/// Substrings that indicate a path is intentionally public / shared.
/// Case-insensitive matching is applied against the full path string.
const PUBLIC_KEYWORDS: &[&str] = &[
    "Public", "Drop", "Common", "Temp",
];

/// The contextual classification of a filesystem path, used to modulate
/// severity scores for the same ACL finding across different folder types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathContext {
    /// Path contains sensitive organizational data keywords.
    Sensitive,
    /// Path is intentionally public / shared.
    Public,
    /// Path does not match any known classification.
    General,
}

/// Classify a path string into a `PathContext` based on keyword matching.
///
/// Uses case-insensitive substring matching against the full path.
/// Sensitive classification takes priority if both match (defense-in-depth).
pub fn classify_path(path: &str) -> PathContext {
    let path_lower = path.to_lowercase();

    // Sensitive takes priority — if someone names a folder "Public_HR_Drop",
    // we want to treat it as sensitive, not public.
    if SENSITIVE_KEYWORDS.iter().any(|kw| path_lower.contains(&kw.to_lowercase())) {
        return PathContext::Sensitive;
    }

    if PUBLIC_KEYWORDS.iter().any(|kw| path_lower.contains(&kw.to_lowercase())) {
        return PathContext::Public;
    }

    PathContext::General
}

/// Severity levels used for triage and colour-coding in the HTML report.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    /// Informational — not a risk, but worth noting (e.g., explicit Allow Read).
    Info,
    /// Low — deviation from best practice but not an immediate threat.
    Low,
    /// Medium — meaningful exposure (e.g., Authenticated Users with Modify).
    Medium,
    /// High — serious over-permissive ACE (e.g., Everyone Full Control).
    High,
    /// Critical — implicit allow-all (missing DACL) or confirmed ransomware-like
    /// ACL cycling detected via the anomaly simulator.
    Critical,
}

/// The type of ACL risk identified on a specific path.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskKind {
    /// "Everyone" or "BUILTIN\Users" with write/modify/full-control permissions.
    /// This is the #1 ransomware blast-radius amplifier in enterprise environments.
    OverPermissiveAce {
        trustee: String,
        access_mask: u32,
        access_mask_human: String,
    },

    /// The folder explicitly blocks inherited permissions from its parent.
    /// This creates "permission islands" that are invisible to top-down audits,
    /// and is the most common source of GDPR/KVKK compliance gaps.
    InheritanceBreak {
        /// True if any ACEs were copied from the parent at the time of the break.
        had_protected_copy: bool,
    },

    /// The SID in an ACE could not be resolved to an active account name.
    /// Indicates a deleted AD user/group whose permissions were never cleaned up.
    /// In large orgs, 5–15% of ACEs can be orphaned SIDs after mergers/offboarding.
    OrphanedSid {
        raw_sid: String,
    },

    /// A folder has NO DACL at all. Win32 semantics: implicit allow-all for
    /// every user on the system. This is almost always a misconfiguration.
    NullDacl,

    /// The anomaly simulator detected rapid ACL cycling — simulated ransomware
    /// behavior that a SIEM with real-time audit visibility would have caught.
    AnomalySimulated {
        cycles_in_ms: u64,
    },
}

/// A single risk finding attached to one filesystem path.
#[derive(Debug, Clone, Serialize)]
pub struct RiskFinding {
    /// The canonical absolute path of the affected directory.
    pub path: String,

    /// Severity of this specific finding.
    pub severity: Severity,

    /// Detailed risk classification with associated metadata.
    pub risk: RiskKind,

    /// Human-readable explanation for the IT admin reading the report.
    pub description: String,

    /// One-liner suggestion for the PowerShell remediation script.
    pub remediation_hint: String,
}

impl RiskFinding {
    /// Convenience constructor for over-permissive ACE findings.
    ///
    /// **Severity escalation rules (v1.2 — context-aware)**:
    ///
    /// | Trustee                          | Sensitive Path | General Path | Public Path |
    /// |----------------------------------|----------------|--------------|-------------|
    /// | Everyone + FullControl/Modify     | CRITICAL       | HIGH         | MEDIUM      |
    /// | Auth Users / BUILTIN\Users + FC/M | HIGH           | MEDIUM       | MEDIUM      |
    /// | Other broad trustees              | MEDIUM         | MEDIUM       | LOW         |
    pub fn over_permissive(
        path: String,
        trustee: String,
        access_mask: u32,
        access_mask_human: String,
    ) -> Self {
        let trustee_lower = trustee.to_lowercase();
        let is_full_control_or_modify =
            access_mask & 0x001F01FF == 0x001F01FF  // Full Control
            || access_mask & 0x000301BF == 0x000301BF; // Modify (approximation)
        let is_everyone = trustee_lower.contains("everyone");
        let is_auth_users = trustee_lower.contains("authenticated users");
        let is_builtin_users = trustee_lower.contains("users");

        let ctx = classify_path(&path);

        let severity = if is_everyone && is_full_control_or_modify {
            // "Everyone" with FullControl/Modify — escalation depends on path.
            match ctx {
                PathContext::Sensitive => Severity::Critical,
                PathContext::General   => Severity::High,
                PathContext::Public    => Severity::Medium,
            }
        } else if (is_auth_users || is_builtin_users) && is_full_control_or_modify {
            // "Authenticated Users" or "BUILTIN\Users" with FullControl/Modify.
            match ctx {
                PathContext::Sensitive => Severity::High,
                PathContext::General   => Severity::Medium,
                PathContext::Public    => Severity::Medium,
            }
        } else if is_everyone {
            // Everyone with lesser write permissions — still escalate on sensitive.
            match ctx {
                PathContext::Sensitive => Severity::High,
                PathContext::General   => Severity::High,
                PathContext::Public    => Severity::Medium,
            }
        } else {
            // Other broad trustees (Anonymous Logon, Creator Owner, etc.)
            match ctx {
                PathContext::Sensitive => Severity::Medium,
                PathContext::General   => Severity::Medium,
                PathContext::Public    => Severity::Low,
            }
        };

        let ctx_label = match ctx {
            PathContext::Sensitive => " [SENSITIVE PATH]",
            PathContext::Public    => " [PUBLIC PATH]",
            PathContext::General   => "",
        };

        let description = format!(
            "Trustee '{}' has over-permissive access ({}).{} \
             This creates a wide blast radius for ransomware or insider threats.",
            trustee, access_mask_human, ctx_label
        );

        let remediation_hint = format!(
            "Remove or restrict explicit ACE for '{}' on this path. \
             Consider replacing with a specific AD security group.",
            trustee
        );

        Self {
            path,
            severity,
            risk: RiskKind::OverPermissiveAce {
                trustee,
                access_mask,
                access_mask_human,
            },
            description,
            remediation_hint,
        }
    }

    /// Convenience constructor for inheritance break findings.
    pub fn inheritance_break(path: String, had_protected_copy: bool) -> Self {
        Self {
            path: path.clone(),
            severity: Severity::Medium,
            risk: RiskKind::InheritanceBreak { had_protected_copy },
            description: format!(
                "Path '{}' explicitly blocks permission inheritance from its parent. \
                 This creates a hidden permission island invisible to top-down audits \
                 and is a common GDPR/KVKK compliance gap.",
                path
            ),
            remediation_hint:
                "Re-enable inheritance or document the explicit permission deviation \
                 in your governance register."
                    .to_string(),
        }
    }

    /// Convenience constructor for orphaned SID findings.
    ///
    /// **Context-aware severity (v1.2)**:
    ///   - Orphaned SIDs on sensitive paths = HIGH (stale permissions on
    ///     regulated data are a compliance violation waiting to happen).
    ///   - Orphaned SIDs elsewhere = LOW (hygiene issue, not an urgent risk).
    pub fn orphaned_sid(path: String, raw_sid: String) -> Self {
        let ctx = classify_path(&path);

        let severity = match ctx {
            PathContext::Sensitive => Severity::High,
            PathContext::General | PathContext::Public => Severity::Low,
        };

        let ctx_label = match ctx {
            PathContext::Sensitive => " This is a SENSITIVE path — stale permissions \
                 here are a compliance risk (GDPR/KVKK/SOX).",
            _ => "",
        };

        Self {
            path: path.clone(),
            severity,
            risk: RiskKind::OrphanedSid {
                raw_sid: raw_sid.clone(),
            },
            description: format!(
                "ACE on '{}' references SID '{}' which could not be resolved to \
                 an active AD account. This is typically a deleted user or group \
                 whose permissions were never cleaned up.{}",
                path, raw_sid, ctx_label
            ),
            remediation_hint: format!(
                "Remove ACE for unresolvable SID '{}'. Run 'Get-ADObject -Filter \
                 {{objectSid -eq \"{}\"}}' to confirm deletion.",
                raw_sid, raw_sid
            ),
        }
    }

    /// Convenience constructor for null/missing DACL findings.
    pub fn null_dacl(path: String) -> Self {
        Self {
            path: path.clone(),
            severity: Severity::Critical,
            risk: RiskKind::NullDacl,
            description: format!(
                "Path '{}' has NO DACL. Windows interprets a missing DACL as \
                 IMPLICIT ALLOW ALL ACCESS for every user on the system. \
                 This is almost certainly a misconfiguration.",
                path
            ),
            remediation_hint:
                "Immediately apply a restrictive explicit DACL. A null DACL is \
                 not the same as an empty DACL (deny all) — it is allow all."
                    .to_string(),
        }
    }
}

/// Summary statistics computed from all findings, embedded in the report header.
#[derive(Debug, Default, Serialize)]
pub struct AuditSummary {
    pub paths_scanned: u64,
    pub paths_with_errors: u64,
    pub total_findings: u64,
    pub critical_count: u64,
    pub high_count: u64,
    pub medium_count: u64,
    pub low_count: u64,
    pub info_count: u64,
    pub inheritance_breaks: u64,
    pub orphaned_sids: u64,
    pub null_dacls: u64,
}

impl AuditSummary {
    /// Compute summary statistics from a slice of findings.
    pub fn from_findings(findings: &[RiskFinding], paths_scanned: u64, error_count: u64) -> Self {
        let mut s = Self {
            paths_scanned,
            paths_with_errors: error_count,
            total_findings: findings.len() as u64,
            ..Default::default()
        };

        for f in findings {
            match f.severity {
                Severity::Critical => s.critical_count += 1,
                Severity::High => s.high_count += 1,
                Severity::Medium => s.medium_count += 1,
                Severity::Low => s.low_count += 1,
                Severity::Info => s.info_count += 1,
            }
            match &f.risk {
                RiskKind::InheritanceBreak { .. } => s.inheritance_breaks += 1,
                RiskKind::OrphanedSid { .. } => s.orphaned_sids += 1,
                RiskKind::NullDacl => s.null_dacls += 1,
                _ => {}
            }
        }

        s
    }
}
