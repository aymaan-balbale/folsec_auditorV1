//! Risk classification types.
//!
//! These structs are the canonical data model for all ACL findings.
//! They derive `Serialize` so they flow directly into the HTML report's
//! embedded JSON data island without any transformation layer.

use serde::Serialize;

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
    pub fn over_permissive(
        path: String,
        trustee: String,
        access_mask: u32,
        access_mask_human: String,
    ) -> Self {
        let severity = if trustee.to_lowercase().contains("everyone") {
            Severity::High
        } else {
            Severity::Medium
        };

        let description = format!(
            "Trustee '{}' has over-permissive access ({}). \
             This creates a wide blast radius for ransomware or insider threats.",
            trustee, access_mask_human
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
    pub fn orphaned_sid(path: String, raw_sid: String) -> Self {
        Self {
            path: path.clone(),
            severity: Severity::Low,
            risk: RiskKind::OrphanedSid {
                raw_sid: raw_sid.clone(),
            },
            description: format!(
                "ACE on '{}' references SID '{}' which could not be resolved to \
                 an active AD account. This is typically a deleted user or group \
                 whose permissions were never cleaned up.",
                path, raw_sid
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
