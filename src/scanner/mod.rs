//! High-speed parallel directory scanner.
//!
//! Architecture:
//!   1. `walkdir` yields `DirEntry` items lazily (low memory, handles deep trees).
//!   2. `rayon::par_bridge()` distributes entries across the thread pool.
//!   3. Each thread calls `acl::extract_dacl_findings` independently.
//!   4. Results are merged into a `DashMap` (concurrent HashMap) without locking.
//!   5. After traversal, we drain the map into a sorted `Vec<RiskFinding>`.
//!
//! Memory model: At no point do we load ALL paths into memory. walkdir streams
//! them. Only the findings (much smaller) accumulate in RAM.

pub mod acl;
pub mod risk;
pub mod sid;

use dashmap::DashMap;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use walkdir::WalkDir;

use crate::errors::ScanError;
pub use risk::{AuditSummary, RiskFinding, Severity};

/// Configuration for a scan run, derived from CLI args.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Root path to start scanning from.
    pub root_path: String,

    /// Maximum directory depth to recurse. 0 = unlimited.
    pub max_depth: usize,

    /// If true, follow symbolic links (risky on some enterprise shares — opt-in).
    pub follow_symlinks: bool,

    /// If true, skip paths that return an access denied error rather than logging them.
    pub skip_access_denied: bool,
}

/// The complete output of a scan run.
#[derive(Debug)]
pub struct ScanResult {
    pub findings: Vec<RiskFinding>,
    pub errors: Vec<ScanError>,
    pub summary: AuditSummary,
}

/// Run the full parallel ACL scan from `config.root_path`.
///
/// This function blocks until all directories have been processed.
/// Progress is displayed via an `indicatif` spinner on stderr.
pub fn run_scan(config: &ScanConfig) -> ScanResult {
    // ── Progress display ─────────────────────────────────────────────────────
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::with_template(
            "{spinner:.cyan} [{elapsed_precise}] Scanned {pos} paths — {msg}",
        )
        .unwrap()
        .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "),
    );
    spinner.set_message("starting...");

    // ── Shared accumulators (thread-safe) ────────────────────────────────────
    // DashMap shards its HashMap across CPU-count buckets internally, so
    // concurrent writes from rayon threads don't contend on a single lock.
    let findings_map: Arc<DashMap<String, Vec<RiskFinding>>> = Arc::new(DashMap::new());
    let errors_vec: Arc<std::sync::Mutex<Vec<ScanError>>> = Arc::new(std::sync::Mutex::new(Vec::new()));

    let paths_scanned = Arc::new(AtomicU64::new(0));
    let ps_clone = Arc::clone(&paths_scanned);

    // ── Build walkdir iterator ───────────────────────────────────────────────
    let walker = {
        let mut builder = WalkDir::new(&config.root_path);

        if config.max_depth > 0 {
            builder = builder.max_depth(config.max_depth);
        }

        builder = builder.follow_links(config.follow_symlinks);

        // `same_file_system` prevents traversal jumping to network mounts
        // unexpectedly on SMB shares with junction points.
        builder = builder.same_file_system(true);

        builder.into_iter()
    };

    // ── Parallel traversal ───────────────────────────────────────────────────
    // `par_bridge()` is the bridge from walkdir's Iterator to rayon's
    // ParallelIterator. It spins up rayon's global thread pool (defaults to
    // num_cpus threads). Each item is processed independently.
    walker
        .filter_map(|entry_result| {
            match entry_result {
                Ok(entry) => {
                    // Only scan directories — files don't have independent DACLs
                    // in a typical NTFS setup (they inherit from their parent).
                    // Scanning only dirs dramatically reduces API call count.
                    if entry.file_type().is_dir() {
                        Some(entry)
                    } else {
                        None
                    }
                }
                Err(e) => {
                    // walkdir error (e.g., no permission to list a directory).
                    let path = e.path().map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| "<unknown>".to_string());

                    if !(config.skip_access_denied
                        && e.io_error()
                            .map(|ie| ie.kind() == std::io::ErrorKind::PermissionDenied)
                            .unwrap_or(false))
                    {
                        let scan_err = ScanError {
                            path,
                            message: e.to_string(),
                        };
                        // Locking the errors mutex is infrequent — only on
                        // traversal errors, not for every directory entry.
                        errors_vec.lock().unwrap().push(scan_err);
                    }
                    None
                }
            }
        })
        .par_bridge() // ← This line is where single-threaded becomes parallel
        .for_each(|entry| {
            let path_str = entry.path().to_string_lossy().to_string();

            // Update progress counter (relaxed ordering: approximate count is fine)
            let count = ps_clone.fetch_add(1, Ordering::Relaxed) + 1;
            if count % 500 == 0 {
                // Updating the spinner on every entry would add contention.
                // Updating every 500 entries is imperceptible to the user.
                spinner.set_position(count);
                spinner.set_message(
                    entry.path()
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default(),
                );
            }

            // ── The actual ACL scan ──────────────────────────────────────────
            match acl::extract_dacl_findings(&path_str) {
                Ok(path_findings) => {
                    if !path_findings.is_empty() {
                        findings_map.insert(path_str, path_findings);
                    }
                }
                Err(e) => {
                    let scan_err = ScanError::new(&path_str, &e);
                    // Mutex contention here is minimal — errors should be rare.
                    // A lock-free structure (e.g., SegQueue) is a V2 optimization.
                    errors_vec.lock().unwrap().push(scan_err);
                }
            }
        });

    spinner.finish_with_message(format!(
        "Scan complete — {} directories examined.",
        paths_scanned.load(Ordering::Relaxed)
    ));

    // ── Collect and sort results ─────────────────────────────────────────────
    // Drain the DashMap into a flat Vec, sorted by severity (critical first)
    // then by path (alphabetical within same severity).
    let mut all_findings: Vec<RiskFinding> = Arc::try_unwrap(findings_map)
        .expect("all rayon threads finished; Arc should have single reference")
        .into_iter()
        .flat_map(|(_, v)| v)
        .collect();

    all_findings.sort_by(|a, b| {
        b.severity.cmp(&a.severity).then(a.path.cmp(&b.path))
    });

    let errors = Arc::try_unwrap(errors_vec)
        .expect("all threads finished")
        .into_inner()
        .unwrap();

    let total_paths = paths_scanned.load(Ordering::Relaxed);
    let summary = AuditSummary::from_findings(&all_findings, total_paths, errors.len() as u64);

    ScanResult {
        findings: all_findings,
        errors,
        summary,
    }
}
