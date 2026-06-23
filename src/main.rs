//! folsec-auditor — NTFS ACL Risk Auditor
//!
//! A blazing-fast, single-binary point-in-time gap analyzer for enterprise
//! file server permissions. Outputs a self-contained HTML report and an
//! optional dry-run PowerShell remediation script.
//!
//! Usage:
//!   folsec-auditor.exe scan --root "\\fileserver\share" --output report.html
//!   folsec-auditor.exe scan --root "C:\Data" --output report.html --remediation fix.ps1
//!   folsec-auditor.exe scan --root "C:\Data" --output report.html --simulate-anomaly
//!
//! Build:
//!   cargo build --release --target x86_64-pc-windows-msvc

// Deny common footguns at the crate level.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod errors;
mod remediation;
mod reporter;
mod scanner;
mod simulator;

use errors::AuditorError;
use scanner::ScanConfig;

// ── CLI Definition ────────────────────────────────────────────────────────────

/// FolSec NTFS ACL Risk Auditor
///
/// Point-in-time gap analysis for enterprise NTFS file server permissions.
/// Exposes over-permissive ACEs, inheritance breaks, orphaned SIDs, and
/// SIEM visibility gaps. Outputs a self-contained HTML report.
#[derive(Parser, Debug)]
#[command(
    name = "folsec-auditor",
    version = env!("CARGO_PKG_VERSION"),
    author  = "FolSec Security Research",
    long_about = None,
    term_width = 100,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan a directory tree for NTFS ACL risks and generate a report.
    Scan(ScanArgs),
    /// Print version and build information.
    Version,
}

/// Arguments for the `scan` subcommand.
#[derive(clap::Args, Debug)]
struct ScanArgs {
    /// Root path to scan (local or UNC). E.g.: C:\DataFiles, \\server\HR
    #[arg(short, long, value_name = "PATH")]
    root: String,

    /// Output path for the self-contained HTML report.
    #[arg(short, long, value_name = "FILE", default_value = "folsec_report.html")]
    output: PathBuf,

    /// Optional: output path for the dry-run PowerShell remediation script.
    /// The generated script only prints what WOULD be done — never modifies ACLs.
    #[arg(long, value_name = "FILE")]
    remediation: Option<PathBuf>,

    /// Maximum directory depth (0 = unlimited).
    #[arg(long, value_name = "N", default_value = "0")]
    max_depth: usize,

    /// Follow symbolic links (CAUTION on SMB shares with junction points).
    #[arg(long, default_value = "false")]
    follow_symlinks: bool,

    /// Skip access-denied directories silently instead of logging them.
    #[arg(long, default_value = "false")]
    skip_access_denied: bool,

    /// Run the anomaly simulator: cycles ACLs on 50 temp files to expose
    /// SIEM blind spots. AUTHORIZED USE ONLY.
    #[arg(long, default_value = "false")]
    simulate_anomaly: bool,

    /// Number of rayon worker threads (0 = all logical CPUs).
    #[arg(long, value_name = "N", default_value = "0")]
    threads: usize,
}

// ── Entry Point ───────────────────────────────────────────────────────────────

fn main() {
    if let Err(e) = run() {
        eprintln!("\n[ERROR] {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), AuditorError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Version => {
            println!(
                "folsec-auditor {} ({})",
                env!("CARGO_PKG_VERSION"),
                if cfg!(target_os = "windows") { "windows" } else { "non-windows (ACL scan disabled)" }
            );
            Ok(())
        }
        Commands::Scan(args) => run_scan(args),
    }
}

fn run_scan(args: ScanArgs) -> Result<(), AuditorError> {
    // ── Platform warning ──────────────────────────────────────────────────
    if !cfg!(target_os = "windows") {
        eprintln!(
            "[WARN] Non-Windows platform detected. ACL scanning requires Win32 APIs. \
             Report will be generated with zero findings (useful for CI testing)."
        );
    }

    // ── Thread pool ───────────────────────────────────────────────────────
    if args.threads > 0 {
        // Ignore error if global pool is already initialized (e.g. in tests).
        rayon::ThreadPoolBuilder::new()
            .num_threads(args.threads)
            .build_global()
            .ok();
    }

    println!(
        "\nFolSec NTFS Auditor v{} — Starting scan",
        env!("CARGO_PKG_VERSION")
    );
    println!("Root:      {}", args.root);
    println!(
        "Max depth: {}",
        if args.max_depth == 0 {
            "unlimited".to_string()
        } else {
            args.max_depth.to_string()
        }
    );
    println!(
        "Threads:   {}",
        if args.threads == 0 {
            "auto (all CPUs)".to_string()
        } else {
            args.threads.to_string()
        }
    );
    println!("Output:    {}", args.output.display());
    println!();

    // ── Anomaly simulation ────────────────────────────────────────────────
    let mut simulation_finding = None;

    if args.simulate_anomaly {
        println!(
            "⚠  Anomaly simulator enabled.\n   \
             This will create 50 temp files, cycle their ACLs 2,500 times,\n   \
             then delete them. Continue? [y/N] "
        );
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();

        if input.trim().to_lowercase() == "y" {
            match simulator::run_simulation(&args.root) {
                Ok(sim_result) => {
                    println!(
                        "[SIM] Done. {} ACL cycles in {}ms.",
                        50 * 50,
                        sim_result.cycling_elapsed_ms
                    );
                    simulation_finding = Some(sim_result.finding);
                }
                Err(e) => {
                    eprintln!("[WARN] Anomaly simulation failed: {}. Continuing scan.", e);
                }
            }
        } else {
            println!("Simulation cancelled. Proceeding with scan only.");
        }
    }

    // ── Main scan ─────────────────────────────────────────────────────────
    let config = ScanConfig {
        root_path: args.root.clone(),
        max_depth: args.max_depth,
        follow_symlinks: args.follow_symlinks,
        skip_access_denied: args.skip_access_denied,
    };

    let mut scan_result = scanner::run_scan(&config);

    // Inject simulation finding at the top (Critical → sorts first).
    if let Some(finding) = simulation_finding {
        scan_result.findings.insert(0, finding);
    }

    // Recompute summary after any injection.
    scan_result.summary = scanner::risk::AuditSummary::from_findings(
        &scan_result.findings,
        scan_result.summary.paths_scanned,
        scan_result.summary.paths_with_errors,
    );

    // ── Console summary ───────────────────────────────────────────────────
    let s = &scan_result.summary;
    println!("\n── Scan Complete ───────────────────────────────────────────");
    println!("  Paths scanned:  {}", s.paths_scanned);
    println!("  Total findings: {}", s.total_findings);
    println!("  CRITICAL:       {}", s.critical_count);
    println!("  HIGH:           {}", s.high_count);
    println!("  MEDIUM:         {}", s.medium_count);
    println!("  LOW:            {}", s.low_count);
    println!("  Scan errors:    {}", s.paths_with_errors);
    println!("────────────────────────────────────────────────────────────\n");

    // ── HTML report ───────────────────────────────────────────────────────
    reporter::generate_html_report(&scan_result, &args.root, &args.output)?;
    println!("✓ HTML report:    {}", args.output.display());

    // ── PowerShell remediation script ─────────────────────────────────────
    if let Some(ps1_path) = &args.remediation {
        remediation::generate_remediation_script(
            &scan_result.findings,
            &args.root,
            ps1_path,
        )?;
        println!("✓ Dry-run script: {}", ps1_path.display());
    }

    println!("\nOpen the HTML report in any browser to begin triage.");
    println!("For continuous monitoring: https://folsec.com\n");

    Ok(())
}
