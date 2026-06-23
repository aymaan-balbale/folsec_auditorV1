//! Self-contained HTML report generator (air-gap safe).
//!
//! Produces a single `.html` file that:
//!   - Embeds ALL CSS inline inside a `<style>` tag — zero CDN dependencies.
//!   - Embeds all scan data as a JSON island (`window.__FOLSEC_DATA__`).
//!   - Uses vanilla JS (no build step, no bundler) to render the findings table.
//!   - Renders identically on air-gapped enterprise servers with no internet.
//!
//! Design: Dark terminal aesthetic with red/amber severity accents.
//! The monospace font reinforces the path/SID data nature. All layout is
//! done with CSS Grid and Flexbox — no framework dependency.

mod html;

use std::path::Path;

use crate::{
    errors::{AuditorError, Result},
    scanner::ScanResult,
};

/// Generate and write the self-contained HTML report.
pub fn generate_html_report(
    result: &ScanResult,
    scan_root: &str,
    output_path: &Path,
) -> Result<()> {
    // Serialize the complete data payload as a JSON string.
    // serde_json::to_string_pretty is used for debuggability in the source;
    // in a production minified build this could be to_string() instead.
    let findings_json = serde_json::to_string_pretty(&result.findings)
        .map_err(AuditorError::Serialization)?;

    let summary_json = serde_json::to_string_pretty(&result.summary)
        .map_err(AuditorError::Serialization)?;

    let errors_json = serde_json::to_string_pretty(&result.errors)
        .map_err(AuditorError::Serialization)?;

    let scan_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    // Inject data into the template.
    let html = HTML_TEMPLATE
        .replace("__SCAN_ROOT__", &html_escape(scan_root))
        .replace("__SCAN_TIME__", &scan_time)
        .replace("__FINDINGS_JSON__", &findings_json)
        .replace("__SUMMARY_JSON__", &summary_json)
        .replace("__ERRORS_JSON__", &errors_json);

    std::fs::write(output_path, html).map_err(|e| AuditorError::Io {
        path: output_path.to_string_lossy().to_string(),
        source: e,
    })?;

    Ok(())
}

/// Minimal HTML escaping for values injected into HTML attributes/text.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// The complete self-contained HTML report template.
///
/// CRITICAL DESIGN DECISION: All CSS is embedded inline. This report MUST
/// render correctly with zero network access. Enterprise file servers are
/// often air-gapped or behind strict egress firewalls — a CDN-dependent
/// report would render as unstyled raw HTML in those environments.
///
/// Layout system: CSS Grid for the card grid, Flexbox for header/filter bars.
/// Typography: System monospace stack with web-safe fallbacks.
/// Color palette: GitHub-dark inspired (#0d1117 bg, #e6edf3 fg) with
/// severity accent colors matching industry conventions (red=critical,
/// orange=high, yellow=medium, blue=low, gray=info).
const HTML_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FolSec NTFS Audit Report — __SCAN_ROOT__</title>
  <style>
    /* ── Reset & Base ──────────────────────────────────────────────────── */
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      /* Severity palette */
      --col-critical:  #ef4444;
      --col-high:      #f97316;
      --col-medium:    #eab308;
      --col-low:       #3b82f6;
      --col-info:      #6b7280;

      /* Surface palette (GitHub Dark inspired) */
      --bg-body:       #0d1117;
      --bg-surface:    #161b22;
      --bg-elevated:   #1c2129;
      --border-color:  #30363d;
      --border-subtle: #21262d;

      /* Text palette */
      --text-primary:  #e6edf3;
      --text-secondary:#8b949e;
      --text-muted:    #484f58;
      --text-accent:   #58a6ff;

      /* Spacing scale */
      --sp-1: 0.25rem; --sp-2: 0.5rem; --sp-3: 0.75rem; --sp-4: 1rem;
      --sp-5: 1.25rem; --sp-6: 1.5rem; --sp-8: 2rem;

      /* Typography */
      --font-mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', 'SF Mono',
                   'Consolas', 'Liberation Mono', monospace;
      --font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica,
                   Arial, sans-serif;
    }

    body {
      background: var(--bg-body);
      color: var(--text-primary);
      font-family: var(--font-mono);
      font-size: 14px;
      line-height: 1.6;
      min-height: 100vh;
    }

    /* ── Layout Container ──────────────────────────────────────────────── */
    .container {
      max-width: 1600px;
      margin: 0 auto;
      padding: 0 var(--sp-8);
    }

    /* ── Header / Masthead ─────────────────────────────────────────────── */
    .masthead {
      border-bottom: 1px solid var(--border-color);
      padding: var(--sp-5) 0;
    }
    .masthead-inner {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: var(--sp-4);
    }
    .masthead-label {
      font-size: 0.65rem;
      color: var(--text-muted);
      letter-spacing: 0.15em;
      text-transform: uppercase;
      margin-bottom: var(--sp-1);
    }
    .masthead-title {
      font-size: 1.5rem;
      font-weight: 700;
      letter-spacing: -0.02em;
    }
    .masthead-title .red  { color: var(--col-critical); }
    .masthead-title .white { color: var(--text-primary); }
    .masthead-title .sub {
      color: var(--text-muted);
      font-weight: 400;
      font-size: 1rem;
      margin-left: var(--sp-2);
    }
    .masthead-meta {
      text-align: right;
      font-size: 0.7rem;
      color: var(--text-muted);
    }
    .masthead-meta span { color: var(--text-secondary); }

    /* ── Sections ──────────────────────────────────────────────────────── */
    main {
      padding: var(--sp-6) 0 var(--sp-8);
    }
    .section { margin-bottom: var(--sp-8); }
    .section-label {
      font-size: 0.65rem;
      color: var(--text-muted);
      letter-spacing: 0.15em;
      text-transform: uppercase;
      margin-bottom: var(--sp-3);
    }

    /* ── Summary Cards (CSS Grid) ──────────────────────────────────────── */
    .card-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
      gap: var(--sp-3);
    }
    .stat-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: var(--sp-3);
      text-align: center;
      transition: border-color 0.2s ease, transform 0.15s ease;
    }
    .stat-card:hover {
      border-color: var(--text-muted);
      transform: translateY(-1px);
    }
    .stat-card .val {
      font-size: 1.75rem;
      font-weight: 700;
      line-height: 1.2;
    }
    .stat-card .label {
      font-size: 0.65rem;
      color: var(--text-muted);
      margin-top: var(--sp-1);
    }

    /* Severity text colors */
    .text-critical { color: var(--col-critical); }
    .text-high     { color: var(--col-high); }
    .text-medium   { color: var(--col-medium); }
    .text-low      { color: var(--col-low); }
    .text-info     { color: var(--col-info); }
    .text-white    { color: var(--text-primary); }
    .text-secondary{ color: var(--text-secondary); }
    .text-purple   { color: #a78bfa; }
    .text-yellow   { color: #ca8a04; }
    .font-bold     { font-weight: 700; }

    /* ── Risk Banner ───────────────────────────────────────────────────── */
    .risk-banner {
      display: none;
      border-radius: 8px;
      padding: var(--sp-4);
      border: 1px solid #7f1d1d;
      background: rgba(127, 29, 29, 0.15);
      margin-bottom: var(--sp-8);
    }
    .risk-banner.visible { display: block; }
    .risk-banner p {
      color: #fca5a5;
      font-size: 0.8rem;
      line-height: 1.5;
    }

    /* ── Simulation Alert (highly visible callout) ─────────────────────── */
    .sim-alert {
      display: none;
      border-radius: 10px;
      padding: var(--sp-6);
      border: 2px solid var(--col-critical);
      background: linear-gradient(135deg, rgba(127,29,29,0.30) 0%, rgba(13,17,23,0.95) 100%);
      margin-bottom: var(--sp-8);
      position: relative;
      overflow: hidden;
    }
    .sim-alert.visible { display: block; }
    .sim-alert::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 3px;
      background: linear-gradient(90deg, var(--col-critical), var(--col-high), var(--col-critical));
      background-size: 200% 100%;
      animation: sim-pulse 2s ease-in-out infinite;
    }
    @keyframes sim-pulse {
      0%, 100% { background-position: 0% 50%; }
      50%      { background-position: 100% 50%; }
    }
    .sim-alert-badge {
      display: inline-block;
      background: var(--col-critical);
      color: #fff;
      font-size: 0.6rem;
      font-weight: 700;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      padding: var(--sp-1) var(--sp-3);
      border-radius: 4px;
      margin-bottom: var(--sp-3);
    }
    .sim-alert h3 {
      color: #fca5a5;
      font-size: 1rem;
      font-weight: 700;
      margin-bottom: var(--sp-2);
      font-family: var(--font-sans);
    }
    .sim-alert p {
      color: var(--text-secondary);
      font-size: 0.8rem;
      line-height: 1.6;
      max-width: 60rem;
    }
    .sim-alert .sim-stat {
      display: inline-block;
      color: var(--col-high);
      font-weight: 700;
      font-family: var(--font-mono);
    }

    /* ── Filters ───────────────────────────────────────────────────────── */
    .filter-bar {
      display: flex;
      flex-wrap: wrap;
      gap: var(--sp-3);
      align-items: center;
      margin-bottom: var(--sp-8);
    }
    .filter-bar .filter-label {
      font-size: 0.65rem;
      color: var(--text-muted);
      letter-spacing: 0.15em;
      text-transform: uppercase;
    }
    .filter-buttons {
      display: flex;
      flex-wrap: wrap;
      gap: var(--sp-2);
    }
    .filter-btn {
      font-family: var(--font-mono);
      font-size: 0.7rem;
      padding: var(--sp-1) var(--sp-3);
      border-radius: 6px;
      border: 1px solid var(--border-color);
      background: transparent;
      color: var(--text-muted);
      cursor: pointer;
      transition: border-color 0.15s ease, color 0.15s ease, background 0.15s ease;
    }
    .filter-btn:hover {
      border-color: var(--text-muted);
      color: var(--text-secondary);
    }
    .filter-btn.active {
      border-color: var(--text-secondary);
      color: var(--text-primary);
      background: var(--bg-elevated);
    }
    .search-input {
      margin-left: auto;
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      padding: var(--sp-1) var(--sp-3);
      font-family: var(--font-mono);
      font-size: 0.8rem;
      color: var(--text-secondary);
      width: 18rem;
      outline: none;
      transition: border-color 0.15s ease;
    }
    .search-input::placeholder { color: var(--text-muted); }
    .search-input:focus { border-color: var(--text-muted); }

    /* ── Findings Table ────────────────────────────────────────────────── */
    .table-wrap {
      overflow-x: auto;
      border-radius: 8px;
      border: 1px solid var(--border-color);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.8rem;
    }
    thead {
      background: rgba(22, 27, 34, 0.6);
      border-bottom: 1px solid var(--border-color);
    }
    th {
      text-align: left;
      padding: var(--sp-2) var(--sp-3);
      font-size: 0.6rem;
      color: var(--text-muted);
      letter-spacing: 0.1em;
      text-transform: uppercase;
      font-weight: 600;
    }
    td {
      padding: var(--sp-2) var(--sp-3);
      vertical-align: top;
    }
    tr { border-bottom: 1px solid var(--border-subtle); }
    tr:last-child { border-bottom: none; }
    tr:hover td { background: var(--bg-surface); }

    .path-cell {
      font-size: 0.7rem;
      word-break: break-all;
      max-width: 30rem;
      color: var(--text-secondary);
    }
    .detail-cell { font-size: 0.7rem; }
    .remediation-cell {
      font-size: 0.7rem;
      color: var(--text-muted);
      max-width: 20rem;
    }
    .idx-cell {
      color: var(--text-muted);
      font-size: 0.65rem;
    }
    .type-cell {
      font-size: 0.65rem;
      color: var(--text-secondary);
      white-space: nowrap;
    }

    /* Severity badges */
    .badge {
      display: inline-block;
      font-size: 0.6rem;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 4px;
      font-family: var(--font-mono);
      letter-spacing: 0.05em;
    }
    .badge-CRITICAL { background: #7f1d1d; color: var(--col-critical); }
    .badge-HIGH     { background: #431407; color: var(--col-high); }
    .badge-MEDIUM   { background: #422006; color: var(--col-medium); }
    .badge-LOW      { background: #1e3a5f; color: var(--col-low); }
    .badge-INFO     { background: #1f2937; color: var(--col-info); }

    .no-results {
      display: none;
      text-align: center;
      padding: var(--sp-8) 0;
      color: var(--text-muted);
      font-size: 0.8rem;
    }
    .no-results.visible { display: block; }

    /* ── Errors Section ────────────────────────────────────────────────── */
    .errors-section { display: none; margin-bottom: var(--sp-8); }
    .errors-section.visible { display: block; }
    .errors-toggle {
      display: flex;
      align-items: center;
      gap: var(--sp-2);
      font-size: 0.65rem;
      color: #ca8a04;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      cursor: pointer;
      background: none;
      border: none;
      font-family: var(--font-mono);
    }
    .errors-toggle:hover { color: var(--col-medium); }
    .errors-toggle .chevron {
      width: 10px;
      height: 10px;
      transition: transform 0.2s ease;
    }
    .errors-toggle.open .chevron { transform: rotate(90deg); }
    .errors-list {
      display: none;
      margin-top: var(--sp-3);
      font-size: 0.7rem;
      font-family: var(--font-mono);
    }
    .errors-list.visible { display: block; }
    .error-item {
      color: #a16207;
      padding: 2px 0;
    }
    .error-item .error-path { color: var(--text-muted); }

    /* ── CTA / FolSec Promo ────────────────────────────────────────────── */
    .cta-section {
      border-radius: 12px;
      border: 1px solid rgba(127, 29, 29, 0.3);
      background: linear-gradient(to right, rgba(127,29,29,0.15), transparent);
      padding: var(--sp-6);
      margin-bottom: var(--sp-8);
    }
    .cta-inner {
      display: flex;
      flex-direction: column;
      gap: var(--sp-4);
    }
    @media (min-width: 768px) {
      .cta-inner {
        flex-direction: row;
        align-items: center;
        justify-content: space-between;
      }
    }
    .cta-inner h3 {
      color: var(--text-primary);
      font-weight: 600;
      font-size: 1.1rem;
      margin-bottom: var(--sp-1);
      font-family: var(--font-sans);
    }
    .cta-inner p {
      color: var(--text-muted);
      font-size: 0.8rem;
      max-width: 36rem;
      line-height: 1.6;
    }
    .cta-btn {
      display: inline-block;
      background: var(--col-critical);
      color: #fff;
      font-weight: 600;
      padding: var(--sp-3) var(--sp-6);
      border-radius: 8px;
      text-decoration: none;
      font-size: 0.85rem;
      font-family: var(--font-sans);
      transition: background 0.15s ease;
      white-space: nowrap;
      flex-shrink: 0;
    }
    .cta-btn:hover { background: #dc2626; }

    /* ── Responsive adjustments ────────────────────────────────────────── */
    @media (max-width: 640px) {
      .container { padding: 0 var(--sp-4); }
      .card-grid { grid-template-columns: repeat(2, 1fr); }
      .search-input { width: 100%; margin-left: 0; margin-top: var(--sp-2); }
      .filter-bar { flex-direction: column; align-items: flex-start; }
      .masthead-inner { flex-direction: column; align-items: flex-start; }
      .masthead-meta { text-align: left; }
    }
  </style>
</head>
<body>

  <!-- ── Masthead ──────────────────────────────────────────────────────── -->
  <header class="masthead">
    <div class="container masthead-inner">
      <div>
        <div class="masthead-label">Enterprise Security</div>
        <h1 class="masthead-title">
          <span class="red">Fol</span><span class="white">Sec</span>
          <span class="sub">// NTFS ACL Risk Report</span>
        </h1>
      </div>
      <div class="masthead-meta">
        <div>Scan root: <span>__SCAN_ROOT__</span></div>
        <div>Generated: <span>__SCAN_TIME__</span></div>
      </div>
    </div>
  </header>

  <main class="container">

    <!-- ── Summary Cards ─────────────────────────────────────────────── -->
    <section class="section">
      <h2 class="section-label">Scan Summary</h2>
      <div id="summary-cards" class="card-grid"></div>
    </section>

    <!-- ── Simulation Alert (highly visible) ──────────────────────────── -->
    <div id="sim-alert" class="sim-alert">
      <span class="sim-alert-badge">⚡ Anomaly Simulation Detected</span>
      <h3 id="sim-alert-title">SIEM Visibility Gap Confirmed</h3>
      <p id="sim-alert-body"></p>
    </div>

    <!-- ── Risk Exposure Banner ──────────────────────────────────────── -->
    <div id="risk-banner" class="risk-banner">
      <p id="risk-banner-text"></p>
    </div>

    <!-- ── Filters ────────────────────────────────────────────────────── -->
    <section class="filter-bar">
      <span class="filter-label">Filter:</span>
      <div id="filter-buttons" class="filter-buttons"></div>
      <input id="search-input" type="text" placeholder="Search path or trustee..."
        class="search-input" />
    </section>

    <!-- ── Findings Table ─────────────────────────────────────────────── -->
    <section class="section">
      <h2 class="section-label">
        Findings (<span id="visible-count">0</span> shown)
      </h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Severity</th>
              <th>Type</th>
              <th>Path</th>
              <th>Details</th>
              <th>Remediation</th>
            </tr>
          </thead>
          <tbody id="findings-tbody"></tbody>
        </table>
        <div id="no-results" class="no-results">
          No findings match your filters.
        </div>
      </div>
    </section>

    <!-- ── Errors Section ─────────────────────────────────────────────── -->
    <div id="errors-section" class="errors-section">
      <button id="errors-toggle" class="errors-toggle">
        <svg class="chevron" fill="currentColor" viewBox="0 0 20 20">
          <path d="M7.293 4.293a1 1 0 011.414 0L14 9.586a1 1 0 010 1.414L8.707 16.707a1 1 0 01-1.414-1.414L11.586 11H3a1 1 0 110-2h8.586L7.293 5.707a1 1 0 010-1.414z"/>
        </svg>
        Scan Errors (<span id="error-count">0</span>)
      </button>
      <div id="errors-list" class="errors-list"></div>
    </div>

    <!-- ── FolSec CTA ──────────────────────────────────────────────────── -->
    <section class="cta-section">
      <div class="cta-inner">
        <div>
          <h3>This was a point-in-time snapshot.</h3>
          <p>
            The risks above existed <em>right now</em>. FolSec provides continuous,
            real-time NTFS audit visibility with anomaly detection, automated remediation
            workflows, and GDPR/KVKK compliance dashboards — so you see the next change
            the moment it happens.
          </p>
        </div>
        <div>
          <a href="https://folsec.com/demo" target="_blank" class="cta-btn">
            Request a Live Demo →
          </a>
        </div>
      </div>
    </section>

  </main>

  <!-- ── Data Island ────────────────────────────────────────────────────── -->
  <script>
    window.__FOLSEC_DATA__ = {
      findings: __FINDINGS_JSON__,
      summary:  __SUMMARY_JSON__,
      errors:   __ERRORS_JSON__
    };
  </script>

  <!-- ── Report Logic (Vanilla JS — zero dependencies) ─────────────────── -->
  <script>
  (function() {
    var data = window.__FOLSEC_DATA__;
    var findings = data.findings;
    var summary  = data.summary;
    var errors   = data.errors;
    var activeFilter = 'ALL';
    var searchTerm   = '';

    // ── Helpers ─────────────────────────────────────────────────────────
    function $(id) { return document.getElementById(id); }
    function esc(s) {
      return String(s)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;')
        .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    var SEV_ORDER = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];

    function severityBadge(sev) {
      return '<span class="badge badge-' + sev + '">' + esc(sev) + '</span>';
    }

    function riskTypePretty(risk) {
      if (!risk || !risk.type) return '\u2014';
      return risk.type.replace(/_/g,' ');
    }

    function riskDetails(risk) {
      if (!risk) return '\u2014';
      switch(risk.type) {
        case 'OVER_PERMISSIVE_ACE':
          return '<span style="color:var(--col-high)">' + esc(risk.trustee) +
                 '</span> \u2192 ' + esc(risk.access_mask_human);
        case 'INHERITANCE_BREAK':
          return risk.had_protected_copy ? 'Protected copy present' : 'No inherited copy';
        case 'ORPHANED_SID':
          return '<span style="color:#ca8a04;font-size:0.65rem">' + esc(risk.raw_sid) + '</span>';
        case 'NULL_DACL':
          return '<span style="color:var(--col-critical)">Implicit ALLOW ALL</span>';
        case 'ANOMALY_SIMULATED':
          return '<span style="color:var(--col-high);font-weight:700">' +
                 risk.cycles_in_ms + 'ms</span> \u2014 SIEM blind spot';
        default:
          return esc(JSON.stringify(risk));
      }
    }

    // ── Summary Cards ────────────────────────────────────────────────────
    var cardDefs = [
      { label: 'Paths Scanned',    val: summary.paths_scanned,      cls: 'text-secondary' },
      { label: 'Total Findings',   val: summary.total_findings,     cls: 'text-white font-bold' },
      { label: 'CRITICAL',         val: summary.critical_count,     cls: 'text-critical font-bold' },
      { label: 'HIGH',             val: summary.high_count,         cls: 'text-high font-bold' },
      { label: 'MEDIUM',           val: summary.medium_count,       cls: 'text-medium' },
      { label: 'Inherit. Breaks',  val: summary.inheritance_breaks, cls: 'text-purple' },
      { label: 'Orphaned SIDs',    val: summary.orphaned_sids,      cls: 'text-yellow' },
      { label: 'Null DACLs',       val: summary.null_dacls,         cls: 'text-critical' }
    ];
    $('summary-cards').innerHTML = cardDefs.map(function(c) {
      return '<div class="stat-card">' +
        '<div class="val ' + c.cls + '">' + c.val + '</div>' +
        '<div class="label">' + c.label + '</div>' +
      '</div>';
    }).join('');

    // ── Simulation Alert ─────────────────────────────────────────────────
    // Check if any finding is ANOMALY_SIMULATED and surface it prominently.
    var simFinding = null;
    for (var i = 0; i < findings.length; i++) {
      if (findings[i].risk && findings[i].risk.type === 'ANOMALY_SIMULATED') {
        simFinding = findings[i];
        break;
      }
    }
    if (simFinding) {
      $('sim-alert').classList.add('visible');
      $('sim-alert-title').textContent =
        'SIEM Visibility Gap — ' + simFinding.risk.cycles_in_ms + 'ms of undetected ACL cycling';
      $('sim-alert-body').innerHTML =
        'The FolSec Anomaly Simulator executed <span class="sim-stat">2,500 ACL modifications</span> ' +
        'across 50 files in <span class="sim-stat">' + simFinding.risk.cycles_in_ms + 'ms</span>. ' +
        'This simulates the exact permission-stripping pattern used by ransomware during encryption. ' +
        'If your SIEM/EDR did <strong style="color:#fca5a5">NOT</strong> alert during this window, ' +
        'you have a confirmed blind spot. ' +
        '<br><br><strong style="color:var(--text-secondary)">Remediation:</strong> ' +
        esc(simFinding.remediation_hint);
    }

    // ── Risk Banner ───────────────────────────────────────────────────────
    if (summary.critical_count > 0 || summary.high_count > 0) {
      $('risk-banner').classList.add('visible');
      $('risk-banner-text').textContent =
        '\u26A0  ' + summary.critical_count + ' CRITICAL and ' + summary.high_count +
        ' HIGH severity findings detected. This environment has immediate exposure ' +
        'to data breach, ransomware blast-radius amplification, or compliance violations. ' +
        'Review critical findings first.';
    }

    // ── Filter Buttons ────────────────────────────────────────────────────
    var filterBtns = [{ label: 'All', key: 'ALL' }];
    for (var s = 0; s < SEV_ORDER.length; s++) {
      filterBtns.push({ label: SEV_ORDER[s], key: SEV_ORDER[s] });
    }
    $('filter-buttons').innerHTML = filterBtns.map(function(f) {
      return '<button data-filter="' + f.key + '" class="filter-btn' +
        (f.key === 'ALL' ? ' active' : '') + '">' + f.label + '</button>';
    }).join('');

    var btns = document.querySelectorAll('.filter-btn');
    for (var b = 0; b < btns.length; b++) {
      btns[b].addEventListener('click', function(e) {
        activeFilter = this.getAttribute('data-filter');
        var all = document.querySelectorAll('.filter-btn');
        for (var j = 0; j < all.length; j++) {
          if (all[j].getAttribute('data-filter') === activeFilter) {
            all[j].classList.add('active');
          } else {
            all[j].classList.remove('active');
          }
        }
        render();
      });
    }

    $('search-input').addEventListener('input', function(e) {
      searchTerm = e.target.value.toLowerCase();
      render();
    });

    // ── Main Render ───────────────────────────────────────────────────────
    function render() {
      var visible = [];
      for (var i = 0; i < findings.length; i++) {
        var f = findings[i];
        var sevMatch = activeFilter === 'ALL' || f.severity === activeFilter;
        var searchMatch = !searchTerm ||
          f.path.toLowerCase().indexOf(searchTerm) !== -1 ||
          f.description.toLowerCase().indexOf(searchTerm) !== -1 ||
          ((f.risk && f.risk.trustee) || '').toLowerCase().indexOf(searchTerm) !== -1 ||
          ((f.risk && f.risk.raw_sid) || '').toLowerCase().indexOf(searchTerm) !== -1;
        if (sevMatch && searchMatch) visible.push(f);
      }

      $('visible-count').textContent = visible.length;

      if (visible.length === 0) {
        $('no-results').classList.add('visible');
      } else {
        $('no-results').classList.remove('visible');
      }

      var rows = '';
      for (var v = 0; v < visible.length; v++) {
        var f = visible[v];
        rows +=
          '<tr>' +
            '<td class="idx-cell">' + (v+1) + '</td>' +
            '<td>' + severityBadge(f.severity) + '</td>' +
            '<td class="type-cell">' + riskTypePretty(f.risk) + '</td>' +
            '<td class="path-cell">' + esc(f.path) + '</td>' +
            '<td class="detail-cell">' + riskDetails(f.risk) + '</td>' +
            '<td class="remediation-cell">' + esc(f.remediation_hint) + '</td>' +
          '</tr>';
      }
      $('findings-tbody').innerHTML = rows;
    }

    // ── Errors Section ─────────────────────────────────────────────────
    if (errors.length > 0) {
      $('errors-section').classList.add('visible');
      $('error-count').textContent = errors.length;

      var errorHtml = '';
      for (var e = 0; e < errors.length; e++) {
        errorHtml +=
          '<div class="error-item">' +
            '<span class="error-path">' + esc(errors[e].path) + ':</span> ' +
            esc(errors[e].message) +
          '</div>';
      }
      $('errors-list').innerHTML = errorHtml;

      $('errors-toggle').addEventListener('click', function() {
        this.classList.toggle('open');
        var list = $('errors-list');
        if (list.classList.contains('visible')) {
          list.classList.remove('visible');
        } else {
          list.classList.add('visible');
        }
      });
    }

    render();
  })();
  </script>
</body>
</html>"#;
