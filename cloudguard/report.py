"""
CloudGuard HTML Report Generator.

Renders a standalone, responsive, interactive executive HTML audit report
using Jinja2. Features embedded CSS and JavaScript with zero external CDN dependencies,
enabling offline viewing in air-gapped environments.

Key Report Features:
1. Executive Posture Dashboard:
   - Summary statistics: Total Findings, Critical, High, Medium, Low counts.
   - Peak Risk Score and CIS Control Coverage count.
2. Interactive Filtering:
   - Dynamic buttons to filter findings by severity (All, Critical, High, Medium, Low).
   - Instant client-side search across resource IDs, check names, and CIS controls.
3. Deep Finding Breakdown:
   - Ranked findings sorted by calculated Risk Score.
   - Flaw severity, network exposure, and asset sensitivity badges.
   - Collapsible raw AWS JSON evidence proof blocks (auto-escaped to prevent XSS).
   - Clear remediation guidance and copyable CLI commands.
4. Graceful Empty Findings Handling:
   - Displays a clean audit certificate when zero misconfigurations are detected.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from jinja2 import Environment, BaseLoader, select_autoescape

from cloudguard.models import Finding
from cloudguard.cis_mapping import CIS_CONTROLS_METADATA


REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CloudGuard Security Audit Report</title>
  <style>
    :root {
      --bg-primary: #0f172a;
      --bg-secondary: #1e293b;
      --bg-tertiary: #334155;
      --card-bg: #1e293b;
      --border-color: #334155;
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;

      --color-critical: #ef4444;
      --color-critical-bg: rgba(239, 68, 68, 0.15);
      --color-high: #f97316;
      --color-high-bg: rgba(249, 115, 22, 0.15);
      --color-medium: #eab308;
      --color-medium-bg: rgba(234, 179, 8, 0.15);
      --color-low: #3b82f6;
      --color-low-bg: rgba(59, 130, 246, 0.15);
      --color-safe: #10b981;
      --color-safe-bg: rgba(16, 185, 129, 0.15);
      --color-purple: #a855f7;
      --color-purple-bg: rgba(168, 85, 247, 0.15);
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background-color: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.5;
      padding: 2rem 1.5rem;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
    }

    /* Header */
    header {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 1.75rem 2rem;
      margin-bottom: 2rem;
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 1rem;
    }

    .brand-icon {
      font-size: 2.25rem;
      background: rgba(59, 130, 246, 0.2);
      border: 1px solid rgba(59, 130, 246, 0.4);
      width: 54px;
      height: 54px;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 10px;
    }

    .brand h1 {
      font-size: 1.5rem;
      font-weight: 700;
      letter-spacing: -0.025em;
    }

    .brand p {
      color: var(--text-secondary);
      font-size: 0.875rem;
    }

    .meta-pills {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
    }

    .meta-pill {
      background: var(--bg-tertiary);
      color: var(--text-secondary);
      padding: 0.35rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 500;
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
    }

    .meta-pill strong {
      color: var(--text-primary);
    }

    /* Partial Audit Warning Banner */
    .partial-audit-banner {
      background: rgba(239, 68, 68, 0.15);
      border: 1px solid var(--color-critical);
      border-radius: 10px;
      padding: 1.25rem 1.5rem;
      margin-bottom: 2rem;
      display: flex;
      align-items: center;
      gap: 1rem;
    }

    .partial-audit-icon {
      font-size: 2rem;
      flex-shrink: 0;
    }

    .partial-audit-text h3 {
      color: var(--color-critical);
      font-size: 1.05rem;
      font-weight: 700;
      margin-bottom: 0.25rem;
    }

    .partial-audit-text p {
      color: #fca5a5;
      font-size: 0.875rem;
    }

    .failed-scanner-tag {
      background: rgba(239, 68, 68, 0.25);
      border: 1px solid rgba(239, 68, 68, 0.5);
      color: #fef2f2;
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
      font-weight: 600;
      font-family: monospace;
    }

    /* Executive Summary Cards */
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }

    .summary-card {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 1.25rem;
      display: flex;
      flex-direction: column;
      position: relative;
      overflow: hidden;
    }

    .summary-card::before {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 4px;
      background: var(--card-accent, var(--border-color));
    }

    .summary-card.total { --card-accent: var(--text-secondary); }
    .summary-card.critical { --card-accent: var(--color-critical); }
    .summary-card.high { --card-accent: var(--color-high); }
    .summary-card.medium { --card-accent: var(--color-medium); }
    .summary-card.low { --card-accent: var(--color-low); }
    .summary-card.score { --card-accent: var(--color-purple); }

    .summary-card-label {
      color: var(--text-secondary);
      font-size: 0.75rem;
      text-transform: uppercase;
      font-weight: 600;
      letter-spacing: 0.05em;
      margin-bottom: 0.5rem;
    }

    .summary-card-value {
      font-size: 2rem;
      font-weight: 800;
      line-height: 1;
      color: var(--card-accent, var(--text-primary));
    }

    .summary-card-desc {
      color: var(--text-muted);
      font-size: 0.75rem;
      margin-top: 0.5rem;
    }

    /* Clean Audit Banner */
    .clean-audit-banner {
      background: var(--color-safe-bg);
      border: 1px solid var(--color-safe);
      border-radius: 12px;
      padding: 3rem 2rem;
      text-align: center;
      margin-bottom: 2rem;
    }

    .clean-audit-icon {
      font-size: 3.5rem;
      margin-bottom: 1rem;
      display: inline-block;
    }

    .clean-audit-banner h2 {
      font-size: 1.75rem;
      color: var(--color-safe);
      margin-bottom: 0.5rem;
    }

    .clean-audit-banner p {
      color: var(--text-secondary);
      max-width: 600px;
      margin: 0 auto;
    }

    /* Controls & Filter Bar */
    .controls-bar {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 1rem 1.25rem;
      margin-bottom: 1.5rem;
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
    }

    .filter-group {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
    }

    .filter-btn {
      background: var(--bg-tertiary);
      border: 1px solid transparent;
      color: var(--text-secondary);
      padding: 0.4rem 0.85rem;
      border-radius: 6px;
      font-size: 0.8125rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease-in-out;
    }

    .filter-btn:hover {
      background: #475569;
      color: var(--text-primary);
    }

    .filter-btn.active {
      background: #2563eb;
      color: #ffffff;
      border-color: #3b82f6;
    }

    .search-box {
      flex: 1;
      max-width: 320px;
      position: relative;
    }

    .search-input {
      width: 100%;
      background: var(--bg-primary);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      padding: 0.45rem 0.85rem;
      color: var(--text-primary);
      font-size: 0.875rem;
      outline: none;
    }

    .search-input:focus {
      border-color: #3b82f6;
    }

    /* Findings List */
    .findings-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
    }

    .findings-header h2 {
      font-size: 1.25rem;
      font-weight: 700;
    }

    .findings-count-badge {
      font-size: 0.875rem;
      color: var(--text-muted);
    }

    .findings-list {
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }

    .finding-card {
      background: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 1.25rem;
      transition: border-color 0.15s ease-in-out;
    }

    .finding-card:hover {
      border-color: #475569;
    }

    .finding-top-row {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: flex-start;
      gap: 0.75rem;
      margin-bottom: 0.75rem;
    }

    .finding-title-group {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      flex-wrap: wrap;
    }

    .finding-rank {
      font-family: monospace;
      font-size: 0.875rem;
      font-weight: 700;
      color: var(--text-muted);
      background: var(--bg-primary);
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      border: 1px solid var(--border-color);
    }

    .finding-title {
      font-size: 1.05rem;
      font-weight: 700;
      color: var(--text-primary);
    }

    .finding-score-pill {
      font-size: 0.8125rem;
      font-weight: 700;
      padding: 0.25rem 0.65rem;
      border-radius: 9999px;
      background: var(--color-purple-bg);
      color: var(--color-purple);
      border: 1px solid rgba(168, 85, 247, 0.3);
      white-space: nowrap;
    }

    /* Badges */
    .badge {
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 0.25rem 0.6rem;
      border-radius: 4px;
      display: inline-block;
    }

    .badge-CRITICAL {
      background: var(--color-critical-bg);
      color: var(--color-critical);
      border: 1px solid rgba(239, 68, 68, 0.4);
    }

    .badge-HIGH {
      background: var(--color-high-bg);
      color: var(--color-high);
      border: 1px solid rgba(249, 115, 22, 0.4);
    }

    .badge-MEDIUM {
      background: var(--color-medium-bg);
      color: var(--color-medium);
      border: 1px solid rgba(234, 179, 8, 0.4);
    }

    .badge-LOW {
      background: var(--color-low-bg);
      color: var(--color-low);
      border: 1px solid rgba(59, 130, 246, 0.4);
    }

    .badge-PUBLIC {
      background: rgba(239, 68, 68, 0.15);
      color: #f87171;
      border: 1px solid rgba(239, 68, 68, 0.3);
    }

    .badge-INTERNAL {
      background: rgba(100, 116, 139, 0.2);
      color: #cbd5e1;
      border: 1px solid rgba(100, 116, 139, 0.3);
    }

    .badge-cis {
      background: rgba(59, 130, 246, 0.15);
      color: #60a5fa;
      border: 1px solid rgba(59, 130, 246, 0.3);
      font-weight: 600;
    }

    /* Metadata details row */
    .finding-meta-row {
      display: flex;
      flex-wrap: wrap;
      gap: 1.25rem;
      color: var(--text-secondary);
      font-size: 0.8125rem;
      margin-bottom: 1rem;
      padding-bottom: 0.75rem;
      border-bottom: 1px solid var(--border-color);
    }

    .meta-item strong {
      color: var(--text-muted);
      margin-right: 0.25rem;
    }

    .resource-code {
      font-family: monospace;
      color: #38bdf8;
      background: rgba(56, 189, 248, 0.1);
      padding: 0.15rem 0.4rem;
      border-radius: 4px;
    }

    /* Collapsible Evidence Section */
    details.evidence-details {
      background: var(--bg-primary);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      margin-bottom: 0.75rem;
      overflow: hidden;
    }

    details.evidence-details summary {
      padding: 0.6rem 0.85rem;
      cursor: pointer;
      font-size: 0.8125rem;
      font-weight: 600;
      color: var(--text-secondary);
      user-select: none;
      background: rgba(51, 65, 85, 0.3);
      outline: none;
    }

    details.evidence-details summary:hover {
      color: var(--text-primary);
    }

    .evidence-content {
      padding: 0.75rem;
      font-family: Consolas, Monaco, "Courier New", monospace;
      font-size: 0.8rem;
      color: #cbd5e1;
      background: var(--bg-primary);
      overflow-x: auto;
      max-height: 280px;
    }

    /* Remediation Box */
    .remediation-box {
      background: rgba(16, 185, 129, 0.05);
      border: 1px solid rgba(16, 185, 129, 0.25);
      border-radius: 6px;
      padding: 0.85rem;
    }

    .remediation-label {
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--color-safe);
      margin-bottom: 0.35rem;
      display: flex;
      align-items: center;
      gap: 0.35rem;
    }

    .remediation-code {
      font-family: Consolas, Monaco, "Courier New", monospace;
      font-size: 0.8125rem;
      color: #a7f3d0;
      white-space: pre-wrap;
      word-break: break-all;
    }

    .remediation-empty {
      font-size: 0.8125rem;
      color: var(--text-muted);
      font-style: italic;
    }

    /* Footer */
    footer {
      margin-top: 3rem;
      text-align: center;
      color: var(--text-muted);
      font-size: 0.8125rem;
      border-top: 1px solid var(--border-color);
      padding-top: 1.5rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <header>
      <div class="brand">
        <div class="brand-icon">🛡️</div>
        <div>
          <h1>CloudGuard Security Audit Report</h1>
          <p>Read-Only Cloud Security Posture Management & CIS Foundations Benchmark</p>
        </div>
      </div>
      <div class="meta-pills">
        <span class="meta-pill"><strong>Profile:</strong> {{ profile }}</span>
        <span class="meta-pill"><strong>Region:</strong> {{ region }}</span>
        <span class="meta-pill"><strong>Generated:</strong> {{ generated_at }}</span>
      </div>
    </header>

    {% if failed_scanners %}
    <!-- Partial Audit Warning Banner -->
    <div class="partial-audit-banner">
      <div class="partial-audit-icon">⚠️</div>
      <div class="partial-audit-text">
        <h3>PARTIAL AUDIT — Some scanners failed; this report may not include all findings.</h3>
        <p>The following scanner(s) encountered errors and could not complete:
          {% for s_name in failed_scanners %}
            <span class="failed-scanner-tag">{{ s_name }}</span>{% if not loop.last %}, {% endif %}
          {% endfor %}
        </p>
      </div>
    </div>
    {% endif %}

    <!-- Executive Summary Metrics -->
    <section class="summary-grid">
      <div class="summary-card total">
        <span class="summary-card-label">Total Findings</span>
        <span class="summary-card-value">{{ total_findings }}</span>
        <span class="summary-card-desc">Audited misconfigurations</span>
      </div>
      <div class="summary-card critical">
        <span class="summary-card-label">Critical</span>
        <span class="summary-card-value">{{ counts.CRITICAL }}</span>
        <span class="summary-card-desc">Immediate action required</span>
      </div>
      <div class="summary-card high">
        <span class="summary-card-label">High</span>
        <span class="summary-card-value">{{ counts.HIGH }}</span>
        <span class="summary-card-desc">Severe configuration flaws</span>
      </div>
      <div class="summary-card medium">
        <span class="summary-card-label">Medium</span>
        <span class="summary-card-value">{{ counts.MEDIUM }}</span>
        <span class="summary-card-desc">Hygiene & monitoring gaps</span>
      </div>
      <div class="summary-card low">
        <span class="summary-card-label">Low</span>
        <span class="summary-card-value">{{ counts.LOW }}</span>
        <span class="summary-card-desc">Informational & lifecycle</span>
      </div>
      <div class="summary-card score">
        <span class="summary-card-label">Max Risk Score</span>
        <span class="summary-card-value">{{ max_risk_score }}</span>
        <span class="summary-card-desc">Peak threat (Range: 1.0 - 50.0)</span>
      </div>
    </section>

    {% if total_findings == 0 %}
    <!-- Clean Audit State -->
    <div class="clean-audit-banner">
      <div class="clean-audit-icon">✅</div>
      <h2>Zero Misconfigurations Detected</h2>
      <p>All scanned AWS resources in this environment comply with configured CIS benchmarks and security baselines. No public exposures, excessive permissions, or unencrypted storage assets were found.</p>
    </div>
    {% else %}
    <!-- Filter & Search Controls -->
    <section class="controls-bar">
      <div class="filter-group">
        <button class="filter-btn active" data-filter="ALL">All ({{ total_findings }})</button>
        <button class="filter-btn" data-filter="CRITICAL">Critical ({{ counts.CRITICAL }})</button>
        <button class="filter-btn" data-filter="HIGH">High ({{ counts.HIGH }})</button>
        <button class="filter-btn" data-filter="MEDIUM">Medium ({{ counts.MEDIUM }})</button>
        <button class="filter-btn" data-filter="LOW">Low ({{ counts.LOW }})</button>
      </div>
      <div class="search-box">
        <input type="text" id="searchInput" class="search-input" placeholder="Search check, resource, or CIS..." />
      </div>
    </section>

    <!-- Findings Section -->
    <section>
      <div class="findings-header">
        <h2>Ranked Security Findings</h2>
        <span class="findings-count-badge" id="visibleCount">Showing {{ total_findings }} of {{ total_findings }} findings</span>
      </div>

      <div class="findings-list" id="findingsList">
        {% for f in findings %}
        <article class="finding-card" data-severity="{{ f.severity }}" data-search="{{ f.check_name | lower }} {{ f.resource_id | lower }} {{ f.cis_id | lower }} {{ f.resource_type | lower }}">
          <div class="finding-top-row">
            <div class="finding-title-group">
              <span class="finding-rank">#{{ loop.index }}</span>
              <span class="badge badge-{{ f.severity }}">{{ f.severity }}</span>
              {% if f.cis_id != "N/A" %}
              <span class="badge badge-cis">{{ f.cis_id }}</span>
              {% endif %}
              <h3 class="finding-title">{{ f.check_name }}</h3>
            </div>
            <span class="finding-score-pill">Risk Score: {{ f.risk_score }}</span>
          </div>

          <div class="finding-meta-row">
            <span class="meta-item"><strong>Resource:</strong> <span class="resource-code">{{ f.resource }}</span></span>
            <span class="meta-item"><strong>Region:</strong> {{ f.region }}</span>
            <span class="meta-item"><strong>Exposure:</strong> <span class="badge badge-{{ f.exposure }}">{{ f.exposure }}</span></span>
            <span class="meta-item"><strong>Sensitivity:</strong> {{ f.sensitivity }}</span>
            {% if f.cis_metadata %}
            <span class="meta-item"><strong>CIS Control:</strong> {{ f.cis_metadata.title }}</span>
            {% endif %}
          </div>

          <details class="evidence-details">
            <summary>🔎 View Raw AWS Evidence</summary>
            <pre class="evidence-content"><code>{{ f.evidence | to_json }}</code></pre>
          </details>

          {% if f.remediation %}
          <div class="remediation-box">
            <div class="remediation-label">⚡ Recommended Remediation Guidance</div>
            <pre class="remediation-code"><code>{{ f.remediation }}</code></pre>
          </div>
          {% else %}
          <div class="remediation-empty">No remediation guidance specified for this finding.</div>
          {% endif %}
        </article>
        {% endfor %}
      </div>
    </section>
    {% endif %}

    <footer>
      <p>CloudGuard Audit Report &bull; Generated strictly via read-only AWS API analysis &bull; Compliant with CIS AWS Foundations Benchmark</p>
    </footer>
  </div>

  <script>
    // Embedded client-side filtering and search (100% offline, zero network dependencies)
    (function() {
      const filterBtns = document.querySelectorAll('.filter-btn');
      const searchInput = document.getElementById('searchInput');
      const cards = document.querySelectorAll('.finding-card');
      const visibleCountEl = document.getElementById('visibleCount');

      let currentFilter = 'ALL';
      let currentQuery = '';

      function updateVisibility() {
        let visibleCount = 0;
        cards.forEach(card => {
          const cardSeverity = card.getAttribute('data-severity');
          const cardSearch = card.getAttribute('data-search') || '';

          const matchesFilter = (currentFilter === 'ALL' || cardSeverity === currentFilter);
          const matchesSearch = (!currentQuery || cardSearch.includes(currentQuery));

          if (matchesFilter && matchesSearch) {
            card.style.display = 'block';
            visibleCount++;
          } else {
            card.style.display = 'none';
          }
        });

        if (visibleCountEl) {
          visibleCountEl.textContent = `Showing ${visibleCount} of ${cards.length} findings`;
        }
      }

      filterBtns.forEach(btn => {
        btn.addEventListener('click', function() {
          filterBtns.forEach(b => b.classList.remove('active'));
          this.classList.add('active');
          currentFilter = this.getAttribute('data-filter');
          updateVisibility();
        });
      });

      if (searchInput) {
        searchInput.addEventListener('input', function() {
          currentQuery = this.value.trim().toLowerCase();
          updateVisibility();
        });
      }
    })();
  </script>
</body>
</html>
"""


def _to_pretty_json(value: Any) -> str:
    """Format dictionary/data as formatted JSON string for safe template rendering."""
    try:
        return json.dumps(value, indent=2, default=str)
    except Exception:
        return str(value)


def generate_html_report(
    findings: List[Finding],
    output_path: str = "reports/audit_report.html",
    profile: str = "cloudguard",
    region: str = "ap-south-1",
    failed_scanners: Optional[List[str]] = None,
) -> str:
    """
    Renders an executive, self-contained HTML audit report from a list of Finding objects.

    Args:
        findings: List of Finding instances (preferably scored and ranked).
        output_path: File system path where the HTML report should be saved.
        profile: Name of AWS profile audited.
        region: Primary AWS region audited.
        failed_scanners: Optional list of scanner names that failed during audit.

    Returns:
        The string path of the generated HTML report file.
    """
    # 1. Ensure target directory exists
    out_file = Path(output_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    # 2. Normalize failed scanner names
    failed_names: List[str] = []
    if failed_scanners:
        for s in failed_scanners:
            if isinstance(s, (list, tuple)):
                failed_names.append(str(s[0]))
            else:
                failed_names.append(str(s))

    # 3. Compute summary metrics
    total_findings = len(findings)
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    max_risk_score = 0.0

    for f in findings:
        sev = f.severity.upper()
        if sev in counts:
            counts[sev] += 1
        if f.risk_score > max_risk_score:
            max_risk_score = f.risk_score

    max_risk_score = round(max_risk_score, 1)

    # 4. Augment finding representations with CIS metadata without altering core Finding dataclass
    augmented_findings = []
    for f in findings:
        f_dict = f.to_dict()
        cis_id = f_dict.get("cis_id", "N/A")
        f_dict["cis_metadata"] = CIS_CONTROLS_METADATA.get(cis_id)
        augmented_findings.append(f_dict)

    # 5. Configure Jinja2 environment with strict autoescaping for XSS prevention
    env = Environment(
        loader=BaseLoader(),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.filters["to_json"] = _to_pretty_json

    template = env.from_string(REPORT_TEMPLATE)

    # 6. Render HTML
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    html_content = template.render(
        findings=augmented_findings,
        total_findings=total_findings,
        counts=counts,
        max_risk_score=max_risk_score,
        profile=profile,
        region=region,
        generated_at=now_utc,
        failed_scanners=failed_names,
    )

    # 7. Write to disk
    with open(out_file, "w", encoding="utf-8") as file:
        file.write(html_content)

    return str(out_file)
