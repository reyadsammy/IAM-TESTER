"""Report generation for console and HTML output."""

import os
from datetime import datetime
from typing import Optional
from models import ScanResult, Severity, SEVERITY_COLORS, Finding
from jinja2 import Template


def print_console_report(scan: ScanResult):
    """Print a rich console report."""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text

    console = Console()

    # Banner
    console.print()
    console.print(Panel.fit(
        "[bold white]IAM Security Tester[/] - Scan Report",
        border_style="bright_blue",
    ))

    # Executive Summary
    sev = scan.findings_by_severity
    summary_table = Table(title="Executive Summary", show_header=True, header_style="bold")
    summary_table.add_column("Metric", style="white")
    summary_table.add_column("Value", justify="right")
    summary_table.add_row("Target", scan.target_url)
    summary_table.add_row("Scan Duration", f"{scan.duration:.1f}s")
    summary_table.add_row("Total Findings", str(scan.total_findings))
    summary_table.add_row("[bold red]Critical[/]", str(sev.get(Severity.CRITICAL, 0)))
    summary_table.add_row("[bold orange1]High[/]", str(sev.get(Severity.HIGH, 0)))
    summary_table.add_row("[bold yellow]Medium[/]", str(sev.get(Severity.MEDIUM, 0)))
    summary_table.add_row("[bold blue]Low[/]", str(sev.get(Severity.LOW, 0)))
    summary_table.add_row("[dim]Info[/]", str(sev.get(Severity.INFO, 0)))
    console.print(summary_table)
    console.print()

    # Module Results
    mod_table = Table(title="Module Results", show_header=True, header_style="bold")
    mod_table.add_column("Module", style="white")
    mod_table.add_column("Tests", justify="right")
    mod_table.add_column("Findings", justify="right")
    mod_table.add_column("Duration", justify="right")
    for r in scan.module_results:
        findings_count = len(r.findings)
        style = "red" if findings_count > 0 else "green"
        mod_table.add_row(
            r.module_name,
            str(r.tests_run),
            f"[{style}]{findings_count}[/]",
            f"{r.duration_seconds:.1f}s",
        )
    console.print(mod_table)
    console.print()

    # Findings Detail
    if scan.all_findings:
        console.print("[bold]Findings Detail[/]")
        console.print()
        for finding in scan.all_findings:
            sev_colors = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "orange1",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "blue",
                Severity.INFO: "dim",
            }
            color = sev_colors.get(finding.severity, "white")
            title = f"[{color}][{finding.severity.value}][/] {finding.name}"
            content = f"[bold]Category:[/] {finding.category}\n"
            if finding.endpoint:
                content += f"[bold]Endpoint:[/] {finding.endpoint}\n"
            content += f"[bold]Description:[/] {finding.description}\n"
            if finding.recommendation:
                content += f"[bold]Recommendation:[/] {finding.recommendation}\n"
            if finding.cwe_id:
                content += f"[bold]CWE:[/] {finding.cwe_id}  [bold]CVSS:[/] {finding.cvss_score}\n"
            console.print(Panel(content, title=title, border_style=color))
    else:
        console.print("[green]No findings! The target appears secure.[/]")

    console.print()


def generate_html_report(scan: ScanResult, output_dir: str = "./reports") -> str:
    """Generate a standalone HTML report and return the file path."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"iam-security-report-{timestamp}.html"
    filepath = os.path.join(output_dir, filename)

    sev = scan.findings_by_severity
    findings_by_cat = {}
    for f in scan.all_findings:
        findings_by_cat.setdefault(f.category, []).append(f)

    html = HTML_TEMPLATE.render(
        scan=scan,
        severity=Severity,
        sev_counts=sev,
        findings_by_cat=findings_by_cat,
        sev_colors=SEVERITY_COLORS,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    return filepath


HTML_TEMPLATE = Template('''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IAM Security Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #0a0e1a; color: #e0e0e0; padding: 2rem; }
  .container { max-width: 1200px; margin: 0 auto; }
  h1 { font-size: 1.8rem; font-weight: 800; margin-bottom: 0.5rem; }
  h2 { font-size: 1.3rem; font-weight: 700; margin: 1.5rem 0 0.75rem; border-bottom: 1px solid #1e2a3a; padding-bottom: 0.5rem; }
  h3 { font-size: 1.1rem; font-weight: 600; margin: 1rem 0 0.5rem; }
  .header { text-align: center; padding: 2rem 0; border-bottom: 1px solid #1e2a3a; margin-bottom: 2rem; }
  .header p { color: #7a8599; font-size: 0.9rem; }
  .metrics { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin: 1.5rem 0; }
  .metric-card { background: rgba(255,255,255,0.03); border: 1px solid #1e2a3a; border-radius: 12px;
                 padding: 1.2rem; text-align: center; }
  .metric-card .value { font-size: 2rem; font-weight: 800; }
  .metric-card .label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.1em; color: #7a8599; margin-top: 0.3rem; }
  .badge { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 20px; font-size: 0.7rem;
           font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }
  .badge-critical { background: rgba(255,68,68,0.15); color: #ff4444; border: 1px solid rgba(255,68,68,0.3); }
  .badge-high { background: rgba(255,140,0,0.15); color: #ff8c00; border: 1px solid rgba(255,140,0,0.3); }
  .badge-medium { background: rgba(255,215,0,0.15); color: #ffd700; border: 1px solid rgba(255,215,0,0.3); }
  .badge-low { background: rgba(77,171,247,0.15); color: #4dabf7; border: 1px solid rgba(77,171,247,0.3); }
  .badge-info { background: rgba(134,142,150,0.15); color: #868e96; border: 1px solid rgba(134,142,150,0.3); }
  table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
  th, td { padding: 0.6rem 0.8rem; text-align: left; border-bottom: 1px solid #1e2a3a; font-size: 0.85rem; }
  th { background: rgba(255,255,255,0.03); font-weight: 600; text-transform: uppercase; font-size: 0.7rem;
       letter-spacing: 0.08em; color: #7a8599; }
  .finding-card { background: rgba(255,255,255,0.02); border: 1px solid #1e2a3a; border-radius: 10px;
                  padding: 1.2rem; margin: 0.75rem 0; }
  .finding-card h4 { font-size: 0.95rem; margin-bottom: 0.5rem; }
  .finding-card p { font-size: 0.85rem; color: #b0b8c5; margin: 0.3rem 0; }
  .finding-card .label { font-weight: 600; color: #e0e0e0; }
  details { margin: 0.5rem 0; }
  details summary { cursor: pointer; color: #4dabf7; font-size: 0.85rem; }
  details pre { background: #0d1117; padding: 0.8rem; border-radius: 6px; overflow-x: auto;
                font-size: 0.75rem; margin-top: 0.5rem; color: #8b949e; white-space: pre-wrap; }
  .footer { text-align: center; padding: 2rem 0; color: #7a8599; font-size: 0.8rem; border-top: 1px solid #1e2a3a; margin-top: 2rem; }
  @media (max-width: 768px) { .metrics { grid-template-columns: repeat(2, 1fr); } }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>IAM Security Tester Report</h1>
    <p>Target: {{ scan.target_url }} | Scan: {{ generated_at }} | Duration: {{ "%.1f"|format(scan.duration) }}s</p>
  </div>

  <h2>Executive Summary</h2>
  <div class="metrics">
    <div class="metric-card">
      <div class="value">{{ scan.total_findings }}</div>
      <div class="label">Total Findings</div>
    </div>
    <div class="metric-card">
      <div class="value" style="color:#ff4444;">{{ sev_counts[severity.CRITICAL] }}</div>
      <div class="label">Critical</div>
    </div>
    <div class="metric-card">
      <div class="value" style="color:#ff8c00;">{{ sev_counts[severity.HIGH] }}</div>
      <div class="label">High</div>
    </div>
    <div class="metric-card">
      <div class="value" style="color:#ffd700;">{{ sev_counts[severity.MEDIUM] }}</div>
      <div class="label">Medium</div>
    </div>
    <div class="metric-card">
      <div class="value" style="color:#4dabf7;">{{ sev_counts[severity.LOW] + sev_counts[severity.INFO] }}</div>
      <div class="label">Low / Info</div>
    </div>
  </div>

  <h2>Module Results</h2>
  <table>
    <thead><tr><th>Module</th><th>Tests Run</th><th>Findings</th><th>Duration</th></tr></thead>
    <tbody>
    {% for r in scan.module_results %}
    <tr>
      <td>{{ r.module_name }}</td>
      <td>{{ r.tests_run }}</td>
      <td>{{ r.findings|length }}</td>
      <td>{{ "%.1f"|format(r.duration_seconds) }}s</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>

  {% for cat, findings in findings_by_cat.items() %}
  <h2>{{ cat }} ({{ findings|length }} findings)</h2>
  {% for f in findings %}
  <div class="finding-card">
    <h4>
      <span class="badge badge-{{ f.severity.value|lower }}">{{ f.severity.value }}</span>
      {{ f.name }}
    </h4>
    {% if f.endpoint %}<p><span class="label">Endpoint:</span> {{ f.endpoint }}</p>{% endif %}
    <p>{{ f.description }}</p>
    {% if f.recommendation %}<p><span class="label">Recommendation:</span> {{ f.recommendation }}</p>{% endif %}
    {% if f.cwe_id %}<p><span class="label">CWE:</span> {{ f.cwe_id }} | <span class="label">CVSS:</span> {{ f.cvss_score }}</p>{% endif %}
    {% if f.evidence %}
    <details>
      <summary>View Evidence</summary>
      <pre>{{ f.evidence }}</pre>
    </details>
    {% endif %}
  </div>
  {% endfor %}
  {% endfor %}

  <div class="footer">
    <p>Generated by IAM Security Tester | {{ generated_at }}</p>
  </div>
</div>
</body>
</html>''')
