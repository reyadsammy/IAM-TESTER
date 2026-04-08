"""IAM Security Tester - Streamlit GUI Dashboard with Breach Simulation & Self-Healing."""

import streamlit as st
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime
from config import ScanConfig
from runner import TestRunner, ATTACK_MODULES, ALL_CATEGORIES, ALL_STORE_CATEGORIES
from target_profiles import TARGET_LABELS
from reporter import generate_html_report
from http_client import SecurityTestClient
from models import Severity, SEVERITY_COLORS, HealingStatus, HEALING_STATUS_COLORS
from breach_simulator import BreachSimulator, SCENARIOS, STORE_SCENARIOS
from self_healer import SelfHealer
from ui_components import (
    inject_css, render_kill_chain, render_terminal_view,
    render_step_timeline, render_animated_welcome, render_metric_card,
)

# Page config
st.set_page_config(
    page_title="IAM Security Tester",
    page_icon="\U0001f512",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject enhanced CSS
inject_css()

# Attack module display info
ATTACK_INFO = {
    "authentication": {"icon": "\U0001f511", "label": "Authentication", "desc": "Brute force, default creds, token manipulation, MFA bypass"},
    "authorization": {"icon": "\U0001f6e1\ufe0f", "label": "Authorization", "desc": "Always-allow bypass, IDOR, privilege escalation"},
    "api_security": {"icon": "\U0001f310", "label": "API Security", "desc": "Missing auth, CORS, method tampering, Swagger exposure"},
    "cryptographic": {"icon": "\U0001f510", "label": "Cryptographic", "desc": "Default keys, token entropy, algorithm confusion"},
    "injection": {"icon": "\U0001f489", "label": "Injection", "desc": "SQL injection, command injection, CRLF, JSON injection"},
    "xss": {"icon": "\u26a1", "label": "XSS", "desc": "Reflected XSS, stored XSS, XSS in error messages"},
    "session": {"icon": "\U0001f3ab", "label": "Session", "desc": "Fixation, replay, enumeration, cross-agent access"},
    "information_disclosure": {"icon": "\U0001f4cb", "label": "Information Disclosure", "desc": "Error leakage, version disclosure, debug mode"},
    "input_validation": {"icon": "\u2705", "label": "Input Validation", "desc": "Boundary testing, encoding bypass, type confusion"},
    "business_logic": {"icon": "\U0001f9e9", "label": "Business Logic", "desc": "Trust manipulation, mass assignment, workflow bypass"},
    "dos_ratelimit": {"icon": "\U0001f6a6", "label": "DoS / Rate Limiting", "desc": "Rate limit testing, resource exhaustion, flooding"},
    "compliance": {"icon": "\U0001f4dc", "label": "Compliance", "desc": "Security headers, CORS policy, HSTS, cookie flags"},
    "store_security": {"icon": "\U0001f6d2", "label": "Store Security", "desc": "IDOR, price manipulation, SQL injection in search, e-commerce flaws"},
}


# ═══════════════════════════════════════════════════════════════
#  SCANNER TAB
# ═══════════════════════════════════════════════════════════════

def run_scan(target_url, timeout, categories, skip_dos, target_type="iam"):
    """Run a scan with given parameters and return the ScanResult."""
    config = ScanConfig(target_url=target_url, timeout=timeout, categories=categories, skip_dos=skip_dos, target_type=target_type)
    runner = TestRunner(config)

    connected, msg = runner.check_connectivity()
    if not connected:
        st.error(f"Cannot connect to {target_url}: {msg}")
        return None

    progress_bar = st.progress(0, text="Starting scan...")

    log_container = st.container()
    log_container.markdown("""<div style="background:rgba(0,0,0,0.4); border:1px solid rgba(255,255,255,0.08);
        border-radius:10px; padding:0.75rem 1rem; margin-bottom:1rem;">
        <div style="font-size:0.75rem; color:#7a8599; text-transform:uppercase; font-weight:700;
            letter-spacing:0.1em; margin-bottom:0.5rem;">Live Attack Log</div>
    </div>""", unsafe_allow_html=True)
    log_area = log_container.empty()
    log_lines = []

    LEVEL_COLORS = {"info": "#7a8599", "success": "#22c55e", "danger": "#ff4444", "warning": "#ff8c00"}
    LEVEL_ICONS = {"info": "~", "success": "+", "danger": "!", "warning": "?"}

    def on_progress(name, idx, total):
        info = ATTACK_INFO.get(name, {})
        label = info.get("label", name)
        icon = info.get("icon", "")
        progress_bar.progress(idx / total, text=f"Testing: {label}...")
        log_lines.append(("module", f"\n{icon} Starting module: {label}", "#3b82f6"))
        _render_log()

    def on_log(module_name, level, message):
        color = LEVEL_COLORS.get(level, "#7a8599")
        icon = LEVEL_ICONS.get(level, "~")
        log_lines.append((level, f"  [{icon}] {message}", color))
        if len(log_lines) > 50:
            log_lines.pop(0)
        _render_log()

    def _render_log():
        html = '<div style="font-family:\'Consolas\',\'Courier New\',monospace; font-size:0.78rem; line-height:1.6; max-height:400px; overflow-y:auto;">'
        for level, line, color in log_lines:
            weight = "700" if level in ("danger", "module") else "400"
            html += f'<div style="color:{color}; font-weight:{weight};">{line}</div>'
        html += '</div>'
        log_area.markdown(html, unsafe_allow_html=True)

    scan = runner.run(progress_callback=on_progress, log_callback=on_log)
    progress_bar.progress(1.0, text="Scan complete!")

    findings_count = scan.total_findings
    sev = scan.findings_by_severity
    crit = sev.get(Severity.CRITICAL, 0)
    high = sev.get(Severity.HIGH, 0)
    log_lines.append(("module", f"\nScan complete: {findings_count} findings ({crit} critical, {high} high)", "#3b82f6"))
    _render_log()

    return scan


def show_results(scan, target_url):
    """Display scan results."""
    sev = scan.findings_by_severity

    st.markdown("---")
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.markdown(render_metric_card(scan.total_findings, "Total Findings"), unsafe_allow_html=True)
    with m2:
        st.markdown(render_metric_card(sev.get(Severity.CRITICAL, 0), "Critical", "#ff4444"), unsafe_allow_html=True)
    with m3:
        st.markdown(render_metric_card(sev.get(Severity.HIGH, 0), "High", "#ff8c00"), unsafe_allow_html=True)
    with m4:
        st.markdown(render_metric_card(sev.get(Severity.MEDIUM, 0), "Medium", "#ffd700"), unsafe_allow_html=True)
    with m5:
        st.markdown(render_metric_card(sev.get(Severity.LOW, 0) + sev.get(Severity.INFO, 0), "Low / Info", "#4dabf7"), unsafe_allow_html=True)

    st.markdown(f"""<div style="text-align:center; padding:0.5rem; color:#7a8599; font-size:0.8rem;">
        Target: {scan.target_url} | Duration: {scan.duration:.1f}s |
        Scan: {scan.scan_start.strftime('%Y-%m-%d %H:%M:%S')}
    </div>""", unsafe_allow_html=True)

    # Charts
    st.markdown("---")
    chart1, chart2 = st.columns(2)

    with chart1:
        labels = [s.value for s in Severity if sev.get(s, 0) > 0]
        values = [sev.get(s, 0) for s in Severity if sev.get(s, 0) > 0]
        colors = [SEVERITY_COLORS[s] for s in Severity if sev.get(s, 0) > 0]
        if labels:
            fig = go.Figure(data=[go.Pie(
                labels=labels, values=values, hole=0.55,
                marker=dict(colors=colors),
                textinfo="label+value",
                textfont=dict(size=12, color="white"),
            )])
            fig.update_layout(
                title=dict(text="Findings by Severity", font=dict(color="#e8eaf0", size=14)),
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e8eaf0"), showlegend=False, height=350,
                margin=dict(t=40, b=20, l=20, r=20),
            )
            st.plotly_chart(fig, use_container_width=True)

    with chart2:
        cat_data = {}
        for f in scan.all_findings:
            cat_data[f.category] = cat_data.get(f.category, 0) + 1
        if cat_data:
            cats = list(cat_data.keys())
            counts = list(cat_data.values())
            fig = go.Figure(data=[go.Bar(
                x=cats, y=counts, marker_color="#3b82f6",
                text=counts, textposition="auto", textfont=dict(color="white"),
            )])
            fig.update_layout(
                title=dict(text="Findings by Category", font=dict(color="#e8eaf0", size=14)),
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e8eaf0"),
                xaxis=dict(tickangle=-45, gridcolor="rgba(255,255,255,0.05)"),
                yaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
                height=350, margin=dict(t=40, b=80, l=40, r=20),
            )
            st.plotly_chart(fig, use_container_width=True)

    # Findings by category
    st.markdown("---")
    st.markdown("### Findings by Category")

    findings_by_cat = {}
    for f in scan.all_findings:
        findings_by_cat.setdefault(f.category, []).append(f)

    for cat, findings in findings_by_cat.items():
        info_key = next((k for k, v in ATTACK_INFO.items() if v["label"] == cat), None)
        icon = ATTACK_INFO[info_key]["icon"] if info_key else "\U0001f50d"

        with st.expander(f"{icon} {cat} \u2014 {len(findings)} findings"):
            for f in findings:
                sev_class = f.severity.value.lower()
                st.markdown(f"""<div class="finding-card">
                    <div style="margin-bottom:0.5rem;">
                        <span class="badge badge-{sev_class}">{f.severity.value}</span>
                        <strong style="margin-left:0.5rem;">{f.name}</strong>
                    </div>
                    <p style="font-size:0.85rem; color:#b0b8c5;">{f.description[:300]}</p>
                    {'<p style="font-size:0.8rem; color:#7a8599;"><strong>Endpoint:</strong> ' + f.endpoint + '</p>' if f.endpoint else ''}
                    {'<p style="font-size:0.8rem; color:#7a8599;"><strong>Recommendation:</strong> ' + f.recommendation + '</p>' if f.recommendation else ''}
                    {'<p style="font-size:0.75rem; color:#5a6577;"><strong>CWE:</strong> ' + f.cwe_id + ' | <strong>CVSS:</strong> ' + str(f.cvss_score) + '</p>' if f.cwe_id else ''}
                </div>""", unsafe_allow_html=True)

                if f.evidence:
                    with st.expander("View Evidence", expanded=False):
                        st.code(f.evidence, language="text")

    # Module results table
    st.markdown("---")
    st.markdown("### Module Results")
    mod_data = []
    for r in scan.module_results:
        mod_data.append({
            "Module": r.module_name,
            "Tests Run": r.tests_run,
            "Findings": len(r.findings),
            "Duration (s)": round(r.duration_seconds, 1),
            "Status": "Issues" if r.findings else "Clean",
        })
    if mod_data:
        st.dataframe(pd.DataFrame(mod_data), use_container_width=True, hide_index=True)


def render_scanner_tab(target_url, timeout, scan_mode, selected_single, skip_dos, run_all_clicked, run_single_clicked, target_type="iam"):
    """Render the Scanner tab content."""
    current_categories = ALL_STORE_CATEGORIES if target_type == "store" else ALL_CATEGORIES
    if run_all_clicked:
        scan = run_scan(target_url, timeout, None, skip_dos, target_type)
        if scan:
            st.session_state["last_scan"] = scan
            if "scan_history" not in st.session_state:
                st.session_state["scan_history"] = []
            st.session_state["scan_history"].append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "categories": "All",
                "findings": scan.total_findings,
            })
            st.rerun()

    if run_single_clicked and selected_single:
        scan = run_scan(target_url, timeout, [selected_single], False, target_type)
        if scan:
            st.session_state["last_scan"] = scan
            if "scan_history" not in st.session_state:
                st.session_state["scan_history"] = []
            info = ATTACK_INFO.get(selected_single, {})
            st.session_state["scan_history"].append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "categories": info.get("label", selected_single),
                "findings": scan.total_findings,
            })
            st.rerun()

    scan = st.session_state.get("last_scan")
    if not scan:
        render_animated_welcome()

        st.markdown("### Available Attacks")
        cols = st.columns(3)
        for i, key in enumerate(current_categories):
            info = ATTACK_INFO.get(key, {})
            with cols[i % 3]:
                st.markdown(f"""<div class="attack-card">
                    <div style="font-size:1.2rem; margin-bottom:0.3rem;">{info.get('icon', '\U0001f50d')}</div>
                    <div style="color:#e8eaf0; font-weight:700; font-size:0.9rem;">{info.get('label', key)}</div>
                    <div style="color:#7a8599; font-size:0.75rem; margin-top:0.2rem;">{info.get('desc', '')}</div>
                </div>""", unsafe_allow_html=True)
        return

    show_results(scan, target_url)


# ═══════════════════════════════════════════════════════════════
#  BREACH SIMULATION TAB
# ═══════════════════════════════════════════════════════════════

def render_breach_tab(target_url, timeout, target_type="iam"):
    """Render the Breach Simulation tab."""
    st.markdown("""<div style="margin-bottom:1rem;">
        <h3 style="margin-bottom:0.3rem;">\U0001f4a3 Breach Simulation Engine</h3>
        <p style="color:#7a8599; font-size:0.85rem;">
            Chain attacks into realistic breach scenarios. Watch the kill chain unfold step by step.
        </p>
    </div>""", unsafe_allow_html=True)

    # Check for existing result
    breach_result = st.session_state.get("breach_result")

    if breach_result:
        _show_breach_results(breach_result)
        if st.button("\U0001f504 Run Another Simulation", use_container_width=True):
            st.session_state.pop("breach_result", None)
            st.rerun()
        return

    # Scenario selection
    active_scenarios = STORE_SCENARIOS if target_type == "store" else SCENARIOS
    st.markdown("#### Select a Breach Scenario")
    cols = st.columns(2)
    for i, scenario in enumerate(active_scenarios):
        with cols[i % 2]:
            st.markdown(f"""<div class="scenario-card">
                <div style="font-size:1.8rem; margin-bottom:0.5rem;">{scenario.icon}</div>
                <div style="color:#e8eaf0; font-weight:700; font-size:1rem; margin-bottom:0.3rem;">{scenario.name}</div>
                <div style="color:#7a8599; font-size:0.8rem; margin-bottom:0.8rem;">{scenario.description}</div>
                <div style="color:#5a6577; font-size:0.72rem;">
                    {len(scenario.steps)} attack steps &bull;
                    {len(scenario.kill_chain_phases)} kill chain phases
                </div>
            </div>""", unsafe_allow_html=True)

            if st.button(f"\u25b6 Launch {scenario.name}", key=f"launch_{scenario.id}", use_container_width=True):
                _run_breach_simulation(scenario.id, target_url, timeout, target_type)


def _run_breach_simulation(scenario_id, target_url, timeout, target_type="iam"):
    """Execute a breach simulation with live updates."""
    config = ScanConfig(target_url=target_url, timeout=timeout, target_type=target_type)
    client = SecurityTestClient(base_url=target_url, timeout=timeout, verify_ssl=False)

    # Check connectivity
    connected, msg = client.check_connectivity()
    if not connected:
        st.error(f"Cannot connect to {target_url}: {msg}")
        return

    simulator = BreachSimulator(client, config)
    all_scenarios = SCENARIOS + STORE_SCENARIOS
    scenario = next(s for s in all_scenarios if s.id == scenario_id)

    st.markdown("---")
    st.markdown(f"### {scenario.icon} {scenario.name}")

    # Kill chain placeholder
    kc_placeholder = st.empty()
    # Progress
    progress_bar = st.progress(0, text="Initializing breach simulation...")
    # Terminal view placeholder
    terminal_placeholder = st.empty()
    # Timeline placeholder
    timeline_placeholder = st.empty()

    terminal_lines = []

    terminal_lines.append(("t-header", f"=== BREACH SIMULATION: {scenario.name} ==="))
    terminal_lines.append(("t-cmd", f"$ target --url {target_url}"))
    terminal_lines.append(("t-response", ""))

    def on_step(step, idx, total):
        progress_bar.progress((idx + 1) / total, text=f"Step {idx + 1}/{total}: {step.name}")

        # Update kill chain
        phase_statuses = {}
        for s in scenario.steps:
            if s.status == "success":
                phase_statuses[s.phase] = "done"
            elif s.status == "failed":
                if s.phase not in phase_statuses or phase_statuses[s.phase] != "done":
                    phase_statuses[s.phase] = "failed"
            elif s.status == "running":
                phase_statuses[s.phase] = "active"
            elif s.status == "skipped":
                if s.phase not in phase_statuses:
                    phase_statuses[s.phase] = "dim"

        with kc_placeholder.container():
            render_kill_chain(scenario.kill_chain_phases, -1, phase_statuses)

        # Update timeline
        with timeline_placeholder.container():
            render_step_timeline(scenario.steps)

    def on_log(level, message):
        css_map = {
            "header": "t-header",
            "cmd": "t-cmd",
            "response": "t-response",
            "success": "t-success",
            "fail": "t-fail",
            "warn": "t-warn",
            "info": "t-response",
        }
        terminal_lines.append((css_map.get(level, "t-response"), message))
        if len(terminal_lines) > 80:
            terminal_lines.pop(1)  # Keep header
        with terminal_placeholder.container():
            render_terminal_view(terminal_lines)

    result = simulator.run_scenario(scenario_id, step_callback=on_step, log_callback=on_log)

    progress_bar.progress(1.0, text="Simulation complete!")
    st.session_state["breach_result"] = result
    st.rerun()


def _show_breach_results(result):
    """Show the results of a completed breach simulation."""
    scenario = result.scenario

    st.markdown(f"### {scenario.icon} {scenario.name}")

    # Summary metrics
    total = len(scenario.steps)
    succeeded = sum(1 for s in scenario.steps if s.status == "success")
    failed = sum(1 for s in scenario.steps if s.status == "failed")
    skipped = sum(1 for s in scenario.steps if s.status == "skipped")

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        color = "#ff4444" if result.breach_successful else "#22c55e"
        label = "BREACHED" if result.breach_successful else "HELD"
        st.markdown(render_metric_card(label, "System Status", color), unsafe_allow_html=True)
    with m2:
        st.markdown(render_metric_card(succeeded, "Steps Succeeded", "#22c55e"), unsafe_allow_html=True)
    with m3:
        st.markdown(render_metric_card(failed, "Steps Failed", "#ff4444"), unsafe_allow_html=True)
    with m4:
        st.markdown(render_metric_card(skipped, "Steps Skipped", "#7a8599"), unsafe_allow_html=True)
    with m5:
        st.markdown(render_metric_card(f"{result.duration:.1f}s", "Duration"), unsafe_allow_html=True)

    # Kill chain final state
    st.markdown("---")
    st.markdown("#### Kill Chain Status")
    phase_statuses = {}
    for s in scenario.steps:
        if s.status == "success":
            phase_statuses[s.phase] = "done"
        elif s.status == "failed":
            if s.phase not in phase_statuses or phase_statuses[s.phase] != "done":
                phase_statuses[s.phase] = "failed"
        elif s.status == "skipped":
            if s.phase not in phase_statuses:
                phase_statuses[s.phase] = "dim"
    render_kill_chain(scenario.kill_chain_phases, -1, phase_statuses)

    # Attack timeline
    st.markdown("---")
    st.markdown("#### Attack Timeline")
    render_step_timeline(scenario.steps)

    # Terminal replay
    st.markdown("---")
    st.markdown("#### Attack Terminal")
    terminal_lines = [("t-header", f"=== BREACH RESULT: {scenario.name} ===")]
    for step in scenario.steps:
        terminal_lines.append(("t-header", f"\n[{step.phase.value}] {step.name}"))
        if step.status == "success" and step.finding:
            terminal_lines.append(("t-success", f"  VULNERABLE: {step.finding.name}"))
            if step.finding.evidence:
                for line in step.finding.evidence.split("\n")[:4]:
                    terminal_lines.append(("t-response", f"    {line}"))
        elif step.status == "failed":
            terminal_lines.append(("t-fail", f"  SECURE: Attack blocked"))
        elif step.status == "skipped":
            terminal_lines.append(("t-warn", f"  SKIPPED: Dependency not met"))
    terminal_lines.append(("t-header", ""))
    if result.breach_successful:
        terminal_lines.append(("t-fail", f"RESULT: SYSTEM BREACHED ({succeeded}/{total} steps)"))
    else:
        terminal_lines.append(("t-success", f"RESULT: SYSTEM SECURE ({failed}/{total} steps blocked)"))
    render_terminal_view(terminal_lines)

    # Detailed findings from breach
    if result.findings:
        st.markdown("---")
        st.markdown("#### Vulnerabilities Discovered")
        for f in result.findings:
            sev_class = f.severity.value.lower()
            st.markdown(f"""<div class="finding-card">
                <span class="badge badge-{sev_class}">{f.severity.value}</span>
                <strong style="margin-left:0.5rem;">{f.name}</strong>
                <p style="font-size:0.82rem; color:#b0b8c5; margin-top:0.3rem;">{f.description[:200]}</p>
            </div>""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════
#  SELF-HEALING TAB
# ═══════════════════════════════════════════════════════════════

def render_healing_tab(target_url, timeout, target_type="iam"):
    """Render the Self-Healing Security System tab."""
    st.markdown("""<div style="margin-bottom:1rem;">
        <h3 style="margin-bottom:0.3rem;">\U0001f6e1\ufe0f Self-Healing Security System</h3>
        <p style="color:#7a8599; font-size:0.85rem;">
            Automatically respond to detected vulnerabilities: isolate agents, rotate tokens,
            restore secure configuration, and verify fixes.
        </p>
    </div>""", unsafe_allow_html=True)

    scan = st.session_state.get("last_scan")
    if not scan or scan.total_findings == 0:
        st.markdown("""<div style="text-align:center; padding:3rem 0;">
            <div style="font-size:3rem; margin-bottom:1rem;">\U0001f6e1\ufe0f</div>
            <h3 style="color:#7a8599 !important;">No Vulnerabilities to Heal</h3>
            <p style="color:#5a6577; max-width:500px; margin:0 auto;">
                Run a security scan first from the <strong>Scanner</strong> tab to detect vulnerabilities,
                then return here to auto-heal them.
            </p>
        </div>""", unsafe_allow_html=True)
        return

    # Initialize healer
    client = SecurityTestClient(base_url=target_url, timeout=timeout, verify_ssl=False)
    config = ScanConfig(target_url=target_url, timeout=timeout, target_type=target_type)
    healer = SelfHealer(client, config)

    # Get or regenerate healing actions
    if "healing_actions" not in st.session_state or st.session_state.get("healing_scan_id") != id(scan):
        actions = healer.get_all_actions(scan)
        st.session_state["healing_actions"] = actions
        st.session_state["healing_scan_id"] = id(scan)
        st.session_state["healing_history"] = []

    actions = st.session_state["healing_actions"]

    # Summary metrics
    summary = healer.get_healing_summary(actions)
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.markdown(render_metric_card(scan.total_findings, "Vulnerabilities", "#ff4444"), unsafe_allow_html=True)
    with m2:
        st.markdown(render_metric_card(summary["total"], "Healable", "#3b82f6"), unsafe_allow_html=True)
    with m3:
        st.markdown(render_metric_card(summary["success"], "Healed", "#22c55e"), unsafe_allow_html=True)
    with m4:
        st.markdown(render_metric_card(summary["failed"], "Failed", "#ff4444"), unsafe_allow_html=True)
    with m5:
        st.markdown(render_metric_card(summary["verified"], "Verified", "#a855f7"), unsafe_allow_html=True)

    if not actions:
        st.info("No automated healing actions available for the detected vulnerabilities.")
        return

    # Reset button if all actions are already executed
    all_done = all(a.status != HealingStatus.PENDING for a in actions)
    if all_done:
        st.markdown("---")
        if st.button("\U0001f504 Reset & Retry All Healing Actions", use_container_width=True):
            # Regenerate fresh actions and execute immediately
            fresh_actions = healer.get_all_actions(scan)
            st.session_state["healing_actions"] = fresh_actions
            st.session_state["healing_scan_id"] = id(scan)
            st.session_state["healing_history"] = []
            _execute_heal_all(healer, fresh_actions, target_url, timeout)

    # Heal All button
    st.markdown("---")
    heal_col1, heal_col2 = st.columns([3, 1])
    with heal_col1:
        st.markdown("""<div style="color:#e8eaf0; font-size:0.9rem; padding:0.5rem 0;">
            <strong>Automated Healing Actions</strong> &mdash; Review and execute remediation
        </div>""", unsafe_allow_html=True)
    with heal_col2:
        if st.button("\u26a1 Heal All Vulnerabilities", type="primary", use_container_width=True):
            _execute_heal_all(healer, actions, target_url, timeout)

    st.markdown("---")

    # Action cards
    for i, action in enumerate(actions):
        status_color = HEALING_STATUS_COLORS.get(action.status, "#7a8599")
        status_label = action.status.value.upper()
        sev_class = action.finding_severity.value.lower()

        extra_class = ""
        if action.status == HealingStatus.SUCCESS:
            extra_class = "heal-card-success"
        elif action.status == HealingStatus.FAILED:
            extra_class = "heal-card-failed"

        st.markdown(f"""<div class="heal-card {extra_class}">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
                <div>
                    <span class="badge badge-{sev_class}">{action.finding_severity.value}</span>
                    <strong style="margin-left:0.5rem; color:#e8eaf0;">{action.finding_name}</strong>
                    <span style="color:#5a6577; font-size:0.75rem; margin-left:0.5rem;">({action.finding_category})</span>
                </div>
                <span style="color:{status_color}; font-weight:700; font-size:0.75rem; text-transform:uppercase;">
                    &#9679; {status_label}
                </span>
            </div>
            <div style="color:#b0b8c5; font-size:0.82rem; margin-bottom:0.5rem;">
                <strong>Action:</strong> {action.description}
            </div>
            <div style="color:#5a6577; font-size:0.75rem;">
                <code style="background:rgba(255,255,255,0.05); padding:0.15rem 0.4rem; border-radius:4px;">
                    {action.api_method} {action.api_endpoint}
                </code>
            </div>
        </div>""", unsafe_allow_html=True)

        # Action buttons
        if action.status == HealingStatus.PENDING:
            btn_col1, btn_col2 = st.columns([1, 5])
            with btn_col1:
                if st.button(f"\U0001f529 Heal", key=f"heal_{action.id}"):
                    _execute_single_heal(healer, action, i)

        if action.status == HealingStatus.FAILED and action.response_body:
            st.error(f"Error: {action.response_body[:200]}")
        elif action.status in (HealingStatus.SUCCESS, HealingStatus.FAILED):
            if action.response_body:
                with st.expander("View Response", expanded=False):
                    st.code(action.response_body, language="text")

        if action.verification_result:
            v_color = "#22c55e" if "VERIFIED" in action.verification_result else "#ff4444"
            st.markdown(f'<div style="color:{v_color}; font-size:0.8rem; padding:0.3rem 0;">{action.verification_result}</div>', unsafe_allow_html=True)

    # Healing history / timeline
    if st.session_state.get("healing_history"):
        st.markdown("---")
        st.markdown("#### Healing Timeline")
        for entry in reversed(st.session_state["healing_history"][-20:]):
            color = "#22c55e" if "Success" in entry["status"] else "#ff4444" if "Failed" in entry["status"] else "#3b82f6"
            st.markdown(f"""<div style="display:flex; gap:1rem; padding:0.3rem 0; font-size:0.8rem;">
                <span style="color:#5a6577; min-width:70px;">{entry['time']}</span>
                <span style="color:{color}; font-weight:600; min-width:80px;">{entry['status']}</span>
                <span style="color:#b0b8c5;">{entry['description']}</span>
            </div>""", unsafe_allow_html=True)

    # Re-scan verification
    st.markdown("---")
    if st.button("\U0001f50d Re-scan & Verify Fixes", use_container_width=True):
        _verify_healing(target_url, timeout, actions, healer, scan, target_type)


def _execute_single_heal(healer, action, action_index):
    """Execute a single healing action."""
    log_entries = []

    def log_cb(level, msg):
        log_entries.append(msg)

    healer.execute_action(action, log_callback=log_cb)

    if "healing_history" not in st.session_state:
        st.session_state["healing_history"] = []
    st.session_state["healing_history"].append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "status": "Success" if action.status == HealingStatus.SUCCESS else "Failed",
        "description": action.description,
    })
    st.rerun()


def _execute_heal_all(healer, actions, target_url, timeout):
    """Execute all pending healing actions."""
    progress = st.progress(0, text="Healing vulnerabilities...")
    terminal_lines = [("t-header", "=== SELF-HEALING INITIATED ===")]
    terminal_placeholder = st.empty()

    pending = [a for a in actions if a.status == HealingStatus.PENDING]
    if not pending:
        st.info("No pending actions to execute.")
        return

    if "healing_history" not in st.session_state:
        st.session_state["healing_history"] = []

    for i, action in enumerate(pending):
        def log_cb(level, msg):
            css_map = {"info": "t-response", "cmd": "t-cmd", "success": "t-success", "fail": "t-fail", "warn": "t-warn"}
            terminal_lines.append((css_map.get(level, "t-response"), msg))
            with terminal_placeholder.container():
                render_terminal_view(terminal_lines[-40:])

        healer.execute_action(action, log_callback=log_cb)
        progress.progress((i + 1) / len(pending), text=f"Healing {i + 1}/{len(pending)}...")

        st.session_state["healing_history"].append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "status": "Success" if action.status == HealingStatus.SUCCESS else "Failed",
            "description": action.description,
        })

    progress.progress(1.0, text="Healing complete!")
    terminal_lines.append(("t-header", ""))
    succeeded = sum(1 for a in pending if a.status == HealingStatus.SUCCESS)
    terminal_lines.append(("t-success" if succeeded else "t-fail",
                           f"COMPLETE: {succeeded}/{len(pending)} actions succeeded"))
    with terminal_placeholder.container():
        render_terminal_view(terminal_lines[-40:])

    st.rerun()


def _verify_healing(target_url, timeout, actions, healer, old_scan, target_type="iam"):
    """Re-scan to verify healed vulnerabilities."""
    st.info("Running verification scan...")
    new_scan = run_scan(target_url, timeout, None, True, target_type)
    if not new_scan:
        return

    old_count = old_scan.total_findings
    new_count = new_scan.total_findings
    fixed = old_count - new_count

    st.markdown("---")
    st.markdown("#### Verification Results")
    v1, v2, v3 = st.columns(3)
    with v1:
        st.markdown(render_metric_card(old_count, "Before Healing", "#ff4444"), unsafe_allow_html=True)
    with v2:
        st.markdown(render_metric_card(new_count, "After Healing", "#22c55e" if new_count < old_count else "#ff4444"), unsafe_allow_html=True)
    with v3:
        st.markdown(render_metric_card(max(0, fixed), "Fixed", "#a855f7"), unsafe_allow_html=True)

    st.session_state["last_scan"] = new_scan


# ═══════════════════════════════════════════════════════════════
#  REPORTS TAB
# ═══════════════════════════════════════════════════════════════

def render_reports_tab(target_url):
    """Render the Reports tab."""
    st.markdown("""<div style="margin-bottom:1rem;">
        <h3 style="margin-bottom:0.3rem;">\U0001f4c4 Reports & History</h3>
        <p style="color:#7a8599; font-size:0.85rem;">
            Download reports, review scan history, and export breach simulation results.
        </p>
    </div>""", unsafe_allow_html=True)

    scan = st.session_state.get("last_scan")
    breach_result = st.session_state.get("breach_result")

    # Scan report
    st.markdown("#### Security Scan Report")
    if scan:
        st.markdown(f"""<div class="finding-card">
            <div style="color:#e8eaf0; font-weight:700;">Latest Scan</div>
            <div style="color:#7a8599; font-size:0.82rem; margin-top:0.3rem;">
                Target: {scan.target_url} |
                Findings: {scan.total_findings} |
                Duration: {scan.duration:.1f}s |
                Time: {scan.scan_start.strftime('%Y-%m-%d %H:%M:%S')}
            </div>
        </div>""", unsafe_allow_html=True)

        if st.button("\U0001f4e5 Download HTML Report", use_container_width=True):
            report_path = generate_html_report(scan)
            with open(report_path, "r", encoding="utf-8") as f:
                html_content = f.read()
            st.download_button(
                label="Save Report",
                data=html_content,
                file_name=f"iam-security-report-{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                mime="text/html",
                use_container_width=True,
            )
    else:
        st.markdown('<div style="color:#5a6577; font-size:0.85rem;">No scan results available. Run a scan first.</div>', unsafe_allow_html=True)

    # Breach simulation report
    st.markdown("---")
    st.markdown("#### Breach Simulation Report")
    if breach_result:
        scenario = breach_result.scenario
        succeeded = sum(1 for s in scenario.steps if s.status == "success")
        status_text = "BREACHED" if breach_result.breach_successful else "SECURE"
        status_color = "#ff4444" if breach_result.breach_successful else "#22c55e"

        st.markdown(f"""<div class="finding-card">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <div>
                    <span style="font-size:1.2rem; margin-right:0.5rem;">{scenario.icon}</span>
                    <strong style="color:#e8eaf0;">{scenario.name}</strong>
                </div>
                <span style="color:{status_color}; font-weight:700;">{status_text}</span>
            </div>
            <div style="color:#7a8599; font-size:0.82rem; margin-top:0.3rem;">
                Steps: {succeeded}/{len(scenario.steps)} succeeded |
                Duration: {breach_result.duration:.1f}s |
                Findings: {len(breach_result.findings)}
            </div>
        </div>""", unsafe_allow_html=True)
    else:
        st.markdown('<div style="color:#5a6577; font-size:0.85rem;">No breach simulation results. Run a simulation first.</div>', unsafe_allow_html=True)

    # Healing report
    st.markdown("---")
    st.markdown("#### Healing Report")
    healing_actions = st.session_state.get("healing_actions", [])
    executed = [a for a in healing_actions if a.status != HealingStatus.PENDING]
    if executed:
        heal_data = []
        for a in executed:
            heal_data.append({
                "Action": a.description,
                "Type": a.action_type,
                "Finding": a.finding_name,
                "Status": a.status.value.upper(),
                "HTTP": a.response_code or "-",
                "Verification": a.verification_result or "-",
            })
        st.dataframe(pd.DataFrame(heal_data), use_container_width=True, hide_index=True)
    else:
        st.markdown('<div style="color:#5a6577; font-size:0.85rem;">No healing actions executed yet.</div>', unsafe_allow_html=True)

    # Scan history
    st.markdown("---")
    st.markdown("#### Scan History")
    history = st.session_state.get("scan_history", [])
    if history:
        hist_data = []
        for h in reversed(history[-10:]):
            hist_data.append({
                "Time": h["time"],
                "Categories": h["categories"],
                "Findings": h["findings"],
            })
        st.dataframe(pd.DataFrame(hist_data), use_container_width=True, hide_index=True)
    else:
        st.markdown('<div style="color:#5a6577; font-size:0.85rem;">No scans recorded yet.</div>', unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    # ── Sidebar ──
    with st.sidebar:
        st.markdown("""<div style="padding:0.5rem 0;">
            <div style="font-weight:800; font-size:1.2rem; color:#e8eaf0;">\U0001f512 IAM Security Tester</div>
            <div style="color:#7a8599; font-size:0.75rem;">Attack \u2022 Detect \u2022 Heal</div>
        </div>""", unsafe_allow_html=True)
        st.markdown("---")

        # Target type selector
        target_type_label = st.radio(
            "Target System",
            list(TARGET_LABELS.values()),
            index=0,
            help="Select the type of system you're testing",
        )
        target_type = next(k for k, v in TARGET_LABELS.items() if v == target_type_label)

        default_url = "http://127.0.0.1:8002" if target_type == "store" else "http://localhost:8000"
        target_url = st.text_input("Target URL", value=default_url)

        # Connectivity check
        try:
            import requests
            resp = requests.get(f"{target_url}/", timeout=3)
            if resp.status_code < 500:
                st.markdown('<div style="color:#22c55e; font-size:0.8rem;">\u25cf Connected</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div style="color:#ff4444; font-size:0.8rem;">\u25cf Error</div>', unsafe_allow_html=True)
        except Exception:
            st.markdown('<div style="color:#ff4444; font-size:0.8rem;">\u25cf Disconnected</div>', unsafe_allow_html=True)

        st.markdown("---")
        timeout = st.slider("Timeout (seconds)", 5, 30, 10)
        st.markdown("---")

        # Scan mode selector
        scan_mode = st.radio("Scan Mode", ["Run All Attacks", "Choose Attack"], index=0)

        selected_single = None
        skip_dos = False
        run_all_clicked = False
        run_single_clicked = False

        current_categories = ALL_STORE_CATEGORIES if target_type == "store" else ALL_CATEGORIES

        if scan_mode == "Run All Attacks":
            skip_dos = st.toggle("Skip DoS Tests", value=False)
            run_all_clicked = st.button("\u25b6 Run All Attacks", type="primary", use_container_width=True)
        else:
            st.markdown('<p style="font-size:0.75rem; color:#7a8599; text-transform:uppercase; font-weight:600; letter-spacing:0.1em;">Select Attack</p>', unsafe_allow_html=True)
            attack_options = []
            for key in current_categories:
                info = ATTACK_INFO.get(key, {})
                attack_options.append(f"{info.get('icon', '\U0001f50d')} {info.get('label', key)}")

            selected_idx = st.radio("Attack", range(len(attack_options)),
                                    format_func=lambda i: attack_options[i], label_visibility="collapsed")
            selected_single = current_categories[selected_idx]
            info = ATTACK_INFO.get(selected_single, {})
            st.markdown(f'<div style="font-size:0.78rem; color:#7a8599; padding:0.3rem 0;">{info.get("desc", "")}</div>', unsafe_allow_html=True)
            run_single_clicked = st.button(f"\u25b6 Run {info.get('label', selected_single)}",
                                           type="primary", use_container_width=True)

        # Action buttons
        st.markdown("---")
        has_results = "last_scan" in st.session_state and st.session_state["last_scan"] is not None
        if has_results:
            if st.button("\U0001f5d1 Clear Results", use_container_width=True):
                st.session_state.pop("last_scan", None)
                st.session_state.pop("scan_history", None)
                st.session_state.pop("healing_actions", None)
                st.session_state.pop("breach_result", None)
                st.rerun()

        if has_results:
            st.markdown("---")
            st.markdown('<p style="font-size:0.75rem; color:#7a8599; text-transform:uppercase; font-weight:600; letter-spacing:0.1em;">Push Results</p>', unsafe_allow_html=True)
            push_url = st.text_input("IAM API URL", value=target_url, key="push_url")
            if st.button("\U0001f4e4 Push to IAM Dashboard", use_container_width=True):
                config = ScanConfig(target_url=push_url)
                runner = TestRunner(config)
                success, msg = runner.push_results_to_iam(st.session_state["last_scan"])
                if success:
                    st.success(msg)
                else:
                    st.warning(msg)

        # Scan history in sidebar
        if "scan_history" in st.session_state and st.session_state.scan_history:
            st.markdown("---")
            st.markdown('<p style="font-size:0.75rem; color:#7a8599; text-transform:uppercase; font-weight:600;">Scan History</p>', unsafe_allow_html=True)
            for h in reversed(st.session_state.scan_history[-5:]):
                st.markdown(
                    f'<div style="font-size:0.8rem; color:#b0b8c5; padding:0.2rem 0;">'
                    f'{h["time"]} \u2014 {h["categories"]} \u2014 {h["findings"]} findings</div>',
                    unsafe_allow_html=True,
                )

    # ── Page Header ──
    st.markdown("""<div class="page-header">
        <h1>\U0001f512 IAM Security Command Center</h1>
        <p style="color:#7a8599; font-size:0.88rem;">
            External black-box security testing, breach simulation &amp; self-healing for Agentic-IAM
        </p>
    </div>""", unsafe_allow_html=True)

    # ── Tabs ──
    tab_scanner, tab_breach, tab_healing, tab_reports = st.tabs([
        "\u2694\ufe0f Scanner",
        "\U0001f4a3 Breach Simulation",
        "\U0001f6e1\ufe0f Self-Healing",
        "\U0001f4c4 Reports",
    ])

    with tab_scanner:
        render_scanner_tab(target_url, timeout, scan_mode, selected_single, skip_dos, run_all_clicked, run_single_clicked, target_type)

    with tab_breach:
        render_breach_tab(target_url, timeout, target_type)

    with tab_healing:
        render_healing_tab(target_url, timeout, target_type)

    with tab_reports:
        render_reports_tab(target_url)


if __name__ == "__main__":
    main()
else:
    main()
