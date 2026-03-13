"""IAM Security Tester - Streamlit GUI Dashboard."""

import streamlit as st
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime
from config import ScanConfig
from runner import TestRunner, ATTACK_MODULES, ALL_CATEGORIES
from reporter import generate_html_report
from models import Severity, SEVERITY_COLORS

# Page config
st.set_page_config(
    page_title="IAM Security Tester",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Dark theme CSS
st.markdown("""<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
    .stApp { background: #0a0e1a; font-family: 'Inter', sans-serif; }
    .main .block-container { padding: 1.5rem 2rem; max-width: 1400px; }
    h1, h2, h3 { color: #e8eaf0 !important; }
    .metric-card {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 14px;
        padding: 1.2rem;
        text-align: center;
    }
    .metric-value { font-size: 2.2rem; font-weight: 800; letter-spacing: -0.04em; }
    .metric-label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.12em;
                    color: #7a8599; margin-top: 0.2rem; font-weight: 600; }
    .sev-critical { color: #ff4444; }
    .sev-high { color: #ff8c00; }
    .sev-medium { color: #ffd700; }
    .sev-low { color: #4dabf7; }
    .sev-info { color: #868e96; }
    .badge { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 20px;
             font-size: 0.7rem; font-weight: 700; text-transform: uppercase; }
    .badge-critical { background: rgba(255,68,68,0.15); color: #ff4444; border: 1px solid rgba(255,68,68,0.3); }
    .badge-high { background: rgba(255,140,0,0.15); color: #ff8c00; border: 1px solid rgba(255,140,0,0.3); }
    .badge-medium { background: rgba(255,215,0,0.15); color: #ffd700; border: 1px solid rgba(255,215,0,0.3); }
    .badge-low { background: rgba(77,171,247,0.15); color: #4dabf7; border: 1px solid rgba(77,171,247,0.3); }
    .badge-info { background: rgba(134,142,150,0.15); color: #868e96; border: 1px solid rgba(134,142,150,0.3); }
    .finding-card {
        background: rgba(255,255,255,0.02);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 10px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    .page-header h1 { font-size: 1.75rem !important; font-weight: 800; margin-bottom: 0.25rem; }
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #3b82f6, #2563eb) !important;
        border: none !important;
        font-weight: 700 !important;
    }
    div[data-testid="stExpander"] { border: 1px solid rgba(255,255,255,0.06) !important; border-radius: 10px !important; }
    .attack-card {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 12px;
        padding: 0.8rem 1rem;
        margin-bottom: 0.5rem;
    }
    .attack-card:hover { border-color: rgba(59,130,246,0.3); }
</style>""", unsafe_allow_html=True)

# Attack module display info
ATTACK_INFO = {
    "authentication": {"icon": "🔑", "label": "Authentication", "desc": "Brute force, default creds, token manipulation, MFA bypass"},
    "authorization": {"icon": "🛡️", "label": "Authorization", "desc": "Always-allow bypass, IDOR, privilege escalation"},
    "api_security": {"icon": "🌐", "label": "API Security", "desc": "Missing auth, CORS, method tampering, Swagger exposure"},
    "cryptographic": {"icon": "🔐", "label": "Cryptographic", "desc": "Default keys, token entropy, algorithm confusion"},
    "injection": {"icon": "💉", "label": "Injection", "desc": "SQL injection, command injection, CRLF, JSON injection"},
    "xss": {"icon": "⚡", "label": "XSS", "desc": "Reflected XSS, stored XSS, XSS in error messages"},
    "session": {"icon": "🎫", "label": "Session", "desc": "Fixation, replay, enumeration, cross-agent access"},
    "information_disclosure": {"icon": "📋", "label": "Information Disclosure", "desc": "Error leakage, version disclosure, debug mode"},
    "input_validation": {"icon": "✅", "label": "Input Validation", "desc": "Boundary testing, encoding bypass, type confusion"},
    "business_logic": {"icon": "🧩", "label": "Business Logic", "desc": "Trust manipulation, mass assignment, workflow bypass"},
    "dos_ratelimit": {"icon": "🚦", "label": "DoS / Rate Limiting", "desc": "Rate limit testing, resource exhaustion, flooding"},
    "compliance": {"icon": "📜", "label": "Compliance", "desc": "Security headers, CORS policy, HSTS, cookie flags"},
}


def run_scan(target_url, timeout, categories, skip_dos):
    """Run a scan with given parameters and return the ScanResult."""
    config = ScanConfig(
        target_url=target_url,
        timeout=timeout,
        categories=categories,
        skip_dos=skip_dos,
    )
    runner = TestRunner(config)

    connected, msg = runner.check_connectivity()
    if not connected:
        st.error(f"Cannot connect to {target_url}: {msg}")
        return None

    progress_bar = st.progress(0, text="Starting scan...")

    # Live attack log
    log_container = st.container()
    log_container.markdown("""<div style="background:rgba(0,0,0,0.4); border:1px solid rgba(255,255,255,0.08);
        border-radius:10px; padding:0.75rem 1rem; margin-bottom:1rem;">
        <div style="font-size:0.75rem; color:#7a8599; text-transform:uppercase; font-weight:700;
            letter-spacing:0.1em; margin-bottom:0.5rem;">Live Attack Log</div>
        <div id="attack-log"></div>
    </div>""", unsafe_allow_html=True)
    log_area = log_container.empty()
    log_lines = []

    LEVEL_COLORS = {
        "info": "#7a8599",
        "success": "#22c55e",
        "danger": "#ff4444",
        "warning": "#ff8c00",
    }
    LEVEL_ICONS = {
        "info": "~",
        "success": "+",
        "danger": "!",
        "warning": "?",
    }

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
        # Keep last 50 lines to avoid slowdown
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

    # Final log summary
    findings_count = scan.total_findings
    sev = scan.findings_by_severity
    from models import Severity
    crit = sev.get(Severity.CRITICAL, 0)
    high = sev.get(Severity.HIGH, 0)
    log_lines.append(("module", f"\nScan complete: {findings_count} findings ({crit} critical, {high} high)", "#3b82f6"))
    _render_log()

    return scan


def show_results(scan, target_url):
    """Display scan results."""
    sev = scan.findings_by_severity

    # ---- Executive Summary ----
    st.markdown("---")
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value">{scan.total_findings}</div>
            <div class="metric-label">Total Findings</div>
        </div>""", unsafe_allow_html=True)
    with m2:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value sev-critical">{sev.get(Severity.CRITICAL, 0)}</div>
            <div class="metric-label">Critical</div>
        </div>""", unsafe_allow_html=True)
    with m3:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value sev-high">{sev.get(Severity.HIGH, 0)}</div>
            <div class="metric-label">High</div>
        </div>""", unsafe_allow_html=True)
    with m4:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value sev-medium">{sev.get(Severity.MEDIUM, 0)}</div>
            <div class="metric-label">Medium</div>
        </div>""", unsafe_allow_html=True)
    with m5:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value sev-low">{sev.get(Severity.LOW, 0) + sev.get(Severity.INFO, 0)}</div>
            <div class="metric-label">Low / Info</div>
        </div>""", unsafe_allow_html=True)

    st.markdown(f"""<div style="text-align:center; padding:0.5rem; color:#7a8599; font-size:0.8rem;">
        Target: {scan.target_url} | Duration: {scan.duration:.1f}s |
        Scan: {scan.scan_start.strftime('%Y-%m-%d %H:%M:%S')}
    </div>""", unsafe_allow_html=True)

    # ---- Charts ----
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

    # ---- Findings by Category ----
    st.markdown("---")
    st.markdown("### Findings by Category")

    findings_by_cat = {}
    for f in scan.all_findings:
        findings_by_cat.setdefault(f.category, []).append(f)

    for cat, findings in findings_by_cat.items():
        info_key = next((k for k, v in ATTACK_INFO.items() if v["label"] == cat), None)
        icon = ATTACK_INFO[info_key]["icon"] if info_key else "🔍"

        with st.expander(f"{icon} {cat} — {len(findings)} findings"):
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

    # ---- Module Results Table ----
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


def main():
    # ---- Sidebar ----
    with st.sidebar:
        st.markdown("""<div style="padding:0.5rem 0;">
            <div style="font-weight:800; font-size:1.2rem; color:#e8eaf0;">🔒 IAM Security Tester</div>
            <div style="color:#7a8599; font-size:0.75rem;">External Security Scanner</div>
        </div>""", unsafe_allow_html=True)
        st.markdown("---")

        target_url = st.text_input("Target URL", value="http://localhost:8000")

        # Connectivity check
        try:
            import requests
            resp = requests.get(f"{target_url}/", timeout=3)
            if resp.status_code < 500:
                st.markdown('<div style="color:#22c55e; font-size:0.8rem;">● Connected</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div style="color:#ff4444; font-size:0.8rem;">● Error</div>', unsafe_allow_html=True)
        except Exception:
            st.markdown('<div style="color:#ff4444; font-size:0.8rem;">● Disconnected</div>', unsafe_allow_html=True)

        st.markdown("---")
        timeout = st.slider("Timeout (seconds)", 5, 30, 10)

        st.markdown("---")

        # Scan mode selector
        scan_mode = st.radio(
            "Scan Mode",
            ["Run All Attacks", "Choose Attack"],
            index=0,
            label_visibility="visible",
        )

        selected_single = None
        skip_dos = False

        if scan_mode == "Run All Attacks":
            skip_dos = st.toggle("Skip DoS Tests", value=False)
            run_all_clicked = st.button("▶ Run All Attacks", type="primary", use_container_width=True)
            run_single_clicked = False
        else:
            # Show attack list with descriptions
            st.markdown('<p style="font-size:0.75rem; color:#7a8599; text-transform:uppercase; font-weight:600; letter-spacing:0.1em;">Select Attack</p>', unsafe_allow_html=True)

            attack_options = []
            for key in ALL_CATEGORIES:
                info = ATTACK_INFO.get(key, {})
                attack_options.append(f"{info.get('icon', '🔍')} {info.get('label', key)}")

            selected_idx = st.radio(
                "Attack",
                range(len(attack_options)),
                format_func=lambda i: attack_options[i],
                label_visibility="collapsed",
            )
            selected_single = ALL_CATEGORIES[selected_idx]

            # Show description of selected attack
            info = ATTACK_INFO.get(selected_single, {})
            st.markdown(f'<div style="font-size:0.78rem; color:#7a8599; padding:0.3rem 0;">{info.get("desc", "")}</div>', unsafe_allow_html=True)

            run_single_clicked = st.button(
                f"▶ Run {info.get('label', selected_single)}",
                type="primary",
                use_container_width=True,
            )
            run_all_clicked = False

        # ---- Action buttons ----
        st.markdown("---")

        # Clear results button
        has_results = "last_scan" in st.session_state and st.session_state["last_scan"] is not None
        if has_results:
            if st.button("🗑 Clear Results", use_container_width=True):
                st.session_state.pop("last_scan", None)
                st.session_state.pop("scan_history", None)
                st.rerun()

        # Push to IAM
        if has_results:
            st.markdown("---")
            st.markdown('<p style="font-size:0.75rem; color:#7a8599; text-transform:uppercase; font-weight:600; letter-spacing:0.1em;">Push Results</p>', unsafe_allow_html=True)
            push_url = st.text_input("IAM API URL", value=target_url, key="push_url")
            if st.button("📤 Push to IAM Dashboard", use_container_width=True):
                config = ScanConfig(target_url=push_url)
                runner = TestRunner(config)
                success, msg = runner.push_results_to_iam(st.session_state["last_scan"])
                if success:
                    st.success(msg)
                else:
                    st.warning(msg)

        # Scan history
        if "scan_history" in st.session_state and st.session_state.scan_history:
            st.markdown("---")
            st.markdown('<p style="font-size:0.75rem; color:#7a8599; text-transform:uppercase; font-weight:600;">Scan History</p>', unsafe_allow_html=True)
            for h in reversed(st.session_state.scan_history[-5:]):
                st.markdown(
                    f'<div style="font-size:0.8rem; color:#b0b8c5; padding:0.2rem 0;">'
                    f'{h["time"]} — {h["categories"]} — {h["findings"]} findings</div>',
                    unsafe_allow_html=True,
                )

    # ---- Main Area ----
    st.markdown("""<div class="page-header">
        <h1>🔒 IAM Security Tester</h1>
        <p style="color:#7a8599; font-size:0.88rem;">
            External black-box security testing for Agentic-IAM
        </p>
    </div>""", unsafe_allow_html=True)

    # ---- Handle scan execution ----
    if run_all_clicked:
        scan = run_scan(target_url, timeout, None, skip_dos)
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
        scan = run_scan(target_url, timeout, [selected_single], False)
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

    # ---- Display results or welcome screen ----
    scan = st.session_state.get("last_scan")
    if not scan:
        # Welcome screen with attack grid
        st.markdown("""<div style="text-align:center; padding:2rem 0;">
            <div style="font-size:3rem; margin-bottom:1rem;">🔒</div>
            <h2 style="color:#7a8599 !important;">Ready to Scan</h2>
            <p style="color:#5a6577; max-width:500px; margin:0 auto 2rem;">
                Choose <strong>Run All Attacks</strong> to test everything, or select
                a specific attack from the sidebar to test individually.
            </p>
        </div>""", unsafe_allow_html=True)

        # Attack grid overview
        st.markdown("### Available Attacks")
        cols = st.columns(3)
        for i, key in enumerate(ALL_CATEGORIES):
            info = ATTACK_INFO.get(key, {})
            with cols[i % 3]:
                st.markdown(f"""<div class="attack-card">
                    <div style="font-size:1.2rem; margin-bottom:0.3rem;">{info.get('icon', '🔍')}</div>
                    <div style="color:#e8eaf0; font-weight:700; font-size:0.9rem;">{info.get('label', key)}</div>
                    <div style="color:#7a8599; font-size:0.75rem; margin-top:0.2rem;">{info.get('desc', '')}</div>
                </div>""", unsafe_allow_html=True)
        return

    show_results(scan, target_url)

    # ---- Bottom actions ----
    st.markdown("---")
    act1, act2 = st.columns(2)

    with act1:
        if st.button("📄 Download HTML Report", use_container_width=True):
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

    with act2:
        if st.button("🔄 New Scan", use_container_width=True):
            st.session_state.pop("last_scan", None)
            st.rerun()


if __name__ == "__main__":
    main()
else:
    main()
