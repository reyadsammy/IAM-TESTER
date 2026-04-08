"""Reusable UI components and enhanced CSS for the IAM Security Tester dashboard."""

import streamlit as st
from models import KillChainPhase, HealingStatus, HEALING_STATUS_COLORS


def inject_css():
    """Inject the full enhanced CSS theme with neon/cyber aesthetics."""
    st.markdown("""<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');

    .stApp { background: #0a0e1a; font-family: 'Inter', sans-serif; }
    .main .block-container { padding: 1.5rem 2rem; max-width: 1400px; }
    h1, h2, h3 { color: #e8eaf0 !important; }

    /* Metric cards */
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

    /* Severity colors */
    .sev-critical { color: #ff4444; }
    .sev-high { color: #ff8c00; }
    .sev-medium { color: #ffd700; }
    .sev-low { color: #4dabf7; }
    .sev-info { color: #868e96; }

    /* Badges */
    .badge { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 20px;
             font-size: 0.7rem; font-weight: 700; text-transform: uppercase; }
    .badge-critical { background: rgba(255,68,68,0.15); color: #ff4444; border: 1px solid rgba(255,68,68,0.3); }
    .badge-high { background: rgba(255,140,0,0.15); color: #ff8c00; border: 1px solid rgba(255,140,0,0.3); }
    .badge-medium { background: rgba(255,215,0,0.15); color: #ffd700; border: 1px solid rgba(255,215,0,0.3); }
    .badge-low { background: rgba(77,171,247,0.15); color: #4dabf7; border: 1px solid rgba(77,171,247,0.3); }
    .badge-info { background: rgba(134,142,150,0.15); color: #868e96; border: 1px solid rgba(134,142,150,0.3); }

    /* Finding cards */
    .finding-card {
        background: rgba(255,255,255,0.02);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 10px;
        padding: 1rem;
        margin: 0.5rem 0;
    }

    /* Page header */
    .page-header h1 { font-size: 1.75rem !important; font-weight: 800; margin-bottom: 0.25rem; }

    /* Buttons */
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #3b82f6, #2563eb) !important;
        border: none !important; font-weight: 700 !important;
    }

    /* Expanders */
    div[data-testid="stExpander"] { border: 1px solid rgba(255,255,255,0.06) !important; border-radius: 10px !important; }

    /* Attack cards */
    .attack-card {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 12px;
        padding: 0.8rem 1rem;
        margin-bottom: 0.5rem;
        transition: all 0.3s ease;
    }
    .attack-card:hover { border-color: rgba(59,130,246,0.3); transform: translateY(-2px); }

    /* ─── Neon / Cyber Enhancements ─── */
    @keyframes neonPulse {
        0%, 100% { box-shadow: 0 0 5px rgba(59,130,246,0.3), 0 0 20px rgba(59,130,246,0.1); }
        50% { box-shadow: 0 0 10px rgba(59,130,246,0.5), 0 0 40px rgba(59,130,246,0.2); }
    }
    @keyframes fadeInUp {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    @keyframes terminalType {
        from { opacity: 0; }
        to { opacity: 1; }
    }
    @keyframes spinGlow {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    @keyframes breathe {
        0%, 100% { opacity: 0.4; }
        50% { opacity: 1; }
    }

    /* Scenario cards */
    .scenario-card {
        background: linear-gradient(135deg, rgba(255,255,255,0.03), rgba(59,130,246,0.05));
        border: 1px solid rgba(59,130,246,0.15);
        border-radius: 16px;
        padding: 1.5rem;
        cursor: pointer;
        transition: all 0.3s ease;
    }
    .scenario-card:hover {
        border-color: rgba(59,130,246,0.4);
        box-shadow: 0 0 20px rgba(59,130,246,0.15);
        transform: translateY(-3px);
    }

    /* Kill chain bar */
    .kill-chain-bar {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 0;
        padding: 1.5rem 0;
    }
    .kc-phase {
        display: flex; align-items: center; justify-content: center;
        padding: 0.5rem 1rem;
        border-radius: 8px;
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        min-width: 110px;
        text-align: center;
        transition: all 0.5s ease;
    }
    .kc-dim { background: rgba(255,255,255,0.03); color: #3a4255; border: 1px solid rgba(255,255,255,0.05); }
    .kc-active { background: rgba(59,130,246,0.15); color: #60a5fa; border: 1px solid rgba(59,130,246,0.4);
                 animation: neonPulse 2s infinite; }
    .kc-done { background: rgba(34,197,94,0.12); color: #22c55e; border: 1px solid rgba(34,197,94,0.3); }
    .kc-failed { background: rgba(255,68,68,0.12); color: #ff4444; border: 1px solid rgba(255,68,68,0.3); }
    .kc-arrow { color: #2a3040; font-size: 1.2rem; margin: 0 0.2rem; }

    /* Terminal view */
    .terminal-container {
        background: #0c0c0c;
        border: 1px solid rgba(34,197,94,0.2);
        border-radius: 12px;
        padding: 0;
        overflow: hidden;
        font-family: 'JetBrains Mono', 'Consolas', monospace;
    }
    .terminal-header {
        background: rgba(34,197,94,0.08);
        padding: 0.5rem 1rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        border-bottom: 1px solid rgba(34,197,94,0.15);
    }
    .terminal-dot { width: 10px; height: 10px; border-radius: 50%; }
    .terminal-body {
        padding: 1rem 1.2rem;
        max-height: 500px;
        overflow-y: auto;
        font-size: 0.78rem;
        line-height: 1.7;
    }
    .t-line { animation: terminalType 0.3s ease forwards; opacity: 0; }
    .t-cmd { color: #22c55e; }
    .t-response { color: #7a8599; }
    .t-success { color: #22c55e; font-weight: 700; }
    .t-fail { color: #ff4444; font-weight: 700; }
    .t-warn { color: #ff8c00; }
    .t-header { color: #60a5fa; font-weight: 700; }

    /* Healing cards */
    .heal-card {
        background: rgba(255,255,255,0.02);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 12px;
        padding: 1rem 1.2rem;
        margin: 0.5rem 0;
        animation: fadeInUp 0.4s ease forwards;
    }
    .heal-card-success { border-color: rgba(34,197,94,0.25); }
    .heal-card-failed { border-color: rgba(255,68,68,0.25); }

    /* Status badges for healing */
    .status-pending { color: #7a8599; }
    .status-in_progress { color: #3b82f6; }
    .status-success { color: #22c55e; }
    .status-failed { color: #ff4444; }
    .status-verified { color: #a855f7; }

    /* Animated welcome */
    .welcome-glow {
        animation: breathe 3s ease-in-out infinite;
    }

    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 0;
        background: rgba(255,255,255,0.02);
        border-radius: 12px;
        padding: 0.3rem;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        font-weight: 600;
        font-size: 0.85rem;
    }

    /* Timeline */
    .timeline-item {
        display: flex;
        gap: 1rem;
        padding: 0.8rem 0;
        border-left: 2px solid rgba(255,255,255,0.08);
        margin-left: 1rem;
        padding-left: 1.5rem;
        position: relative;
    }
    .timeline-item::before {
        content: '';
        position: absolute;
        left: -5px;
        top: 1rem;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #3b82f6;
    }
    .timeline-done::before { background: #22c55e; }
    .timeline-fail::before { background: #ff4444; }
    .timeline-active::before { background: #3b82f6; animation: breathe 1.5s ease-in-out infinite; }
</style>""", unsafe_allow_html=True)


def render_kill_chain(phases, active_index, step_statuses=None):
    """Render a horizontal kill chain bar.

    phases: list of KillChainPhase
    active_index: index of the currently active phase (-1 if none)
    step_statuses: optional dict mapping phase -> 'done'|'failed'|'active'|'dim'
    """
    html = '<div class="kill-chain-bar">'
    for i, phase in enumerate(phases):
        if step_statuses and phase in step_statuses:
            css_class = f"kc-{step_statuses[phase]}"
        elif i < active_index:
            css_class = "kc-done"
        elif i == active_index:
            css_class = "kc-active"
        else:
            css_class = "kc-dim"

        if i > 0:
            html += '<span class="kc-arrow">&#9656;</span>'
        html += f'<div class="kc-phase {css_class}">{phase.value}</div>'
    html += '</div>'
    st.markdown(html, unsafe_allow_html=True)


def render_terminal_view(lines):
    """Render an animated terminal view with green-on-black hacker aesthetic.

    lines: list of (css_class, text) tuples.
    css_class: 't-cmd', 't-response', 't-success', 't-fail', 't-warn', 't-header'
    """
    html = '<div class="terminal-container">'
    html += '<div class="terminal-header">'
    html += '<div class="terminal-dot" style="background:#ff5f57;"></div>'
    html += '<div class="terminal-dot" style="background:#febc2e;"></div>'
    html += '<div class="terminal-dot" style="background:#28c840;"></div>'
    html += '<span style="color:#7a8599; font-size:0.75rem; margin-left:0.5rem;">breach-simulator</span>'
    html += '</div>'
    html += '<div class="terminal-body">'
    for i, (css_class, text) in enumerate(lines):
        delay = i * 0.08
        escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        html += f'<div class="t-line {css_class}" style="animation-delay:{delay:.2f}s;">{escaped}</div>'
    html += '</div></div>'
    st.markdown(html, unsafe_allow_html=True)


def render_step_timeline(steps):
    """Render a vertical timeline of attack or healing steps."""
    html = ''
    for step in steps:
        if step.status == "success":
            cls = "timeline-done"
            icon = "&#10003;"
            icon_color = "#22c55e"
        elif step.status == "failed":
            cls = "timeline-fail"
            icon = "&#10007;"
            icon_color = "#ff4444"
        elif step.status == "running":
            cls = "timeline-active"
            icon = "&#9679;"
            icon_color = "#3b82f6"
        elif step.status == "skipped":
            cls = ""
            icon = "&#8212;"
            icon_color = "#3a4255"
        else:
            cls = ""
            icon = "&#9675;"
            icon_color = "#3a4255"

        phase_label = step.phase.value if hasattr(step, 'phase') else ""
        html += f'''<div class="timeline-item {cls}">
            <div style="min-width:180px;">
                <div style="color:{icon_color}; font-weight:700; font-size:0.85rem;">
                    <span style="margin-right:0.4rem;">{icon}</span>{step.name}
                </div>
                <div style="color:#5a6577; font-size:0.72rem; margin-top:0.15rem;">{phase_label}</div>
            </div>
            <div style="flex:1; color:#7a8599; font-size:0.8rem;">{step.description}</div>
        </div>'''
    st.markdown(html, unsafe_allow_html=True)


def render_animated_welcome():
    """Render the enhanced animated welcome screen."""
    st.markdown("""<div style="text-align:center; padding:3rem 0;">
        <div class="welcome-glow" style="font-size:4rem; margin-bottom:1rem;">&#128274;</div>
        <h2 style="color:#e8eaf0 !important; font-weight:800; margin-bottom:0.5rem;">
            IAM Security Command Center
        </h2>
        <p style="color:#5a6577; max-width:600px; margin:0 auto 1rem; font-size:0.9rem;">
            Attack simulation, vulnerability detection, and automated self-healing
            for your Agentic-IAM system.
        </p>
        <div style="display:flex; justify-content:center; gap:2rem; margin-top:2rem;">
            <div style="text-align:center;">
                <div style="font-size:1.5rem; margin-bottom:0.3rem;">&#9876;</div>
                <div style="color:#7a8599; font-size:0.75rem; font-weight:600;">SCANNER</div>
            </div>
            <div style="text-align:center;">
                <div style="font-size:1.5rem; margin-bottom:0.3rem;">&#128163;</div>
                <div style="color:#7a8599; font-size:0.75rem; font-weight:600;">BREACH SIM</div>
            </div>
            <div style="text-align:center;">
                <div style="font-size:1.5rem; margin-bottom:0.3rem;">&#128737;</div>
                <div style="color:#7a8599; font-size:0.75rem; font-weight:600;">SELF-HEAL</div>
            </div>
        </div>
    </div>""", unsafe_allow_html=True)


def render_metric_card(value, label, color="#e8eaf0"):
    """Return HTML for a styled metric card."""
    return f"""<div class="metric-card">
        <div class="metric-value" style="color:{color};">{value}</div>
        <div class="metric-label">{label}</div>
    </div>"""
