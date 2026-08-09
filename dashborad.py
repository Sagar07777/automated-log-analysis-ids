import streamlit as st
import sqlite3
import pandas as pd
import time

st.set_page_config(
    page_title="IDS Dashboard",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ---------- Custom CSS ----------
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    .main {
        background-color: #0b0e14;
    }

    /* Hide default streamlit chrome */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}

    /* Title block */
    .app-header {
        display: flex;
        align-items: center;
        gap: 14px;
        padding: 4px 0 20px 0;
        border-bottom: 1px solid #1e2530;
        margin-bottom: 28px;
    }
    .app-header h1 {
        font-size: 26px;
        font-weight: 800;
        color: #f2f4f8;
        margin: 0;
        letter-spacing: -0.3px;
    }
    .app-header p {
        color: #6b7280;
        font-size: 13px;
        margin: 2px 0 0 0;
        font-family: 'JetBrains Mono', monospace;
    }

    /* Status banner */
    .status-banner {
        padding: 16px 22px;
        border-radius: 10px;
        margin-bottom: 26px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 15px;
        font-weight: 600;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .status-danger {
        background: linear-gradient(135deg, #2a0f14, #1a0a0d);
        border: 1px solid #7f1d2e;
        color: #ff6b7f;
    }
    .status-safe {
        background: linear-gradient(135deg, #0d1f17, #0a1510);
        border: 1px solid #1f6b45;
        color: #4ade80;
    }

    /* Metric cards */
    .metric-card {
        background: #11151d;
        border: 1px solid #1e2530;
        border-radius: 12px;
        padding: 20px 22px;
        text-align: left;
    }
    .metric-label {
        color: #6b7280;
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.6px;
        margin-bottom: 8px;
    }
    .metric-value {
        color: #f2f4f8;
        font-size: 32px;
        font-weight: 800;
        font-family: 'JetBrains Mono', monospace;
    }
    .metric-sub {
        color: #4b5563;
        font-size: 11px;
        margin-top: 4px;
    }

    /* Section headers */
    .section-title {
        color: #f2f4f8;
        font-size: 16px;
        font-weight: 700;
        margin: 32px 0 14px 0;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    /* Badges for event types */
    .badge-blocked {
        background: #2a0f14; color: #ff6b7f; border: 1px solid #7f1d2e;
        padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
    }
    .badge-failed {
        background: #2a2010; color: #fbbf24; border: 1px solid #7f6a1d;
        padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
    }
    .badge-unblocked {
        background: #0f1a2a; color: #60a5fa; border: 1px solid #1d4e7f;
        padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
    }
    .badge-allow {
        background: #0d1f17; color: #4ade80; border: 1px solid #1f6b45;
        padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
    }

    .ip-mono {
        font-family: 'JetBrains Mono', monospace;
        color: #d1d5db;
    }

    .empty-state {
        color: #4b5563;
        font-size: 13px;
        font-style: italic;
        padding: 20px;
        text-align: center;
        border: 1px dashed #1e2530;
        border-radius: 10px;
    }
</style>
""", unsafe_allow_html=True)

# ---------- Data loading ----------
def load_data():
    conn = sqlite3.connect("events.db")
    df = pd.read_sql_query("SELECT * FROM events ORDER BY id DESC", conn)
    conn.close()
    return df

df = load_data()

blocked_ips = df[df["event_type"] == "blocked"]["ip"].unique() if not df.empty else []
unblocked_ips = df[df["event_type"] == "unblocked"]["ip"].unique() if not df.empty else []
currently_blocked = [ip for ip in blocked_ips if ip not in unblocked_ips]

# ---------- Header ----------
st.markdown("""
<div class="app-header">
    <div style="font-size: 30px;">🛡</div>
    <div>
        <h1>Automated Log Analysis & Incident Response</h1>
        <p>Live SSH brute-force detection · auto-mitigation · audit trail</p>
    </div>
</div>
""", unsafe_allow_html=True)

# ---------- Status banner ----------
if currently_blocked:
    st.markdown(f"""
    <div class="status-banner status-danger">
        <span>🔴 ACTIVE THREAT — {len(currently_blocked)} IP(s) currently blocked</span>
        <span style="font-size:12px; opacity:0.7;">last checked {time.strftime('%H:%M:%S')}</span>
    </div>
    """, unsafe_allow_html=True)
else:
    st.markdown(f"""
    <div class="status-banner status-safe">
        <span>🟢 NO ACTIVE THREATS — system nominal</span>
        <span style="font-size:12px; opacity:0.7;">last checked {time.strftime('%H:%M:%S')}</span>
    </div>
    """, unsafe_allow_html=True)

# ---------- Metric cards ----------
total_events = len(df)
unique_ips = df["ip"].nunique() if not df.empty else 0
total_blocked_alltime = df[df["event_type"] == "blocked"]["ip"].nunique() if not df.empty else 0
allow_attempts = len(df[df["event_type"] == "allowlisted_attempt"]) if not df.empty else 0

c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(f"""<div class="metric-card"><div class="metric-label">Total Events</div>
    <div class="metric-value">{total_events}</div><div class="metric-sub">all recorded activity</div></div>""", unsafe_allow_html=True)
with c2:
    st.markdown(f"""<div class="metric-card"><div class="metric-label">Unique Source IPs</div>
    <div class="metric-value">{unique_ips}</div><div class="metric-sub">seen in logs</div></div>""", unsafe_allow_html=True)
with c3:
    st.markdown(f"""<div class="metric-card"><div class="metric-label">IPs Blocked (all-time)</div>
    <div class="metric-value">{total_blocked_alltime}</div><div class="metric-sub">auto-mitigated</div></div>""", unsafe_allow_html=True)
with c4:
    st.markdown(f"""<div class="metric-card"><div class="metric-label">Allowlisted Attempts</div>
    <div class="metric-value">{allow_attempts}</div><div class="metric-sub">ignored, never blocked</div></div>""", unsafe_allow_html=True)

# ---------- Currently blocked ----------
st.markdown('<div class="section-title">🚫 Currently Blocked IPs</div>', unsafe_allow_html=True)
if currently_blocked:
    st.dataframe(
        pd.DataFrame(currently_blocked, columns=["Blocked IP"]),
        use_container_width=True,
        hide_index=True
    )
else:
    st.markdown('<div class="empty-state">No IPs currently blocked</div>', unsafe_allow_html=True)

# ---------- Timeline chart ----------
st.markdown('<div class="section-title">📈 Failed Login Attempts Over Time</div>', unsafe_allow_html=True)
failed_df = df[df["event_type"] == "failed_login"].copy()
if not failed_df.empty:
    failed_df["timestamp"] = pd.to_datetime(failed_df["timestamp"])
    chart_data = failed_df.groupby(failed_df["timestamp"].dt.floor("min")).size()
    st.line_chart(chart_data, color="#ff6b7f", height=260)
else:
    st.markdown('<div class="empty-state">No failed login data yet</div>', unsafe_allow_html=True)

# ---------- Full event log ----------
st.markdown('<div class="section-title">📋 Full Event Log</div>', unsafe_allow_html=True)
if not df.empty:
    display_df = df.copy()
    badge_map = {
        "blocked": "🔴 blocked",
        "failed_login": "🟡 failed_login",
        "unblocked": "🔵 unblocked",
        "allowlisted_attempt": "🟢 allowlisted"
    }
    display_df["event_type"] = display_df["event_type"].map(lambda x: badge_map.get(x, x))
    st.dataframe(
        display_df[["timestamp", "ip", "event_type", "details"]],
        use_container_width=True,
        hide_index=True,
        height=320
    )
else:
    st.markdown('<div class="empty-state">No events recorded yet</div>', unsafe_allow_html=True)

st.markdown(
    '<p style="color:#374151; font-size:11px; margin-top:24px;">Auto-refreshes every 5 seconds · built with Python, SQLite & Streamlit</p>',
    unsafe_allow_html=True
)

time.sleep(5)
st.rerun()
