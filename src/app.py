from ai_explainer import explain_event
from textwrap import dedent
import json
from collections import Counter
from pathlib import Path

import pandas as pd
import streamlit as st

from detector import detect_brute_force
from log_parser import parse_log_line


# ---------------------------------------------------------
# Page configuration
# ---------------------------------------------------------

st.set_page_config(
    page_title="DF-101 | AI Linux Authentication Log Analyzer",
    page_icon="🐧",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------
# Custom styling
# ---------------------------------------------------------

st.markdown(
    """
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap');

        :root {
            --bg-main: #080c0a;
            --bg-secondary: #0d1410;
            --bg-card: #111a14;
            --bg-card-hover: #162119;
            --border: #243329;
            --border-bright: #31553b;
            --text-main: #e5f4e8;
            --text-muted: #8da495;
            --linux-green: #55ff7f;
            --green-dark: #1ca64c;
            --amber: #ffbe55;
            --red: #ff5f56;
            --blue: #65a8ff;
        }

        html,
        body,
        [class*="css"] {
            font-family: "Inter", sans-serif;
        }

        code,
        pre,
        .terminal-text,
        .metric-value,
        .card-meta {
            font-family: "JetBrains Mono", monospace !important;
        }

        .stApp {
            background:
                linear-gradient(rgba(85, 255, 127, 0.025) 1px, transparent 1px),
                linear-gradient(90deg, rgba(85, 255, 127, 0.025) 1px, transparent 1px),
                #080c0a;
            background-size: 34px 34px;
            color: var(--text-main);
        }

        .block-container {
            max-width: 1550px;
            padding-top: 1rem;
            padding-bottom: 3rem;
        }

        #MainMenu,
        footer {
            visibility: hidden;
        }

        header[data-testid="stHeader"] {
            background: transparent;
        }

        /* Sidebar */

        section[data-testid="stSidebar"] {
            background:
                linear-gradient(180deg, #0d1410 0%, #09100c 100%);
            border-right: 1px solid var(--border);
        }

        section[data-testid="stSidebar"] > div {
            padding-top: 1rem;
        }

        section[data-testid="stSidebar"] * {
            color: var(--text-main);
        }

        section[data-testid="stSidebar"] label,
        section[data-testid="stSidebar"] p,
        section[data-testid="stSidebar"] span {
            color: var(--text-muted) !important;
        }

        .sidebar-logo {
            font-family: "JetBrains Mono", monospace;
            font-size: 19px;
            font-weight: 700;
            color: var(--linux-green);
            margin-bottom: 5px;
        }

        .sidebar-caption {
            font-size: 11px;
            color: var(--text-muted);
            margin-bottom: 22px;
            font-family: "JetBrains Mono", monospace;
        }

        .sidebar-menu-item {
            background: rgba(17, 26, 20, 0.8);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 11px 12px;
            margin-bottom: 8px;
            color: #b8c8bc;
            font-size: 13px;
            font-weight: 600;
            transition: 0.2s ease;
        }

        .sidebar-menu-item:hover {
            border-color: var(--border-bright);
            background: var(--bg-card-hover);
        }

        .sidebar-menu-active {
            background: rgba(85, 255, 127, 0.1);
            border-color: var(--green-dark);
            color: var(--linux-green);
            box-shadow: inset 3px 0 0 var(--linux-green);
        }

        section[data-testid="stSidebar"] .sidebar-menu-active,
        section[data-testid="stSidebar"] .sidebar-menu-active * {
            color: var(--linux-green) !important;
        }

        /* Header */

        .top-header {
            background:
                linear-gradient(135deg, rgba(19, 31, 22, 0.98), rgba(9, 16, 12, 0.98));
            border: 1px solid var(--border-bright);
            border-radius: 12px;
            padding: 18px 22px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow:
                0 12px 36px rgba(0, 0, 0, 0.28),
                inset 0 1px 0 rgba(255, 255, 255, 0.03);
        }

        .brand-area {
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .brand-icon {
            width: 48px;
            height: 48px;
            border-radius: 10px;
            border: 1px solid var(--green-dark);
            background: rgba(85, 255, 127, 0.08);
            color: var(--linux-green);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 25px;
            box-shadow: 0 0 18px rgba(85, 255, 127, 0.08);
        }

        .brand-title {
            font-family: "JetBrains Mono", monospace;
            font-size: 20px;
            font-weight: 700;
            color: var(--text-main);
            margin: 0;
        }

        .brand-subtitle {
            font-family: "JetBrains Mono", monospace;
            font-size: 11px;
            color: var(--text-muted);
            margin-top: 5px;
        }

        .status-pill {
            background: rgba(85, 255, 127, 0.08);
            color: var(--linux-green);
            border: 1px solid var(--green-dark);
            border-radius: 999px;
            padding: 8px 13px;
            font-size: 11px;
            font-weight: 700;
            font-family: "JetBrains Mono", monospace;
            box-shadow: 0 0 14px rgba(85, 255, 127, 0.08);
        }

        /* Section text */

        .section-heading {
            font-family: "JetBrains Mono", monospace;
            font-size: 15px;
            font-weight: 700;
            color: var(--linux-green);
            margin: 11px 0 12px;
        }

        .section-heading::before {
            content: "$ ";
            color: var(--text-muted);
        }

        .section-description {
            font-size: 12px;
            color: var(--text-muted);
            margin-bottom: 15px;
            line-height: 1.7;
        }

        /* Metrics */

        .metric-card {
            background:
                linear-gradient(145deg, #111a14 0%, #0d1510 100%);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 18px;
            min-height: 128px;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.18);
            transition: transform 0.2s ease, border-color 0.2s ease;
        }

        .metric-card:hover {
            transform: translateY(-2px);
            border-color: var(--border-bright);
        }

        .metric-label {
            color: var(--text-muted);
            font-family: "JetBrains Mono", monospace;
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }

        .metric-value {
            font-size: 30px;
            font-weight: 700;
            color: var(--linux-green);
            margin-top: 12px;
        }

        .metric-note {
            font-size: 11px;
            color: #718276;
            margin-top: 5px;
        }

        /* Boards */

        .board-column {
            background:
                linear-gradient(145deg, rgba(17, 26, 20, 0.97), rgba(11, 18, 14, 0.97));
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 15px;
            min-height: 355px;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
        }

        .board-title {
            font-family: "JetBrains Mono", monospace;
            font-size: 12px;
            font-weight: 700;
            color: var(--text-main);
            margin-bottom: 13px;
            padding-bottom: 9px;
            border-bottom: 1px solid var(--border);
        }

        .event-card {
            border-radius: 8px;
            padding: 13px;
            margin-bottom: 10px;
            border: 1px solid transparent;
            font-size: 13px;
            background: #101812;
        }

        .success-card {
            background: rgba(48, 201, 91, 0.08);
            border-color: rgba(48, 201, 91, 0.28);
        }

        .failure-card {
            background: rgba(255, 190, 85, 0.08);
            border-color: rgba(255, 190, 85, 0.3);
        }

        .danger-card {
            background: rgba(255, 95, 86, 0.08);
            border-color: rgba(255, 95, 86, 0.32);
        }

        .info-card {
            background: rgba(101, 168, 255, 0.08);
            border-color: rgba(101, 168, 255, 0.28);
        }

        .card-event-title {
            font-family: "JetBrains Mono", monospace;
            font-size: 12px;
            font-weight: 700;
            color: var(--text-main);
            margin-bottom: 8px;
        }

        .card-meta {
            color: var(--text-muted);
            font-size: 10px;
            line-height: 1.65;
        }

        .card-meta strong {
            color: #c7d8ca;
        }

        /* Alerts */

        .critical-alert {
            background: rgba(255, 95, 86, 0.07);
            border: 1px solid rgba(255, 95, 86, 0.35);
            border-left: 4px solid var(--red);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 12px;
            box-shadow: 0 0 20px rgba(255, 95, 86, 0.04);
        }

        .critical-title {
            color: var(--red);
            font-family: "JetBrains Mono", monospace;
            font-size: 12px;
            font-weight: 700;
            margin-bottom: 7px;
        }

        .critical-description {
            color: #c9b4b1;
            font-size: 12px;
            line-height: 1.6;
        }

        /* File uploader */

        [data-testid="stFileUploader"] {
            background:
                linear-gradient(145deg, #111a14, #0c130e);
            border: 1px dashed var(--border-bright);
            border-radius: 10px;
            padding: 14px;
        }

        [data-testid="stFileUploader"] section {
            background: transparent;
        }

        [data-testid="stFileUploader"] button {
            background: rgba(85, 255, 127, 0.09) !important;
            color: var(--linux-green) !important;
            border: 1px solid var(--green-dark) !important;
            border-radius: 7px !important;
            font-family: "JetBrains Mono", monospace;
            font-weight: 700;
        }

        [data-testid="stFileUploader"] button:hover {
            background: rgba(85, 255, 127, 0.16) !important;
            border-color: var(--linux-green) !important;
        }

        [data-testid="stFileUploader"] button * {
            color: var(--linux-green) !important;
        }

        [data-testid="stFileUploader"] svg {
            color: var(--linux-green) !important;
        }

        /* Buttons */

        .stDownloadButton > button,
        .stButton > button {
            width: 100%;
            min-height: 42px;
            border-radius: 7px;
            background: #121d16;
            border: 1px solid var(--border-bright);
            color: var(--text-main);
            font-family: "JetBrains Mono", monospace;
            font-weight: 600;
            transition: 0.2s ease;
        }

        .stDownloadButton > button:hover,
        .stButton > button:hover {
            color: var(--linux-green);
            border-color: var(--linux-green);
            background: rgba(85, 255, 127, 0.07);
        }

        /* Dataframe */

        [data-testid="stDataFrame"] {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            overflow: hidden;
        }

        /* Expanders and containers */

        [data-testid="stExpander"] {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
        }

        [data-testid="stVerticalBlockBorderWrapper"] {
            background: var(--bg-card);
            border-color: var(--border);
        }

        /* Slider */

        [data-testid="stSlider"] [role="slider"] {
            background: var(--linux-green);
        }

        /* Divider */

        hr {
            border-color: var(--border);
        }

        /* Alerts generated by Streamlit */

        [data-testid="stAlert"] {
            background: #111a14;
            border: 1px solid var(--border);
            color: var(--text-main);
        }

        /* Scrollbar */

        ::-webkit-scrollbar {
            width: 9px;
            height: 9px;
        }

        ::-webkit-scrollbar-track {
            background: #090e0b;
        }

        ::-webkit-scrollbar-thumb {
            background: #26372b;
            border-radius: 10px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: #35523d;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------
# Helper functions
# ---------------------------------------------------------

def load_events(lines: list[str]) -> list[dict]:
    events = []

    for line in lines:
        parsed_event = parse_log_line(line)

        if parsed_event:
            events.append(parsed_event)

    return events


def render_event_card(event: dict, card_class: str) -> None:
    username = event.get("username") or "Unknown"
    ip_address = event.get("ip_address") or "Local system"
    timestamp = event.get("timestamp") or "Unknown time"

    event_names = {
        "successful_login": "Successful Login",
        "failed_login": "Failed Login",
        "invalid_user": "Invalid User Attempt",
        "sudo_usage": "Sudo Activity",
    }

    readable_name = event_names.get(
        event.get("event_type"),
        event.get("event_type", "Authentication Event").replace("_", " ").title(),
    )

    st.markdown(
        f"""
        <div class="event-card {card_class}">
            <div class="card-event-title">{readable_name}</div>
            <div class="card-meta">
                <strong>User:</strong> {username}<br>
                <strong>Source:</strong> {ip_address}<br>
                <strong>Time:</strong> {timestamp}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------
# Sidebar
# ---------------------------------------------------------

with st.sidebar:
    st.markdown(
        """
        <div class="sidebar-logo">🐧 DF-101 // AUTHGUARD</div>
<div class="sidebar-caption">
    root@digital-fort:~/security/auth-analysis
</div>

        <div class="sidebar-menu-item sidebar-menu-active">
            ◉ Analysis Workspace
        </div>

        <div class="sidebar-menu-item">
            ◫ Authentication Events
        </div>

        <div class="sidebar-menu-item">
            ⚠ Security Alerts
        </div>

        <div class="sidebar-menu-item">
            ⇩ Export Reports
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.divider()

    st.markdown(
    dedent(
        """
        <div class="top-header">
            <div class="brand-area">
                <div class="brand-icon">🐧</div>

                <div>
                    <div class="brand-title">
                        DF-101 // AI Linux Authentication Log Analyzer
                    </div>

                    <div class="brand-subtitle">
                        root@authguard:~$ monitor --source auth.log --mode detection
                    </div>
                </div>
            </div>

            <div class="status-pill">
                ● ENGINE ONLINE
            </div>
        </div>
        """
    ),
    unsafe_allow_html=True,
)

    brute_force_threshold = st.slider(
        "Brute-force threshold",
        min_value=3,
        max_value=15,
        value=5,
        help="Number of failed attempts required to create an alert.",
    )

    show_raw_logs = st.toggle(
        "Show raw log entries",
        value=False,
    )

    st.divider()

    st.caption("DF-101 Security Engineering Project")
    st.caption("Linux Authentication Log Analyzer")


# ---------------------------------------------------------
# Top header
# ---------------------------------------------------------

st.markdown(
    dedent(
    """
    <div class="top-header">
        <div class="brand-area">
            <div class="brand-icon">⌁</div>
            <div>
                <div class="brand-title">Authentication Analysis Workspace</div>
                <div class="brand-subtitle">
                    Upload, classify and investigate Linux authentication activity
                </div>
            </div>
        </div>

        <div class="status-pill">
            ● Detection engine active
        </div>
    </div>
    """
    ),
    unsafe_allow_html=True,
)


# ---------------------------------------------------------
# Upload area
# ---------------------------------------------------------

upload_column, information_column = st.columns([1.5, 1], gap="large")

with upload_column:
    st.markdown(
        '<div class="section-heading">Upload authentication logs</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="section-description">
            Select a Linux <strong>auth.log</strong> or text file. The analyzer
            extracts login outcomes, usernames, source IP addresses and sudo activity.
        </div>
        """,
        unsafe_allow_html=True,
    )

    uploaded_file = st.file_uploader(
        "Upload file",
        type=["log", "txt"],
        label_visibility="collapsed",
    )

with information_column:
    st.markdown(
        '<div class="section-heading">Detection coverage</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="board-column" style="min-height: 145px;">
            <div class="event-card info-card">
                <div class="card-event-title">Authentication monitoring</div>
                <div class="card-meta">
                    Successful and failed SSH login detection
                </div>
            </div>

            <div class="event-card danger-card">
                <div class="card-event-title">Threat detection</div>
                <div class="card-meta">
                    Invalid users, repeated failures and possible brute-force activity
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------
# Main analysis
# ---------------------------------------------------------

if uploaded_file is not None:
    try:
        raw_text = uploaded_file.read().decode("utf-8")
    except UnicodeDecodeError:
        st.error(
            "The uploaded file could not be read as UTF-8 text. "
            "Please upload a valid Linux authentication log."
        )
        st.stop()

    lines = raw_text.splitlines()
    events = load_events(lines)

    if not events:
        st.warning(
            "The file was uploaded successfully, but no supported authentication "
            "events were detected."
        )
        st.stop()

    alerts = detect_brute_force(
        events,
        threshold=brute_force_threshold,
    )

    event_counts = Counter(
        event.get("event_type", "unknown")
        for event in events
    )

    successful_count = event_counts.get("successful_login", 0)
    failed_count = event_counts.get("failed_login", 0)
    invalid_count = event_counts.get("invalid_user", 0)
    sudo_count = event_counts.get("sudo_usage", 0)

    unique_ips = len(
        {
            event.get("ip_address")
            for event in events
            if event.get("ip_address")
        }
    )

    st.markdown(
        '<div class="section-heading">Security overview</div>',
        unsafe_allow_html=True,
    )

    metric_columns = st.columns(5, gap="medium")

    metrics = [
        (
            "Total Events",
            len(events),
            "Parsed authentication records",
        ),
        (
            "Failed Logins",
            failed_count,
            "Unsuccessful authentication attempts",
        ),
        (
            "Successful Logins",
            successful_count,
            "Confirmed successful sessions",
        ),
        (
            "Source IPs",
            unique_ips,
            "Unique remote addresses",
        ),
        (
            "Critical Alerts",
            len(alerts),
            "Possible brute-force patterns",
        ),
    ]

    for column, metric in zip(metric_columns, metrics):
        label, value, note = metric

        with column:
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-label">{label}</div>
                    <div class="metric-value">{value}</div>
                    <div class="metric-note">{note}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("<br>", unsafe_allow_html=True)

    st.markdown(
        '<div class="section-heading">Authentication event board</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="section-description">
            Events are grouped into operational categories for faster SOC investigation.
        </div>
        """,
        unsafe_allow_html=True,
    )

    success_column, failure_column, suspicious_column, privilege_column = st.columns(
        4,
        gap="medium",
    )

    successful_events = [
        event
        for event in events
        if event.get("event_type") == "successful_login"
    ]

    failed_events = [
        event
        for event in events
        if event.get("event_type") == "failed_login"
    ]

    invalid_events = [
        event
        for event in events
        if event.get("event_type") == "invalid_user"
    ]

    sudo_events = [
        event
        for event in events
        if event.get("event_type") == "sudo_usage"
    ]

    with success_column:
        st.markdown(
            '<div class="board-title">Successful Access</div>',
            unsafe_allow_html=True,
        )

        if successful_events:
            for event in successful_events[:5]:
                render_event_card(event, "success-card")
        else:
            st.caption("No successful login events.")

    with failure_column:
        st.markdown(
            '<div class="board-title">Failed Authentication</div>',
            unsafe_allow_html=True,
        )

        if failed_events:
            for event in failed_events[:5]:
                render_event_card(event, "failure-card")
        else:
            st.caption("No failed login events.")

    with suspicious_column:
        st.markdown(
            '<div class="board-title">Suspicious Users</div>',
            unsafe_allow_html=True,
        )

        if invalid_events:
            for event in invalid_events[:5]:
                render_event_card(event, "danger-card")
        else:
            st.caption("No invalid-user attempts.")

    with privilege_column:
        st.markdown(
            '<div class="board-title">Privilege Activity</div>',
            unsafe_allow_html=True,
        )

        if sudo_events:
            for event in sudo_events[:5]:
                render_event_card(event, "info-card")
        else:
            st.caption("No sudo activity detected.")

    st.markdown("<br>", unsafe_allow_html=True)

    # -----------------------------------------------------
    # Alerts
    # -----------------------------------------------------

    st.markdown(
        '<div class="section-heading">Security alerts</div>',
        unsafe_allow_html=True,
    )

    if alerts:
        for alert in alerts:
            st.markdown(
                f"""
                <div class="critical-alert">
                    <div class="critical-title">
                        Possible Brute-Force Attack · {alert["severity"]}
                    </div>
                    <div class="critical-description">
                        {alert["description"]}<br>
                        <strong>Recommended action:</strong>
                        Review the source IP, disable the targeted account if necessary,
                        and apply rate limiting or automated blocking.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.success(
            "No brute-force pattern crossed the configured threshold."
        )

    # -----------------------------------------------------
    # Detailed table
    # -----------------------------------------------------

    st.markdown("<br>", unsafe_allow_html=True)

    st.markdown(
        '<div class="section-heading">Detailed event records</div>',
        unsafe_allow_html=True,
    )

    dataframe = pd.DataFrame(events)

    visible_columns = [
        column
        for column in [
            "timestamp",
            "event_type",
            "username",
            "ip_address",
            "outcome",
            "raw_log",
        ]
        if column in dataframe.columns
    ]

    if not show_raw_logs and "raw_log" in visible_columns:
        visible_columns.remove("raw_log")

    st.dataframe(
        dataframe[visible_columns],
        use_container_width=True,
        hide_index=True,
    )

    # -----------------------------------------------------
    # Export reports
    # -----------------------------------------------------

    st.markdown("<br>", unsafe_allow_html=True)

    st.markdown(
        '<div class="section-heading">Export analysis</div>',
        unsafe_allow_html=True,
    )

    csv_data = dataframe.to_csv(index=False).encode("utf-8")

    json_data = json.dumps(
        {
            "summary": {
                "total_events": len(events),
                "successful_logins": successful_count,
                "failed_logins": failed_count,
                "invalid_users": invalid_count,
                "sudo_events": sudo_count,
                "alerts": len(alerts),
            },
            "events": events,
            "alerts": alerts,
        },
        indent=2,
    )

    csv_column, json_column, summary_column = st.columns(
        3,
        gap="medium",
    )

    with csv_column:
        st.download_button(
            label="Download CSV Report",
            data=csv_data,
            file_name="authentication_analysis.csv",
            mime="text/csv",
        )

    with json_column:
        st.download_button(
            label="Download JSON Report",
            data=json_data,
            file_name="authentication_analysis.json",
            mime="application/json",
        )

    with summary_column:
        if st.button("Generate AI Investigation", key="generate_ai"):
            event_for_ai = alerts[0] if alerts else events[0]
            try:
                with st.spinner("Gemini is investigating the security event..."):
                    st.session_state["ai_investigation"] = explain_event(event_for_ai)
            except Exception as error:
                st.error(f"AI investigation failed: {error}")
                
                if "ai_investigation" in st.session_state:
                    st.markdown("<br>", unsafe_allow_html=True)
                    st.markdown(
                        '<div class="section-heading">AI Security Investigation</div>',
                        unsafe_allow_html=True,
                        )
                    with st.container(border=True):
                        st.markdown(st.session_state["ai_investigation"])

else:
    st.markdown("<br>", unsafe_allow_html=True)

    st.markdown(
        """
        <div class="board-column">
            <div class="board-title">Workspace is ready</div>

            <div class="event-card info-card">
                <div class="card-event-title">1. Upload authentication logs</div>
                <div class="card-meta">
                    Select an auth.log file using the upload area above.
                </div>
            </div>

            <div class="event-card success-card">
                <div class="card-event-title">2. Review classified events</div>
                <div class="card-meta">
                    Successful logins, failures, invalid users and sudo events
                    are automatically grouped.
                </div>
            </div>

            <div class="event-card failure-card">
                <div class="card-event-title">3. Investigate security alerts</div>
                <div class="card-meta">
                    Repeated authentication failures are evaluated for possible
                    brute-force activity.
                </div>
            </div>

            <div class="event-card danger-card">
                <div class="card-event-title">4. Export the investigation</div>
                <div class="card-meta">
                    Download structured CSV and JSON reports for documentation.
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )