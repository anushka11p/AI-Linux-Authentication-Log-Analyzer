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
    page_title="SentinelAuth | Linux Log Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------
# Custom styling
# ---------------------------------------------------------

st.markdown(
    """
    <style>
        /* Main application */
        .stApp {
            background-color: #f5f6f8;
            color: #172033;
        }

        .block-container {
            max-width: 1500px;
            padding-top: 1.2rem;
            padding-bottom: 3rem;
        }

        /* Hide Streamlit branding */
        #MainMenu {
            visibility: hidden;
        }

        footer {
            visibility: hidden;
        }

        header[data-testid="stHeader"] {
            background: transparent;
        }

        /* Sidebar */
        section[data-testid="stSidebar"] {
            background-color: #ffffff;
            border-right: 1px solid #e5e7eb;
        }

        section[data-testid="stSidebar"] > div {
            padding-top: 1.2rem;
        }

        /* Header */
        .top-header {
            background: #ffffff;
            border: 1px solid #e5e7eb;
            border-radius: 16px;
            padding: 18px 22px;
            margin-bottom: 18px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: 0 4px 18px rgba(15, 23, 42, 0.04);
        }

        .brand-area {
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .brand-icon {
            width: 46px;
            height: 46px;
            border-radius: 13px;
            background: #171a2b;
            color: #ffffff;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
        }

        .brand-title {
            font-size: 21px;
            font-weight: 750;
            color: #111827;
            margin: 0;
        }

        .brand-subtitle {
            font-size: 13px;
            color: #6b7280;
            margin-top: 3px;
        }

        .status-pill {
            background: #ecfdf3;
            color: #18794e;
            border: 1px solid #b7ebcd;
            border-radius: 999px;
            padding: 7px 13px;
            font-size: 12px;
            font-weight: 700;
        }

        /* Section headings */
        .section-heading {
            font-size: 17px;
            font-weight: 750;
            color: #172033;
            margin: 8px 0 12px 0;
        }

        .section-description {
            font-size: 13px;
            color: #6b7280;
            margin-bottom: 15px;
        }

        /* Metric cards */
        .metric-card {
            background: #ffffff;
            border: 1px solid #e5e7eb;
            border-radius: 15px;
            padding: 18px;
            min-height: 128px;
            box-shadow: 0 5px 18px rgba(15, 23, 42, 0.035);
        }

        .metric-label {
            color: #6b7280;
            font-size: 12px;
            font-weight: 650;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .metric-value {
            font-size: 31px;
            font-weight: 800;
            color: #111827;
            margin-top: 12px;
        }

        .metric-note {
            font-size: 12px;
            color: #8490a3;
            margin-top: 4px;
        }

        /* Workspace board */
        .board-column {
            background: #ffffff;
            border: 1px solid #e3e6eb;
            border-radius: 15px;
            padding: 15px;
            min-height: 355px;
            box-shadow: 0 4px 15px rgba(15, 23, 42, 0.03);
        }

        .board-title {
            font-size: 14px;
            font-weight: 750;
            color: #1f2937;
            margin-bottom: 12px;
        }

        .event-card {
            border-radius: 11px;
            padding: 13px;
            margin-bottom: 10px;
            border: 1px solid transparent;
            font-size: 13px;
        }

        .success-card {
            background: #eaf7ef;
            border-color: #bde4ca;
        }

        .failure-card {
            background: #fff3d9;
            border-color: #f3d897;
        }

        .danger-card {
            background: #ffe7e7;
            border-color: #f1b4b4;
        }

        .info-card {
            background: #e9f2ff;
            border-color: #b8d3f5;
        }

        .card-event-title {
            font-size: 13px;
            font-weight: 750;
            color: #202938;
            margin-bottom: 6px;
        }

        .card-meta {
            color: #596579;
            font-size: 12px;
            line-height: 1.55;
        }

        /* Alert */
        .critical-alert {
            background: #fff5f5;
            border: 1px solid #f0b7b7;
            border-left: 5px solid #cf3f3f;
            border-radius: 12px;
            padding: 15px;
            margin-bottom: 12px;
        }

        .critical-title {
            color: #9f2424;
            font-size: 14px;
            font-weight: 800;
            margin-bottom: 5px;
        }

        .critical-description {
            color: #613a3a;
            font-size: 13px;
            line-height: 1.55;
        }

        /* Upload box */
        [data-testid="stFileUploader"] {
            background: #ffffff;
            border: 1px dashed #bbc3d0;
            border-radius: 14px;
            padding: 12px;
        }

        /* Buttons */
        .stDownloadButton > button,
        .stButton > button {
            width: 100%;
            border-radius: 10px;
            font-weight: 700;
            min-height: 42px;
        }

        /* Dataframe */
        [data-testid="stDataFrame"] {
            background: #ffffff;
            border: 1px solid #e5e7eb;
            border-radius: 14px;
            overflow: hidden;
        }

        /* Sidebar logo */
        .sidebar-logo {
            font-size: 21px;
            font-weight: 800;
            color: #111827;
            margin-bottom: 4px;
        }

        .sidebar-caption {
            font-size: 12px;
            color: #7b8495;
            margin-bottom: 22px;
        }

        .sidebar-menu-item {
            background: #f7f8fa;
            border: 1px solid #e7e9ed;
            border-radius: 10px;
            padding: 11px 12px;
            margin-bottom: 8px;
            color: #344054;
            font-size: 13px;
            font-weight: 650;
        }

        .sidebar-menu-active {
            background: #171a2b;
            color: #ffffff;
            border-color: #171a2b;
        }

        /* Force all sidebar text to remain visible */
section[data-testid="stSidebar"] {
    color: #172033 !important;
}

section[data-testid="stSidebar"] * {
    color: #172033;
}

section[data-testid="stSidebar"] label,
section[data-testid="stSidebar"] p,
section[data-testid="stSidebar"] span,
section[data-testid="stSidebar"] div[data-testid="stMarkdownContainer"] {
    color: #172033 !important;
}

/* Keep active menu item white */
section[data-testid="stSidebar"] .sidebar-menu-active,
section[data-testid="stSidebar"] .sidebar-menu-active * {
    color: #ffffff !important;
}

/* Slider labels and values */
section[data-testid="stSidebar"] [data-testid="stSlider"] label,
section[data-testid="stSidebar"] [data-testid="stSlider"] p {
    color: #344054 !important;
}

/* Toggle text */
section[data-testid="stSidebar"] [data-testid="stCheckbox"] label,
section[data-testid="stSidebar"] [data-testid="stToggle"] label {
    color: #344054 !important;
}

/* Sidebar captions */
section[data-testid="stSidebar"] .stCaption,
section[data-testid="stSidebar"] [data-testid="stCaptionContainer"] {
    color: #7b8495 !important;
}

[data-testid="stFileUploader"] button {
    background-color: #1f2937 !important;
    color: white !important;
    border: none !important;
    font-weight: 600;
}

[data-testid="stFileUploader"] button:hover {
    background-color: #111827 !important;
    color: white !important;
}

/* Upload icon */
[data-testid="stFileUploader"] svg {
    color: white !important;
}

/* Upload text */
[data-testid="stFileUploader"] span {
    color: white !important;
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
        <div class="sidebar-logo">🛡️ SentinelAuth</div>
        <div class="sidebar-caption">
            AI-powered authentication monitoring
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
    '<div style="font-size:15px;font-weight:700;color:#172033;margin-bottom:12px;">Analysis settings</div>',
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