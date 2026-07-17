from ai_explainer import explain_event
from textwrap import dedent
import html
import json
from collections import Counter

import pandas as pd
import streamlit as st

from detector import detect_brute_force
from log_parser import parse_log_line


st.set_page_config(
    page_title="DF-101 | AI Linux Authentication Log Analyzer",
    page_icon="🐧",
    layout="wide",
    initial_sidebar_state="expanded",
)


st.markdown(
    dedent(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap');

        :root {
            --bg-main: #070b08;
            --bg-sidebar: #0a100c;
            --bg-card: #101813;
            --bg-card-hover: #142019;
            --border: #233229;
            --border-bright: #356044;
            --text-main: #e7f5ea;
            --text-muted: #8da497;
            --linux-green: #54f579;
            --green-dark: #1c9d48;
            --amber: #ffbd52;
            --red: #ff6259;
            --blue: #68a9ff;
        }

        html, body, [class*="css"] {
            font-family: "Inter", sans-serif;
        }

        code, pre, .metric-value, .card-meta, .terminal-line {
            font-family: "JetBrains Mono", monospace !important;
        }

        .stApp {
            background:
                linear-gradient(rgba(84, 245, 121, 0.018) 1px, transparent 1px),
                linear-gradient(90deg, rgba(84, 245, 121, 0.018) 1px, transparent 1px),
                var(--bg-main);
            background-size: 38px 38px;
            color: var(--text-main);
        }

        .block-container {
            max-width: 1500px;
            padding-top: 1.1rem;
            padding-bottom: 3rem;
        }

        #MainMenu, footer { visibility: hidden; }
        header[data-testid="stHeader"] { background: transparent; }

        section[data-testid="stSidebar"] {
            background: linear-gradient(180deg, #0c130e, #080d0a);
            border-right: 1px solid var(--border);
        }

        section[data-testid="stSidebar"] > div {
            padding-top: 1.1rem;
        }

        section[data-testid="stSidebar"] label,
        section[data-testid="stSidebar"] p,
        section[data-testid="stSidebar"] span {
            color: var(--text-muted) !important;
        }

        .sidebar-brand {
            border: 1px solid var(--border);
            background: linear-gradient(145deg, #101914, #0c120e);
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 16px;
        }

        .sidebar-logo {
            font-family: "JetBrains Mono", monospace;
            color: var(--linux-green);
            font-size: 17px;
            font-weight: 700;
        }

        .sidebar-caption {
            color: var(--text-muted);
            font-family: "JetBrains Mono", monospace;
            font-size: 10px;
            line-height: 1.55;
            margin-top: 7px;
        }

        .sidebar-section {
            color: #708177;
            font-family: "JetBrains Mono", monospace;
            font-size: 9px;
            font-weight: 700;
            letter-spacing: .14em;
            margin: 18px 0 8px;
        }

        .sidebar-menu-item {
            background: rgba(16, 24, 19, .86);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 10px 12px;
            margin-bottom: 7px;
            color: #b8c8bc;
            font-family: "JetBrains Mono", monospace;
            font-size: 11px;
        }

        .sidebar-menu-active {
            background: rgba(84, 245, 121, .08);
            border-color: var(--green-dark);
            color: var(--linux-green);
            box-shadow: inset 3px 0 0 var(--linux-green);
        }

        .top-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 20px;
            background: linear-gradient(135deg, rgba(18, 29, 21, .98), rgba(9, 15, 11, .98));
            border: 1px solid var(--border-bright);
            border-radius: 13px;
            padding: 20px 22px;
            margin-bottom: 20px;
            box-shadow: 0 14px 38px rgba(0, 0, 0, .28);
        }

        .brand-area {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .brand-icon {
            width: 48px;
            height: 48px;
            border-radius: 10px;
            border: 1px solid var(--green-dark);
            background: rgba(84, 245, 121, .08);
            display: flex;
            justify-content: center;
            align-items: center;
            font-size: 24px;
        }

        .brand-title {
            color: var(--text-main);
            font-family: "JetBrains Mono", monospace;
            font-size: 18px;
            font-weight: 700;
        }

        .brand-subtitle {
            color: var(--text-muted);
            font-family: "JetBrains Mono", monospace;
            font-size: 10px;
            margin-top: 6px;
        }

        .status-pill {
            flex-shrink: 0;
            color: var(--linux-green);
            background: rgba(84, 245, 121, .07);
            border: 1px solid var(--green-dark);
            border-radius: 999px;
            padding: 8px 12px;
            font-family: "JetBrains Mono", monospace;
            font-size: 10px;
            font-weight: 700;
        }

        .section-heading {
            color: var(--linux-green);
            font-family: "JetBrains Mono", monospace;
            font-size: 14px;
            font-weight: 700;
            margin: 16px 0 10px;
        }

        .section-heading::before {
            content: "root@authguard:~$ ";
            color: #6f8175;
            font-weight: 500;
        }

        .section-description {
            color: var(--text-muted);
            font-size: 12px;
            line-height: 1.65;
            margin-bottom: 14px;
        }

        .metric-card {
            min-height: 118px;
            background: linear-gradient(145deg, #111b15, #0d1510);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 17px;
            box-shadow: 0 8px 24px rgba(0, 0, 0, .16);
        }

        .metric-card:hover { border-color: var(--border-bright); }

        .metric-label {
            color: var(--text-muted);
            font-family: "JetBrains Mono", monospace;
            font-size: 9px;
            font-weight: 700;
            letter-spacing: .1em;
            text-transform: uppercase;
        }

        .metric-value {
            color: var(--linux-green);
            font-size: 29px;
            font-weight: 700;
            margin-top: 11px;
        }

        .metric-note {
            color: #718176;
            font-size: 10px;
            margin-top: 5px;
        }

        .board-title {
            color: var(--text-main);
            border-bottom: 1px solid var(--border);
            font-family: "JetBrains Mono", monospace;
            font-size: 11px;
            font-weight: 700;
            padding-bottom: 9px;
            margin-bottom: 11px;
        }

        .event-card {
            background: #101812;
            border: 1px solid transparent;
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 9px;
        }

        .success-card {
            background: rgba(48, 201, 91, .07);
            border-color: rgba(48, 201, 91, .26);
        }

        .failure-card {
            background: rgba(255, 189, 82, .07);
            border-color: rgba(255, 189, 82, .28);
        }

        .danger-card {
            background: rgba(255, 98, 89, .07);
            border-color: rgba(255, 98, 89, .30);
        }

        .info-card {
            background: rgba(104, 169, 255, .07);
            border-color: rgba(104, 169, 255, .27);
        }

        .card-event-title {
            color: var(--text-main);
            font-family: "JetBrains Mono", monospace;
            font-size: 11px;
            font-weight: 700;
            margin-bottom: 7px;
        }

        .card-meta {
            color: var(--text-muted);
            font-size: 9px;
            line-height: 1.7;
        }

        .card-meta strong { color: #c6d6c9; }

        .critical-alert {
            background: rgba(255, 98, 89, .07);
            border: 1px solid rgba(255, 98, 89, .35);
            border-left: 4px solid var(--red);
            border-radius: 8px;
            padding: 14px;
            margin-bottom: 10px;
        }

        .critical-title {
            color: var(--red);
            font-family: "JetBrains Mono", monospace;
            font-size: 11px;
            font-weight: 700;
            margin-bottom: 7px;
        }

        .critical-description {
            color: #c7b5b2;
            font-size: 11px;
            line-height: 1.6;
        }

        .terminal-panel {
            background: #060907;
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 14px 16px;
            margin: 10px 0 18px;
        }

        .terminal-bar {
            color: #718176;
            font-family: "JetBrains Mono", monospace;
            font-size: 9px;
            border-bottom: 1px solid #19231d;
            padding-bottom: 8px;
            margin-bottom: 9px;
        }

        .terminal-line {
            color: #a9b8ad;
            font-size: 10px;
            line-height: 1.8;
        }

        .terminal-ok { color: var(--linux-green); }
        .terminal-warn { color: var(--amber); }
        .terminal-danger { color: var(--red); }

        [data-testid="stFileUploader"] {
            background: linear-gradient(145deg, #111a14, #0c130e);
            border: 1px dashed var(--border-bright);
            border-radius: 10px;
            padding: 13px;
        }

        [data-testid="stFileUploader"] section { background: transparent; }

        [data-testid="stFileUploader"] button {
            background: rgba(84, 245, 121, .09) !important;
            color: var(--linux-green) !important;
            border: 1px solid var(--green-dark) !important;
            border-radius: 7px !important;
            font-family: "JetBrains Mono", monospace !important;
            font-weight: 700 !important;
        }

        [data-testid="stFileUploader"] button * {
            color: var(--linux-green) !important;
        }

        .stDownloadButton > button, .stButton > button {
            width: 100%;
            min-height: 42px;
            border-radius: 7px;
            background: #121d16;
            border: 1px solid var(--border-bright);
            color: var(--text-main);
            font-family: "JetBrains Mono", monospace;
            font-weight: 600;
        }

        .stDownloadButton > button:hover, .stButton > button:hover {
            color: var(--linux-green);
            border-color: var(--linux-green);
            background: rgba(84, 245, 121, .07);
        }

        [data-testid="stDataFrame"], [data-testid="stExpander"] {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            overflow: hidden;
        }

        [data-testid="stSlider"] [role="slider"] { background: var(--linux-green); }
        [data-testid="stAlert"] {
            background: #111a14;
            border: 1px solid var(--border);
            color: var(--text-main);
        }

        hr { border-color: var(--border); }

        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: #080c09; }
        ::-webkit-scrollbar-thumb { background: #27372c; border-radius: 10px; }

        @media (max-width: 900px) {
            .top-header { align-items: flex-start; flex-direction: column; }
            .brand-title { font-size: 15px; }
        }
        </style>
        """
    ),
    unsafe_allow_html=True,
)


def load_events(lines: list[str]) -> list[dict]:
    events = []
    for line in lines:
        parsed_event = parse_log_line(line)
        if parsed_event:
            events.append(parsed_event)
    return events


def safe(value: object, fallback: str) -> str:
    if value is None or value == "":
        return fallback
    return html.escape(str(value))


def render_event_card(event: dict, card_class: str) -> None:
    event_names = {
        "successful_login": "Successful Login",
        "failed_login": "Failed Login",
        "invalid_user": "Invalid User Attempt",
        "sudo_usage": "Sudo Activity",
    }

    event_type = str(event.get("event_type", "authentication_event"))
    readable_name = event_names.get(
        event_type,
        event_type.replace("_", " ").title(),
    )

    st.markdown(
        dedent(
            f"""
            <div class="event-card {card_class}">
                <div class="card-event-title">{safe(readable_name, "Authentication Event")}</div>
                <div class="card-meta">
                    <strong>User:</strong> {safe(event.get("username"), "Unknown")}<br>
                    <strong>Source:</strong> {safe(event.get("ip_address"), "Local system")}<br>
                    <strong>Time:</strong> {safe(event.get("timestamp"), "Unknown time")}
                </div>
            </div>
            """
        ),
        unsafe_allow_html=True,
    )



# -----------------------------------------------------------------------------
# Interactive sidebar navigation
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown(
        dedent(
            """
            <div class="sidebar-brand">
                <div class="sidebar-logo">DF-101 // AUTHGUARD</div>
                <div class="sidebar-caption">
                    root@digital-fort:~/security/auth-analysis
                </div>
            </div>
            <div class="sidebar-section">WORKSPACE</div>
            """
        ),
        unsafe_allow_html=True,
    )

    page = st.radio(
        "Workspace navigation",
        [
            "01 / Analysis Workspace",
            "02 / Authentication Events",
            "03 / Security Alerts",
            "04 / Export Reports",
        ],
        label_visibility="collapsed",
        key="workspace_page",
    )

    st.markdown('<div class="sidebar-section">LOG SOURCE</div>', unsafe_allow_html=True)
    uploaded_file = st.file_uploader(
        "Upload auth.log",
        type=["log", "txt"],
        key="auth_log_upload",
    )

    st.markdown('<div class="sidebar-section">DETECTION SETTINGS</div>', unsafe_allow_html=True)
    brute_force_threshold = st.slider(
        "Brute-force threshold",
        min_value=3,
        max_value=15,
        value=5,
        help="Failed attempts required to create an alert.",
    )
    show_raw_logs = st.toggle("Show raw log entries", value=False)

    st.divider()
    st.caption("DF-101 Security Engineering Project")
    st.caption("Local Python detection · Gemini explanations")


st.markdown(
    dedent(
        """
        <div class="top-header">
            <div class="brand-area">
                <div class="brand-icon">⌁</div>
                <div>
                    <div class="brand-title">DF-101 // AI Linux Authentication Log Analyzer</div>
                    <div class="brand-subtitle">
                        root@authguard:~$ monitor --source auth.log --mode detection
                    </div>
                </div>
            </div>
            <div class="status-pill">● ENGINE ONLINE</div>
        </div>
        """
    ),
    unsafe_allow_html=True,
)


# Parse the uploaded file once per rerun and keep the results available to every page.
if uploaded_file is not None:
    try:
        raw_bytes = uploaded_file.getvalue()
        raw_text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        st.error("The uploaded file is not valid UTF-8 text.")
        st.stop()

    lines = raw_text.splitlines()
    events = load_events(lines)
    alerts = detect_brute_force(events, threshold=brute_force_threshold) if events else []

    st.session_state["log_lines"] = lines
    st.session_state["events"] = events
    st.session_state["alerts"] = alerts
    st.session_state["uploaded_filename"] = uploaded_file.name
else:
    lines = st.session_state.get("log_lines", [])
    events = st.session_state.get("events", [])
    alerts = st.session_state.get("alerts", [])

# Recalculate alerts when the threshold changes.
if events:
    alerts = detect_brute_force(events, threshold=brute_force_threshold)
    st.session_state["alerts"] = alerts




def render_ai_investigation(ai_candidates: list[dict], key_prefix: str) -> None:
    """Render the Gemini investigation controls on any workspace page."""
    if not ai_candidates:
        return

    st.markdown('<div class="section-heading">ai investigation</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-description">Select a detected event or alert and generate a Gemini-assisted explanation.</div>',
        unsafe_allow_html=True,
    )

    selected_index = st.selectbox(
        "Event to investigate",
        range(len(ai_candidates)),
        format_func=lambda i: (
            f"{i + 1}. {ai_candidates[i].get('event_type', 'alert').replace('_', ' ').title()}"
            f" · {ai_candidates[i].get('ip_address', ai_candidates[i].get('source_ip', 'unknown source'))}"
        ),
        key=f"{key_prefix}_ai_event",
    )

    if st.button(
        "Generate AI Investigation",
        key=f"{key_prefix}_generate_ai",
        type="primary",
        use_container_width=True,
    ):
        try:
            with st.spinner("Gemini is investigating the selected event..."):
                st.session_state["ai_investigation"] = explain_event(ai_candidates[selected_index])
        except Exception as error:
            st.error(f"AI investigation failed: {error}")

    if st.session_state.get("ai_investigation"):
        with st.container(border=True):
            st.markdown(st.session_state["ai_investigation"])


def render_empty_state(message: str) -> None:
    st.markdown(
        dedent(
            f"""
            <div class="terminal-panel">
                <div class="terminal-bar">authguard-console / waiting</div>
                <div class="terminal-line"><span class="terminal-ok">[READY]</span> Detection engine initialized</div>
                <div class="terminal-line">$ {safe(message, "Upload auth.log to begin")}</div>
            </div>
            """
        ),
        unsafe_allow_html=True,
    )


# Shared calculated values
if events:
    event_counts = Counter(event.get("event_type", "unknown") for event in events)
    successful_count = event_counts.get("successful_login", 0)
    failed_count = event_counts.get("failed_login", 0)
    invalid_count = event_counts.get("invalid_user", 0)
    sudo_count = event_counts.get("sudo_usage", 0)
    unique_ips = len({event.get("ip_address") for event in events if event.get("ip_address")})
    dataframe = pd.DataFrame(events)
else:
    successful_count = failed_count = invalid_count = sudo_count = unique_ips = 0
    dataframe = pd.DataFrame()


# -----------------------------------------------------------------------------
# Page 1: Analysis Workspace
# -----------------------------------------------------------------------------
if page == "01 / Analysis Workspace":
    st.markdown('<div class="section-heading">analysis workspace</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-description">Upload a Linux authentication log from the sidebar to run local Python detection.</div>',
        unsafe_allow_html=True,
    )

    if not events:
        render_empty_state("upload auth.log from the left sidebar to begin local analysis")
        st.markdown(
            dedent(
                """
                <div class="event-card info-card">
                    <div class="card-event-title">Detection coverage</div>
                    <div class="card-meta">
                        Successful and failed SSH logins, invalid users, sudo activity,
                        repeated failures and brute-force patterns.
                    </div>
                </div>
                """
            ),
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            dedent(
                f"""
                <div class="terminal-panel">
                    <div class="terminal-bar">authguard-console / local-analysis</div>
                    <div class="terminal-line"><span class="terminal-ok">[OK]</span> Loaded {len(lines)} log lines</div>
                    <div class="terminal-line"><span class="terminal-ok">[OK]</span> Extracted {len(events)} authentication events</div>
                    <div class="terminal-line"><span class="terminal-warn">[WARN]</span> Detected {failed_count} failed logins and {invalid_count} invalid-user attempts</div>
                    <div class="terminal-line"><span class="terminal-danger">[ALERT]</span> {len(alerts)} brute-force pattern(s) crossed the active threshold</div>
                </div>
                """
            ),
            unsafe_allow_html=True,
        )

        st.markdown('<div class="section-heading">summary</div>', unsafe_allow_html=True)
        metric_columns = st.columns(5, gap="medium")
        metrics = [
            ("Total Events", len(events), "Parsed authentication records"),
            ("Failed Logins", failed_count, "Unsuccessful attempts"),
            ("Successful Logins", successful_count, "Confirmed sessions"),
            ("Source IPs", unique_ips, "Unique remote addresses"),
            ("Critical Alerts", len(alerts), "Brute-force patterns"),
        ]
        for column, (label, value, note) in zip(metric_columns, metrics):
            with column:
                st.markdown(
                    dedent(
                        f"""
                        <div class="metric-card">
                            <div class="metric-label">{safe(label, "")}</div>
                            <div class="metric-value">{safe(value, "0")}</div>
                            <div class="metric-note">{safe(note, "")}</div>
                        </div>
                        """
                    ),
                    unsafe_allow_html=True,
                )

        st.markdown('<div class="section-heading">recent activity</div>', unsafe_allow_html=True)
        recent = events[-8:][::-1]
        for event in recent:
            card_class = {
                "successful_login": "success-card",
                "failed_login": "failure-card",
                "invalid_user": "danger-card",
                "sudo_usage": "info-card",
            }.get(event.get("event_type"), "info-card")
            render_event_card(event, card_class)

        render_ai_investigation(alerts if alerts else events, "analysis")


# -----------------------------------------------------------------------------
# Page 2: Authentication Events
# -----------------------------------------------------------------------------
elif page == "02 / Authentication Events":
    st.markdown('<div class="section-heading">authentication events</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-description">Search, filter and review every parsed authentication event.</div>',
        unsafe_allow_html=True,
    )

    if not events:
        render_empty_state("upload auth.log before opening the authentication event explorer")
    else:
        filter_col, search_col = st.columns([1, 2], gap="medium")
        available_types = sorted(dataframe["event_type"].dropna().unique().tolist()) if "event_type" in dataframe else []
        with filter_col:
            event_type_filter = st.selectbox("Event type", ["All"] + available_types)
        with search_col:
            search_text = st.text_input("Search username, IP address or raw log")

        filtered = dataframe.copy()
        if event_type_filter != "All":
            filtered = filtered[filtered["event_type"] == event_type_filter]
        if search_text:
            mask = filtered.astype(str).apply(
                lambda column: column.str.contains(search_text, case=False, na=False)
            ).any(axis=1)
            filtered = filtered[mask]

        visible_columns = [
            column for column in
            ["timestamp", "event_type", "username", "ip_address", "outcome", "raw_log"]
            if column in filtered.columns
        ]
        if not show_raw_logs and "raw_log" in visible_columns:
            visible_columns.remove("raw_log")

        st.caption(f"Showing {len(filtered)} of {len(events)} events")
        st.dataframe(filtered[visible_columns], use_container_width=True, hide_index=True)


# -----------------------------------------------------------------------------
# Page 3: Security Alerts
# -----------------------------------------------------------------------------
elif page == "03 / Security Alerts":
    st.markdown('<div class="section-heading">security alerts</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-description">Review brute-force findings and generate a Gemini-assisted investigation.</div>',
        unsafe_allow_html=True,
    )

    if not events:
        render_empty_state("upload auth.log before opening the alert investigation workspace")
    else:
        if alerts:
            for index, alert in enumerate(alerts, start=1):
                st.markdown(
                    dedent(
                        f"""
                        <div class="critical-alert">
                            <div class="critical-title">Alert {index:02d} · Possible Brute-Force Attack · {safe(alert.get("severity"), "HIGH")}</div>
                            <div class="critical-description">
                                {safe(alert.get("description"), "Repeated authentication failures detected.")}<br>
                                <strong>Recommended action:</strong> Review the source IP, inspect the targeted account,
                                block malicious traffic and apply authentication rate limiting.
                            </div>
                        </div>
                        """
                    ),
                    unsafe_allow_html=True,
                )
        else:
            st.success("No brute-force pattern crossed the configured threshold.")

        render_ai_investigation(alerts if alerts else events, "alerts")


# -----------------------------------------------------------------------------
# Page 4: Export Reports
# -----------------------------------------------------------------------------
elif page == "04 / Export Reports":
    st.markdown('<div class="section-heading">export reports</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-description">Download the complete analysis as structured CSV or JSON.</div>',
        unsafe_allow_html=True,
    )

    if not events:
        render_empty_state("upload auth.log before exporting an analysis report")
    else:
        report_summary = {
            "total_events": len(events),
            "successful_logins": successful_count,
            "failed_logins": failed_count,
            "invalid_users": invalid_count,
            "sudo_events": sudo_count,
            "alerts": len(alerts),
            "brute_force_threshold": brute_force_threshold,
        }

        summary_columns = st.columns(3, gap="medium")
        summary_items = [
            ("Events", len(events)),
            ("Alerts", len(alerts)),
            ("Source IPs", unique_ips),
        ]
        for col, (label, value) in zip(summary_columns, summary_items):
            with col:
                st.metric(label, value)

        csv_data = dataframe.to_csv(index=False).encode("utf-8")
        json_data = json.dumps(
            {"summary": report_summary, "events": events, "alerts": alerts},
            indent=2,
            default=str,
        )

        csv_column, json_column = st.columns(2, gap="medium")
        with csv_column:
            st.download_button(
                "Download CSV Report",
                csv_data,
                "authentication_analysis.csv",
                "text/csv",
                use_container_width=True,
            )
        with json_column:
            st.download_button(
                "Download JSON Report",
                json_data,
                "authentication_analysis.json",
                "application/json",
                use_container_width=True,
            )