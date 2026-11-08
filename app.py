
import hashlib
import html

import pandas as pd
import plotly.express as px
import streamlit as st

from cyberrisk_ai.controller.openssh_parser import (
    parse_openssh_logs,
)
from cyberrisk_ai.controller.filters import (
    filter_authentication_events,
    sort_authentication_events,
)
from cyberrisk_ai.validation.evidence_validation import (
    validate_authentication_evidence,
)
from cyberrisk_ai.dashboard.methodology import (
    render_methodology_page,
)


# ============================================================
# 1. APPLICATION CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="CyberRisk AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# 2. SESSION STATE
# ============================================================

DEFAULT_STATE = {
    "openssh_df": None,
    "filtered_openssh_df": None,
    "openssh_filename": None,
    "openssh_file_id": None,
    "theme_mode": "Dark",
}

for key, value in DEFAULT_STATE.items():
    if key not in st.session_state:
        st.session_state[key] = value


# ============================================================
# 3. SIDEBAR NAVIGATION
# ============================================================

with st.sidebar:
    st.title("🛡️ CyberRisk AI")
    st.caption("Security Operations & Risk Analysis")

    st.divider()

    st.selectbox(
        "Appearance",
        ["Dark", "Light"],
        key="theme_mode",
    )

    st.divider()

    page = st.radio(
        "Navigation",
        [
            "Dashboard",
            "Upload OpenSSH Logs",
            "SOC Analysis",
            "Evidence Validation",
            "GRC Risk Assessment",
            "Results & Reporting",
            "Methodology & Workflow",
        ],
    )

    st.divider()
    st.caption("Research Prototype | Fall 2026")
    st.caption("Current Dataset: OpenSSH Authentication")


# ============================================================
# 4. THEME COLORS
# ============================================================

if st.session_state["theme_mode"] == "Dark":
    COLORS = {
        "background": "#0E1117",
        "card": "#1B2430",
        "text": "#F9FAFB",
        "muted": "#D1D5DB",
        "border": "#465365",
        "failure": "#FCA5A5",
        "success": "#86EFAC",
        "primary": "#93C5FD",
        "chart": "#83C6F4",
    }
else:
    COLORS = {
        "background": "#FFFFFF",
        "card": "#F3F4F6",
        "text": "#111827",
        "muted": "#374151",
        "border": "#D1D5DB",
        "failure": "#B91C1C",
        "success": "#15803D",
        "primary": "#1D4ED8",
        "chart": "#2563EB",
    }

st.markdown(
    f"""
    <style>
    .stApp {{
        background-color: {COLORS["background"]};
        color: {COLORS["text"]};
    }}

    .cyber-card {{
        background-color: {COLORS["card"]};
        border: 1px solid {COLORS["border"]};
        border-radius: 12px;
        padding: 22px 14px;
        text-align: center;
        min-height: 135px;
        margin-bottom: 12px;
    }}

    .cyber-label {{
        color: {COLORS["muted"]};
        font-size: 14px;
        font-weight: 600;
        margin-bottom: 12px;
    }}

    .cyber-number {{
        font-size: 34px;
        font-weight: 750;
        line-height: 1.2;
        font-variant-numeric: tabular-nums;
    }}

    .cyber-failure {{
        color: {COLORS["failure"]};
    }}

    .cyber-success {{
        color: {COLORS["success"]};
    }}

    .cyber-primary {{
        color: {COLORS["primary"]};
    }}
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# 5. CONSTANTS
# ============================================================

COLUMN_LABELS = {
    "line_number": "Log Line",
    "timestamp": "Timestamp",
    "status": "Authentication Status",
    "username": "Username",
    "source_ip": "Source IP Address",
    "port": "Source Port",
    "auth_method": "Authentication Method",
    "event_count": "Authentication Event Count",
    "raw_message": "Original Log Message",
}

SORT_OPTIONS = {
    "Timestamp": "timestamp",
    "Source IP Address": "source_ip",
    "Username": "username",
    "Authentication Status": "status",
    "Authentication Event Count": "event_count",
}


# ============================================================
# 6. REUSABLE DISPLAY FUNCTIONS
# ============================================================

def metric_card(label, value, color_class="cyber-primary"):
    """Display a professional metric card."""

    safe_label = html.escape(str(label))
    safe_value = html.escape(str(value))

    st.markdown(
        f"""
        <div class="cyber-card">
            <div class="cyber-label">{safe_label}</div>
            <div class="cyber-number {color_class}">
                {safe_value}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def section_header(title, description=None):
    """Display a consistent section heading."""

    st.subheader(title)

    if description:
        st.caption(description)


def get_active_data():
    """Return filtered data when available."""

    filtered = st.session_state.get(
        "filtered_openssh_df"
    )

    if filtered is not None:
        return filtered

    return st.session_state.get("openssh_df")


def display_event_table(df):
    """Display readable headings without renaming columns."""

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        column_config={
            column: label
            for column, label in COLUMN_LABELS.items()
            if column in df.columns
        },
    )


def calculate_metrics(df):
    """Calculate preliminary authentication statistics."""

    counts = pd.to_numeric(
        df["event_count"],
        errors="coerce",
    ).fillna(0)

    failures = int(
        counts[df["status"] == "FAILURE"].sum()
    )

    successes = int(
        counts[df["status"] == "SUCCESS"].sum()
    )

    return {
        "parsed_records": len(df),
        "failed_events": failures,
        "successful_events": successes,
        "total_events": failures + successes,
        "unique_ips": int(df["source_ip"].nunique()),
        "unique_usernames": int(
            df["username"].nunique()
        ),
    }


def display_authentication_metrics(df):
    """Display three authentication overview cards."""

    summary = calculate_metrics(df)

    col1, col2, col3 = st.columns(3)

    with col1:
        metric_card(
            "Failed Authentication Events",
            f'{summary["failed_events"]:,}',
            "cyber-failure",
        )

    with col2:
        metric_card(
            "Successful Authentication Events",
            f'{summary["successful_events"]:,}',
            "cyber-success",
        )

    with col3:
        metric_card(
            "Unique Source IP Addresses",
            f'{summary["unique_ips"]:,}',
            "cyber-primary",
        )


def display_evidence_summary(summary):
    """Display six evidence metrics and outcome rates."""

    section_header(
        "Evidence Validation Summary",
        "Authentication statistics calculated from "
        "the selected OpenSSH records.",
    )

    row1 = st.columns(3)

    with row1[0]:
        metric_card(
            "Parsed Log Records",
            f'{summary["parsed_records"]:,}',
        )

    with row1[1]:
        metric_card(
            "Total Authentication Events",
            f'{summary["total_events"]:,}',
        )

    with row1[2]:
        metric_card(
            "Failed Authentication Events",
            f'{summary["failed_events"]:,}',
            "cyber-failure",
        )

    row2 = st.columns(3)

    with row2[0]:
        metric_card(
            "Successful Authentication Events",
            f'{summary["successful_events"]:,}',
            "cyber-success",
        )

    with row2[1]:
        metric_card(
            "Unique Source IP Addresses",
            f'{summary["unique_ips"]:,}',
        )

    with row2[2]:
        metric_card(
            "Unique Usernames",
            f'{summary["unique_usernames"]:,}',
        )

    st.divider()

    section_header(
        "Authentication Outcome Analysis",
        "Distribution of failed and successful "
        "authentication events.",
    )

    total = summary["total_events"]

    if total > 0:
        failure_rate = (
            summary["failed_events"] / total
        ) * 100

        success_rate = (
            summary["successful_events"] / total
        ) * 100

        col1, col2 = st.columns(2)

        with col1:
            st.metric(
                "Failed Authentication Rate",
                f"{failure_rate:.1f}%",
            )
            st.progress(failure_rate / 100)

        with col2:
            st.metric(
                "Successful Authentication Rate",
                f"{success_rate:.1f}%",
            )
            st.progress(success_rate / 100)

    st.info(
        "These figures are calculated from parsed "
        "authentication records. They do not independently "
        "verify the original source log."
    )


# ============================================================
# 7. VERTICAL BAR CHART FUNCTION
# ============================================================

def display_vertical_chart(
    df,
    category_column,
    chart_title,
    top_n=10,
):
    """
    Display vertical bars with horizontal category labels.

    IP addresses appear beneath the bars without
    being rotated vertically.
    """

    chart_data = (
        df.groupby(
            category_column,
            dropna=False,
        )["event_count"]
        .sum()
        .sort_values(ascending=False)
        .head(top_n)
        .reset_index()
    )

    chart_data.columns = [
        "Category",
        "Authentication Events",
    ]

    chart_data["Category"] = (
        chart_data["Category"]
        .fillna("Unknown")
        .astype(str)
    )

    if chart_data.empty:
        st.info("No authentication events to display.")
        return

    fig = px.bar(
        chart_data,
        x="Category",
        y="Authentication Events",
        text="Authentication Events",
    )

    fig.update_traces(
        marker_color=COLORS["chart"],
        textposition="outside",
        cliponaxis=False,
    )

    fig.update_layout(
        title=None,
        height=420,
        margin=dict(
            l=30,
            r=30,
            t=20,
            b=80,
        ),
        xaxis=dict(
            title=None,
            tickangle=0,
            type="category",
            automargin=True,
            tickfont=dict(size=12),
        ),
        yaxis=dict(
            title="Authentication Event Count",
            rangemode="tozero",
            tickformat=",d",
        ),
        showlegend=False,
        font=dict(
            color=COLORS["text"],
        ),
        paper_bgcolor=COLORS["background"],
        plot_bgcolor=COLORS["background"],
    )

    st.plotly_chart(
        fig,
        use_container_width=True,
        key=f"chart_{category_column}_{chart_title}",
    )


# ============================================================
# 8. DASHBOARD
# ============================================================

if page == "Dashboard":

    st.title("🛡️ CyberRisk AI")

    st.subheader(
        "OpenSSH Security Operations & GRC Analysis"
    )

    st.write(
        "A locally hosted cybersecurity research platform "
        "for examining OpenSSH authentication activity "
        "and supporting evidence-based investigations."
    )

    st.divider()

    df = st.session_state.get("openssh_df")

    if df is None or df.empty:
        st.info(
            "No OpenSSH authentication dataset is loaded. "
            "Select Upload OpenSSH Logs to begin."
        )

    else:
        section_header("Authentication Overview")

        display_authentication_metrics(df)

        section_header(
            "Authentication Event Distribution"
        )

        display_vertical_chart(
            df,
            category_column="status",
            chart_title="Authentication Distribution",
        )

        st.caption(
            "Statistics remain preliminary until raw-log "
            "reconciliation is completed."
        )


# ============================================================
# 9. UPLOAD OPENSSH LOGS
# ============================================================

elif page == "Upload OpenSSH Logs":

    st.title("Upload OpenSSH Authentication Logs")

    st.write(
        "Upload, inspect, filter, and sort OpenSSH "
        "authentication records."
    )

    uploaded_file = st.file_uploader(
        "Select an OpenSSH Log File",
        type=["log", "txt"],
    )

    if uploaded_file is not None:

        raw_bytes = uploaded_file.getvalue()

        if not raw_bytes:
            st.error("The uploaded file is empty.")
            st.stop()

        file_id = hashlib.sha256(raw_bytes).hexdigest()

        if file_id != st.session_state["openssh_file_id"]:

            log_content = raw_bytes.decode(
                "utf-8",
                errors="replace",
            )

            try:
                parsed_df = parse_openssh_logs(
                    log_content
                )

            except Exception as error:
                st.error(
                    f"OpenSSH parsing failed: {error}"
                )
                st.stop()

            st.session_state["openssh_df"] = parsed_df
            st.session_state["filtered_openssh_df"] = None
            st.session_state["openssh_filename"] = (
                uploaded_file.name
            )
            st.session_state["openssh_file_id"] = file_id

        df = st.session_state["openssh_df"]

        st.success(
            f"File loaded: {uploaded_file.name}"
        )

        with st.expander("View Original Log Preview"):

            preview = raw_bytes[:10000].decode(
                "utf-8",
                errors="replace",
            )

            st.text_area(
                "Original OpenSSH Log",
                value=preview,
                height=250,
            )

        if df.empty:
            st.warning(
                "No supported OpenSSH authentication "
                "events were detected."
            )

            st.session_state[
                "filtered_openssh_df"
            ] = None

        else:
            section_header(
                "Authentication Filters",
                "Select criteria to narrow the "
                "authentication evidence.",
            )

            col1, col2, col3 = st.columns(3)

            with col1:
                selected_ips = st.multiselect(
                    "Source IP Address",
                    sorted(
                        df["source_ip"]
                        .dropna()
                        .unique()
                        .tolist()
                    ),
                )

            with col2:
                selected_users = st.multiselect(
                    "Username",
                    sorted(
                        df["username"]
                        .dropna()
                        .unique()
                        .tolist()
                    ),
                )

            with col3:
                selected_statuses = st.multiselect(
                    "Authentication Status",
                    ["FAILURE", "SUCCESS"],
                    format_func=lambda status: {
                        "FAILURE": "Failed",
                        "SUCCESS": "Successful",
                    }[status],
                )

            filtered_df = filter_authentication_events(
                df,
                source_ips=selected_ips,
                usernames=selected_users,
                statuses=selected_statuses,
            )

            section_header("Sorting Options")

            sort_col, order_col = st.columns(2)

            with sort_col:
                selected_sort = st.selectbox(
                    "Sort Authentication Events By",
                    list(SORT_OPTIONS.keys()),
                )

            with order_col:
                sort_order = st.radio(
                    "Sort Direction",
                    ["Ascending", "Descending"],
                    horizontal=True,
                )

            filtered_df = sort_authentication_events(
                filtered_df,
                sort_column=SORT_OPTIONS[selected_sort],
                ascending=(
                    sort_order == "Ascending"
                ),
            )

            st.session_state[
                "filtered_openssh_df"
            ] = filtered_df

            section_header("Authentication Metrics")

            display_authentication_metrics(filtered_df)

            section_header(
                "Filtered Authentication Events"
            )

            st.caption(
                f"Displaying {len(filtered_df):,} "
                f"of {len(df):,} parsed records."
            )

            display_event_table(filtered_df)

            st.download_button(
                "Download Filtered Events (CSV)",
                data=filtered_df.to_csv(index=False),
                file_name="cyberrisk_filtered_openssh.csv",
                mime="text/csv",
            )

    else:
        st.info(
            "Upload a .log or .txt file to begin analysis."
        )


# ============================================================
# 10. SOC ANALYSIS
# ============================================================

elif page == "SOC Analysis":

    st.title("Security Operations Center Analysis")

    df = get_active_data()

    if df is None or df.empty:
        st.info(
            "Upload OpenSSH authentication logs "
            "before running SOC analysis."
        )

    else:
        section_header("Authentication Overview")

        display_authentication_metrics(df)

        st.divider()

        section_header(
            "Top Source IP Addresses",
            "Source IP addresses ranked by observed "
            "authentication event count.",
        )

        display_vertical_chart(
            df,
            category_column="source_ip",
            chart_title="Top Source IP Addresses",
            top_n=10,
        )

        st.divider()

        section_header(
            "Authentication Methods",
            "Distribution of observed OpenSSH "
            "authentication methods.",
        )

        display_vertical_chart(
            df,
            category_column="auth_method",
            chart_title="Authentication Methods",
            top_n=10,
        )

        st.divider()

        st.info(
            "AI-generated SOC explanations and "
            "claim validation will be integrated "
            "in a later development stage."
        )


# ============================================================
# 11. EVIDENCE VALIDATION
# ============================================================

elif page == "Evidence Validation":

    st.title("OpenSSH Evidence Validation")

    st.write(
        "Evaluate the structural integrity and "
        "internal consistency of parsed OpenSSH "
        "authentication evidence."
    )

    df = get_active_data()

    if df is None or df.empty:
        st.info(
            "Upload OpenSSH logs before running "
            "evidence validation."
        )

    else:
        result = validate_authentication_evidence(df)

        checks = result["checks"]
        summary = result["summary"]

        passed = int(
            (checks["Status"] == "PASS").sum()
        )

        failed = int(
            (checks["Status"] == "FAIL").sum()
        )

        unchecked = int(
            (checks["Status"] == "NOT CHECKED").sum()
        )

        section_header(
            "Validation Overview",
            "Structural and consistency checks "
            "performed on the selected dataset.",
        )

        col1, col2, col3 = st.columns(3)

        with col1:
            metric_card(
                "Passed Validation Checks",
                str(passed),
                "cyber-success",
            )

        with col2:
            metric_card(
                "Failed Validation Checks",
                str(failed),
                "cyber-failure",
            )

        with col3:
            metric_card(
                "Checks Requiring Review",
                str(unchecked),
                "cyber-primary",
            )

        section_header(
            "Detailed Validation Results"
        )

        st.dataframe(
            checks,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Check": st.column_config.TextColumn(
                    "Validation Check",
                    width="medium",
                ),
                "Status": st.column_config.TextColumn(
                    "Result",
                    width="small",
                ),
                "Details": st.column_config.TextColumn(
                    "Validation Details",
                    width="large",
                ),
            },
        )

        if failed > 0:
            st.error(
                "One or more structural consistency "
                "checks failed. Review the validation "
                "results before interpreting the evidence."
            )
        else:
            st.success(
                "No failures were detected in the "
                "structural consistency checks performed."
            )

        if unchecked > 0:
            st.warning(
                "Some checks remain incomplete. "
                "Raw-log reconciliation and "
                "repeated-message verification "
                "have not yet been completed."
            )

        st.divider()

        if summary is not None:
            display_evidence_summary(summary)
        else:
            st.warning(
                "An evidence summary could not be "
                "generated because required validation "
                "checks failed."
            )

        st.divider()

        section_header("Export Validation Results")

        st.download_button(
            "Download Validation Results (CSV)",
            data=checks.to_csv(index=False),
            file_name="cyberrisk_validation_results.csv",
            mime="text/csv",
        )


# ============================================================
# 12. GRC RISK ASSESSMENT
# ============================================================

elif page == "GRC Risk Assessment":

    st.title(
        "Governance, Risk & Compliance Assessment"
    )

    st.write(
        "Evaluate authentication-related risk "
        "indicators using evidence-based methods."
    )

    st.info(
        "The OpenSSH Authentication Risk Score "
        "is currently under development."
    )

    section_header(
        "Planned Authentication Risk Indicators"
    )

    st.markdown(
        """
        - Failed Authentication Activity
        - Repeated Authentication Attempts
        - Privileged Account Targeting
        - Source IP Authentication Patterns
        - Authentication Control Evidence
        """
    )

    st.caption(
        "The proposed 0–100 score will assess "
        "OpenSSH authentication indicators only. "
        "It will not represent organization-wide "
        "regulatory compliance."
    )


# ============================================================
# 13. RESULTS AND REPORTING
# ============================================================

elif page == "Results & Reporting":

    st.title("Results & Reporting")

    df = get_active_data()

    if df is None or df.empty:
        st.info(
            "Upload OpenSSH authentication logs "
            "to generate exportable results."
        )

    else:
        section_header("Dataset Information")

        st.write(
            "**Uploaded File:**",
            st.session_state.get(
                "openssh_filename"
            ),
        )

        st.write(
            "**Displayed Authentication Records:**",
            f"{len(df):,}",
        )

        section_header("Authentication Overview")

        display_authentication_metrics(df)

        section_header(
            "Authentication Event Results"
        )

        display_event_table(df)

        section_header("Export Results")

        st.download_button(
            "Export Authentication Events (CSV)",
            data=df.to_csv(index=False),
            file_name="cyberrisk_openssh_results.csv",
            mime="text/csv",
        )

        st.info(
            "Validated SOC/GRC reports and additional "
            "export formats are planned."
        )


# ============================================================
# 14. METHODOLOGY & WORKFLOW
# ============================================================

elif page == "Methodology & Workflow":

    render_methodology_page()


# ============================================================
# END OF CYBERRISK AI APPLICATION
# ============================================================
