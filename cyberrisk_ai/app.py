"""OpenSSH Log Analyzer — Streamlit interface.
Run: py -m streamlit run app.py
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from urllib import error

import pandas as pd
import plotly.express as px
import streamlit as st
from analysis_core import (
    DEFAULT_MODEL,
    MAX_FILE_BYTES,
    ai_payload,
    filter_events,
    ollama_generate,
    ollama_models,
    parse_logs,
    summarize,
    validate,
)
from stakeholder_reporting import executive_pdf, stakeholder_summary

APP_NAME = "OpenSSH Log Analyzer"


def ollama_connection_panel(url: str) -> list[str] | None:
    """Show friendly local setup guidance and return installed models when reachable."""
    try:
        models = ollama_models(url)
    except (OSError, ValueError, error.URLError):
        st.warning("Local AI is offline — security analysis and reports still work.")
        st.markdown("**Set up Ollama on the computer running this application:**")
        st.link_button(
            "Download Ollama (official website)",
            "https://ollama.com/download",
            width="stretch",
        )
        st.markdown("**1.** Install Ollama, then open PowerShell and download a model:")
        st.code("ollama pull llama3.2", language="powershell")
        st.markdown("**2.** If Ollama isn't running, start its service:")
        st.code("ollama serve", language="powershell")
        st.caption(
            "If Ollama is already running, you do not need to start a second service. "
            "For a remotely hosted Streamlit app, localhost refers to the server, not the visitor's computer."
        )
        if st.button(
            "Check connection again",
            width="stretch",
            key="ollama_retry_offline",
        ):
            st.rerun()
        return None
    st.success("Ollama is connected.")
    if not models:
        st.info(
            "Ollama is running, but no AI models were found. Install one to continue:"
        )
        st.code("ollama pull llama3.2", language="powershell")
        if st.button("Check models again", key="ollama_retry_models"):
            st.rerun()
    return models


def validation_visual(checks: pd.DataFrame, *, compact: bool = False) -> None:
    """Explain each check with an accessible status and plain-language detail."""
    counts = checks["Status"].value_counts()
    cols = st.columns(4)
    for col, status, label in zip(
        cols,
        ["PASS", "REVIEW", "FAIL", "NOT CHECKED"],
        ["Passed", "Needs review", "Failed", "Not assessed"],
    ):
        col.metric(label, int(counts.get(status, 0)))
    st.caption(
        "PASS = check succeeded · REVIEW = manual inspection needed · FAIL = discrepancy · NOT CHECKED = outside the tool's checks"
    )
    symbols = {"PASS": "✅", "REVIEW": "⚠️", "FAIL": "❌", "NOT CHECKED": "◻️"}
    if not compact:
        st.markdown("**Validation results explained**")
    for _, record in checks.iterrows():
        status = str(record["Status"])
        with st.container(border=True):
            left, right = st.columns([3, 1])
            left.markdown(f"**{symbols.get(status, '•')} {record['Check']}**")
            right.caption(status)
            st.caption(str(record["Details"]))
    st.caption(
        "These checks are internal consistency tests, not independent forensic certification."
    )


def report_visual(report: dict) -> None:
    """Readable, visual alternative to a raw JSON report."""
    st.markdown("#### Report contents")
    st.caption("Explore the same data included in the downloadable JSON report.")
    overview, evidence, quality, caveats = st.tabs(
        ["📊 Findings", "📁 Evidence", "🛡️ Validation", "ℹ️ Limitations"]
    )
    with overview:
        evidence_overview(report["summary"])
        st.info(
            "These counts describe observed authentication activity, not a confirmed attack."
        )
    with evidence:
        st.markdown("**Uploaded evidence**")
        st.write("Filename:", report["source_filename"])
        fingerprint_display(report["source_sha256"])
        metadata = report["parser_metadata"]
        cols = st.columns(3)
        cols[0].metric("Detected SSH lines", metadata.get("sshd_lines", 0))
        cols[1].metric(
            "Unsupported messages", metadata.get("unsupported_sshd_lines", 0)
        )
        cols[2].metric("Repeat summaries", metadata.get("repeat_summary_lines", 0))
        with st.expander("Additional file metadata"):
            st.dataframe(
                pd.DataFrame(
                    [
                        {"Property": k.replace("_", " ").title(), "Value": str(v)}
                        for k, v in metadata.items()
                    ]
                ),
                hide_index=True,
                width="stretch",
            )
    with quality:
        validation_visual(pd.DataFrame(report["validation"]), compact=True)
    with caveats:
        st.markdown("**How to interpret these findings**")
        for item in report["limitations"]:
            st.markdown(f"- {item}")
        st.warning(
            "A log entry alone cannot establish intent, compromise, or business impact."
        )
    with st.expander("Advanced: view original machine-readable JSON"):
        st.json(report)


@st.cache_data(ttl=60, show_spinner=False)
def cached_sidebar_ollama_models(url: str) -> list[str]:
    """Avoid repeating a potentially slow network request on every page change."""
    return ollama_models(url)


def sidebar_ollama_status(url: str) -> None:
    """Compact AI status with consistent spacing and accessible text."""
    with st.sidebar, st.container(key="ollama_status_panel"):
        st.markdown(
            "<div class='ai-section-title'>LOCAL AI STATUS</div>",
            unsafe_allow_html=True,
        )
        try:
            models = cached_sidebar_ollama_models(url)
        except (OSError, ValueError, error.URLError):
            st.markdown(
                '<div class="ollama-status ollama-offline">'
                '<span class="ollama-dot"></span>Ollama offline</div>',
                unsafe_allow_html=True,
            )
            st.caption("AI is optional. Analysis and reporting work without it.")
            st.link_button(
                "Install Ollama",
                "https://ollama.com/download",
                width="stretch",
            )
        else:
            if models:
                st.markdown(
                    '<div class="ollama-status ollama-online">'
                    f'<span class="ollama-dot"></span>Ollama connected · {len(models)} model(s)</div>',
                    unsafe_allow_html=True,
                )
                st.caption("Available: " + ", ".join(models[:3]))
            else:
                st.markdown(
                    '<div class="ollama-status ollama-offline">'
                    '<span class="ollama-dot"></span>Ollama connected · no models</div>',
                    unsafe_allow_html=True,
                )
                st.caption("Install a model to enable AI explanations:")
                st.code("ollama pull llama3.2", language="powershell")
        if st.button(
            "↻ Refresh AI status",
            width="stretch",
            key="refresh_ai_status",
        ):
            cached_sidebar_ollama_models.clear()
            st.rerun()


def application_theme_css(mode: str) -> None:
    """Apply a cohesive, eye-friendly theme to the entire Streamlit interface.

    CSS is used because Streamlit does not expose a supported runtime API for
    switching its configured theme. These selectors are presentation-only.
    """
    dark = mode == "Dark"
    colors = (
        {
            "bg": "#101824",
            "side": "#151f2d",
            "panel": "#1b2838",
            "raised": "#233246",
            "text": "#e7edf5",
            "muted": "#b0c0d1",
            "line": "#344459",
            "accent": "#91b8ff",
            "hover": "#293a50",
            "input": "#1c2b3d",
            "button": "#283c56",
            "button_text": "#f2f6fd",
        }
        if dark
        else {
            "bg": "#e9eef3",
            "side": "#e2eaf0",
            "panel": "#f4f7f9",
            "raised": "#e9f0f5",
            "text": "#263648",
            "muted": "#53677c",
            "line": "#cbd7e0",
            "accent": "#255f9c",
            "hover": "#d7e3ec",
            "input": "#f5f8fa",
            "button": "#d5e3ee",
            "button_text": "#233e59",
        }
    )
    c = colors
    st.markdown(
        f"""<style>
      /* Application-wide background and readable text. */
      .stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"],
      [data-testid="stMainBlockContainer"] {{ background-color: {c["bg"]}; color: {c["text"]}; }}
      [data-testid="stHeader"] {{ background-color: {c["bg"]}; }}
      .stApp, .stApp p, .stApp label, .stApp li,
      .stApp h1, .stApp h2, .stApp h3, .stApp h4,
      .stApp [data-testid="stMarkdownContainer"] {{ color: {c["text"]}; }}
      .stApp [data-testid="stCaptionContainer"] p,
      .stApp small {{ color: {c["muted"]}; }}
      .stApp hr {{ border-color: {c["line"]}; }}
      .stApp a {{ color: {c["accent"]}; }}
      /* Cards and metrics. */
      .stApp [data-testid="stMetric"],
      .stApp [data-testid="stVerticalBlockBorderWrapper"]:has(> div [data-testid="stMetric"]) {{
        background: {c["panel"]}; border-color: {c["line"]};
      }}
      .stApp [data-testid="stMetricValue"],
      .stApp [data-testid="stMetricLabel"] {{ color: {c["text"]}; }}
      /* All inputs and controls, not just sidebar controls. */
      .stApp [data-baseweb="input"] > div,
      .stApp [data-baseweb="textarea"] > div,
      .stApp [data-baseweb="select"] > div,
      .stApp [data-baseweb="base-input"],
      .stApp [data-testid="stNumberInput"] input,
      .stApp [data-testid="stTextInput"] input,
      .stApp textarea {{ background-color: {c["input"]} !important;
        color: {c["text"]} !important; border-color: {c["line"]} !important; }}
      .stApp input::placeholder, .stApp textarea::placeholder {{ color: {c["muted"]} !important; }}
      .stApp [data-testid="stBaseButton-secondary"],
      .stApp [data-testid="stBaseButton-minimal"],
      .stApp [data-testid="stLinkButton"] a,
      .stApp [data-testid="stDownloadButton"] button {{
        background: {c["button"]} !important; color: {c["button_text"]} !important;
        border: 1px solid {c["line"]} !important; border-radius: 9px !important;
      }}
      .stApp [data-testid="stBaseButton-secondary"]:hover,
      .stApp [data-testid="stBaseButton-minimal"]:hover,
      .stApp [data-testid="stLinkButton"] a:hover {{ background: {c["hover"]} !important; }}
      .stApp [data-testid="stBaseButton-secondary"] p,
      .stApp [data-testid="stBaseButton-secondary"] span,
      .stApp [data-testid="stBaseButton-secondary"] svg,
      .stApp [data-testid="stLinkButton"] a p,
      .stApp [data-testid="stLinkButton"] a span {{ color: {c["button_text"]} !important; }}
      .stApp [data-testid="stBaseButton-primary"] {{ background: #326ea8; color: #ffffff; border-color: #326ea8; }}
      .stApp [data-testid="stBaseButton-primary"] p {{ color: #ffffff; }}
      .stApp [data-testid="stExpander"] {{ border-color: {c["line"]}; }}
      /* Balanced sidebar: comfortable navigation without oversized gaps. */
      [data-testid="stSidebar"] {{ background: {c["side"]}; color: {c["text"]};
        border-right: 1px solid {c["line"]}; }}
      /* Avoid global sidebar spacing overrides; they add gaps inside nested widgets. */
      [data-testid="stSidebar"] [data-testid="stRadio"] [role="radiogroup"] {{
        gap: .38rem !important;
      }}
      [data-testid="stSidebar"] [data-testid="stRadio"] label {{
        background: transparent !important; border-radius: 7px;
        padding: .44rem .60rem !important; min-height: 38px; margin: 0 !important;
      }}
      [data-testid="stSidebar"] [data-testid="stRadio"] label:hover {{ background: {c["hover"]} !important; }}
      [data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) {{
        background: {c["raised"]} !important;
      }}
      [data-testid="stSidebar"] hr {{ margin: .72rem 0 !important; }}
      [data-testid="stSidebar"] [data-testid="stCaptionContainer"] p {{
        color: {c["muted"]} !important; margin-bottom: 0 !important;
      }}
      [data-testid="stSidebar"] .ssh-brand-name {{ color: {c["text"]} !important; }}
      [data-testid="stSidebar"] .ssh-brand-kicker,
      [data-testid="stSidebar"] .ssh-brand-desc {{ color: {c["muted"]} !important; opacity: 1; }}
      [data-testid="stSidebar"] .ssh-brand {{
        padding: 8px 0 14px !important; margin-bottom: 8px !important;
        border-color: {c["line"]};
      }}
      [data-testid="stSidebar"] .ssh-brand-kicker {{ margin-top: 8px !important; }}
      [data-testid="stSidebar"] [data-testid="stAlert"] {{
        border: 1px solid {c["line"]}; border-radius: 9px;
      }}
      /* Compact AI status: consistent rhythm without nested alert padding. */
      [data-testid="stSidebar"] .st-key-ollama_status_panel > div > [data-testid="stVerticalBlock"] {{
        gap: .25rem !important;
      }}
      [data-testid="stSidebar"] .st-key-ollama_status_panel .ai-section-title {{
        font-size: .78rem; font-weight: 700; letter-spacing: .04em;
        margin: 0 0 .15rem 0; color: {c["text"]};
      }}
      [data-testid="stSidebar"] .st-key-ollama_status_panel [data-testid="stMarkdownContainer"] p {{
        margin: 0 !important;
      }}
      [data-testid="stSidebar"] .st-key-ollama_status_panel [data-testid="stCaptionContainer"] {{
        margin: 0 !important; padding: 0 !important;
      }}
      [data-testid="stSidebar"] .st-key-ollama_status_panel .ollama-status {{
        display: flex; align-items: center; gap: .55rem;
        padding: .48rem .7rem; border-radius: 8px;
        font-size: .9rem; font-weight: 600;
        border: 1px solid {c["line"]};
        background: {c["raised"]}; color: {c["text"]};
      }}
      [data-testid="stSidebar"] .st-key-ollama_status_panel .ollama-dot {{
        width: 8px; height: 8px; border-radius: 50%;
        flex: 0 0 8px; background: #d69e48;
      }}
      [data-testid="stSidebar"] .st-key-ollama_status_panel .ollama-online .ollama-dot {{
        background: #45b78a;
      }}
      [data-testid="stSidebar"] .st-key-ollama_status_panel [data-testid="stCaptionContainer"] p {{
        line-height: 1.4 !important;
      }}
      [data-testid="stSidebar"] .st-key-ollama_status_panel button,
      [data-testid="stSidebar"] .st-key-ollama_status_panel [data-testid="stLinkButton"] a {{
        min-height: 36px !important; border-radius: 8px !important;
      }}
      /* Override the dark Refresh AI status button in soft light mode. */
      [data-testid="stSidebar"] [data-testid="stBaseButton-secondary"] {{
        background: {c["button"]} !important; color: {c["button_text"]} !important;
        border: 1px solid {c["line"]} !important;
      }}
      [data-testid="stSidebar"] [data-testid="stBaseButton-secondary"] p,
      [data-testid="stSidebar"] [data-testid="stBaseButton-secondary"] span {{
        color: {c["button_text"]} !important;
      }}
    </style>""",
        unsafe_allow_html=True,
    )


def download_csv(df: pd.DataFrame, filename: str, key: str) -> None:
    st.download_button(
        "Download CSV",
        df.to_csv(index=False).encode("utf-8-sig"),
        filename,
        "text/csv",
        key=key,
    )


def heading(title: str, subtitle: str) -> None:
    st.title(title)
    st.caption(subtitle)


def metrics(df: pd.DataFrame) -> None:
    """Compact visual KPI row using Streamlit's accessible native metrics."""
    summary = summarize(df)
    items = [
        ("Login attempts", summary["total"], "Recognized authentication events"),
        ("Unsuccessful", summary["failed"], "Failed login attempts"),
        ("Accepted", summary["successful"], "Successful logins"),
        (
            "Failure rate",
            f"{summary['failure_rate']:.1f}%",
            "Share of observed attempts",
        ),
    ]
    for col, (label, value, help_text) in zip(st.columns(4), items):
        col.metric(label, value, help=help_text)


def outcome_chart(df: pd.DataFrame) -> None:
    summary = summarize(df)
    if not summary["total"]:
        st.info("No authentication outcomes available for this selection.")
        return
    outcome = pd.DataFrame(
        [
            {"Outcome": "Unsuccessful", "Events": summary["failed"]},
            {"Outcome": "Accepted", "Events": summary["successful"]},
        ]
    )
    fig = px.bar(
        outcome,
        x="Outcome",
        y="Events",
        color="Outcome",
        text="Events",
        color_discrete_map={"Unsuccessful": "#e17772", "Accepted": "#29a987"},
    )
    fig.update_traces(textposition="outside", marker_line_width=0)
    fig.update_layout(
        showlegend=False,
        height=320,
        margin={"l": 12, "r": 12, "t": 28, "b": 16},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        yaxis={"rangemode": "tozero", "gridcolor": "rgba(128,128,128,.14)"},
        xaxis={"title": None, "tickangle": 0},
        bargap=0.48,
    )
    st.plotly_chart(fig, width="stretch")


def charts(df: pd.DataFrame) -> None:
    if df.empty:
        st.info("No matching authentication events to chart. Adjust your filters.")
        return
    left, right = st.columns(2)
    with left:
        st.markdown("**Activity by source IP**")
        by_ip = (
            df.groupby("source_ip", as_index=False)["event_count"]
            .sum()
            .sort_values("event_count", ascending=False)
            .head(10)
        )
        fig = px.bar(
            by_ip,
            x="source_ip",
            y="event_count",
            text="event_count",
            labels={"source_ip": "Source IP address", "event_count": "Events"},
            color_discrete_sequence=["#4d8ee5"],
        )
        fig.update_traces(textposition="outside", marker_line_width=0)
        fig.update_layout(
            height=320,
            margin={"l": 12, "r": 12, "t": 28, "b": 16},
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            xaxis={"tickangle": 0, "automargin": True},
            yaxis={"rangemode": "tozero", "gridcolor": "rgba(128,128,128,.14)"},
        )
        st.plotly_chart(fig, width="stretch")
    with right:
        st.markdown("**Authentication outcomes**")
        outcome_chart(df)


def visual_section(title: str, description: str = "") -> None:
    st.markdown(f"### {title}")
    if description:
        st.caption(description)


def evidence_overview(stats: dict) -> None:
    """Human-readable evidence summary; never substitutes for original evidence."""
    a, b, c = st.columns(3)
    a.metric("Recognized events", stats["total"])
    b.metric("Failed authentication", stats["failed"])
    c.metric("Successful authentication", stats["successful"])
    failure = max(0.0, min(float(stats["failure_rate"]) / 100.0, 1.0))
    st.markdown("**Authentication outcomes**")
    st.progress(
        failure,
        text=f"{stats['failure_rate']:.1f}% failed · {100 - stats['failure_rate']:.1f}% successful",
    )
    left, right = st.columns(2)
    left.metric("Unique source IPs", stats["unique_ips"])
    right.metric("Unique usernames", stats["unique_users"])
    st.markdown(
        f"**Most active source IP:** `{stats['top_ip']}` · **{stats['top_ip_events']}** event(s)"
    )


def fingerprint_display(value: str) -> None:
    st.markdown("**SHA-256 fingerprint of uploaded file**")
    st.code(value, language=None)
    st.caption(
        "A hash identifies the uploaded bytes; it does not establish source authenticity or chain of custody."
    )


def executive_page(src: dict) -> None:
    """Plain-English stakeholder presentation derived only from measured values."""
    df = src["df"]
    stats = summarize(df)
    info = src["info"]
    narrative = stakeholder_summary(stats, info)
    heading(
        "Executive Summary",
        "Understand what happened, why it matters, and what to verify next.",
    )
    st.caption(
        f"Evidence: {src['filename']}  ·  {stats['total']} recognized authentication events"
    )
    if info["unsupported_sshd_lines"] or info["repeat_summary_lines"]:
        st.warning(
            "**Coverage needs review.** Some sshd messages were not counted as login events."
        )
    else:
        st.info(
            "**Investigation status: verification recommended.** These records do not establish a security breach."
        )
    metrics(df)
    st.divider()
    left, right = st.columns([1.3, 1])
    with left:
        st.subheader("What we observed")
        st.write(narrative["overview"])
        st.markdown("**Login outcomes**")
        if stats["total"]:
            st.progress(
                min(max(stats["failure_rate"] / 100, 0), 1),
                text=f"{stats['failed']} unsuccessful · {stats['successful']} accepted",
            )
        st.subheader("What to do next")
        st.write(narrative["action"])
    with right:
        st.markdown("**Observed login activity**")
        outcome_chart(df)
    st.divider()
    st.subheader("How complete is the evidence?")
    c1, c2, c3 = st.columns(3)
    c1.metric("Detected sshd lines", info["sshd_lines"])
    c2.metric("Unsupported messages", info["unsupported_sshd_lines"])
    c3.metric("Repeat summaries", info["repeat_summary_lines"])
    st.write(narrative["coverage"])
    st.caption(narrative["limitations"])
    mode = st.segmented_control(
        "Audience", ["Stakeholder", "Technical analyst"], default="Stakeholder"
    )
    if mode == "Technical analyst":
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Indicator": "Unique source IPs",
                        "Value": str(stats["unique_ips"]),
                    },
                    {
                        "Indicator": "Unique usernames",
                        "Value": str(stats["unique_users"]),
                    },
                    {"Indicator": "Most active IP", "Value": str(stats["top_ip"])},
                    {
                        "Indicator": "Events from most active IP",
                        "Value": str(stats["top_ip_events"]),
                    },
                ]
            ),
            hide_index=True,
            width="stretch",
        )
        fingerprint_display(src["sha256"])
        with st.expander("Technical validation checks — explained visually"):
            validation_visual(validate(df, src["raw"], info))
    else:
        st.success(
            "**Management takeaway:** Verify the observed activity before determining incident status or business risk."
        )
    st.divider()
    st.subheader("Share this analysis")
    st.caption(
        "PDF includes calculated evidence, recommended verification, and limitations—not AI speculation."
    )
    st.download_button(
        "Download Executive Summary PDF",
        data=executive_pdf(src, stats, narrative),
        file_name="openssh_executive_summary.pdf",
        mime="application/pdf",
        type="primary",
    )


def main() -> None:
    st.set_page_config(page_title=APP_NAME, page_icon="🛡️", layout="wide")
    st.markdown(
        """<style>
        .block-container {padding-top: 1.7rem; padding-bottom:3rem; max-width: 1420px;}
        h1 {letter-spacing:-.035em; font-weight:750;}
        h2,h3 {letter-spacing:-.02em;}
        [data-testid="stMetric"] {background:rgba(128,128,128,.045); min-height:110px;}
        [data-testid="stMetricValue"] {font-weight:750; letter-spacing:-.04em;}
        [data-testid="stVerticalBlockBorderWrapper"] {border-radius:14px;}
        [data-testid="stSidebar"] [data-testid="stRadio"] label {font-weight:550;}
        [data-testid="stMetric"] {border:1px solid rgba(128,128,128,.22);border-radius:12px;padding:14px;}
        [data-testid="stSidebar"] {border-right:1px solid rgba(128,128,128,.15);}
        .ssh-brand { padding: 10px 0 20px; margin-bottom: 12px; border-bottom: 1px solid rgba(128,128,128,.22); }
        .ssh-brand-top { display: flex; align-items: center; gap: 12px; }
        .ssh-brand-mark { display:flex; align-items:center; justify-content:center; width:44px; height:44px; flex-shrink:0; border-radius:12px; background:rgba(59,130,246,.13); border:1px solid rgba(59,130,246,.27); color:#60a5fa; }
        .ssh-brand-name { font-size: 18px; font-weight: 750; line-height: 1.16; letter-spacing: -.35px; color:var(--text-color); }
        .ssh-brand-kicker { margin-top:16px; display:flex; align-items:center; gap:8px; font-size:10px; font-weight:700; letter-spacing:1.05px; color:var(--text-color); opacity:.77; }
        .ssh-brand-dot { height:7px; width:7px; border-radius:50%; background:#22c55e; flex-shrink:0; }
        .ssh-brand-desc { margin-top:8px; font-size:12px; line-height:1.55; color:var(--text-color); opacity:.64; }
        </style>""",
        unsafe_allow_html=True,
    )
    if "source" not in st.session_state:
        st.session_state.source = None
    if "ai_result" not in st.session_state:
        st.session_state.ai_result = None

    st.sidebar.markdown(
        '<div class="ssh-brand">'
        '<div class="ssh-brand-top">'
        '<div class="ssh-brand-mark">'
        '<svg xmlns="http://www.w3.org/2000/svg" width="25" height="25" viewBox="0 0 24 24" '
        'fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
        '<path d="m9 12 2 2 4-4"/>'
        "</svg></div>"
        '<div class="ssh-brand-name">OpenSSH<br>Log Analyzer</div>'
        "</div>"
        '<div class="ssh-brand-kicker"><span class="ssh-brand-dot"></span>SECURITY ANALYTICS</div>'
        '<div class="ssh-brand-desc">Authentication monitoring &bull; Evidence validation &bull; SOC analysis</div>'
        "</div>",
        unsafe_allow_html=True,
    )
    st.sidebar.caption("APPEARANCE")
    sidebar_mode = st.sidebar.radio(
        "Application theme",
        ["Dark", "Light"],
        horizontal=True,
        key="sidebar_mode",
        label_visibility="collapsed",
    )
    application_theme_css(sidebar_mode)
    st.sidebar.divider()
    st.sidebar.caption("WORKSPACE")
    page = st.sidebar.radio(
        "Navigation",
        [
            "Dashboard",
            "Upload OpenSSH Logs",
            "SOC Analysis",
            "Evidence Validation",
            "AI Prompt Studio",
            "GRC Risk Assessment",
            "Results & Reporting",
            "Executive Summary",
            "Methodology & Workflow",
        ],
    )
    st.sidebar.divider()
    if st.session_state.source:
        src = st.session_state.source
        st.sidebar.success("Log loaded")
        st.sidebar.caption(f"{src['filename']} · {len(src['df'])} recognized events")
        if st.sidebar.button("Clear uploaded evidence"):
            st.session_state.source = None
            st.session_state.ai_result = None
            st.rerun()
    else:
        st.sidebar.info("No evidence loaded")
        st.sidebar.caption("Go to Upload OpenSSH Logs to get started.")

    st.sidebar.divider()
    sidebar_url = st.session_state.get("ollama_service_url", "http://127.0.0.1:11434")
    sidebar_ollama_status(sidebar_url)

    if page == "Upload OpenSSH Logs":
        heading(
            "Upload OpenSSH Logs",
            "Import an sshd text log. Files remain in this Streamlit process; local Ollama is optional.",
        )
        year = st.number_input(
            "Assumed year for traditional syslog timestamps",
            min_value=2000,
            max_value=2100,
            value=datetime.now().year,
            help="Traditional syslog timestamps omit the year. This is an analyst assumption, not verified evidence.",
        )
        file = st.file_uploader("Choose a .log or .txt file", type=["log", "txt"])
        if file:
            if file.size > MAX_FILE_BYTES:
                st.error("File exceeds the 15 MB limit.")
            elif st.button("Parse authentication events", type="primary"):
                raw_bytes = file.getvalue()
                raw = raw_bytes.decode("utf-8-sig", errors="replace")
                df, info = parse_logs(raw, assumed_year=int(year))
                st.session_state.source = {
                    "filename": file.name,
                    "raw": raw,
                    "df": df,
                    "info": info,
                    "sha256": hashlib.sha256(raw_bytes).hexdigest(),
                }
                st.session_state.ai_result = None
                st.success(f"Parsed {len(df)} explicit authentication events.")
        st.info(
            "Supported: common OpenSSH 'Accepted' and 'Failed' sshd lines with traditional syslog or ISO timestamps. Other sshd messages are not automatically interpreted as login events."
        )
        if st.session_state.source:
            src = st.session_state.source
            st.subheader("Import summary")
            st.dataframe(
                pd.DataFrame([src["info"]]).T.rename(columns={0: "Value"}).astype(str),
                width="stretch",
            )
            st.code(src["sha256"], language="text")
            st.caption(
                "SHA-256 of uploaded file bytes. A hash supports later comparison but does not establish provenance or authenticity."
            )
        return

    src = st.session_state.source
    if not src:
        heading(page, "OpenSSH authentication log analysis")
        st.info(
            "**Get started:** Upload an OpenSSH log to see security metrics, source activity, and stakeholder reports."
        )
        st.markdown("#### Your analysis workflow")
        x, y, z = st.columns(3)
        x.markdown(
            "**1. Import evidence**\n\nChoose a `.log` or `.txt` file containing sshd authentication messages."
        )
        y.markdown(
            "**2. Investigate**\n\nReview login outcomes, source IPs, and evidence checks."
        )
        z.markdown(
            "**3. Communicate**\n\nOpen Executive Summary to export a stakeholder-friendly PDF."
        )
        if page == "AI Prompt Studio":
            st.markdown("### Optional local AI setup")
            url = st.text_input("Ollama service URL", value="http://127.0.0.1:11434")
            ollama_connection_panel(url)
        if page == "Methodology & Workflow":
            methodology()
        return

    original: pd.DataFrame = src["df"]
    if page == "Executive Summary":
        executive_page(src)

    elif page == "Dashboard":
        heading(
            "Security Overview",
            f"Source: {src['filename']} · Parsed authentication events only",
        )
        metrics(original)
        st.divider()
        st.subheader("At a glance")
        summary = summarize(original)
        if summary["total"]:
            st.progress(
                min(max(summary["failure_rate"] / 100, 0), 1),
                text=f"{summary['failed']} failed / {summary['successful']} accepted logins",
            )
        st.caption("Authentication failures alone do not prove malicious activity.")
        charts(original)
        st.subheader("Recent recognized events")
        st.dataframe(
            original.drop(columns=["raw_line"], errors="ignore").tail(20).iloc[::-1],
            width="stretch",
            hide_index=True,
        )
        if src["info"]["unsupported_sshd_lines"] or src["info"]["repeat_summary_lines"]:
            st.warning(
                "Some sshd lines were not converted into authentication events. Review Evidence Validation before drawing conclusions."
            )

    elif page == "SOC Analysis":
        heading(
            "SOC Analysis",
            "Explore parsed authentication events with transparent filters.",
        )
        a, b, c = st.columns(3)
        statuses = a.multiselect(
            "Outcome",
            sorted(original["status"].unique().tolist()),
            default=sorted(original["status"].unique().tolist()),
        )
        ips = b.multiselect(
            "Source IP", sorted(original["source_ip"].unique().tolist())
        )
        users = c.multiselect(
            "Username", sorted(original["username"].unique().tolist())
        )
        search = st.text_input("Search user, IP, method, or host")
        filtered = (
            filter_events(original, statuses, ips, users, search)
            if statuses
            else original.iloc[0:0].copy()
        )
        metrics(filtered)
        charts(filtered)
        st.subheader("Matching authentication events")
        st.dataframe(
            filtered.drop(columns=["raw_line"], errors="ignore"),
            width="stretch",
            hide_index=True,
        )
        download_csv(filtered, "openssh_filtered_events.csv", "soc_csv")
        st.caption(
            "Filters apply to this SOC view and its CSV export. Other pages analyze the full uploaded dataset."
        )

    elif page == "Evidence Validation":
        heading(
            "Evidence Validation",
            "Quality checks and source-line traceability; not a forensic certification.",
        )
        checks = validate(original, src["raw"], src["info"])
        a, b, c = st.columns(3)
        a.metric("PASS", int((checks["Status"] == "PASS").sum()))
        b.metric("REVIEW", int((checks["Status"] == "REVIEW").sum()))
        c.metric(
            "FAIL / NOT CHECKED",
            int(checks["Status"].isin(["FAIL", "NOT CHECKED"]).sum()),
        )
        st.dataframe(checks, width="stretch", hide_index=True)
        with st.expander("What do these validation results mean?"):
            st.markdown(
                "**PASS:** Implemented check succeeded. **REVIEW:** Human inspection needed. **FAIL:** Check found a discrepancy. **NOT CHECKED:** Not assessed by this tool. These results are not forensic certification."
            )
        visual_section(
            "Source reconciliation",
            "Coverage of recognized OpenSSH authentication messages in the uploaded file.",
        )
        info = src["info"]
        a, b, c = st.columns(3)
        a.metric("Recognized authentication events", info["parsed_events"])
        b.metric("Unsupported sshd lines", info["unsupported_sshd_lines"])
        c.metric("Repeated-message summaries", info["repeat_summary_lines"])
        if info["unsupported_sshd_lines"] or info["repeat_summary_lines"]:
            st.warning(
                "Some sshd lines were excluded or require manual review. Event coverage is incomplete."
            )
        else:
            st.success(
                "No unsupported sshd lines or repeated-message summaries detected by the parser."
            )
        if info["sshd_lines"]:
            st.progress(
                min(info["parsed_events"] / info["sshd_lines"], 1.0),
                text=f"{info['parsed_events']} of {info['sshd_lines']} detected sshd lines parsed as authentication events",
            )
        st.markdown(f"**Evidence file:** `{src['filename']}`")
        fingerprint_display(src["sha256"])
        with st.expander("Technical source metadata (optional)"):
            st.dataframe(
                pd.DataFrame(
                    [
                        {"Property": k.replace("_", " ").title(), "Value": str(v)}
                        for k, v in info.items()
                    ]
                ),
                hide_index=True,
                width="stretch",
            )
            st.download_button(
                "Download source metadata (JSON)",
                json.dumps(
                    {"filename": src["filename"], "sha256": src["sha256"], **info},
                    indent=2,
                ),
                "openssh_source_metadata.json",
                "application/json",
            )
        st.caption(
            "The same recognition rules are used for parsing and reconciliation. This is not an independent verification of complete event coverage."
        )

    elif page == "AI Prompt Studio":
        heading(
            "AI Prompt Studio",
            "Optional local AI explanations. The rest of the application works offline.",
        )
        metrics(original)
        url = st.text_input(
            "Ollama service URL",
            value="http://127.0.0.1:11434",
            help="For a local installation, keep the default address.",
            key="ollama_service_url",
        )
        installed_models = ollama_connection_panel(url)
        if installed_models is None or not installed_models:
            st.stop()
        preferred = (
            DEFAULT_MODEL if DEFAULT_MODEL in installed_models else installed_models[0]
        )
        model = st.selectbox(
            "Installed AI model",
            installed_models,
            index=installed_models.index(preferred),
        )
        temp = st.slider("Response creativity", 0.0, 1.0, 0.2, 0.1)
        prompt = st.text_area(
            "Analyst prompt",
            value="Summarize the observed authentication activity, identify patterns worth investigating, "
            "and recommend next verification steps without assuming compromise.",
            height=120,
        )
        payload = ai_payload(original, src["info"], src["sha256"])
        with st.expander("View Evidence Used by AI", expanded=True):
            st.caption(
                "Visual summary of the structured evidence supplied to the selected AI endpoint. This does not mean AI analysis has already occurred."
            )
            evidence_overview(payload["summary"])
            st.markdown("**Source IP activity**")
            ip_counts = payload.get("source_ip_counts", {})
            if ip_counts:
                ip_df = pd.DataFrame(
                    [
                        {"Source IP": ip, "Events": count}
                        for ip, count in ip_counts.items()
                    ]
                )
                fig = px.bar(
                    ip_df, x="Source IP", y="Events", text="Events", title=None
                )
                fig.update_traces(textposition="outside")
                fig.update_xaxes(tickangle=0, automargin=True)
                fig.update_layout(
                    margin={"l": 10, "r": 10, "t": 15, "b": 20}, height=280
                )
                st.plotly_chart(fig, width="stretch")
            st.caption(
                "Structured statistics and a limited event sample are sent; raw log lines are not included. Confirm the configured Ollama URL is trusted."
            )
            with st.expander("Technical AI payload (optional)"):
                st.json(payload)
                st.download_button(
                    "Download AI evidence (JSON)",
                    json.dumps(payload, indent=2, default=str),
                    "openssh_ai_evidence.json",
                    "application/json",
                )
        if st.button(
            "Generate Local AI Explanation", type="primary", disabled=original.empty
        ):
            try:
                with st.spinner("Waiting for local Ollama..."):
                    output = ollama_generate(url, model, prompt, payload, temp)
                if not output:
                    st.warning("The model returned an empty response.")
                else:
                    st.session_state.ai_result = output
            except (OSError, ValueError, error.URLError) as exc:
                st.error(f"Local AI request failed: {exc}")
                st.info(
                    "Check that Ollama is running and that the selected model is installed."
                )
        if st.session_state.ai_result:
            st.subheader("AI-generated explanation — verify before use")
            st.markdown(st.session_state.ai_result)
            st.download_button(
                "Download AI explanation",
                st.session_state.ai_result,
                "openssh_ai_explanation.txt",
                "text/plain",
            )

    elif page == "GRC Risk Assessment":
        heading(
            "GRC Risk Assessment",
            "Descriptive risk indicators for triage; no validated numeric risk score.",
        )
        stats = summarize(original)
        metrics(original)
        st.subheader("Observed indicators")
        indicators = [
            (
                "Failed authentication attempts",
                str(stats["failed"]),
                "Failed logins can indicate mistakes, automated probing, or unauthorized attempts; context is required.",
            ),
            (
                "Failure proportion",
                f"{stats['failure_rate']:.1f}%",
                "A high proportion alone does not prove an attack.",
            ),
            (
                "Distinct source IP addresses",
                str(stats["unique_ips"]),
                "Multiple sources may be normal or may warrant review.",
            ),
            (
                "Most active source",
                str(stats["top_ip"]),
                f"{stats['top_ip_events']} observed events from this address.",
            ),
        ]
        st.dataframe(
            pd.DataFrame(
                indicators,
                columns=["Indicator", "Observed value", "Interpretation / limitation"],
            ),
            width="stretch",
            hide_index=True,
        )
        st.subheader("Recommended analyst actions")
        st.markdown(
            "1. Verify whether source addresses belong to trusted systems.\n2. Review successful logins in surrounding context.\n3. Correlate with host, firewall, and identity-provider records.\n4. Document any business impact and control gaps before assigning a formal risk rating."
        )
        st.info(
            "A formal GRC risk rating requires defined likelihood, impact, asset criticality, controls, and organizational criteria. This prototype does not calculate one."
        )

    elif page == "Results & Reporting":
        heading(
            "Results & Reporting",
            "Export reproducible data and a concise analysis summary.",
        )
        stats = summarize(original)
        metrics(original)
        st.subheader("Parsed authentication events")
        st.dataframe(
            original.drop(columns=["raw_line"], errors="ignore"),
            width="stretch",
            hide_index=True,
        )
        download_csv(original, "openssh_authentication_events.csv", "results_csv")
        report = {
            "application": APP_NAME,
            "source_filename": src["filename"],
            "source_sha256": src["sha256"],
            "summary": stats,
            "parser_metadata": src["info"],
            "validation": validate(original, src["raw"], src["info"]).to_dict(
                orient="records"
            ),
            "limitations": [
                "Only explicit Accepted/Failed sshd authentication events are counted.",
                "Syslog year is analyst-assumed.",
                "Source-line traceability is not independent forensic verification.",
                "No finding alone establishes malicious intent or compromise.",
            ],
        }
        st.download_button(
            "Download summary report (JSON)",
            json.dumps(report, indent=2, default=str),
            "openssh_analysis_report.json",
            "application/json",
        )
        visual_section(
            "Investigation report overview",
            "Readable summary of the exportable report.",
        )
        evidence_overview(stats)
        st.markdown("**Evidence and parsing details**")
        a, b = st.columns(2)
        a.metric("Detected sshd lines", src["info"]["sshd_lines"])
        b.metric("Unsupported sshd lines", src["info"]["unsupported_sshd_lines"])
        st.markdown(f"**Source file:** `{src['filename']}`")
        fingerprint_display(src["sha256"])
        st.markdown("**Validation checks**")
        st.dataframe(
            validate(original, src["raw"], src["info"]),
            hide_index=True,
            width="stretch",
        )
        st.info(
            "These results describe recognized authentication activity. They do not independently establish malicious intent, completeness, or evidence provenance."
        )
        with st.expander("Technical report details — visual explorer", expanded=False):
            report_visual(report)

    elif page == "Methodology & Workflow":
        heading(
            "Methodology & Workflow", "Transparent analytical scope and limitations."
        )
        methodology()


def methodology() -> None:
    st.markdown("""### Analysis workflow
1. **Acquire:** Import a local OpenSSH/sshd log and calculate a SHA-256 hash of its original bytes.
2. **Parse:** Recognize explicit `Accepted` and `Failed` authentication messages in supported timestamp formats.
3. **Structure:** Preserve source line numbers and raw lines alongside parsed event fields.
4. **Analyze:** Calculate event counts, outcomes, source-IP frequencies, and filtered SOC views.
5. **Validate:** Check internal consistency and traceability; flag unrecognized sshd lines and repeated-message summaries.
6. **Explain (optional):** Submit a limited structured evidence summary to a locally configured Ollama model.
7. **Report:** Export events and a summary containing counts, checks, assumptions, and limitations.

### Important limitations
- This tool is designed for **OpenSSH authentication logs**, not all Linux system logs.
- It recognizes a conservative subset of `sshd` messages. Unsupported formats are excluded from event counts.
- A traditional syslog timestamp does not include a year; the analyst selects the assumed year.
- Repeated-message summaries are not expanded into invented authentication events.
- Source-line traceability uses the same parsed source; it is **not independent forensic verification**.
- File hashing helps detect changes but does not establish chain of custody or provenance.
- Failed logins, source frequency, and AI narratives do not independently prove an attack or compromise.
- This is an educational investigation-support prototype, not a certified forensic tool or SIEM.

### Privacy
Uploaded logs are processed by the running Streamlit server. When Ollama is enabled, the selected structured evidence is sent to the configured Ollama endpoint. Do not expose the server or send sensitive evidence to an untrusted endpoint.
""")


if __name__ == "__main__":
    main()
