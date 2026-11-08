"""Deterministic stakeholder communication and printable PDF reports."""

from __future__ import annotations

from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def stakeholder_summary(stats: dict, info: dict) -> dict:
    """Describe observed events without inferring an incident or formal risk rating."""
    total = int(stats["total"])
    failed = int(stats["failed"])
    successful = int(stats["successful"])
    unsupported = int(info["unsupported_sshd_lines"])
    repeats = int(info["repeat_summary_lines"])
    if not total:
        overview = "No supported authentication events were recognized in the uploaded evidence."
        action = "Verify the log format, collection scope, and whether authentication messages are present."
    else:
        overview = (
            f"Of {total} recognized login attempt(s), {failed} failed and {successful} succeeded. "
            "These observations do not establish unauthorized access or a security incident."
        )
        action = (
            "Verify whether the source addresses and successful logins belong to authorized users. "
            "Correlate with host and identity records before determining incident status."
        )
    if unsupported or repeats:
        coverage = (
            f"{unsupported} unsupported sshd line(s) and {repeats} repeated-message summary line(s) "
            "require review; the event counts may not cover all authentication activity."
        )
    else:
        coverage = (
            "No unsupported sshd lines or repeat summaries were detected by the parser. "
            "This does not independently prove complete log coverage."
        )
    return {
        "status": "Review data coverage"
        if unsupported or repeats
        else ("No recognized events" if not total else "Verification recommended"),
        "overview": overview,
        "action": action,
        "coverage": coverage,
        "limitations": (
            "No confirmed compromise, malicious intent, business impact, or formal risk score "
            "can be inferred from these counts alone."
        ),
    }


def executive_pdf(source: dict, stats: dict, narrative: dict) -> bytes:
    """Create a portable, evidence-linked executive PDF; never include raw log lines."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=(8.5 * inch, 11 * inch),
        rightMargin=48,
        leftMargin=48,
        topMargin=48,
        bottomMargin=48,
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="ExecTitleCustom",
            parent=styles["Title"],
            fontSize=20,
            leading=25,
            textColor=colors.HexColor("#183153"),
            alignment=TA_CENTER,
            spaceAfter=14,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ExecSectionCustom",
            parent=styles["Heading2"],
            fontSize=11,
            textColor=colors.HexColor("#183153"),
            spaceBefore=14,
            spaceAfter=6,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ExecBodyCustom", parent=styles["BodyText"], fontSize=9.5, leading=15
        )
    )
    story = [
        Paragraph("OpenSSH Log Analyzer", styles["ExecTitleCustom"]),
        Paragraph("Executive Security Summary", styles["Heading2"]),
        Paragraph(
            "Evidence file: " + escape(str(source["filename"])),
            styles["ExecBodyCustom"],
        ),
        Spacer(1, 12),
    ]
    rows = [
        ["Recognized login attempts", str(stats["total"])],
        ["Failed logins", str(stats["failed"])],
        ["Successful logins", str(stats["successful"])],
        ["Failure rate", f"{stats['failure_rate']:.1f}%"],
        ["Unique source addresses", str(stats["unique_ips"])],
        ["Unique usernames", str(stats["unique_users"])],
        ["Most active source", str(stats["top_ip"])],
    ]
    table = Table(rows, colWidths=[245, 245], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
                (
                    "ROWBACKGROUNDS",
                    (0, 0),
                    (-1, -1),
                    [colors.white, colors.HexColor("#f1f5f9")],
                ),
                ("LINEBELOW", (0, 0), (-1, -1), 0.35, colors.HexColor("#d8e1ea")),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(table)
    for title, key in [
        ("Management overview", "overview"),
        ("Recommended action", "action"),
        ("Evidence coverage", "coverage"),
        ("Assessment limitations", "limitations"),
    ]:
        story.append(
            KeepTogether(
                [
                    Paragraph(title, styles["ExecSectionCustom"]),
                    Paragraph(escape(narrative[key]), styles["ExecBodyCustom"]),
                ]
            )
        )
    story += [
        Spacer(1, 14),
        Paragraph("SHA-256 evidence fingerprint", styles["ExecSectionCustom"]),
        Paragraph(escape(str(source["sha256"])), styles["ExecBodyCustom"]),
        Paragraph(
            "Fingerprint recorded for comparison only; authenticity and chain of custody are not established.",
            styles["ExecBodyCustom"],
        ),
    ]
    doc.build(story)
    return buffer.getvalue()
