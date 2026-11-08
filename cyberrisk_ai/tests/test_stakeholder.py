from stakeholder_reporting import executive_pdf, stakeholder_summary


def test_stakeholder_summary_does_not_claim_attack():
    stats = {
        "total": 3,
        "failed": 2,
        "successful": 1,
        "failure_rate": 66.7,
        "unique_ips": 2,
        "unique_users": 3,
        "top_ip": "192.168.1.50",
        "top_ip_events": 2,
    }
    info = {"unsupported_sshd_lines": 0, "repeat_summary_lines": 0}
    narrative = stakeholder_summary(stats, info)
    assert "do not establish" in narrative["overview"]
    assert "independently prove" in narrative["coverage"]
    pdf = executive_pdf(
        {"filename": "sample.log", "sha256": "abc123"}, stats, narrative
    )
    assert pdf.startswith(b"%PDF-")


def test_stakeholder_summary_flags_coverage_and_empty_data():
    stats = {
        "total": 0,
        "failed": 0,
        "successful": 0,
        "failure_rate": 0.0,
        "unique_ips": 0,
        "unique_users": 0,
        "top_ip": "N/A",
        "top_ip_events": 0,
    }
    narrative = stakeholder_summary(
        stats, {"unsupported_sshd_lines": 2, "repeat_summary_lines": 1}
    )
    assert narrative["status"] == "Review data coverage"
    assert "No supported authentication events" in narrative["overview"]
