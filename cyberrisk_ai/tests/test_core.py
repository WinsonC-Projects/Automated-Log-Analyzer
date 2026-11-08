import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis_core import ai_payload, filter_events, parse_logs, summarize, validate

SAMPLE = """Oct 25 14:00:01 server sshd[101]: Failed password for root from 192.168.1.50 port 50100 ssh2
Oct 25 14:00:05 server sshd[102]: Failed password for root from 192.168.1.50 port 50101 ssh2
Oct 25 14:01:01 server sshd[103]: Accepted publickey for analyst from 192.168.1.20 port 50102 ssh2"""


def test_parse_and_summary():
    df, info = parse_logs(SAMPLE, 2026)
    assert len(df) == 3
    assert info["parsed_events"] == 3
    stats = summarize(df)
    assert stats["failed"] == 2
    assert stats["successful"] == 1
    assert stats["top_ip"] == "192.168.1.50"
    assert stats["failure_rate"] == 66.7


def test_validation_and_traceability():
    df, info = parse_logs(SAMPLE, 2026)
    checks = validate(df, SAMPLE, info)
    assert (
        checks.loc[checks["Check"] == "Raw-line traceability", "Status"].iloc[0]
        == "PASS"
    )
    assert (
        checks.loc[checks["Check"] == "Independent parser verification", "Status"].iloc[
            0
        ]
        == "NOT CHECKED"
    )


def test_filters():
    df, _ = parse_logs(SAMPLE, 2026)
    filtered = filter_events(df, ["FAILURE"], ["192.168.1.50"], [], "root")
    assert len(filtered) == 2


def test_repeat_not_invented():
    df, info = parse_logs(
        SAMPLE + "\nOct 25 14:02:00 server sshd[104]: last message repeated 5 times",
        2026,
    )
    assert len(df) == 3
    assert info["repeat_summary_lines"] == 1


def test_payload_is_structured():
    df, info = parse_logs(SAMPLE, 2026)
    payload = ai_payload(df, info, "examplehash")
    assert payload["summary"]["total"] == 3
    assert len(payload["sample_events"]) == 3
    assert "raw_line" not in payload["sample_events"][0]


def test_empty_file():
    df, info = parse_logs("", 2026)
    assert df.empty
    assert summarize(df)["total"] == 0
    assert info["parsed_events"] == 0


def test_unsupported_ssh_message_flagged():
    raw = (
        SAMPLE
        + "\nOct 25 14:05:00 server sshd[105]: Connection closed by authenticating user root 192.168.1.50 port 5555"
    )
    df, info = parse_logs(raw, 2026)
    assert len(df) == 3
    assert info["unsupported_sshd_lines"] == 1
    checks = validate(df, raw, info)
    assert (
        checks.loc[checks["Check"] == "Unrecognized sshd formats", "Status"].iloc[0]
        == "REVIEW"
    )


def test_raw_line_provenance():
    df, _info = parse_logs(SAMPLE, 2026)
    assert df.loc[0, "line_number"] == 1
    assert df.loc[0, "raw_line"] == SAMPLE.splitlines()[0]


def test_iso_log_timestamp():
    raw = "2026-10-25T14:00:01Z server sshd[1]: Failed password for root from 10.0.0.1 port 12345 ssh2"
    df, info = parse_logs(raw, 2026)
    assert len(df) == 1
    assert info["unsupported_sshd_lines"] == 0
    assert summarize(df)["failed"] == 1


def test_no_fabricated_events_from_noise():
    raw = "Oct 25 14:00:01 server sshd[1]: Invalid user root from 10.0.0.1 port 12345\n"
    df, info = parse_logs(raw, 2026)
    assert df.empty
    assert info["unsupported_sshd_lines"] == 1
