from pathlib import Path
import argparse
import json
import re

import pandas as pd
import ollama


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_DATA_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "ip_group_59.63.188.30.csv"
)


def load_logs(data_file):
    """Load authentication records exported from KNIME."""
    return pd.read_csv(data_file)


def get_repeat_count(raw_log):
    """
    Extract the repeat count from a syslog compressed message.

    Example:
    'message repeated 5 times' -> 5

    A normal record returns 1 because it represents one event.
    """
    match = re.search(
        r"message repeated (\d+) times",
        str(raw_log),
        re.IGNORECASE,
    )

    if match:
        return int(match.group(1))

    return 1


def build_verified_evidence(logs):
    """Create structured evidence using deterministic Python analysis."""

    total_records = len(logs)

    failed_records = int(
        (logs["Authentication_Result"] == "FAILURE").sum()
    )

    successful_records = int(
        (logs["Authentication_Result"] == "SUCCESS").sum()
    )

    event_counts = logs["Raw_Log"].apply(get_repeat_count)

    compressed_mask = (
        logs["Raw_Log"]
        .astype(str)
        .str.contains(
            r"message repeated \d+ times",
            case=False,
            regex=True,
            na=False,
        )
    )

    compressed_records = int(compressed_mask.sum())
    ordinary_records = int((~compressed_mask).sum())

    repeated_events = int(
        event_counts[compressed_mask].sum()
    )

    ordinary_events = ordinary_records

    total_events = int(event_counts.sum())

    failed_event_count = int(
        event_counts[
            logs["Authentication_Result"] == "FAILURE"
        ].sum()
    )

    successful_event_count = int(
        event_counts[
            logs["Authentication_Result"] == "SUCCESS"
        ].sum()
    )

    source_ips = (
        logs["Source_IP"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    usernames = (
        logs["Username"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    methods = (
        logs["Authentication_Method"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    timestamps = pd.to_datetime(
        "2000 " + logs["Timestamp"].astype(str),
        format="%Y %b %d %H:%M:%S",
        errors="coerce",
    )

    valid_timestamps = timestamps.dropna()

    if not valid_timestamps.empty:
        first_event = valid_timestamps.min()
        last_event = valid_timestamps.max()

        duration_seconds = int(
            (last_event - first_event).total_seconds()
        )

        minutes, seconds = divmod(duration_seconds, 60)

        first_record = first_event.strftime(
            "%b %d %H:%M:%S"
        )

        last_record = last_event.strftime(
            "%b %d %H:%M:%S"
        )

        duration = (
            f"{minutes} minutes {seconds} seconds"
        )

    else:
        first_record = "Unknown"
        last_record = "Unknown"
        duration = "Unknown"

    evidence = {
        "total_csv_records": total_records,
        "ordinary_authentication_records": ordinary_records,
        "compressed_repeat_records": compressed_records,
        "ordinary_events_represented": ordinary_events,
        "repeated_events_represented": repeated_events,
        "total_authentication_events_represented": total_events,
        "failed_csv_records": failed_records,
        "successful_csv_records": successful_records,
        "failed_authentication_events_represented":
            failed_event_count,
        "successful_authentication_events_represented":
            successful_event_count,
        "source_ip_addresses": source_ips,
        "usernames": usernames,
        "authentication_methods": methods,
        "first_record": first_record,
        "last_record": last_record,
        "observed_time_span": duration,
        "counting_method": (
            "Normal log records count as one authentication event. "
            "Records containing 'message repeated N times' count as N "
            "authentication events based on the repeat value recorded "
            "by syslog."
        ),
        "evidence_limitations": [
            (
                "Authentication event counts are derived from the "
                "information represented in the supplied OpenSSH logs."
            ),
            (
                "The logs establish authentication activity but do "
                "not by themselves identify the intent or identity "
                "of the source."
            ),
            (
                "Conclusions apply only to the records supplied to "
                "this analysis."
            ),
        ],
    }

    return evidence


def build_llm_prompt(evidence):
    """Build a constrained SOC prompt from verified evidence."""

    evidence_json = json.dumps(
        evidence,
        indent=2,
    )

    return f"""
You are assisting a Security Operations Center (SOC) analyst.

Python has already analyzed the supplied OpenSSH authentication
records and calculated the authentication event counts.

Your job is to explain the verified evidence. Do not recalculate,
modify, estimate, or invent values.

VERIFIED EVIDENCE:

{evidence_json}

STRICT REQUIREMENTS:

- Use only the verified evidence above.
- Distinguish CSV log records from authentication events.
- Do not replace verified event counts with your own calculations.
- Do not invent IP addresses, usernames, ports, timestamps,
  protocols, security products, system configurations, or events.
- Do not describe a source as an attacker unless the evidence
  establishes intent.
- You may state that a pattern is consistent with possible
  brute-force activity when supported by the evidence.
- Do not claim unauthorized access succeeded unless the supplied
  evidence supports that conclusion.
- Clearly distinguish observations from security interpretation.
- If something cannot be determined, explicitly state that it
  cannot be determined from the supplied evidence.
- Keep the explanation concise and useful to a SOC analyst.

You MUST return exactly these six sections:

AUTHENTICATION SUMMARY

TIMELINE

OBSERVED INDICATORS

SECURITY INTERPRETATION

RISK LEVEL

RECOMMENDED SOC ACTIONS

For RISK LEVEL, select exactly one:
LOW, MEDIUM, HIGH, or CRITICAL.
"""


def analyze_with_llm(prompt):
    """Send structured verified evidence to local Llama 3.2."""

    print(
        "\nSending Python-verified evidence "
        "to Llama 3.2..."
    )

    response = ollama.chat(
        model="llama3.2",
        messages=[
            {
                "role": "user",
                "content": prompt,
            }
        ],
    )

    return response["message"]["content"]


def parse_arguments():
    """Read command-line options for selecting an input CSV."""

    parser = argparse.ArgumentParser(
        description=(
            "Analyze a KNIME-exported OpenSSH authentication "
            "CSV and generate a SOC-style explanation."
        )
    )

    parser.add_argument(
        "csv_file",
        nargs="?",
        default=str(DEFAULT_DATA_FILE),
        help=(
            "Path to the KNIME-exported CSV file. "
            "If omitted, the original IP-group sample is used."
        ),
    )

    return parser.parse_args()


def main():
    """Run deterministic analysis followed by LLM explanation."""

    args = parse_arguments()

    data_file = Path(args.csv_file)

    if not data_file.is_absolute():
        data_file = PROJECT_ROOT / data_file

    if not data_file.exists():
        raise FileNotFoundError(
            f"Input CSV file was not found: {data_file}"
        )

    print(
        f"\nAnalyzing file: "
        f"{data_file.relative_to(PROJECT_ROOT)}"
    )

    logs = load_logs(data_file)

    evidence = build_verified_evidence(logs)

    print(
        "\n===== PYTHON VERIFIED EVIDENCE V5 =====\n"
    )

    print(
        json.dumps(
            evidence,
            indent=2,
        )
    )

    prompt = build_llm_prompt(evidence)

    analysis = analyze_with_llm(prompt)

    print(
        "\n===== LLM SOC ANALYSIS V5 =====\n"
    )

    print(analysis)


if __name__ == "__main__":
    main()