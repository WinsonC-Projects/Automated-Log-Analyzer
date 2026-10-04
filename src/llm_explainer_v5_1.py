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
    Extract the repeat count from a compressed syslog message.

    Example:
    'message repeated 5 times' -> 5

    A normal record represents one event.
    """
    match = re.search(
        r"message repeated (\d+) times",
        str(raw_log),
        re.IGNORECASE,
    )

    if match:
        return int(match.group(1))

    return 1


def format_duration(duration_seconds):
    """Convert seconds into a SOC-friendly duration."""

    days, remainder = divmod(duration_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    parts = []

    if days:
        parts.append(f"{days} days")

    if hours:
        parts.append(f"{hours} hours")

    if minutes:
        parts.append(f"{minutes} minutes")

    parts.append(f"{seconds} seconds")

    return ", ".join(parts)


def build_verified_evidence(logs):
    """Create deterministic evidence from the supplied records."""

    total_records = len(logs)

    failed_mask = (
        logs["Authentication_Result"] == "FAILURE"
    )

    successful_mask = (
        logs["Authentication_Result"] == "SUCCESS"
    )

    failed_records = int(failed_mask.sum())
    successful_records = int(successful_mask.sum())

    event_counts = logs["Raw_Log"].apply(
        get_repeat_count
    )

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

    compressed_records = int(
        compressed_mask.sum()
    )

    ordinary_records = int(
        (~compressed_mask).sum()
    )

    repeated_events = int(
        event_counts[compressed_mask].sum()
    )

    ordinary_events = ordinary_records

    total_events = int(
        event_counts.sum()
    )

    failed_event_count = int(
        event_counts[failed_mask].sum()
    )

    successful_event_count = int(
        event_counts[successful_mask].sum()
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
            (
                last_event - first_event
            ).total_seconds()
        )

        first_record = first_event.strftime(
            "%b %d %H:%M:%S"
        )

        last_record = last_event.strftime(
            "%b %d %H:%M:%S"
        )

        duration = format_duration(
            duration_seconds
        )

    else:
        first_record = "Unknown"
        last_record = "Unknown"
        duration = "Unknown"

    evidence = {
        "total_csv_records":
            total_records,

        "ordinary_authentication_records":
            ordinary_records,

        "compressed_repeat_records":
            compressed_records,

        "ordinary_events_represented":
            ordinary_events,

        "repeated_events_represented":
            repeated_events,

        "total_authentication_events_represented":
            total_events,

        "failed_csv_records":
            failed_records,

        "successful_csv_records":
            successful_records,

        "failed_authentication_events_represented":
            failed_event_count,

        "successful_authentication_events_represented":
            successful_event_count,

        "unique_source_ip_count":
            len(source_ips),

        "source_ip_addresses":
            source_ips,

        "unique_username_count":
            len(usernames),

        "usernames":
            usernames,

        "authentication_methods":
            methods,

        "first_record":
            first_record,

        "last_record":
            last_record,

        "observed_time_span":
            duration,

        "counting_method": (
            "Normal log records count as one authentication "
            "event. Records containing 'message repeated N "
            "times' count as N authentication events based "
            "on the repeat value recorded by syslog."
        ),

        "evidence_limitations": [
            (
                "Authentication event counts are derived "
                "from the information represented in the "
                "supplied OpenSSH logs."
            ),
            (
                "Successful authentication does not by "
                "itself establish that the activity was "
                "authorized or legitimate."
            ),
            (
                "The logs do not by themselves establish "
                "the identity or intent of a source."
            ),
            (
                "Conclusions apply only to the records "
                "supplied to this analysis."
            ),
        ],
    }

    return evidence


def build_llm_prompt(evidence):
    """Build a constrained prompt from verified evidence."""

    evidence_json = json.dumps(
        evidence,
        indent=2,
    )

    return f"""
You are assisting a Security Operations Center (SOC) analyst.

Python has already calculated the factual values below.

Your role is to explain these verified facts, not recalculate them.

VERIFIED EVIDENCE:

{evidence_json}

STRICT REQUIREMENTS:

- Use only the verified evidence above.
- Do not change any verified number.
- Use unique_source_ip_count when stating the number of source IPs.
- Use unique_username_count when stating the number of usernames.
- Distinguish CSV records from represented authentication events.
- A successful authentication does not prove that activity was
  legitimate or authorized.
- Zero failed authentication records does not mean the CSV or log
  data is error-free.
- Do not describe a source as an attacker unless intent is
  established by the evidence.
- Do not state that brute-force activity was detected or not detected
  unless the supplied evidence is sufficient to support that
  conclusion.
- Absence of failed authentication events in the supplied sample is
  not evidence that brute-force activity did not occur outside the
  sample.
- Do not claim unauthorized access succeeded unless the evidence
  supports that conclusion.
- Do not invent ports, timestamps, protocols, security products,
  configurations, identities, motives, or events.
- Do not contradict the authentication_methods field.
- If password appears in authentication_methods, do not state that
  password authentication was absent.
- Clearly distinguish factual observations from interpretation.
- If something cannot be determined, state that it cannot be
  determined from the supplied evidence.
- Keep the response concise and useful to a SOC analyst.

You MUST return exactly these six sections:

AUTHENTICATION SUMMARY

TIMELINE

OBSERVED INDICATORS

SECURITY INTERPRETATION

RISK LEVEL

RECOMMENDED SOC ACTIONS

For RISK LEVEL, select exactly one:

LOW
MEDIUM
HIGH
CRITICAL
"""


def analyze_with_llm(prompt):
    """Send verified evidence to the local Llama 3.2 model."""

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


def extract_claimed_count(
    llm_output,
    patterns,
):
    """
    Extract a numerical claim from LLM text.

    The patterns are intentionally restricted so numerical
    claims cannot be accidentally matched across lines.
    """

    for pattern in patterns:
        match = re.search(
            pattern,
            llm_output,
            re.IGNORECASE,
        )

        if match:
            return int(match.group(1))

    return None


def validate_llm_output(
    evidence,
    llm_output,
):
    """
    Compare selected numerical LLM claims with Python-verified facts.

    PASS means an explicit numerical claim matches Python.
    FAIL means an explicit numerical claim conflicts with Python.
    NOT CHECKED means no reliably extractable claim was found.
    """

    checks = []

    validation_targets = [
        {
            "name": "Source IP count",
            "verified": evidence[
                "unique_source_ip_count"
            ],
            "patterns": [
                (
                    r"\b(\d+)[ \t]+"
                    r"unique source IP addresses\b"
                ),
                (
                    r"\b(\d+)[ \t]+"
                    r"unique source IPs\b"
                ),
                (
                    r"\bunique source IP addresses"
                    r"[ \t]*:[ \t]*(\d+)\b"
                ),
                (
                    r"\bunique source IPs"
                    r"[ \t]*:[ \t]*(\d+)\b"
                ),
            ],
            "zero_patterns": [
                r"\bno unique source IP addresses\b",
                r"\bno source IP addresses\b",
            ],
        },
        {
            "name": "Username count",
            "verified": evidence[
                "unique_username_count"
            ],
            "patterns": [
                (
                    r"\b(\d+)[ \t]+"
                    r"unique usernames\b"
                ),
                (
                    r"\b(\d+)[ \t]+"
                    r"unique users\b"
                ),
                (
                    r"\bunique usernames"
                    r"[ \t]*:[ \t]*(\d+)\b"
                ),
                (
                    r"\bunique users"
                    r"[ \t]*:[ \t]*(\d+)\b"
                ),
            ],
            "zero_patterns": [
                r"\bno unique usernames\b",
                r"\bno usernames\b",
            ],
        },
        {
            "name": "Total authentication events",
            "verified": evidence[
                "total_authentication_events_represented"
            ],
            "patterns": [
                (
                    r"\btotal authentication events"
                    r"[ \t]+represented"
                    r"[ \t]*:[ \t]*(\d+)\b"
                ),
                (
                    r"\btotal authentication events"
                    r"[ \t]*:[ \t]*(\d+)\b"
                ),
                (
                    r"\btotal number of authentication events"
                    r"[ \t]*:[ \t]*(\d+)\b"
                ),
                (
                    r"\b(\d+)[ \t]+"
                    r"total authentication events\b"
                ),
                (
                    r"\b(\d+)[ \t]+authentication events "
                    r"were[ \t]+successfully authenticated\b"
                ),
                (
                    r"\b(\d+)[ \t]+authentication events\b"
                ),
            ],
            "zero_patterns": [
                r"\bno authentication events\b",
            ],
        },
        {
            "name": "Successful authentication events",
            "verified": evidence[
                "successful_authentication_events_represented"
            ],
            "patterns": [
                (
                    r"\bsuccessful authentication events"
                    r"[ \t]+represented"
                    r"[ \t]*:[ \t]*(\d+)\b"
                ),
                (
                    r"\bsuccessful authentication events"
                    r"[ \t]*:[ \t]*(\d+)\b"
                ),
                (
                    r"\b(\d+)[ \t]+successful "
                    r"authentication events\b"
                ),
                (
                    r"\b(\d+)[ \t]+authentication events "
                    r"were[ \t]+successfully authenticated\b"
                ),
                (
                    r"\b(\d+)[ \t]+authentication events "
                    r"(?:were|are)[ \t]+successful\b"
                ),
            ],
            "zero_patterns": [
                r"\bno successful authentication events\b",
            ],
        },
        {
            "name": "Failed authentication events",
            "verified": evidence[
                "failed_authentication_events_represented"
            ],
            "patterns": [
                (
                    r"\bfailed authentication events"
                    r"[ \t]+represented"
                    r"[ \t]*:[ \t]*(\d+)\b"
                ),
                (
                    r"\bfailed authentication events"
                    r"[ \t]*:[ \t]*(\d+)\b"
                ),
                (
                    r"\b(\d+)[ \t]+"
                    r"failed authentication events\b"
                ),
            ],
            "zero_patterns": [
                r"\bno failed authentication events\b",
                r"\bno failed events\b",
            ],
        },
    ]

    for target in validation_targets:
        claimed = extract_claimed_count(
            llm_output,
            target["patterns"],
        )

        if claimed is None:
            for zero_pattern in target["zero_patterns"]:
                if re.search(
                    zero_pattern,
                    llm_output,
                    re.IGNORECASE,
                ):
                    claimed = 0
                    break

        if claimed is None:
            status = "NOT CHECKED"

        elif claimed == target["verified"]:
            status = "PASS"

        else:
            status = "FAIL"

        checks.append(
            {
                "name": target["name"],
                "status": status,
                "verified": target["verified"],
                "claimed": claimed,
            }
        )

    return checks


def print_validation_report(checks):
    """Display the deterministic LLM validation results."""

    print(
        "\n===== LLM OUTPUT VALIDATION V5.1 =====\n"
    )

    failures = 0
    checked = 0

    for check in checks:
        print(
            f"[{check['status']}] "
            f"{check['name']}"
        )

        print(
            f"  Python verified: "
            f"{check['verified']}"
        )

        if check["claimed"] is None:
            print(
                "  LLM claim: "
                "No reliably extractable numerical claim"
            )

        else:
            checked += 1

            print(
                f"  LLM claimed: "
                f"{check['claimed']}"
            )

        if check["status"] == "FAIL":
            failures += 1

        print()

    print(
        f"Numerical claims checked: {checked}"
    )

    print(
        f"Numerical inconsistencies detected: "
        f"{failures}"
    )

    if failures:
        print(
            "\nWARNING: The LLM output contains "
            "numerical inconsistencies."
        )

        print(
            "Human analyst review is required."
        )

    else:
        print(
            "\nNo numerical inconsistencies were "
            "detected among the claims that could "
            "be checked automatically."
        )

        print(
            "This does not prove that every narrative "
            "statement made by the LLM is correct."
        )


def parse_arguments():
    """Read the input CSV path from the command line."""

    parser = argparse.ArgumentParser(
        description=(
            "Analyze a KNIME-exported OpenSSH "
            "authentication CSV, generate an LLM "
            "explanation, and validate selected "
            "numerical claims."
        )
    )

    parser.add_argument(
        "csv_file",
        nargs="?",
        default=str(DEFAULT_DATA_FILE),
        help=(
            "Path to the KNIME-exported CSV file. "
            "If omitted, the original IP-group "
            "sample is used."
        ),
    )

    return parser.parse_args()


def main():
    """Run the V5.1 analysis and validation pipeline."""

    args = parse_arguments()

    data_file = Path(args.csv_file)

    if not data_file.is_absolute():
        data_file = PROJECT_ROOT / data_file

    if not data_file.exists():
        raise FileNotFoundError(
            f"Input CSV file was not found: "
            f"{data_file}"
        )

    try:
        display_path = data_file.relative_to(
            PROJECT_ROOT
        )

    except ValueError:
        display_path = data_file

    print(
        f"\nAnalyzing file: {display_path}"
    )

    logs = load_logs(data_file)

    evidence = build_verified_evidence(logs)

    print(
        "\n===== PYTHON VERIFIED EVIDENCE V5.1 =====\n"
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
        "\n===== LLM SOC ANALYSIS V5.1 =====\n"
    )

    print(analysis)

    checks = validate_llm_output(
        evidence,
        analysis,
    )

    print_validation_report(checks)


if __name__ == "__main__":
    main()