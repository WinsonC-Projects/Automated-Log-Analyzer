from pathlib import Path
import json
import pandas as pd
import ollama


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "ip_group_59.63.188.30.csv"
)


def load_logs():
    """Load authentication events exported from KNIME."""
    return pd.read_csv(DATA_FILE)


def build_verified_evidence(logs):
    """Create structured evidence using deterministic Python analysis."""

    total_records = len(logs)

    failures = int(
        (logs["Authentication_Result"] == "FAILURE").sum()
    )

    successes = int(
        (logs["Authentication_Result"] == "SUCCESS").sum()
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
        errors="coerce"
    )

    valid_timestamps = timestamps.dropna()

    if not valid_timestamps.empty:
        first_event = valid_timestamps.min()
        last_event = valid_timestamps.max()

        duration_seconds = int(
            (last_event - first_event).total_seconds()
        )

        minutes, seconds = divmod(duration_seconds, 60)

        first_record = first_event.strftime("%b %d %H:%M:%S")
        last_record = last_event.strftime("%b %d %H:%M:%S")
        duration = f"{minutes} minutes {seconds} seconds"

    else:
        first_record = "Unknown"
        last_record = "Unknown"
        duration = "Unknown"

    repeated_records = (
        logs["Raw_Log"]
        .astype(str)
        .str.contains(
            r"message repeated \d+ times",
            case=False,
            regex=True,
            na=False
        )
        .sum()
    )

    evidence = {
        "total_csv_records": total_records,
        "failed_records": failures,
        "successful_records": successes,
        "source_ip_addresses": source_ips,
        "usernames": usernames,
        "authentication_methods": methods,
        "first_record": first_record,
        "last_record": last_record,
        "observed_time_span": duration,
        "records_with_repeated_message_notation": int(repeated_records),
        "evidence_limitations": [
            (
                "A CSV row represents a log record and does not necessarily "
                "represent one individual authentication attempt."
            ),
            (
                "Some OpenSSH records contain 'message repeated N times', "
                "which represents compressed repeated events."
            ),
            (
                "The exact number of underlying authentication attempts "
                "has not been calculated in this version."
            ),
            (
                "The provided evidence does not by itself establish that "
                "unauthorized access was successful."
            )
        ]
    }

    return evidence


def build_llm_prompt(evidence):
    """Build a constrained prompt using only Python-verified evidence."""

    evidence_json = json.dumps(
        evidence,
        indent=2
    )

    return f"""
You are assisting a Security Operations Center (SOC) analyst.

Python has already analyzed the OpenSSH authentication records.

Your job is NOT to recalculate, modify, or add facts.

Use ONLY the verified evidence provided below.

VERIFIED EVIDENCE:

{evidence_json}

STRICT REQUIREMENTS:

- Do not invent IP addresses, usernames, ports, protocols, timestamps,
  counts, security products, system configurations, or events.
- Do not recalculate the supplied values.
- Do not estimate the number of authentication attempts.
- Do not describe the source as an "attacker" unless the evidence proves it.
- You may describe the pattern as suspicious or consistent with possible
  brute-force activity when supported by the evidence.
- Do not claim that unauthorized access succeeded.
- Clearly distinguish verified observations from security interpretation.
- If something cannot be determined from the evidence, say so.
- Keep the response concise and useful to a SOC analyst.

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
    """Send verified evidence to the local Llama 3.2 model."""

    print("\nSending structured verified evidence to Llama 3.2...")

    response = ollama.chat(
        model="llama3.2",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    return response["message"]["content"]


if __name__ == "__main__":

    logs = load_logs()

    evidence = build_verified_evidence(logs)

    print("\n===== PYTHON VERIFIED EVIDENCE =====\n")
    print(json.dumps(evidence, indent=2))

    analysis = analyze_with_llm(
        build_llm_prompt(evidence)
    )

    print("\n===== LLM SOC ANALYSIS V4 =====\n")
    print(analysis)