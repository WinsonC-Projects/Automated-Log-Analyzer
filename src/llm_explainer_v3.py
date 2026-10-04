from pathlib import Path
import pandas as pd
import ollama


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "ip_group_59.63.188.30.csv"
)

PROMPT_FILE = (
    PROJECT_ROOT
    / "prompts"
    / "soc_analysis_prompt.txt"
)


def load_prompt():
    """Load the SOC analysis instructions."""
    with open(PROMPT_FILE, "r", encoding="utf-8") as file:
        return file.read()


def load_logs():
    """Load authentication events exported from KNIME."""
    return pd.read_csv(DATA_FILE)


def generate_verified_facts(logs):
    """Generate deterministic facts before sending evidence to the LLM."""

    total_records = len(logs)

    failures = (
        logs["Authentication_Result"] == "FAILURE"
    ).sum()

    successes = (
        logs["Authentication_Result"] == "SUCCESS"
    ).sum()

    source_ips = logs["Source_IP"].dropna().unique().tolist()
    usernames = logs["Username"].dropna().unique().tolist()
    methods = logs["Authentication_Method"].dropna().unique().tolist()

    # Parse timestamps using a temporary year because the Loghub
    # OpenSSH records do not contain a year.
    timestamps = pd.to_datetime(
        "2000 " + logs["Timestamp"].astype(str),
        format="%Y %b %d %H:%M:%S",
        errors="coerce"
    )

    valid_timestamps = timestamps.dropna()

    if not valid_timestamps.empty:
        first_event = valid_timestamps.min()
        last_event = valid_timestamps.max()
        duration = last_event - first_event

        duration_seconds = int(duration.total_seconds())
        minutes, seconds = divmod(duration_seconds, 60)

        time_summary = (
            f"First record: {first_event.strftime('%b %d %H:%M:%S')}\n"
            f"Last record: {last_event.strftime('%b %d %H:%M:%S')}\n"
            f"Observed time span: {minutes} minutes {seconds} seconds"
        )
    else:
        time_summary = "Time range could not be calculated."

    facts = f"""
VERIFIED FACTS CALCULATED BY PYTHON

Total CSV log records: {total_records}
Failed records: {failures}
Successful records: {successes}
Source IP addresses: {source_ips}
Usernames: {usernames}
Authentication methods: {methods}

{time_summary}

IMPORTANT:
These facts were calculated programmatically from the structured data.
Do not contradict or recalculate these values.

A CSV row represents a log record and does not necessarily represent
one individual authentication attempt. Some raw OpenSSH records contain
messages such as "message repeated 5 times," indicating compressed
repeated events.
"""

    return facts


def build_llm_prompt(instructions, verified_facts, logs):
    """Combine instructions, verified facts, and raw evidence."""

    log_text = logs.to_csv(index=False)

    return f"""
{instructions}

{verified_facts}

AUTHENTICATION LOG EVIDENCE:

{log_text}
"""


def analyze_with_llm(prompt):
    """Send verified authentication evidence to local Llama 3.2."""

    print("\nSending verified authentication evidence to Llama 3.2...")

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
    instructions = load_prompt()
    logs = load_logs()

    verified_facts = generate_verified_facts(logs)

    print("\n===== PYTHON VERIFIED FACTS =====")
    print(verified_facts)

    final_prompt = build_llm_prompt(
        instructions,
        verified_facts,
        logs
    )

    analysis = analyze_with_llm(final_prompt)

    print("\n===== LLM SOC ANALYSIS =====\n")
    print(analysis)