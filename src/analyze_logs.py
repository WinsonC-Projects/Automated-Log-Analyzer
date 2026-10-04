from pathlib import Path
import pandas as pd


# Locate the project folders
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = PROJECT_ROOT / "data" / "processed" / "ip_group_59.63.188.30.csv"


def load_logs(file_path):
    """Load processed authentication logs exported from KNIME."""
    try:
        logs = pd.read_csv(file_path)
        print("Authentication log file loaded successfully.")
        print(f"Total events loaded: {len(logs)}")
        return logs

    except FileNotFoundError:
        print(f"Error: Could not find {file_path}")
        return None


def analyze_logs(logs):
    """Analyze authentication activity from the processed OpenSSH logs."""

    print("\n===== AUTHENTICATION ANALYSIS =====")

    print("\nAuthentication Results:")
    print(logs["Authentication_Result"].value_counts())

    print("\nTop Source IP Addresses:")
    print(logs["Source_IP"].value_counts().head(10))

    print("\nMost Targeted Usernames:")
    print(logs["Username"].value_counts().head(10))

    print("\nAuthentication Methods:")
    print(logs["Authentication_Method"].value_counts())

    print("\n===== END OF ANALYSIS =====")


def generate_soc_summary(logs):
    """Generate a simple SOC-style summary from authentication events."""

    total_events = len(logs)
    failures = (logs["Authentication_Result"] == "FAILURE").sum()
    successes = (logs["Authentication_Result"] == "SUCCESS").sum()

    top_ip = logs["Source_IP"].value_counts().idxmax()
    top_user = logs["Username"].value_counts().idxmax()
    top_method = logs["Authentication_Method"].value_counts().idxmax()

    print("\n===== SOC SUMMARY =====")

    print(f"Total authentication events analyzed: {total_events}")
    print(f"Failed authentication events: {failures}")
    print(f"Successful authentication events: {successes}")
    print(f"Most active source IP: {top_ip}")
    print(f"Most targeted username: {top_user}")
    print(f"Primary authentication method: {top_method}")

    if failures >= 10 and successes == 0:
        print(
            "\nObservation: A repeated sequence of failed authentication "
            "attempts was identified."
        )
        print(
            "Interpretation: This pattern may be consistent with automated "
            "login attempts or brute-force activity and should be "
            "investigated by a SOC analyst."
        )

    print("\n===== END OF SOC SUMMARY =====")


def generate_timeline(logs):
    """Display authentication events as a chronological sequence."""

    print("\n===== AUTHENTICATION TIMELINE =====")

    for index, row in logs.iterrows():
        print(
            f"{index + 1}. "
            f"{row['Timestamp']} | "
            f"{row['Authentication_Result']} | "
            f"IP: {row['Source_IP']} | "
            f"User: {row['Username']} | "
            f"Port: {row['Source_Port']} | "
            f"Method: {row['Authentication_Method']}"
        )

    print("\n===== END OF TIMELINE =====")


if __name__ == "__main__":
    logs = load_logs(DATA_FILE)

    if logs is not None:
        print("\nColumns:")
        print(logs.columns.tolist())

        print("\nFirst 5 authentication events:")
        print(logs.head())

        analyze_logs(logs)
        generate_soc_summary(logs)
        generate_timeline(logs)