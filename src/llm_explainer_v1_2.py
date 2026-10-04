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
    """Load the authentication events exported from KNIME."""

    return pd.read_csv(DATA_FILE)


def build_llm_prompt(instructions, logs):
    """Combine SOC instructions with authentication evidence."""

    log_text = logs.to_csv(index=False)

    prompt = f"""
{instructions}

AUTHENTICATION LOG EVIDENCE:

{log_text}
"""

    return prompt


def analyze_with_llm(prompt):
    """Send authentication evidence to the local Llama 3.2 model."""

    print("\nSending authentication logs to Llama 3.2...")

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

    final_prompt = build_llm_prompt(instructions, logs)

    analysis = analyze_with_llm(final_prompt)

    print("\n===== LLM SOC ANALYSIS =====\n")
    print(analysis)