# OpenSSH Log Analyzer

**An educational OpenSSH authentication log analysis and evidence-validation application.**

## Overview
This Python/Streamlit application parses a deliberately limited set of OpenSSH (`sshd`) authentication messages and provides an interactive security dashboard, SOC filtering, evidence validation, descriptive GRC indicators, CSV/JSON reporting, and optional AI explanations using a separately installed local Ollama server.

**Scope:** Explicit `Accepted` and `Failed` OpenSSH authentication messages. This is not a complete SIEM, forensic certification tool, or compromise detector.

## Requirements
- Windows 10/11, macOS, or Linux
- Python 3.11+ (project intended for Python 3.14 as well, but not validated here)
- Network access once to install dependencies
- Optional: Ollama with a local model such as `llama3.2`

## Install and run (VS Code integrated PowerShell)
Extract the ZIP, open the **OpenSSH Log Analyzer** folder in VS Code, and run:

```powershell
py -m pip install -r requirements.txt
py -m pytest -q
py -m streamlit run app.py
```

If using a virtual environment:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest -q
python -m streamlit run app.py
```

## Demonstration
1. Open **Upload OpenSSH Logs**.
2. Set assumed syslog year to **2026**.
3. Upload `sample_data/demo_auth.log` and click **Parse authentication events**.
4. Open **Dashboard**, **SOC Analysis**, **Evidence Validation**, **GRC Risk Assessment**, and **Results & Reporting**.
5. Confirm 6 recognized authentication events: 4 failures and 2 successes.
6. Confirm 1 unsupported sshd line and 1 repeat summary are flagged for review.
7. Export CSV and JSON reports.

## Optional Ollama
Install Ollama separately, start its local service, and run `ollama pull llama3.2` in VS Code terminal. Use **AI Prompt Studio** to check the connection before generating. No AI connection is required for the other pages.

**Privacy:** Uploaded logs are processed by the Streamlit host. The AI feature sends structured evidence (including usernames and IP addresses) to the configured Ollama endpoint. Keep that endpoint local and trusted for sensitive data.

## Files
- `app.py`: Streamlit interface and page navigation
- `analysis_core.py`: parsing, metrics, validation, filters, and optional Ollama requests
- `tests/test_core.py`: automated checks
- `sample_data/demo_auth.log`: synthetic demonstration log
- `SUBMISSION_REPORT.md`: methodology, findings, and limitations
- `DEMO_CHECKLIST.md`: final demonstration checklist

## Validation and limits
- File SHA-256 is computed from uploaded original bytes. It does not prove chain of custody.
- Every recognized event retains its original line and line number.
- Internal validation is not an independent parser comparison.
- Syslog year must be assumed by the analyst when omitted from source lines.
- Unsupported `sshd` lines and repeat summaries are not counted as authentication events.
- Risk indicators are descriptive; no formal likelihood × impact score is calculated.
- The optional AI output is a hypothesis-generating aid and requires human verification.

## Academic integrity
Document your own contributions, testing, and any assistance/tools used according to course policy. Be prepared to demonstrate and explain the parser, validation, and reporting logic.

## Stakeholder reporting

The **Executive Summary** page presents deterministic, plain-English findings from recognized OpenSSH events. Switch between Executive view and Technical view. Export an **Executive Summary PDF** with key metrics, suggested verification actions, evidence-coverage limitations, and the SHA-256 fingerprint. The PDF contains no raw log lines. No Ollama connection is required for this report. The narrative does not infer confirmed compromise or a formal risk rating.

`stakeholder_reporting.py` implements the executive narrative and PDF generation. The PDF feature requires `reportlab` (included in `requirements.txt`).


## User experience

The redesigned interface provides visual authentication charts, executive summaries, readable validation guidance, and PDF export. Stakeholder interpretations use deterministic calculations rather than AI-generated claims.

### Windows VS Code quick start

Open the folder containing `app.py` in VS Code, then run:

```powershell
py -m pip install -r requirements.txt
py -m pytest -q
py -m streamlit run app.py
```

Upload `sample_data/demo_auth.log` to explore the interface.


### Visual reporting and appearance
The sidebar includes a Light/Dark appearance switch and a live local Ollama status indicator.
The Executive Summary appears directly below Results & Reporting in navigation.
Open **Technical report details — visual explorer** for Findings, Evidence, Validation and Limitations tabs.
Open **Technical validation checks — explained visually** in the Executive Summary's Technical analyst view.

Ollama checks occur on each page rerun and may take a few seconds when offline.
The appearance switch controls the sidebar palette; the main content follows your Streamlit theme.


### Comfort theme update
The sidebar Appearance control now applies an application-wide soft light or dark color palette. Light mode uses a muted blue-gray background and lower-glare cards; sidebar navigation spacing is compact and AI status controls use matching contrast. Streamlit custom CSS may require adjustment after major Streamlit upgrades.
