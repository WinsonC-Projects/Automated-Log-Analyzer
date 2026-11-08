# OpenSSH Log Analyzer — Technical Project Report

**Project type:** Cybersecurity / digital forensics educational prototype  
**Author:** [Enter your name]  
**Course:** [Enter course and instructor]  
**Submission date:** [Enter date]

## 1. Abstract
OpenSSH Log Analyzer is a Python-based application that processes supported `sshd` authentication messages into structured records, summarizes authentication outcomes, supports filtered SOC-style inspection, checks internal evidence traceability, and exports reproducible reports. Optional local language-model integration can explain structured observations but does not make authoritative forensic determinations.

## 2. Problem statement
Manual inspection of SSH authentication logs can be time-consuming and prone to inconsistent counting. A transparent analysis workflow can help investigators quickly identify failed and successful logins, active source addresses, and records requiring further examination while retaining source-line references.

## 3. Objectives
- Extract explicitly recognized OpenSSH authentication outcomes.
- Calculate transparent counts and frequencies.
- Preserve source line numbers and raw-line references.
- Identify unrecognized sshd messages and repeated-message summaries as limitations.
- Produce interpretable tables, charts, and downloadable artifacts.
- Optionally provide constrained AI-assisted explanations.

## 4. Implementation
The project uses Python, pandas, Plotly, and Streamlit. `analysis_core.py` contains parsing, statistics, validation, filtering, and Ollama communication. `app.py` provides eight navigable views: Dashboard; Upload OpenSSH Logs; SOC Analysis; Evidence Validation; AI Prompt Studio; GRC Risk Assessment; Results & Reporting; and Methodology & Workflow.

### Data processing workflow
1. Upload a `.log` or `.txt` file (15 MB maximum).
2. Hash original bytes using SHA-256.
3. Decode text as UTF-8 with replacement for invalid bytes.
4. Recognize supported syslog/ISO `sshd` lines and explicit `Accepted`/`Failed` authentication messages.
5. Preserve event source line and line number.
6. Calculate event summaries and filtered views.
7. Run internal validation and generate reports.
8. Optionally send a limited structured evidence payload to a trusted Ollama endpoint.

## 5. Demonstration findings (synthetic dataset)
For `sample_data/demo_auth.log` with assumed year **2026**, expected outputs are:

| Measure | Expected |
|---|---:|
| Recognized authentication events | 6 |
| Failed logins | 4 |
| Successful logins | 2 |
| Failure rate | 66.7% |
| Distinct source IP addresses | 2 |
| Most active source | 192.168.1.50 |
| Events from most active source | 4 |
| Unsupported sshd lines | 1 |
| Repeated-message summary lines | 1 |

The data is fictional and does not demonstrate an actual intrusion.

## 6. Verification strategy
Automated tests cover parsing and metrics, source-line traceability, filtering, repeat handling, AI evidence payload construction, empty input, unsupported lines, and ISO timestamps. Run `py -m pytest -q` and record the observed output in the final submission. Manually check page navigation and exported artifacts.

## 7. Limitations and threats to validity
- Only a conservative subset of OpenSSH messages is recognized; counts may underrepresent activity in other formats.
- Traditional syslog lacks year information; a selected year is an assumption.
- Repeated-message summaries are not expanded into fabricated events.
- SHA-256 supports integrity comparison, not source authenticity or chain of custody.
- Internal source-line checks do not independently establish parser completeness.
- Descriptive indicators do not establish malicious intent, compromise, or a validated GRC risk score.
- Local Ollama explanations are optional, unverified, and may be inaccurate.
- Testing with a synthetic dataset does not establish generalization to all production logs.

## 8. Privacy and responsible use
Do not upload confidential logs to a publicly accessible Streamlit deployment. Configure AI requests only to a trusted endpoint. Usernames and IP addresses may be sensitive. Review results with additional host, network, and identity records before drawing conclusions.

## 9. Conclusion and future work
The prototype demonstrates an explainable pipeline from raw authentication lines to structured SOC-style indicators and reproducible reports. Future work may include a wider range of OpenSSH formats, independent parser cross-checks, timestamp normalization, larger test corpora, and documented GRC scoring methodology.

## 10. References to add before submission
Include course-required citations for OpenSSH logging conventions, Python/pandas/Streamlit/Plotly documentation, and any AI or code assistance. Do not submit placeholder references as final citations.
