# Automated OpenSSH Log Analyzer

## Overview

The Automated OpenSSH Log Analyzer is a cybersecurity project that analyzes OpenSSH authentication logs and generates evidence-based explanations that may assist Security Operations Center (SOC) analysts.

The project combines **KNIME Analytics Platform**, **Python**, and a locally hosted **Llama 3.2 Large Language Model (LLM)** through **Ollama**.

KNIME is used to filter and structure authentication logs, Python performs deterministic analysis and verifies factual evidence, and Llama 3.2 converts the verified evidence into a concise SOC-style explanation.

A major focus of this project is evaluating the reliability of LLMs for cybersecurity log analysis and determining how deterministic processing can reduce unsupported or hallucinated information.

## Project Objectives

- Extract successful and failed OpenSSH authentication activity.
- Structure raw authentication logs using KNIME.
- Analyze authentication patterns using Python.
- Create timelines and calculate authentication activity from log evidence.
- Use a local LLM to generate SOC-readable explanations.
- Evaluate hallucinations and limitations in LLM-generated security analysis.
- Improve LLM reliability by providing Python-verified evidence.

## Architecture

```text
OpenSSH Loghub Dataset
        |
        v
KNIME Analytics Platform
        |
        |-- Filter authentication records
        |-- Extract structured fields
        |-- Group activity by source IP
        |
        v
Structured CSV Data
        |
        v
Python
        |
        |-- Calculate verified statistics
        |-- Build authentication timelines
        |-- Process syslog repeated messages
        |
        v
Verified Evidence
        |
        v
Ollama + Llama 3.2
        |
        v
SOC-Style Explanation
```

The architecture separates **factual analysis** from **LLM interpretation**. Python is responsible for calculations and evidence processing, while the LLM is primarily responsible for explaining verified findings.

## Dataset

The project uses OpenSSH authentication logs from the **Loghub** dataset.

Initial KNIME processing identified:

- **655,147** raw log records
- **197,587** records containing `Failed password`
- **182** records containing `Accepted password` or `Accepted publickey`
- **197,769** combined authentication records
- **1,042** unique source IP addresses

The most active source IP in the processed authentication data was `59.63.188.30`, with **28,766 log records**.

A 50-record sample from this source IP was selected for the primary Python and LLM experiments.

## Key Finding

Python analysis identified an important difference between **CSV log records** and the number of **authentication events represented by those records**.

The selected sample contained:

```text
CSV log records:                         50
Ordinary authentication records:         25
Compressed repeat records:               25
Repeated events represented:            125
Total authentication events represented: 150
Failed authentication events:           150
Successful authentication events:         0
```

The compressed records contained syslog notation such as:

```text
message repeated 5 times: [ Failed password ... ]
```

Python therefore handles the repeat value deterministically instead of asking the LLM to estimate authentication activity.

The analyzed activity involved:

```text
Source IP:              59.63.188.30
Username:                        root
Authentication method:       password
Observed time span:     6 min 26 sec
```

## LLM Experiments

Four stages of the LLM pipeline were evaluated:

| Version | Approach                                    | Result                                                                                           |
| ------- | ------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| V1/V2   | Raw logs + prompt engineering               | Useful interpretation, but factual and formatting problems remained                              |
| V3      | Python-verified facts + raw logs            | Verified facts were provided, but the LLM still introduced unsupported information               |
| V4      | Structured Python evidence only             | Hallucinations were reduced and format compliance improved                                       |
| V4.1    | Expanded event counts + structured evidence | Best experimental result with clearer separation between records, events, and LLM interpretation |

The experiments showed that **prompt engineering alone was not enough to guarantee factual accuracy**. Reliability improved when Python became responsible for factual calculations and the LLM received only structured, verified evidence.

Detailed experiment results are documented in the `docs/` directory.

## Installation

Install the Python dependencies:

```powershell
python -m pip install -r requirements.txt
```

The project currently uses:

```text
pandas==3.0.6
ollama==0.6.3
```

Ollama must also be installed separately. After installing Ollama, download Llama 3.2:

```powershell
ollama pull llama3.2
```

## Usage

Run the deterministic Python analysis:

```powershell
python src/analyze_logs.py
```

Run the latest LLM experiment:

```powershell
python src/llm_explainer_v4_1.py
```

Earlier experimental versions are preserved in `src/` so that changes in LLM behavior and reliability can be compared.

The KNIME workflow is available at:

```text
knime/OpenSSH Authentication Log Analysis.knwf
```

## Project Structure

```text
Automated-Log-Analyzer/
├── data/
│   ├── raw/
│   └── processed/
├── docs/
├── knime/
├── output/
├── prompts/
├── src/
├── tests/
├── .gitignore
├── README.md
└── requirements.txt
```

Raw dataset files are kept locally and are not intended to be committed to the repository.

## Limitations

The project currently analyzes selected authentication samples rather than sending the entire dataset to the LLM. The analyzed timestamps do not include a year, and the supplied logs alone cannot establish the identity or intent of a source IP.

LLM-generated explanations may also vary between runs and may contain unsupported information. For this reason, LLM output should be validated against deterministic analysis and reviewed by a human analyst before supporting a security decision.

## Documentation

Detailed project documentation is maintained separately:

- `docs/methodology.md` — KNIME workflow, Python analysis, and event-counting methodology
- `docs/llm_experiments.md` — V1/V2 through V4.1 testing and observed LLM behavior
- `docs/findings.md` — Evidence, results, interpretation, and final findings

## Conclusion

This project demonstrates that LLMs can assist with translating authentication evidence into readable SOC explanations, but they should not be relied upon as the primary source of factual log analysis.

Testing showed that reliability improved when **KNIME and Python handled evidence processing and deterministic calculations while the LLM was limited to explaining verified evidence**.

The project therefore uses the LLM as an analytical support tool rather than a replacement for deterministic processing or human cybersecurity judgment.
