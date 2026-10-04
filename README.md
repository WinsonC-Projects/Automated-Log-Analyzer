# Automated OpenSSH Log Analyzer

## Overview

The Automated OpenSSH Log Analyzer is a cybersecurity project that analyzes OpenSSH authentication logs and generates evidence-based explanations that may assist Security Operations Center (SOC) analysts.

The project combines **KNIME Analytics Platform**, **Python**, and a locally hosted **Llama 3.2 Large Language Model (LLM)** through **Ollama**.

KNIME is used to filter and structure authentication logs. Python performs deterministic analysis and calculates verified evidence. Llama 3.2 receives the Python-verified evidence and converts it into a concise SOC-style explanation.

A major focus of this project is evaluating the reliability of LLMs for cybersecurity log analysis. The experiments demonstrate why deterministic processing and automated validation are important when LLMs are used to explain security evidence.

## Project Objectives

- Extract successful and failed OpenSSH authentication activity.
- Structure raw authentication logs using KNIME.
- Analyze authentication patterns using Python.
- Create timelines and calculate authentication activity from log evidence.
- Correctly interpret compressed syslog repeat messages.
- Use a local LLM to generate SOC-readable explanations.
- Evaluate hallucinations and limitations in LLM-generated security analysis.
- Improve LLM reliability by providing Python-verified evidence.
- Automatically compare selected LLM numerical claims with verified Python results.
- Test critical analysis and validation functions using automated unit tests.

## Architecture

```text
OpenSSH Loghub Dataset
        |
        v
KNIME Analytics Platform
        |
        |-- Filter authentication records
        |-- Extract structured fields
        |-- Label SUCCESS / FAILURE
        |-- Group activity by source IP
        |-- Export selected samples
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
        |-- Count represented authentication events
        |
        v
Verified Evidence
        |
        v
Ollama + Llama 3.2
        |
        v
SOC-Style Explanation
        |
        v
Python Validation
        |
        |-- Compare selected numerical claims
        |-- PASS / FAIL / NOT CHECKED
        |
        v
Human Analyst Review
```

The architecture separates **factual analysis** from **LLM interpretation**. Python is responsible for calculations and evidence processing, while the LLM is primarily responsible for explaining verified findings.

The final validation stage does not assume that LLM output is correct. Selected numerical claims are compared with Python-verified values before the explanation is accepted for analyst review.

## Dataset

The project uses OpenSSH authentication logs from the **Loghub** dataset.

Initial KNIME processing identified:

- **655,147** raw log records
- **197,587** records containing `Failed password`
- **182** records containing `Accepted password` or `Accepted publickey`
- **197,769** combined authentication records
- **1,042** unique source IP addresses

The most active source IP in the processed authentication data was:

```text
59.63.188.30
```

It appeared in **28,766 log records**.

A 50-record sample from this source IP was selected for the primary failed-authentication experiments.

A separate 50-record successful-authentication sample was also exported from KNIME to evaluate whether the final pipeline could analyze a different type of authentication activity.

## KNIME Processing

The KNIME workflow separates successful and failed authentication activity before creating a structured dataset.

The general workflow is:

```text
SSH Log
 ├── Failed Password
 │      └── Authentication_Result = FAILURE
 │
 └── Accepted Password / Publickey
        └── Authentication_Result = SUCCESS
                 |
                 v
             Concatenate
                 |
                 v
             Source_IP
                 |
                 v
              Username
                 |
                 v
             Timestamp
                 |
                 v
            Source_Port
                 |
                 v
       Authentication_Method
                 |
        +--------+--------+
        |                 |
        v                 v
Source-IP Samples    Successful Sample
        |
        v
GroupBy / Sort / CSV Export
```

The exported structured fields allow Python to perform deterministic analysis without requiring the LLM to parse the original raw dataset independently.

## Key Finding: Records vs. Authentication Events

Python analysis identified an important difference between **CSV log records** and the number of **authentication events represented by those records**.

The primary failed-authentication sample contained:

```text
CSV log records:                         50
Ordinary authentication records:         25
Compressed repeat records:               25
Repeated events represented:            125
Total authentication events represented: 150
Failed authentication events:           150
Successful authentication events:         0
```

Some records contained syslog notation such as:

```text
message repeated 5 times: [ Failed password ... ]
```

A compressed record therefore may represent multiple authentication events.

Python handles the repeat value deterministically instead of asking the LLM to estimate the number of authentication attempts.

The analyzed failed-authentication sample involved:

```text
Source IP:              59.63.188.30
Username:                       root
Authentication method:      password
Observed time span:     6 min 26 sec
```

## Successful Authentication Sample

The final pipeline was also tested against a separate 50-record successful-authentication sample.

Python verified:

```text
Total CSV records:                         50
Ordinary authentication records:           50
Compressed repeat records:                  0
Total authentication events represented:   50
Successful authentication events:          50
Failed authentication events:               0
Unique source IP addresses:                 14
Unique usernames:                            5
Authentication method:                password
Observed time span: 8 days, 11 hours,
                    21 minutes, 51 seconds
```

The usernames represented in this sample were:

```text
fztu
jmzhu
curi
zachary
suyuxin
```

This experiment demonstrated that the pipeline could analyze a sample containing successful authentication activity rather than being limited to the original failed-authentication IP group.

A successful authentication event does **not** by itself prove that the activity was legitimate or authorized.

## LLM Experiment Progression

The project preserved multiple experimental versions to demonstrate how the analysis pipeline changed over time.

| Version  | Approach                                                                 | Main Result                                                                                          |
| -------- | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------- |
| V1/V2    | Raw logs + prompt engineering                                            | Produced useful explanations, but factual and formatting problems remained                           |
| V3       | Python-verified facts + raw logs                                         | Verified facts were supplied, but the LLM still introduced unsupported information                   |
| V4       | Structured Python evidence only                                          | Reduced hallucinations and improved separation between evidence and explanation                      |
| V4.1     | Expanded event counting + structured evidence                            | Correctly distinguished CSV records from authentication events represented by syslog repeat messages |
| V5       | Generalized CSV input                                                    | Allowed the same pipeline to analyze different KNIME-exported authentication samples                 |
| **V5.1** | **Verified evidence + LLM explanation + automated numerical validation** | **Final version; selected LLM numerical claims are compared with deterministic Python results**      |

The experiments showed that **prompt engineering alone was not enough to guarantee factual accuracy**.

Reliability improved when Python became responsible for factual calculations and the LLM received structured, verified evidence.

## Final V5.1 Pipeline

V5.1 is the final experimental version of the project.

It performs the following process:

```text
KNIME CSV
   |
   v
Python Evidence Calculation
   |
   |-- CSV record counts
   |-- Represented event counts
   |-- SUCCESS / FAILURE counts
   |-- Source IPs
   |-- Usernames
   |-- Authentication methods
   |-- Timeline
   |
   v
Verified Evidence
   |
   v
Llama 3.2
   |
   v
SOC Explanation
   |
   v
Python Validator
   |
   |-- Source IP count
   |-- Username count
   |-- Total authentication events
   |-- Successful authentication events
   |-- Failed authentication events
   |
   v
PASS / FAIL / NOT CHECKED
   |
   v
Human Analyst Review
```

The validator intentionally reports `NOT CHECKED` when it cannot reliably extract a numerical claim from the LLM's wording. This is preferable to incorrectly assuming that a claim is correct.

## V5.1 Validation Result

During the final successful-authentication experiment, the LLM correctly reported several Python-verified numerical values.

The validator produced:

```text
[PASS] Source IP count
Python verified: 14
LLM claimed: 14

[PASS] Username count
Python verified: 5
LLM claimed: 5

[NOT CHECKED] Total authentication events
Python verified: 50

[PASS] Successful authentication events
Python verified: 50
LLM claimed: 50

[PASS] Failed authentication events
Python verified: 0
LLM claimed: 0

Numerical claims checked: 4
Numerical inconsistencies detected: 0
```

The `NOT CHECKED` result demonstrates an important limitation of automated LLM-output validation: an LLM can express the same information using different wording that may not match a deterministic validation pattern.

For this reason, the validator is an additional safeguard rather than a replacement for human review.

## Automated Testing

The project includes automated unit tests for important deterministic functions.

Tests cover:

- Normal authentication event counting.
- Compressed syslog repeat counting.
- Different repeat values to ensure counting is not hard-coded.
- CSV record counts.
- Failed authentication event counts.
- Ordinary vs. compressed records.
- Total represented authentication events.
- Source information.
- Timeline calculations.
- Correct LLM numerical claims.
- Detection of an incorrect username count.
- Protection against interpreting an IP-address octet as a username count.

Run the complete test suite with:

```powershell
python -m unittest discover -s tests -v
```

Final test result:

```text
Ran 12 tests
OK
```

The tests are designed to verify deterministic portions of the pipeline without requiring an LLM call.

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

Ollama must also be installed separately.

After installing Ollama, download the Llama 3.2 model:

```powershell
ollama pull llama3.2
```

## Usage

### Run Deterministic Python Analysis

```powershell
python src/analyze_logs.py
```

### Run Final V5.1 Using the Default Sample

```powershell
python src/llm_explainer_v5_1.py
```

### Analyze the Successful Authentication Sample

```powershell
python src/llm_explainer_v5_1.py data/processed/success_authentication_sample.csv
```

### Run Automated Tests

```powershell
python -m unittest discover -s tests -v
```

Earlier experimental versions are preserved in `src/` so changes in LLM behavior and reliability can be compared.

The KNIME workflow is available at:

```text
knime/OpenSSH Authentication Log Analysis.knwf
```

## Project Structure

```text
Automated-Log-Analyzer/
├── data/
│   ├── raw/
│   │   └── SSH.log                 # Local / ignored by Git
│   └── processed/
│       ├── ip_group_59.63.188.30.csv
│       └── success_authentication_sample.csv
├── docs/
│   ├── findings.md
│   ├── llm_experiments.md
│   └── methodology.md
├── knime/
│   └── OpenSSH Authentication Log Analysis.knwf
├── output/
│   └── Experimental LLM outputs
├── prompts/
│   └── soc_analysis_prompt.txt
├── src/
│   ├── analyze_logs.py
│   ├── llm_explainer_v1_2.py
│   ├── llm_explainer_v3.py
│   ├── llm_explainer_v4.py
│   ├── llm_explainer_v4_1.py
│   ├── llm_explainer_v5.py
│   └── llm_explainer_v5_1.py
├── tests/
│   ├── test_repeat_count.py
│   ├── test_verified_evidence.py
│   └── test_llm_validator_v5_1.py
├── .gitattributes
├── .gitignore
├── README.md
└── requirements.txt
```

Raw dataset files are kept locally and are not intended to be committed to the repository.

## Limitations

This project has several important limitations.

The analysis uses selected authentication samples rather than sending the complete OpenSSH dataset to the LLM. The timestamps in the supplied dataset do not contain a year, so Python uses an artificial year only to calculate relative time differences.

The supplied authentication logs alone cannot establish the identity or intent of a source IP. Likewise, a successful authentication does not establish that the activity was legitimate or authorized.

LLM-generated explanations may vary between runs. Earlier experiments demonstrated that the LLM could change numerical values, introduce unsupported interpretations, or assign different risk levels when analyzing the same evidence.

Even when numerical validation passes, narrative statements may still be inaccurate or unsupported. The V5.1 validator checks selected numerical claims and does not prove that every statement generated by the LLM is correct.

LLM recommendations may also be generic or refer to actions that are not directly established by the supplied evidence. Human analyst review therefore remains necessary.

## Documentation

Detailed project documentation is maintained separately:

- `docs/methodology.md` — KNIME workflow, Python analysis, deterministic event counting, and final pipeline methodology.
- `docs/llm_experiments.md` — Development from V1/V2 through final V5.1 and observed LLM behavior.
- `docs/findings.md` — Evidence, experiment results, limitations, and final findings.

## Conclusion

This project demonstrates that LLMs can assist with translating authentication evidence into readable SOC explanations, but they should not be relied upon as the primary source of factual log analysis.

The experiments showed that **prompt engineering alone did not guarantee factual accuracy**. LLM reliability improved when KNIME structured the authentication data and Python performed deterministic calculations before information was provided to the model.

The final V5.1 pipeline adds another safeguard by comparing selected numerical LLM claims with Python-verified evidence. Automated unit testing further verifies critical deterministic functions used by the project.

The final design therefore follows this principle:

> **KNIME structures the evidence, Python verifies the facts, the LLM explains the findings, automated validation checks selected claims, and a human analyst makes the final judgment.**

This approach treats the LLM as a cybersecurity analysis support tool rather than a replacement for deterministic processing or professional SOC judgment.
