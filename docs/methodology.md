# Methodology

## 1. Overview

This project uses a multi-stage methodology to analyze OpenSSH authentication logs and generate Security Operations Center (SOC)-style explanations.

The final methodology separates the project into five responsibilities:

1. **KNIME Analytics Platform** — log extraction, filtering, transformation, and sampling.
2. **Python** — deterministic calculations and evidence verification.
3. **Llama 3.2 through Ollama** — natural-language interpretation of verified evidence.
4. **Python Validation** — comparison of selected LLM numerical claims against verified evidence.
5. **Human Analyst Review** — final review of the LLM explanation and security interpretation.

This separation became an important part of the project because early testing showed that a Large Language Model (LLM) could provide useful security interpretations while also introducing unsupported facts, incorrect calculations, or inconsistent conclusions.

The goal is therefore not to allow the LLM to independently analyze all raw evidence. Instead, KNIME structures the authentication data and Python establishes the factual evidence before the LLM generates an explanation.

The final V5.1 pipeline also performs automated validation of selected numerical claims made by the LLM.

---

## 2. OpenSSH Dataset

The project uses OpenSSH authentication logs obtained from the Loghub dataset.

The original OpenSSH log contained:

```text
655,147 raw log records
```

The raw log data was loaded into KNIME Analytics Platform for preprocessing.

Because the raw data is large, the complete raw log file is stored locally under:

```text
data/raw/
```

The raw dataset is not intended to be committed directly to the GitHub repository.

---

## 3. KNIME Log Processing

### 3.1 Reading the Raw Logs

The OpenSSH log is loaded into KNIME using a Line Reader node.

Each raw log entry is stored in a column named:

```text
Raw_Log
```

This preserves the original log message while additional structured fields are created during processing.

### 3.2 Authentication Filtering

The raw OpenSSH records are divided into failed and successful authentication branches.

The failure branch identifies records containing:

```text
Failed password
```

This produced:

```text
197,587 failed-password records
```

The success branch identifies records containing either:

```text
Accepted password
```

or:

```text
Accepted publickey
```

This produced:

```text
182 accepted authentication records
```

The two branches are assigned authentication results:

```text
FAILURE
SUCCESS
```

The branches are then combined, producing:

```text
197,769 authentication records
```

It is important to note that the failure count specifically represents records matching `Failed password`. It should not automatically be interpreted as every possible type of OpenSSH authentication failure.

---

## 4. Structured Field Extraction

After the authentication branches are combined, KNIME extracts information from the raw log messages.

The resulting structured dataset contains:

```text
Raw_Log
Authentication_Result
Source_IP
Username
Timestamp
Source_Port
Authentication_Method
```

These fields allow authentication activity to be analyzed without relying entirely on the original unstructured log message.

The `Timestamp` field does not contain a year because the supplied OpenSSH log format does not provide one.

---

## 5. Source IP Grouping and Sampling

KNIME groups the structured authentication records by `Source_IP` and counts the number of associated records.

This identified:

```text
1,042 unique source IP addresses
```

The source IP with the largest number of authentication records was:

```text
59.63.188.30
```

with:

```text
28,766 records
```

This IP group was selected as the primary sample for additional Python and LLM analysis.

The first 50 records from this group were exported as:

```text
data/processed/ip_group_59.63.188.30.csv
```

A separate 50-record sample of successful authentication activity was also exported as:

```text
data/processed/success_authentication_sample.csv
```

Using two samples allowed the project to evaluate the analysis pipeline against both failed and successful authentication activity.

---

## 6. Python Deterministic Analysis

Python is used after KNIME preprocessing to calculate facts that should not depend on LLM interpretation.

For the selected 50-record failed-authentication sample, Python verified:

```text
CSV log records:          50
Failed CSV records:       50
Successful CSV records:    0

Source IP:        59.63.188.30
Username:                 root
Method:               password

First record:  Jan 03 10:07:06
Last record:   Jan 03 10:13:32
Time span:         6 min 26 sec
```

For duration calculations, Python temporarily assigns a year to timestamp strings so that they can be converted into datetime values.

The temporary year is used only for relative duration calculations and is not treated as evidence of the actual year in which the authentication events occurred.

Python is responsible for calculations because deterministic processing produces repeatable results and reduces the need for the LLM to perform arithmetic or infer factual values.

---

## 7. Syslog Repeated-Message Analysis

### 7.1 Discovery

During Python analysis, some records were found to contain syslog repetition notation similar to:

```text
message repeated 5 times: [ Failed password for root ... ]
```

This created an important distinction between the number of CSV records and the number of authentication events represented by those records.

Counting every CSV row as exactly one authentication event would therefore underestimate the activity represented in the selected sample.

### 7.2 Deterministic Counting Method

Python uses a regular expression to identify:

```text
message repeated N times
```

For the project's counting method:

```text
Normal record = 1 represented authentication event

"message repeated N times" record
= N represented authentication events
```

The repeat value is extracted directly from the supplied log evidence rather than estimated by the LLM.

### 7.3 Failed-Authentication Sample Results

Within the selected 50-record sample, Python identified:

```text
Ordinary authentication records:           25
Compressed repeat records:                 25

Ordinary events represented:               25
Repeated events represented:              125

Total authentication events represented:  150
```

All compressed records in this sample contained a repeat value of:

```text
5
```

Therefore:

```text
25 ordinary events
+
(25 compressed records × 5 repeated events)
=
150 represented authentication events
```

All 150 represented authentication events were classified as failures based on the processed evidence.

No successful authentication event was present in this selected sample.

---

## 8. LLM Evidence Preparation

The project initially experimented with providing authentication evidence more directly to Llama 3.2.

Testing showed that the model could recognize useful security patterns but could also:

- Recalculate verified values incorrectly.
- Introduce unsupported authentication counts.
- Misinterpret authentication methods.
- Introduce unsupported assumptions.
- Add information that was not present in the evidence.
- Ignore requested report formatting.
- Produce different interpretations between runs.

The methodology was therefore changed so that Python performs factual analysis before the evidence reaches the LLM.

In the later experimental pipeline, Python creates structured verified evidence containing values such as:

```text
CSV record counts
ordinary record counts
compressed repeat counts
represented event counts
authentication results
source IP addresses
usernames
authentication methods
first timestamp
last timestamp
observed time span
counting methodology
evidence limitations
```

The LLM is instructed to explain these values rather than independently calculate them.

This creates a clearer separation between factual evidence and natural-language interpretation.

---

## 9. Local LLM Analysis

Llama 3.2 is run locally using Ollama.

The LLM receives Python-verified evidence and generates a SOC-style explanation using six requested sections:

```text
AUTHENTICATION SUMMARY

TIMELINE

OBSERVED INDICATORS

SECURITY INTERPRETATION

RISK LEVEL

RECOMMENDED SOC ACTIONS
```

The prompt instructs the model to distinguish observations from interpretations.

It is also instructed not to claim that malicious intent, unauthorized access, or a specific attack has been established unless the supplied evidence supports that conclusion.

Running the model locally allows the project to experiment with LLM-assisted analysis without sending the authentication dataset to an external LLM API.

---

## 10. Experimental Development

The LLM portion of the project was developed through multiple experimental stages.

### V1/V2 — Raw Evidence and Prompt Engineering

The early versions relied more heavily on raw authentication evidence and prompt engineering.

The LLM could produce readable security explanations, but it also introduced factual and formatting problems.

This demonstrated that prompt instructions alone were not enough to guarantee accuracy.

### V3 — Python-Verified Facts and Raw Logs

V3 supplied Python-calculated facts together with authentication evidence.

Although this improved the information available to the model, the LLM could still introduce unsupported counts, rates, or interpretations.

### V4 — Structured Verified Evidence

V4 reduced the amount of raw information provided to the LLM and focused on structured Python-verified evidence.

This reduced hallucinations and improved the separation between deterministic facts and LLM interpretation.

### V4.1 — Represented Authentication Event Counting

V4.1 improved the deterministic analysis of compressed syslog messages.

This version clearly distinguished:

```text
CSV records
```

from:

```text
authentication events represented by those records
```

This was important because the primary sample contained 50 CSV records but represented 150 authentication events.

### V5 — Generalized CSV Analysis

V5 generalized the analysis so that the program could accept different KNIME-exported CSV samples.

This allowed the same analysis process to be tested against the successful-authentication sample rather than being limited to the original source-IP sample.

### V5.1 — Final Validation Pipeline

V5.1 is the final project version.

It combines:

```text
KNIME preprocessing
        ↓
Python deterministic analysis
        ↓
Python-verified evidence
        ↓
Llama 3.2 SOC explanation
        ↓
Python numerical validation
        ↓
Human analyst review
```

The purpose of V5.1 is not to assume that the LLM is correct.

Instead, selected numerical statements generated by the model are compared against Python-verified evidence.

---

## 11. Automated LLM Output Validation

### 11.1 Validation Purpose

The final V5.1 pipeline performs automated checks on selected numerical claims contained in the LLM response.

The validator evaluates claims involving:

```text
Source IP count
Username count
Total authentication events
Successful authentication events
Failed authentication events
```

The validator compares an extracted LLM claim with the value already calculated by Python.

### 11.2 Validation Results

A validation result can be:

```text
PASS
FAIL
NOT CHECKED
```

`PASS` means that the extracted LLM value matches the Python-verified value.

`FAIL` means that the extracted LLM value does not match the Python-verified value.

`NOT CHECKED` means that the program could not reliably extract a numerical claim from the wording used by the LLM.

The `NOT CHECKED` result is intentional. The validator does not assume that a statement is correct when it cannot reliably interpret the LLM's wording.

### 11.3 Validation Limitation

Automated numerical validation does not prove that the complete LLM response is correct.

An LLM may produce numerically correct information while still introducing:

- Unsupported interpretations.
- Generic recommendations.
- Incorrect security conclusions.
- Inconsistent risk assessments.
- Statements not directly supported by the supplied evidence.

Human analyst review therefore remains part of the methodology.

---

## 12. Successful-Authentication V5.1 Experiment

The generalized pipeline was tested using:

```text
data/processed/success_authentication_sample.csv
```

Python verified:

```text
Total CSV records:                         50
Ordinary authentication records:           50
Compressed repeat records:                  0

Ordinary events represented:               50
Repeated events represented:                0
Total authentication events represented:   50

Failed CSV records:                         0
Successful CSV records:                    50

Failed authentication events represented:  0
Successful authentication events:          50

Unique source IP addresses:                14
Unique usernames:                           5
Authentication method:               password

First record:             Dec 10 09:32:20
Last record:              Dec 18 20:54:11
Observed time span:       8 days, 11 hours,
                          21 minutes, 51 seconds
```

The five usernames were:

```text
fztu
jmzhu
curi
zachary
suyuxin
```

The LLM generated all six requested SOC sections during the final run.

The automated validator reported:

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

The total authentication event claim received `NOT CHECKED` because the LLM did not express the value using wording that the validator could reliably extract.

This result demonstrates both the usefulness and limitation of deterministic LLM-output validation.

---

## 13. Automated Testing

Automated unit tests were added to verify important deterministic parts of the project.

The tests evaluate:

- Normal authentication event counting.
- Syslog repeat-message counting.
- Different repeat values.
- CSV record counts.
- Ordinary and compressed record counts.
- Represented authentication event counts.
- Failed authentication calculations.
- Source information.
- Timeline calculations.
- Correct LLM numerical claims.
- Incorrect LLM numerical claims.
- Protection against false numerical extraction.

One validation test specifically checks that an IP address such as:

```text
137.189.241.248
```

is not incorrectly interpreted as a username-count claim because of the final octet `248`.

This test was added after experimentation demonstrated that overly broad regular-expression matching could incorrectly capture numbers from nearby text.

The final automated test suite produced:

```text
Ran 12 tests in 0.018s

OK
```

The unit tests do not require an LLM call. They test deterministic Python behavior so the results can be reproduced consistently.

---

## 14. Evidence Interpretation

### 14.1 Failed-Authentication Sample

The primary sample demonstrates repeated failed password authentication activity involving:

```text
Source IP:             59.63.188.30
Username:                      root
Authentication method:     password
```

The activity occurs within an observed period of:

```text
6 minutes 26 seconds
```

The repeated failures may be described as **consistent with possible brute-force authentication activity**.

However, the supplied log evidence alone does not establish the identity or intent of the source.

The selected sample also does not establish that unauthorized access was successful.

### 14.2 Successful-Authentication Sample

The successful-authentication sample contains 50 represented successful authentication events involving 14 source IP addresses and five usernames.

The supplied evidence confirms successful password authentication events within the selected sample.

However, successful authentication does not by itself establish that the activity was legitimate or authorized.

The logs also do not establish the identity or intent of the source IP addresses.

### 14.3 Observation vs. Interpretation

For this reason, the project distinguishes between:

**Observation** — information directly supported by the processed evidence.

**Interpretation** — a security explanation or assessment based on the observed evidence.

Python is primarily responsible for observations that can be deterministically calculated.

The LLM assists with interpretation and explanation, while the human analyst remains responsible for reviewing the final result.

---

## 15. Methodology Limitations

The final methodology has several limitations:

- The LLM experiments use selected authentication samples rather than the complete dataset.
- The timestamps in the supplied dataset do not contain a year.
- The failure branch specifically identifies `Failed password` records and should not be interpreted as every possible OpenSSH authentication failure.
- Repeated-event calculations depend on the repeat notation contained in the supplied syslog records.
- The supplied logs do not establish the identity or intent of a source IP.
- Successful authentication does not by itself prove that an event was legitimate or authorized.
- No external threat intelligence is currently used.
- LLM responses can vary between executions.
- LLM-generated risk levels are interpretations rather than deterministic evidence.
- LLM recommendations may contain generic statements that are not directly supported by the supplied evidence.
- Numerical validation only checks selected claims that can be reliably extracted.
- A `PASS` result does not prove that every narrative statement in an LLM response is correct.
- A `NOT CHECKED` result does not mean that a statement is correct or incorrect; it means that the validator could not reliably evaluate the claim.
- Human analyst review remains necessary.

These limitations are important because the project is intended to evaluate how an LLM can assist cybersecurity analysis, not demonstrate that an LLM can replace deterministic tools or professional judgment.

---

## 16. Final Methodology

The final project follows this process:

```text
OpenSSH Loghub Dataset
        ↓
KNIME Analytics Platform
        ↓
Filter and structure authentication evidence
        ↓
Export selected CSV samples
        ↓
Python
        ↓
Calculate and verify deterministic evidence
        ↓
Llama 3.2 through Ollama
        ↓
Generate SOC-style explanation
        ↓
Python Validator
        ↓
Compare selected LLM claims with verified evidence
        ↓
Human Analyst
        ↓
Review evidence, interpretation, and recommendations
```

The methodology can be summarized as:

> **KNIME structures the evidence, Python verifies the facts, the LLM explains the findings, automated validation checks selected claims, and a human analyst makes the final judgment.**

This approach does not assume that an LLM can replace traditional log processing or analyst judgment.

Instead, the project demonstrates how an LLM can function as an **explanation and analytical support layer** after cybersecurity evidence has already been structured and deterministically analyzed.

The experimental progression also demonstrates an important finding: improving the prompt alone does not guarantee factual accuracy. Greater reliability was achieved by reducing the factual responsibilities assigned to the LLM and increasing the amount of deterministic processing performed by Python.

The final V5.1 methodology therefore treats the LLM as a supporting component of the analysis pipeline rather than the authoritative source of cybersecurity evidence.
