# Methodology

## 1. Overview

This project uses a multi-stage methodology to analyze OpenSSH authentication logs and generate Security Operations Center (SOC)-style explanations.

The methodology separates the project into three primary responsibilities:

1. **KNIME Analytics Platform** — log extraction, filtering, transformation, and sampling.
2. **Python** — deterministic calculations and evidence verification.
3. **Llama 3.2 through Ollama** — natural-language interpretation of verified evidence.

This separation became an important part of the project because early testing showed that a Large Language Model (LLM) could provide useful security interpretations while also introducing unsupported facts or calculations.

The goal is therefore not to allow the LLM to independently analyze all raw evidence. Instead, KNIME and Python establish the factual evidence before the LLM generates an explanation.

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

These fields allow the authentication activity to be analyzed without relying entirely on the original unstructured log message.

The `Timestamp` field does not contain a year because the supplied OpenSSH log format does not provide one.

---

## 5. Source IP Grouping

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

A separate sample of successful authentication records was exported as:

```text
data/processed/success_authentication_sample.csv
```

The successful-authentication sample is preserved for comparison and future analysis.

---

## 6. Python Deterministic Analysis

Python is used after KNIME preprocessing to calculate facts that should not depend on LLM interpretation.

For the selected 50-record sample, Python verified:

```text
CSV log records:          50
Failed CSV records:       50
Successful CSV records:    0

Source IP:       59.63.188.30
Username:                 root
Method:               password

First record:  Jan 03 10:07:06
Last record:   Jan 03 10:13:32
Time span:       6 min 26 sec
```

For duration calculations, Python temporarily assigns a year to the timestamp strings so that they can be converted into datetime values. The temporary year is used only for calculation and is not treated as evidence of the actual year in which the events occurred.

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

### 7.3 Sample Results

Within the selected 50-record sample, Python identified:

```text
Ordinary authentication records:          25
Compressed repeat records:                25

Ordinary events represented:              25
Repeated events represented:             125

Total authentication events represented: 150
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

The project initially experimented with providing raw authentication evidence directly to Llama 3.2.

Testing showed that the model could recognize useful security patterns but could also:

- Recalculate verified values incorrectly.
- Introduce unsupported authentication counts.
- Misinterpret authentication methods.
- Introduce unsupported assumptions.
- Ignore requested report formatting.

The methodology was therefore changed so that Python performs factual analysis before the evidence reaches the LLM.

In the later experimental pipeline, Python creates structured verified evidence containing values such as:

```text
record counts
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

---

## 9. Local LLM Analysis

Llama 3.2 is run locally using Ollama.

The LLM receives Python-verified evidence and generates a SOC-style explanation using six sections:

```text
AUTHENTICATION SUMMARY

TIMELINE

OBSERVED INDICATORS

SECURITY INTERPRETATION

RISK LEVEL

RECOMMENDED SOC ACTIONS
```

The prompt instructs the model to distinguish observations from interpretations and avoid claiming that malicious intent or successful unauthorized access has been established when the evidence does not support those conclusions.

Running the model locally also allows the project to experiment with LLM-assisted analysis without sending the authentication dataset to an external LLM API.

---

## 10. Evidence Interpretation

The analyzed sample demonstrates repeated failed password authentication activity involving:

```text
Source IP: 59.63.188.30
Username: root
Authentication method: password
```

The activity occurs within an observed period of approximately:

```text
6 minutes 26 seconds
```

The repeated failures may be described as **consistent with possible brute-force authentication activity**.

However, the log evidence alone does not establish the identity or intent of the source. The selected sample also does not establish that unauthorized access was successful.

For this reason, the project distinguishes between:

**Observation** — information directly supported by the processed evidence.

**Interpretation** — a security explanation or assessment based on the observed evidence.

---

## 11. Methodology Limitations

The methodology currently has several limitations:

- The primary LLM experiment uses a selected 50-record sample rather than the complete dataset.
- The timestamps do not contain a year.
- The failure branch specifically identifies `Failed password` records and should not be interpreted as every possible OpenSSH failure type.
- The repeated-event calculation depends on the repeat notation contained in the supplied syslog records.
- The analyzed sample does not establish the identity or intent of the source IP.
- No external threat intelligence is currently used.
- LLM responses can vary between executions.
- LLM-generated risk levels remain interpretations rather than deterministic evidence.
- The successful-authentication sample has been exported but has not yet undergone the same complete V4.1 experimental analysis.

---

## 12. Methodology Summary

The project follows the principle:

```text
KNIME
    ↓
Structure the evidence

Python
    ↓
Verify and calculate the evidence

LLM
    ↓
Explain the verified evidence

Human Analyst
    ↓
Review and validate the interpretation
```

This approach does not assume that an LLM can replace traditional log processing or analyst judgment.

Instead, the project investigates how an LLM can function as an **explanation layer** after factual cybersecurity evidence has already been processed and verified.
