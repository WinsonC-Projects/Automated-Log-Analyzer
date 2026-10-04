# LLM Experiments

## 1. Purpose

This project evaluates whether a locally hosted Large Language Model (LLM) can assist a Security Operations Center (SOC) analyst by converting OpenSSH authentication evidence into a concise and understandable security explanation.

Llama 3.2 was run locally through Ollama.

The experiments were performed in multiple versions because the initial LLM responses contained factual errors, unsupported assumptions, and formatting inconsistencies.

Instead of removing these unsuccessful results, they were preserved as part of the project because they demonstrate the limitations of using an LLM directly for cybersecurity log analysis.

The experimental progression was:

```text
V1/V2
Raw Logs + Prompt Engineering
        ↓
V3
Python-Verified Facts + Raw Logs
        ↓
V4
Structured Python-Verified Evidence
        ↓
V4.1
Expanded Event Counts + Structured Evidence
```

---

## 2. Version 1/2 — Prompt Engineering

### Approach

The first approach provided the selected authentication log records directly to Llama 3.2.

A SOC analysis prompt instructed the model to:

- Summarize authentication activity.
- Create a timeline.
- Identify source IP addresses.
- Identify usernames.
- Identify authentication methods.
- Identify repeated activity.
- Interpret potentially suspicious patterns.
- Assign a risk level.
- Recommend SOC actions.

The prompt was later strengthened with additional requirements designed to prevent unsupported conclusions.

These requirements included instructions to:

- Use only the supplied evidence.
- Avoid inventing information.
- Distinguish observations from interpretations.
- Avoid claiming that an attack succeeded without supporting evidence.
- Recognize `message repeated N times`.
- Avoid modifying timestamps.
- Use cautious wording such as `consistent with` and `may indicate`.

### Observed Results

The model successfully recognized that the logs contained repeated failed authentication activity involving a single source IP and the `root` username.

However, several problems remained.

Observed issues included:

- Incorrect time-span calculations.
- Duplicated or misinterpreted timestamps.
- Inconsistent identification of the authentication method.
- Failure to consistently follow the required six-section format.
- Unsupported assumptions about the source of the activity.
- Unsupported or inaccurate security recommendations.

One experimental response even recommended upgrading to:

```text
sshv3 or sshv4
```

This recommendation was unsupported and technically inaccurate.

### Finding

The experiment demonstrated that a detailed prompt could improve the structure of the LLM's reasoning but could not guarantee factual accuracy.

**Conclusion:** Prompt engineering alone was insufficient for reliable authentication-log analysis.

---

## 3. Version 3 — Python-Verified Facts + Raw Logs

### Approach

Version 3 introduced deterministic Python analysis before the LLM was called.

Python verified:

```text
CSV records:          50
Failed records:       50
Successful records:    0
Source IP:    59.63.188.30
Username:              root
Method:            password
First record: Jan 03 10:07:06
Last record:  Jan 03 10:13:32
Time span:      6 min 26 sec
```

These verified facts were supplied to Llama 3.2 together with the raw authentication records.

The expectation was that explicitly providing verified calculations would prevent the model from creating its own unsupported values.

### Observed Results

Python produced the expected deterministic values.

However, the LLM still introduced unsupported information.

Examples included:

```text
144 failed attempts
```

The model also introduced claims about:

- Source-port ranges.
- Estimated authentication-attempt rates.
- System logging or monitoring behavior.

These claims were not established by the Python-verified evidence provided to the model.

### Finding

Version 3 demonstrated an important limitation.

Providing correct facts to an LLM does not guarantee that the model will use only those facts when it also receives a large amount of raw evidence.

The LLM continued to perform its own interpretation and calculations even when deterministic results had already been supplied.

**Conclusion:** Verified facts alone were not enough while the LLM was still responsible for interpreting raw evidence.

---

## 4. Version 4 — Structured Python-Verified Evidence

### Approach

Version 4 changed the architecture of the experiment.

Instead of providing the raw CSV records to Llama 3.2, Python first analyzed the records and created structured evidence.

The LLM received values such as:

```text
total_csv_records
failed_records
successful_records
source_ip_addresses
usernames
authentication_methods
first_record
last_record
observed_time_span
records_with_repeated_message_notation
evidence_limitations
```

The LLM was explicitly instructed:

```text
Do not recalculate, modify, estimate, or invent values.
```

### Observed Results

Version 4 produced a noticeable improvement.

The model generally:

- Preserved the Python-calculated time span.
- Used the correct source IP.
- Used the correct username.
- Used the correct authentication method.
- Followed the requested six-section SOC format.
- Avoided claiming that unauthorized access succeeded.
- Reduced unsupported factual statements.

However, an important problem remained.

The model could describe the 50 CSV records as 50 authentication attempts without fully accounting for the compressed syslog repeat notation.

### Risk-Level Variation

Repeated testing also revealed that LLM output was not completely deterministic.

Using the same underlying evidence, different runs produced different risk classifications, including:

```text
MEDIUM
```

and:

```text
HIGH
```

The underlying Python evidence had not changed.

### Finding

Version 4 significantly reduced hallucinations, but the experiment demonstrated that an LLM-generated risk level remains an interpretation and can vary between executions.

**Conclusion:** Restricting the LLM to structured evidence improved factual reliability, but deterministic preprocessing still needed improvement.

---

## 5. Version 4.1 — Expanded Authentication Event Counts

### Approach

Version 4.1 addressed the distinction between CSV records and represented authentication events.

Python was modified to detect syslog messages containing:

```text
message repeated N times
```

A regular expression extracts the value of `N`.

The deterministic counting method is:

```text
Normal record = 1 represented authentication event

Compressed "message repeated N times" record
= N represented authentication events
```

For the selected sample, Python calculated:

```text
Total CSV records:                       50
Ordinary authentication records:         25
Compressed repeat records:               25

Ordinary events represented:             25
Repeated events represented:            125

Total authentication events represented: 150

Failed authentication events:            150
Successful authentication events:          0
```

Python also verified:

```text
Source IP:             59.63.188.30
Username:                       root
Authentication method:      password
First record:        Jan 03 10:07:06
Last record:         Jan 03 10:13:32
Observed time span:     6 min 26 sec
```

Only this structured evidence was supplied to Llama 3.2.

### Observed Results

Version 4.1 produced the strongest experimental response.

The model correctly preserved the distinction between:

```text
50 CSV records
```

and:

```text
150 represented authentication events
```

It also correctly described the 150 represented events as consisting of:

```text
25 ordinary events
+
125 repeated events
```

The response:

- Used the correct source IP.
- Used the `root` username.
- Identified `password` as the authentication method.
- Preserved the 6-minute, 26-second observed time span.
- Followed the six requested SOC sections.
- Described the pattern as consistent with possible brute-force activity.
- Avoided claiming that malicious intent had been proven.
- Avoided claiming that unauthorized access was successful.

The model assigned a risk level of:

```text
MEDIUM
```

This value is treated as an LLM interpretation rather than a deterministic finding.

### Finding

Version 4.1 demonstrated that LLM reliability improved when factual calculations were removed from the model's responsibilities.

**Conclusion:** The LLM performed best when Python generated a small, structured, verified evidence set and the model was used primarily for explanation.

---

## 6. Experiment Comparison

| Version | Evidence Given to LLM                                       | Major Result                                                       |
| ------- | ----------------------------------------------------------- | ------------------------------------------------------------------ |
| V1/V2   | Raw authentication logs                                     | Useful pattern recognition but factual and formatting problems     |
| V3      | Python facts + raw logs                                     | Correct facts were available, but unsupported LLM claims continued |
| V4      | Structured Python evidence only                             | Major reduction in unsupported factual claims                      |
| V4.1    | Structured evidence + deterministic repeat-count processing | Strongest separation between factual analysis and LLM explanation  |

The progression showed that increasing prompt complexity was less effective than reducing the amount of factual reasoning assigned to the LLM.

---

## 7. Key Lessons

The experiments produced several important findings.

### Prompt Engineering Does Not Guarantee Accuracy

Detailed instructions improved the model's behavior but did not prevent hallucinations.

### Correct Facts Can Still Be Ignored

Version 3 demonstrated that an LLM can receive correct Python-calculated facts and still introduce conflicting information.

### Deterministic Processing Should Handle Calculations

Python was more appropriate for:

```text
record counting
event counting
timestamp calculations
authentication-result counting
repeat-message processing
```

These operations can be reproduced and validated.

### LLMs Are Better Used for Explanation

The LLM performed more reliably when its primary responsibility was converting verified evidence into a readable SOC explanation.

### LLM Output Still Requires Human Review

Even the strongest experimental version should not be treated as an independent security determination.

The generated explanation and risk level should be reviewed against the evidence by a human analyst.

---

## 8. Experimental Conclusion

Testing demonstrated that Llama 3.2 could provide useful natural-language interpretations of OpenSSH authentication activity, but prompt engineering alone did not eliminate hallucinations.

Even when Python supplied verified statistics, earlier versions of the model introduced unsupported values and assumptions.

The strongest experimental design used:

```text
KNIME
    ↓
Log extraction and structuring

Python
    ↓
Deterministic evidence verification

Llama 3.2
    ↓
Natural-language explanation

Human Analyst
    ↓
Validation and security judgment
```

The results support keeping deterministic log processing responsible for factual calculations while treating LLM output as an **explanatory aid that requires validation before SOC use**.
