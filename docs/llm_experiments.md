# LLM Experiments

## 1. Purpose

This project evaluates whether a locally hosted Large Language Model (LLM) can assist a Security Operations Center (SOC) analyst by converting OpenSSH authentication evidence into a concise and understandable security explanation.

Llama 3.2 was run locally through Ollama.

The experiments were performed in multiple versions because the initial LLM responses contained factual errors, unsupported assumptions, numerical inconsistencies, and formatting problems.

Instead of removing unsuccessful results, they were preserved as part of the project because they demonstrate the limitations of using an LLM directly for cybersecurity log analysis.

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
        ↓
V5
Generalized CSV Analysis
        ↓
V5.1
Verified Evidence + LLM + Numerical Validation
```

The purpose of the progression was not simply to improve the wording of the LLM response. The larger goal was to determine which responsibilities should belong to deterministic tools and which responsibilities could reasonably be assigned to an LLM.

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

The experiment demonstrated that a detailed prompt could improve the structure of the LLM response but could not guarantee factual accuracy.

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
Username:             root
Method:           password

First record: Jan 03 10:07:06
Last record:  Jan 03 10:13:32
Time span:        6 min 26 sec
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

Instead of providing the raw CSV records directly to Llama 3.2, Python first analyzed the records and created structured evidence.

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
Total CSV records:                          50
Ordinary authentication records:            25
Compressed repeat records:                  25

Ordinary events represented:                25
Repeated events represented:               125

Total authentication events represented:   150

Failed authentication events:              150
Successful authentication events:            0
```

Python also verified:

```text
Source IP:              59.63.188.30
Username:                       root
Authentication method:      password
First record:         Jan 03 10:07:06
Last record:          Jan 03 10:13:32
Observed time span:       6 min 26 sec
```

Only structured evidence was supplied to Llama 3.2.

### Observed Results

Version 4.1 produced the strongest experimental response up to that stage.

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

**Conclusion:** The LLM performed better when Python generated a small, structured, verified evidence set and the model was used primarily for explanation.

---

## 6. Version 5 — Generalized CSV Analysis

### Approach

Version 5 expanded the project beyond one hard-coded authentication sample.

The script was modified so that a CSV file could be supplied as an input argument.

For example:

```powershell
python src/llm_explainer_v5.py data/processed/success_authentication_sample.csv
```

This allowed the same general analysis process to be applied to a separate successful-authentication sample exported from KNIME.

### Successful Sample

Python analysis of the 50-record successful-authentication sample identified:

```text
Total CSV records:                         50
Ordinary authentication records:           50
Compressed repeat records:                  0

Total authentication events represented:   50
Successful authentication events:          50
Failed authentication events:               0

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

### Observed LLM Results

The V5 experiments demonstrated another important limitation.

Even though the deterministic Python evidence remained the same, repeated LLM runs could produce different numerical statements.

Examples included incorrect claims about:

- The number of unique source IP addresses.
- The number of unique usernames.
- Security interpretations.
- Risk level.

In one run, the model reported fewer source IPs than Python had verified.

In another run, the model reported an incorrect username count even though the supplied evidence contained the correct value.

The model could also make unsupported interpretations about whether the successful authentication activity was legitimate.

### Finding

V5 demonstrated that generalized input worked, but it also reinforced that supplying verified evidence does not guarantee that the LLM will reproduce every value correctly.

The successful-authentication experiment was especially useful because it showed that the LLM could make factual errors even when analyzing a relatively simple evidence set containing no failed events and no compressed repeat records.

**Conclusion:** The project needed a way to compare selected LLM claims against Python after the LLM generated its response.

---

## 7. Version 5.1 — Automated LLM Output Validation

### Approach

V5.1 is the final experimental version of the project.

The architecture was expanded to:

```text
KNIME
    ↓
Structured CSV
    ↓
Python Deterministic Analysis
    ↓
Verified Evidence
    ↓
Llama 3.2
    ↓
SOC-Style Explanation
    ↓
Python Numerical Validator
    ↓
Human Analyst Review
```

The validator compares selected numerical claims in the LLM response with values already verified by Python.

The selected validation categories are:

```text
Source IP count
Username count
Total authentication events
Successful authentication events
Failed authentication events
```

### Validation Status

Each claim can receive:

```text
PASS
FAIL
NOT CHECKED
```

`PASS` indicates that the numerical claim extracted from the LLM response matches the Python-verified value.

`FAIL` indicates that the extracted LLM claim conflicts with the Python-verified value.

`NOT CHECKED` indicates that a reliable numerical claim could not be extracted from the wording used by the LLM.

The validator intentionally does not assume that a claim is correct when it cannot reliably extract a value.

### Final Successful-Authentication Run

The final V5.1 run used:

```text
data/processed/success_authentication_sample.csv
```

Python verified:

```text
Total CSV records:                         50
Ordinary authentication records:           50
Compressed repeat records:                  0
Total authentication events represented:   50

Failed CSV records:                         0
Successful CSV records:                    50

Failed authentication events:              0
Successful authentication events:         50

Unique source IP addresses:               14
Unique usernames:                          5
Authentication method:              password

Observed time span:
8 days, 11 hours, 21 minutes, 51 seconds
```

The LLM generated all six requested sections:

```text
AUTHENTICATION SUMMARY
TIMELINE
OBSERVED INDICATORS
SECURITY INTERPRETATION
RISK LEVEL
RECOMMENDED SOC ACTIONS
```

It assigned:

```text
RISK LEVEL: MEDIUM
```

The model correctly stated several important values, including:

```text
14 source IPs
5 usernames
50 successful authentication events
0 failed authentication events
```

### Final Validation Result

The V5.1 validator reported:

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
```

The final summary was:

```text
Numerical claims checked: 4
Numerical inconsistencies detected: 0
```

All four numerical claims that could be automatically evaluated matched the deterministic Python evidence.

### NOT CHECKED Finding

The total authentication event count received:

```text
NOT CHECKED
```

This was not treated as a failure.

The LLM expressed the authentication information in wording that the validator could not reliably match to the expected numerical pattern.

This became an important experimental finding because it demonstrates that automated validation also has limitations.

A validator should not claim that an LLM statement is correct when the statement cannot be reliably interpreted.

### Narrative Limitation

The final LLM response was numerically stronger than several earlier runs, but numerical correctness did not guarantee that every narrative statement was ideal.

For example, some recommended SOC actions were general recommendations rather than statements directly established by the supplied authentication evidence.

This demonstrates why the final message from the validator states:

```text
No numerical inconsistencies were detected among the claims
that could be checked automatically.

This does not prove that every narrative statement made by
the LLM is correct.
```

### Finding

V5.1 improved the pipeline by adding a deterministic check after LLM generation.

However, it did not attempt to prove that the entire natural-language response was correct.

**Conclusion:** Automated validation is a useful safeguard, but it supplements rather than replaces human analyst review.

---

## 8. Validator Development Finding

Developing the validator produced an additional finding.

Regular expressions used to extract LLM numerical claims must be carefully limited.

During development, overly broad matching could incorrectly capture numbers from nearby text.

For example, an IP address such as:

```text
137.189.241.248
```

contains several numerical values.

A poorly constrained extraction pattern could mistakenly interpret the final octet:

```text
248
```

as another numerical claim.

The validator was adjusted to use more restrictive matching behavior, and automated tests were added to detect this problem.

This demonstrates that the validation component itself must also be tested rather than automatically assumed to be correct.

---

## 9. Automated Testing

Automated unit tests were created for important deterministic functions.

The tests cover:

- Normal authentication event counting.
- Compressed syslog repeat counting.
- Different repeat values.
- Verified evidence generation.
- CSV record counts.
- Represented authentication event counts.
- Authentication result counts.
- Timeline calculations.
- Correct LLM numerical claims.
- Incorrect LLM numerical claims.
- Protection against false numerical extraction from IP addresses.

The final test suite produced:

```text
Ran 12 tests in 0.018s

OK
```

All 12 tests passed.

The tests do not require an LLM call because they are designed to verify deterministic Python behavior.

This is important because LLM responses can vary, while deterministic functions should produce repeatable results for the same input.

---

## 10. Experiment Comparison

| Version  | Evidence / Method                                   | Major Result                                                                                             |
| -------- | --------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| V1/V2    | Raw authentication logs + prompt engineering        | Useful pattern recognition, but factual and formatting problems remained                                 |
| V3       | Python facts + raw logs                             | Correct facts were supplied, but unsupported LLM claims continued                                        |
| V4       | Structured Python evidence only                     | Major reduction in unsupported factual claims                                                            |
| V4.1     | Structured evidence + deterministic repeat counting | Correctly distinguished 50 CSV records from 150 represented events                                       |
| V5       | Generalized CSV input                               | Allowed testing with different authentication samples but exposed additional LLM numerical inconsistency |
| **V5.1** | **Verified evidence + LLM + numerical validator**   | **Final version; automatically compares selected LLM claims with deterministic Python evidence**         |

The progression showed that increasing prompt complexity was less effective than reducing the amount of factual reasoning assigned to the LLM.

The later experiments also demonstrated that validation should occur **after** LLM generation rather than assuming that providing correct input guarantees correct output.

---

## 11. LLM Variability

Repeated experiments demonstrated that LLM output is not deterministic.

The same or similar evidence could result in differences involving:

```text
numerical claims
risk levels
wording
recommendations
format compliance
security interpretations
```

This is different from deterministic Python processing.

Given the same input and analysis code, deterministic calculations should reproduce the same factual values.

This distinction became one of the main reasons for separating evidence calculation from natural-language explanation.

---

## 12. Key Lessons

### Prompt Engineering Does Not Guarantee Accuracy

Detailed instructions improved model behavior but did not prevent hallucinations or inconsistencies.

### Correct Facts Can Still Be Changed

Version 3 and later experiments demonstrated that an LLM can receive correct Python-calculated facts and still produce conflicting information.

### Raw Evidence Increases LLM Responsibility

When the LLM received more raw evidence, it had greater opportunity to perform its own calculations and introduce unsupported conclusions.

### Deterministic Processing Should Handle Calculations

Python was more appropriate for:

```text
record counting
event counting
timestamp calculations
authentication-result counting
repeat-message processing
source IP counting
username counting
numerical validation
```

These operations can be reproduced and tested.

### Successful Authentication Does Not Prove Legitimacy

The successful-authentication experiment demonstrated the importance of separating authentication results from security conclusions.

A successful authentication event does not by itself establish that the activity was authorized or legitimate.

### LLMs Are Better Used for Explanation

The LLM performed more reliably when its primary responsibility was converting verified evidence into a readable SOC explanation.

### Validation Also Has Limitations

The `NOT CHECKED` result demonstrated that deterministic validation depends on being able to reliably identify a claim in natural-language output.

Automated validation should therefore avoid making assumptions when the wording cannot be reliably interpreted.

### Validators Must Also Be Tested

The IP-address extraction issue demonstrated that validation logic can contain its own errors.

The validator was therefore included in the automated unit-testing process.

### Numerical Accuracy Does Not Guarantee Narrative Accuracy

Even if all automatically checked numbers are correct, an LLM may still generate unsupported interpretations or recommendations.

### Human Review Remains Necessary

Neither the LLM nor the numerical validator replaces analyst judgment.

The final explanation, recommendations, and risk assessment should be reviewed against the underlying evidence.

---

## 13. Final Experimental Architecture

The final V5.1 experimental design is:

```text
OpenSSH Loghub Dataset
        ↓
KNIME Analytics Platform
        ↓
Log Extraction and Structuring
        ↓
Structured CSV Sample
        ↓
Python
        ↓
Deterministic Evidence Verification
        ↓
Llama 3.2 through Ollama
        ↓
SOC-Style Natural-Language Explanation
        ↓
Python Validator
        ↓
Selected Numerical Claim Verification
        ↓
Human Analyst
        ↓
Final Evidence and Security Judgment
```

Each component has a different responsibility.

```text
KNIME
→ Structure and filter authentication evidence.

Python
→ Calculate reproducible factual evidence.

Llama 3.2
→ Explain the verified evidence.

Python Validator
→ Check selected numerical LLM claims.

Human Analyst
→ Review the complete result and make the final judgment.
```

---

## 14. Experimental Conclusion

Testing demonstrated that Llama 3.2 can provide useful natural-language interpretations of OpenSSH authentication activity, but prompt engineering alone does not eliminate hallucinations or inconsistent output.

Even when Python supplied verified statistics, earlier versions demonstrated that the LLM could introduce unsupported values, assumptions, or interpretations.

The experimental progression therefore gradually reduced the amount of factual reasoning assigned to the LLM.

The final V5.1 design follows this principle:

> **KNIME structures the evidence, Python verifies the facts, the LLM explains the findings, automated validation checks selected claims, and a human analyst makes the final judgment.**

The final successful-authentication experiment produced:

```text
4 automatically checked numerical claims
4 PASS
0 FAIL
1 additional claim NOT CHECKED
```

The final deterministic test suite produced:

```text
12 tests
12 passed
```

These results do not demonstrate that LLM output can be trusted without review.

Instead, they demonstrate that combining deterministic preprocessing, constrained LLM use, automated validation, testing, and human review provides stronger safeguards than relying on an LLM to independently calculate and interpret raw authentication evidence.

The final project therefore treats Llama 3.2 as an **analytical explanation tool**, not as the authoritative source of cybersecurity evidence.
