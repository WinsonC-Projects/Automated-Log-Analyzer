# Findings

## 1. Overview

This document summarizes the primary findings from the OpenSSH authentication log analysis.

The findings are based on authentication records processed in KNIME Analytics Platform and verified using deterministic Python analysis.

The primary sample contains the first 50 processed authentication records associated with source IP address:

```text
59.63.188.30
```

The purpose of this analysis is to describe what is supported by the available evidence while separating direct observations from security interpretations.

---

## 2. Dataset Findings

The original OpenSSH dataset contained:

```text
655,147 raw log records
```

KNIME processing identified:

```text
Failed password records:                   197,587
Accepted password/publickey records:           182
Combined authentication records:           197,769
Unique source IP addresses:                  1,042
```

The most active source IP in the processed authentication records was:

```text
59.63.188.30
```

This source IP was associated with:

```text
28,766 authentication log records
```

The first 50 records from this source IP group were selected for the primary Python and LLM experiments.

---

## 3. Primary Sample Findings

Python verified the following information for the selected sample:

| Finding                | Result               |
| ---------------------- | -------------------- |
| CSV log records        | 50                   |
| Failed CSV records     | 50                   |
| Successful CSV records | 0                    |
| Source IP              | `59.63.188.30`       |
| Username               | `root`               |
| Authentication method  | `password`           |
| First record           | `Jan 03 10:07:06`    |
| Last record            | `Jan 03 10:13:32`    |
| Observed time span     | 6 minutes 26 seconds |

The selected sample therefore contains repeated failed password authentication activity involving the `root` account from the same source IP.

---

## 4. Syslog Repeat Finding

An important finding was that the number of CSV records did not equal the number of authentication events represented in the logs.

Within the 50-record sample:

```text
Ordinary authentication records:          25
Compressed repeat records:                25
```

The compressed records contained syslog notation similar to:

```text
message repeated 5 times: [ Failed password ... ]
```

All 25 compressed records in the analyzed sample contained a repeat value of five.

Using the project's deterministic counting method:

```text
Ordinary events represented:
25 × 1 = 25

Repeated events represented:
25 × 5 = 125

Total represented authentication events:
25 + 125 = 150
```

Therefore, the 50 CSV records represent:

```text
150 failed authentication events
```

No successful authentication event was identified within the selected sample.

---

## 5. Timeline Finding

The selected activity begins at:

```text
Jan 03 10:07:06
```

and ends at:

```text
Jan 03 10:13:32
```

This produces an observed time span of:

```text
6 minutes 26 seconds
```

During this period, the evidence shows repeated failed password authentication activity involving:

```text
Source IP:             59.63.188.30
Username:                       root
Authentication method:      password
```

The source ports vary across the authentication records.

---

## 6. Observed Indicators

The evidence directly supports the following observations:

- Repeated failed password authentication activity occurred.
- The analyzed records involve the same source IP address.
- The analyzed records target the `root` username.
- The authentication method is `password`.
- The sample contains 50 CSV records.
- Twenty-five records contain compressed syslog repeat notation.
- The 50 records represent 150 authentication events under the project's counting method.
- All 150 represented authentication events are failures.
- No successful authentication event appears in the selected sample.
- The selected activity spans 6 minutes and 26 seconds.

These statements are treated as observations because they are derived from the processed log evidence and deterministic Python analysis.

---

## 7. Security Interpretation

The concentration of repeated failed password authentication activity against the `root` account from one source IP within a short period is **consistent with possible brute-force authentication activity**.

However, the evidence does not establish the identity or intent of the system or individual responsible for the authentication activity.

The evidence also does not establish that unauthorized access was successful.

Therefore, the activity can be identified as potentially suspicious and worthy of investigation without claiming that a confirmed compromise occurred.

---

## 8. LLM Finding

The project also found that Llama 3.2 was more reliable when explaining structured Python-verified evidence than when analyzing raw authentication records directly.

Earlier experiments introduced unsupported counts, calculations, and assumptions.

The strongest experimental version, V4.1, preserved the major Python-verified findings, including:

```text
50 CSV records
150 represented authentication events
150 failed authentication events
0 successful authentication events
Source IP 59.63.188.30
Username root
Authentication method password
6 minute 26 second observed time span
```

This supports using the LLM primarily as an explanation layer rather than as the source of deterministic security calculations.

---

## 9. What Cannot Be Concluded

The supplied evidence does not establish:

- The identity of the person or system responsible for the source IP activity.
- The intent behind the authentication attempts.
- Whether the source IP is known to be malicious.
- Whether successful unauthorized access occurred outside the selected sample.
- Whether other authentication methods or accounts were targeted outside the selected evidence.
- Whether the same activity continued before or after the selected 50-record sample.

These limitations are important because suspicious authentication activity should not automatically be described as a confirmed attack or compromise without supporting evidence.

---

## 10. Final Finding

The primary analysis identified a concentrated sequence of failed password authentication activity targeting the `root` account from source IP `59.63.188.30`.

The selected 50 CSV records represent **150 failed authentication events** under the project's syslog repeat-counting method and occur within an observed period of **6 minutes and 26 seconds**.

The activity is **consistent with possible brute-force behavior**, but the available evidence does not establish malicious intent or successful unauthorized access.

The project also demonstrates that combining **KNIME for preprocessing, Python for deterministic evidence analysis, and an LLM for constrained explanation** produces more reliable results than relying on the LLM to independently calculate and interpret raw authentication evidence.
