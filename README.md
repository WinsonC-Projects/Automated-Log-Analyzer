# Automated Log Analyzer

A Python-based tool for analyzing authorized system logs and identifying unusual or suspicious activity.

## Project Description

This graduate research project will develop a basic automated log analyzer. The analyzer will read a selected dataset from LogHub, organize log events, and identify unusual patterns using documented detection rules.

The project combines cybersecurity, digital forensics, Python programming, and data analysis.

## Research Questions

1. How effectively can a Python-based automated log analyzer parse and organize events from a selected LogHub system-log dataset?

2. How accurately can the analyzer identify unusual log-event patterns using documented detection rules?

## Project Goals

The goals of this project are to:

- Research cybersecurity log management and automated log analysis.
- Select and document one LogHub dataset.
- Build a Python program that reads and processes log files.
- Extract useful information from each log event.
- Identify unusual or suspicious patterns.
- Generate a clear analysis report.
- Test the analyzer using safe and authorized data.
- Document the project's results and limitations.

## Planned Features

The initial version of the analyzer may:

- Read a selected system-log file.
- Parse dates, times, event types, usernames, and source addresses when available.
- Count and organize log events.
- Detect repeated or unusual events.
- Assign a basic severity level.
- Export results to a CSV or text report.
- Run from the command line.

The final features may change as the project develops.

## Dataset

The project will use a selected dataset from LogHub:

https://github.com/logpai/loghub

The exact dataset and file will be documented after reviewing the available LogHub data.

Raw datasets will not be uploaded to this repository unless their usage conditions permit redistribution. Sensitive information, credentials, tokens, and unauthorized institutional data will not be included.

## Research Process

The project will follow these general steps:

1. Review research about cybersecurity log management and log analysis.
2. Select and document the log dataset.
3. Study the log format and identify important fields.
4. Create the initial Python log parser.
5. Add detection rules.
6. Generate analysis reports.
7. Test the analyzer.
8. Review the results.
9. Revise the project based on feedback.
10. Complete the final paper and presentation.

## Evaluation

The analyzer will be evaluated based on:

- Whether it correctly reads the selected log format.
- Whether it extracts important event information.
- How accurately it identifies unusual events.
- The number of false positives.
- The number of missed events.
- Processing time.
- Clarity of the generated report.
- Reproducibility of the results.

## Limitations

The initial version may have the following limitations:

- It may support only one type of log.
- It may use basic rule-based detection.
- It may produce false-positive results.
- It may miss some types of suspicious activity.
- The selected dataset may not contain labels for every event.
- The analyzer will not replace a cybersecurity professional.

## Tools

The project may use:

- Python.
- Visual Studio Code.
- GitHub Desktop.
- GitHub.
- A Linux environment or virtual machine.
- Python libraries for data processing and testing.
- Google Scholar for reference management.

## Repository Structure

```text
automated-log-analyzer/
├── README.md
├── .gitignore
├── requirements.txt
├── src/
├── tests/
├── data/
├── reports/
├── research/
└── slides/
```

## Data Safety

Testing will use public, synthetic, sanitized, or otherwise authorized data.

This project will not test:

- The College network.
- An employer's network.
- Unauthorized internet systems.
- Systems without written permission.

## Project Status

The project is currently in the planning and setup phase.

Current activities include:

- Creating the GitHub repository.
- Finalizing the project scope.
- Selecting the LogHub dataset.
- Reviewing research sources.
- Planning the analyzer and testing process.

## AI-Use Statement

AI tools may be used for brainstorming, organization, editing, and troubleshooting. Any AI assistance will be disclosed in the related assignment or project submission.

All code, sources, and written work will be reviewed and explained by the researcher.

## Author

Graduate student researcher in cybersecurity and digital forensics.
