## LogAnalyzer – Adaptive Log Analysis & Anomaly Detection CLI

LogAnalyzer is a Python-based command-line tool that analyzes real-world log files,
builds historical baselines, and detects anomalous error spikes using
explainable, rule-based logic.

This project is designed to simulate how production monitoring systems work,
using real Apache access logs and stateful analysis.


## Features

- Supports real-world Apache HTTP access logs
- Normalizes multiple log formats into a unified structure
- Maintains persistent historical state across runs
- Detects anomalies using historical baselines
- Generates explainable alerts (no black-box ML)
- CLI-based interface (automation & deployment friendly)

##  Project Structure

LogAnalyzer/
├── src/
│ └── main.py
├── logs/
│ └── apache_access.log
├── state/
│ └── system_state.json
├── README.md
└── .gitignore
└──__init__.py


##  How It Works

1. Reads raw log files
2. Parses and normalizes log entries
3. Performs per-run analysis (levels, services, timestamps)
4. Loads historical state from disk
5. Detects anomalies by comparing current behavior to historical averages
6. Updates state for future runs
7. Outputs a human-readable system summary


## Usage

### Basic analysis

```bash
python src/main.py analyze --log logs/apache_access.log
python src/main.py analyze --log logs/apache_access.log --threshold 1.5

Anomaly Detection Logic
An anomaly is triggered when:

## current_errors > historical_average × threshold 

This avoids false positives and ensures alerts fire only on meaningful deviations.


## Example Output:

ANOMALY ALERTS
Service: web_server
Current Errors: 8
Historical Avg: 3.0
Severity: HIGH


## Why This Project Matters

This project demonstrates:

Real-world log processing
Stateful analytics
Time-based reasoning
Production-style CLI design
Explainable anomaly detection

It is intentionally built without ML to focus on correctness,
interpretability, and engineering fundamentals.

## Future Improvements

Real-time (continuous) monitoring mode

Multi-service inference from URL paths

SQLite-based state storage

Alert export (Slack / Email)

## License
Personal learning project.
