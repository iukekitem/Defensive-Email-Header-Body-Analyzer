# Defensive Email Header & Body Analyzer (Python)

A modular, rules-based cybersecurity tool that programmatically inspects raw email files (`.eml`), parses key metadata and headers, evaluates security flags, and generates a structured risk assessment report.

## Features

1. **Email Parsing**: Ingests `.eml` files to extract envelope metadata, message headers, body (plain text & HTML), and attachments.
2. **Analysis Rules Engine**:
   - **Sender Domain Alignment**: Verifies if the domain in the `From` header aligns with the domain in the `Return-Path`.
   - **Urgency Detection**: Scans email subject and body for high-pressure words.
   - **Link Verification**: Checks links for raw IP addresses or domains mismatched with the sender's domain.
   - **Email Authentication (SPF/DKIM)**: Checks security headers like `Received-SPF` and `Authentication-Results` for pass/fail.
   - **Suspicious Attachment Check**: Flags extensions matching known malicious execution types (e.g., `.exe`, `.scr`, `.zip`, `.js`).
3. **Risk Scoring**: Weighted vulnerability scoring with customizable thresholds.
4. **Flexible Output**: Generates a visually clean terminal dashboard or a machine-readable JSON report.

## Installation

This tool supports standard ANSI-colored terminal reporting natively. For an enhanced, rich visual dashboard, install the requirements:

```bash
pip install -r requirements.txt
```

## Usage

Analyze an email file and output the terminal dashboard:
```bash
python analyzer.py samples/phishing_scam.eml
```

Analyze an email file and output a JSON report:
```bash
python analyzer.py samples/phishing_scam.eml --json
```

Specify a custom risk threshold:
```bash
python analyzer.py samples/phishing_scam.eml --threshold 5
```
