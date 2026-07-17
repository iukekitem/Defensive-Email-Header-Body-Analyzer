# Implementation Plan - Defensive Email Header & Body Analyzer (Python)

This project implements a security-oriented command-line tool that programmatically inspects raw email (`.eml`) files, evaluates them against security rules (sender mismatch, urgency words, suspicious URLs, authentication status, and attachments), and outputs a structured risk assessment report (in both terminal dashboard and JSON formats).

We will create a self-contained python project directory at `/Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer` and recommend the user set it as their active workspace.

## Proposed System Architecture

The tool is split into modular components for clarity and maintenance:

1. **Parser (`parser.py`)**: Uses Python's standard `email` module to read `.eml` files, extract body text (plain & HTML), parse headers (e.g., `From`, `Return-Path`, `Received-SPF`, `Authentication-Results`), and extract attachments.
2. **Rules Engine (`rules.py`)**: Analyzes the parsed email data for key indicators of compromise (IoCs) and phishing signals:
   - **Sender Domain Mismatch**: Comparing domain of `From` header with domain of `Return-Path`.
   - **Authentication Status Check**: Parsing SPF and DKIM verification results from headers like `Received-SPF` or `Authentication-Results`.
   - **Urgency Detection**: Scanning subject line and body text for high-pressure words (e.g. "urgent", "immediate action", "suspended", "verify account").
   - **Link Verification**:
     - Extracting URLs from the HTML and plain-text body.
     - Detecting raw IP address URLs (e.g., `http://192.168.1.50/`).
     - Comparing link domains with the sender's claimed domain to check for mismatch.
     - Lookalike/typosquatting check (optional basic distance comparison).
   - **Suspicious Attachment Check**: Identifying extensions associated with malware delivery (e.g. `.exe`, `.scr`, `.zip`, `.js`, `.vbs`).
3. **Scoring Engine (`rules.py` / `analyzer.py`)**: Computes a weighted score based on active indicators:
   - Sender mismatch: +5 pts
   - Return-path mismatch: +4 pts
   - SPF/DKIM fail/none: +3 pts (if configured to check auth)
   - Raw IP address in link: +5 pts
   - Mismatched domain link: +4 pts
   - Urgency keywords: +2 pts per match (cap at +6 pts)
   - Malicious attachment extension: +5 pts
4. **Reporter (`reporter.py`)**: Outputs results:
   - CLI Dashboard: A colored terminal report showing summary, indicators triggered, extracted links, and risk level.
   - JSON output: A structured dictionary representation of the assessment.
5. **Main Entrypoint (`analyzer.py`)**: Orchestrates the parse-analyze-report pipeline.

---

## User Review Required

### Dependencies
We can build this tool using **zero third-party dependencies** (relying completely on Python's built-in modules `email`, `re`, `urllib.parse`, `json`, `argparse`, etc.).
However, if we want a **premium-looking terminal dashboard** with tables, status bars, and vibrant colors, we could add `rich` to `requirements.txt`.
> [!NOTE]
> To keep installation simple and instant, we propose using standard ANSI color codes and clean terminal layouts, but we will write it with a design that degrades gracefully or optionally uses `rich`. Let's design a clean custom CLI formatter using ANSI colors that looks outstanding without needing external packages, or let's use `rich` if you prefer it.

### Risk Thresholds
We define three risk categories:
* **Low Risk** (Score 0-2): Clean/Safe
* **Medium Risk** (Score 3-6): Suspicious (e.g., urgency keyword or mild mismatch)
* **High Risk** (Score >= 7): Danger/Phishing (e.g., sender mismatch + urgency, or raw IP links)

---

## Proposed Changes

We will create a directory `/Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer` containing:

### [NEW] [analyzer.py](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/analyzer.py)
The CLI entry point. Implements argument parsing (input eml path, output format json/text, verbose mode) and runs the pipeline.

### [NEW] [parser.py](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/parser.py)
Handles parsing of email files:
- Parsing metadata (`From`, `To`, `Subject`, `Date`, `Return-Path`, `Message-ID`).
- Extracting plain text and HTML bodies.
- Parsing authentication headers (`Received-SPF`, `Authentication-Results`).
- Detecting and listing attachment names/extensions.

### [NEW] [rules.py](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/rules.py)
Defines the `Indicator` rules, scoring weights, and performs the analysis. Returns a detailed structured dictionary of findings.

### [NEW] [reporter.py](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/reporter.py)
Generates the output:
- Generates JSON to stdout or a file.
- Prints a polished terminal dashboard with visual threat levels (GREEN for Low, YELLOW for Medium, RED for High), details of each triggered rule, and a breakdown of findings.

### [NEW] [samples/](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/samples)
We will create a `samples/` directory with multiple `.eml` test files:
1. [safe_email.eml](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/samples/safe_email.eml): Safe newsletter or personal communication (Low Risk).
2. [spoofed_sender.eml](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/samples/spoofed_sender.eml): Discrepancy between From domain and Return-Path (Medium Risk).
3. [phishing_scam.eml](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/samples/phishing_scam.eml): Urgency words, mismatched domain links, and raw IP address link (High Risk).
4. [malicious_attachment.eml](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/samples/malicious_attachment.eml): Suspicious executable attachment (High Risk).

### [NEW] [requirements.txt](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/requirements.txt)
Empty if zero-dependency, or lists `rich` if we decide to use it. We will write code that uses standard python but optionally utilizes `rich` if installed, or we can just include `rich` to guarantee a beautiful dashboard. Let's list `rich` for the best visual experience.

### [NEW] [README.md](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/README.md)
Project documentation explaining execution, scoring, design, and examples.

---

## Verification Plan

### Automated Tests
We will write a test runner `test_analyzer.py` that executes the analyzer against the sample emails and asserts that:
1. `safe_email.eml` receives a "Low Risk" rating.
2. `spoofed_sender.eml` receives a "Medium Risk" rating (or High depending on scoring).
3. `phishing_scam.eml` receives a "High Risk" rating.
4. `malicious_attachment.eml` receives a "High Risk" rating.

### Manual Verification
We will run the command:
```bash
python analyzer.py samples/phishing_scam.eml
python analyzer.py samples/phishing_scam.eml --json
```
And check that the command-line dashboard and JSON output look correct, clean, and provide clear security insights.
