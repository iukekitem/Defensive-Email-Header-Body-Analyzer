# Walkthrough: Defensive Email Header & Body Analyzer

We have successfully built and verified the Defensive Email Header & Body Analyzer in Python. The tool parses raw `.eml` files, runs rule checks for phishing and spoofing vectors, calculates risk scores, and outputs a visually rich CLI dashboard or JSON report.

---

## 🛠️ Changes Implemented

All code files are located in the project directory at `/Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer`:

1. **[requirements.txt](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/requirements.txt)**: Specifies project dependencies, including `rich` for formatting.
2. **[parser.py](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/parser.py)**: Loads raw `.eml` files, decodes complex headers, extracts plain text/HTML body content, reads authentication headers (`Received-SPF`/`Authentication-Results`), and lists attachments.
3. **[rules.py](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/rules.py)**: Performs rule checks and scores the email:
   - *Sender alignment check* (comparing From domain against Return-Path domain).
   - *Security authentication header evaluation* (SPF and DKIM pass/fail status).
   - *Urgency & high-pressure text recognition* (categorized word grouping).
   - *Link vetting* (flagging raw IP addresses or mismatched domains).
   - *Suspicious attachment extensions check* (flagging `.exe`, `.scr`, `.js`, etc.).
4. **[reporter.py](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/reporter.py)**: Formats analysis results into an interactive CLI dashboard (using the `rich` library, with a fallback to standard ANSI sequences if `rich` is missing) or serializes to JSON.
5. **[analyzer.py](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/analyzer.py)**: Entrypoint script connecting the pipeline, supporting CLI arguments (path, `--json`, `--threshold`).
6. **[test_analyzer.py](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/test_analyzer.py)**: Automated verification suite covering 4 threat-scenario emails.
7. **[samples/](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/samples)**:
   - [safe_email.eml](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/samples/safe_email.eml) - Low Risk (Newsletter)
   - [spoofed_sender.eml](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/samples/spoofed_sender.eml) - High Risk (From/Return-Path Mismatch + SPF Fail)
   - [phishing_scam.eml](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/samples/phishing_scam.eml) - High Risk (Urgency language + Raw IP + Lookalike link domain)
   - [malicious_attachment.eml](file:///Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer/samples/malicious_attachment.eml) - Medium Risk (Potential Executable Payload)

---

## 🧪 Verification & Results

We set up a python virtual environment, installed dependencies, and ran our verification tests:

### Test Suite Execution
```bash
./venv/bin/python test_analyzer.py
```

**Output:**
```
============================================================
RUNNING EMAIL ANALYZER TEST SUITE
============================================================
Testing Safe Email...
  PASS: Score: 0, Risk: Low Risk
  Indicators triggered: []
------------------------------------------------------------
Testing Spoofed Sender Email...
  PASS: Score: 15, Risk: High Risk
  Indicators triggered: ['Sender Domain Mismatch', 'SPF Authentication Failure', 'DKIM Verification Failure']
------------------------------------------------------------
Testing Phishing Scam Email...
  PASS: Score: 13, Risk: High Risk
  Indicators triggered: ['Urgent Language Detected', 'Raw IP Address Link', 'Mismatched Link Domain']
------------------------------------------------------------
Testing Malicious Attachment Email...
  PASS: Score: 5, Risk: Medium Risk
  Indicators triggered: ['Suspicious Attachment Detected']
------------------------------------------------------------
ALL TESTS PASSED SUCCESSFULLY!
```

---

## 📸 Sample CLI Dashboard Renderings

### 1. Phishing Email Analysis

Running:
```bash
python analyzer.py samples/phishing_scam.eml
```

Shows the high-risk verdict panel, envelope details, and specific breakdown of indicators and flagged links:

```text
╔══════════════════════════════════════════════════════════════════════════════╗
║ DEFENSIVE EMAIL HEADER & BODY ANALYZER                                       ║
║ File path: samples/phishing_scam.eml                                         ║
╚══════════════════════════════════════════════════════════════════════════════╝
╭────────────────────────────────── Verdict ───────────────────────────────────╮
│ 🔥 HIGH RISK DEVIATION DETECTED  [Score: 13]                                 │
╰──────────────────────────────────────────────────────────────────────────────╯
...
╭───────────────────── Security Indicators Triggered (3) ──────────────────────╮
│ ╭────────────┬───────────────────────────┬──────────┬──────────────────────╮ │
│ │  Severity  │ Indicator                 │   Impact │ Description          │ │
│ ├────────────┼───────────────────────────┼──────────┼──────────────────────┤ │
│ │   Medium   │ Urgent Language Detected  │       +4 │ High-pressure words  │ │
│ │            │                           │          │ found: Immediate ... │ │
│ │    High    │ Raw IP Address Link       │       +5 │ Detected 1 link(s) ...│ │
│ │    High    │ Mismatched Link Domain    │       +4 │ Detected link ...    │ │
│ ╰────────────┴───────────────────────────┴──────────┴──────────────────────╯ │
╰──────────────────────────────────────────────────────────────────────────────╯
```

---

## 📈 Next Steps

> [!TIP]
> To use the tool, you can activate the virtual environment and run the analyzer on any of your own `.eml` files:
> ```bash
> cd /Users/joaochristiansen/.gemini/antigravity/scratch/email_analyzer
> source venv/bin/activate
> python analyzer.py path/to/your/email.eml
> ```
