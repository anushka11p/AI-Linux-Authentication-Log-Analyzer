# DF-101: AI Linux Authentication Log Analyzer

A Python-based security analysis tool that parses Linux authentication logs, detects suspicious authentication activities using rule-based detection, and generates AI-assisted security explanations. The project is designed to automate authentication log analysis while ensuring that all core detection logic is implemented locally without relying on external SIEM platforms.

---

## Overview

Linux authentication logs (`auth.log`) contain valuable information about user logins, authentication failures, privilege escalation, and potential security incidents. Manually analyzing these logs is time-consuming and requires expertise.

The AI Linux Authentication Log Analyzer automates this process by:

- Parsing Linux authentication logs
- Detecting authentication-related security events
- Identifying suspicious login behavior
- Detecting brute-force attacks
- Tracking privilege escalation attempts
- Generating AI-powered security explanations
- Exporting investigation results

The application follows a hybrid architecture where detection is performed entirely in Python, while Google's Gemini model is used only to generate analyst-friendly explanations for detected events.

---

## Features

- Authentication log parsing
- Successful login detection
- Failed login detection
- Invalid user detection
- Sudo activity detection
- Brute-force attack detection
- Rule-based detection engine
- AI-generated investigation summaries
- Streamlit-based dashboard
- CSV export
- JSON export
- Security metrics dashboard

---

## Technology Stack

### Backend

- Python 3
- Streamlit
- Pandas
- Regular Expressions (Regex)
- python-dotenv

### AI

- Google Gemini API
- google-genai SDK

### Testing

- pytest

---

## Project Structure

```
DF-101-AI-Linux-Auth-Log-Analyzer/
│
├── src/
│   ├── app.py
│   ├── log_parser.py
│   ├── detector.py
│   ├── ai_explainer.py
│   ├── config.py
│   └── utils.py
│
├── data/
│   └── sample_logs/
│
├── output/
│
├── tests/
│
├── requirements.txt
├── README.md
└── .env
```

---

## System Architecture

```
                    Linux auth.log
                           │
                           ▼
                  Log Parsing Engine
                           │
                           ▼
                 Authentication Events
                           │
                           ▼
                Rule-Based Detection Engine
                           │
          ┌────────────────┴────────────────┐
          ▼                                 ▼
 Streamlit Dashboard             Gemini AI Explanation
          │                                 │
          └────────────────┬────────────────┘
                           ▼
                  Security Investigation
                           │
                           ▼
                  CSV / JSON Export
```

---

## Detection Capabilities

The detection engine is implemented completely in Python.

Supported detections include:

- Successful SSH logins
- Failed SSH logins
- Invalid user attempts
- Multiple failed login attempts
- Brute-force attacks
- Sudo privilege escalation
- Authentication anomalies

No external SIEM or log analysis service is used for parsing or event detection.

---

## AI Integration

Artificial Intelligence is used only after the detection engine identifies a security event.

Gemini generates:

- Executive Summary
- Event Severity
- Business Impact
- Possible Cause
- MITRE ATT&CK Mapping
- Recommended Mitigation

The AI model does not participate in log parsing or attack detection.

---

## Installation

Clone the repository.

```bash
git clone https://github.com/anushka11p/AI-Linux-Authentication-Log-Analyzer.git

cd AI-Linux-Authentication-Log-Analyzer
```

Create a virtual environment.

```bash
python3 -m venv venv
```

Activate the environment.

macOS / Linux

```bash
source venv/bin/activate
```

Windows

```powershell
venv\Scripts\activate
```

Install dependencies.

```bash
pip install -r requirements.txt
```

---

## Environment Variables

Create a `.env` file in the project root.

```env
GEMINI_API_KEY=YOUR_API_KEY
```

---

## Running the Application

```bash
streamlit run src/app.py
```

The application will be available at

```
http://localhost:8501
```

---

## Workflow

1. Upload a Linux `auth.log` file.
2. Parse authentication records.
3. Detect security events.
4. Display findings in the dashboard.
5. Generate AI explanations for selected events.
6. Export investigation reports.

---

## Sample Events Detected

- Failed SSH Login
- Successful SSH Login
- Invalid Username Attempt
- Brute Force Detection
- Sudo Privilege Escalation

---

## Security Design

The project intentionally separates detection logic from AI.

- Log parsing is implemented locally.
- Event detection is rule-based.
- AI is used only for explanation.
- Authentication logs are never processed by external security platforms.

This architecture ensures transparency, reproducibility, and deterministic detection.

---

## Future Enhancements

- Real-time log monitoring
- PDF investigation reports
- Interactive filtering
- Timeline visualization
- Additional Linux log support
- Threat intelligence integration
- Email alerting
- Container deployment

---

## Testing

Run the test suite.

```bash
pytest
```

---

## License

This project was developed as part of the DF-101 cybersecurity implementation assignment and is intended for educational and research purposes.

---

## Author

**Anushka Prasad**

Electronics and Computer Engineering  
SRM Institute of Science and Technology

GitHub: https://github.com/anushka11p
