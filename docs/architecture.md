# Architecture Design

## System Overview

The AI Linux Authentication Log Analyzer is a standalone Python application that reads Linux auth.log files, extracts authentication events, detects suspicious activity, and generates AI-based explanations using Gemini AI.

## Architecture Flow

User uploads auth.log file  
↓  
Log Parser reads each line  
↓  
Event Extractor extracts timestamp, username, IP, and outcome  
↓  
Detection Engine classifies events  
↓  
Gemini AI explains each event  
↓  
Streamlit UI displays results  
↓  
Output report is saved to output folder

## Modules

### 1. Streamlit UI

Handles file upload, displays parsed events, severity, AI explanation, and downloadable output.

### 2. Log Parser

Reads raw auth.log lines and filters authentication-related events.

### 3. Event Extractor

Uses regex to extract timestamp, username, IP address, and login outcome.

### 4. Detection Engine

Detects:

- Successful logins
- Failed logins
- Invalid users
- Sudo usage
- Repeated failures
- Possible brute-force attacks

### 5. AI Explanation Engine

Uses Gemini AI to generate simple SOC-style explanations for each event.

### 6. Report Generator

Exports results as CSV or JSON into the output folder.

## Suggested File Structure

```text
project/
├── src/
│   ├── app.py
│   ├── log_parser.py
│   ├── detector.py
│   ├── ai_explainer.py
│   └── report_generator.py
├── data/
├── output/
├── screenshots/
├── tests/
├── docs/
│   ├── requirements_analysis.md
│   └── architecture.md
├── requirements.txt
└── README.md