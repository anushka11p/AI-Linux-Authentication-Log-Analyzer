# DF-101 – AI Linux Authentication Log Analyzer

## Requirement Analysis

The project analyzes Linux authentication logs such as auth.log and helps SOC analysts understand login-related security events.

## Problem

SOC analysts manually inspect authentication logs to identify failed logins, successful logins, invalid users, sudo usage, and brute-force attempts. This is time-consuming and may miss repeated suspicious behavior.

## Input

Linux auth.log file containing SSH, sudo, and authentication events.

## Data to Extract

- Timestamp
- Username
- Source IP address
- Authentication outcome
- Event type
- Severity

## Events to Detect

- Successful SSH login
- Failed SSH login
- Invalid user login attempt
- Repeated failed login attempts
- Possible brute-force attack
- Sudo command usage

## AI Output

For each detected event, Gemini AI should explain:

- What happened
- Why it matters
- Severity
- Business impact
- Mitigation steps

## Users

- SOC analysts
- Cybersecurity engineers
- Students learning log analysis

## Expected Output

The application should display parsed events in a clean Streamlit UI and generate an output report in CSV or JSON format.

## Acceptance Criteria

- Reads auth.log file
- Extracts key fields correctly
- Detects suspicious authentication activity
- Generates AI explanations
- Provides clean UI
- Includes documentation and testing evidence