import time

from google import genai
from google.genai import errors

from config import GEMINI_API_KEY


if not GEMINI_API_KEY:
    raise ValueError(
        "GEMINI_API_KEY is missing. Add it to the .env file in the project root."
    )


client = genai.Client(api_key=GEMINI_API_KEY)

MODEL_NAMES = [
    "gemini-flash-latest",
    "gemini-3.1-flash-lite-preview",
]


def explain_event(event: dict) -> str:
    prompt = f"""
You are a Senior SOC Analyst.

Analyze the following Linux authentication security event.

Event type: {event.get("event_type", "Unknown")}
Timestamp: {event.get("timestamp", "Unknown")}
Username: {event.get("username", "Unknown")}
Source IP: {event.get("ip_address", "Unknown")}
Outcome: {event.get("outcome", "Unknown")}
Failed attempts: {event.get("failed_attempts", "Not provided")}
Description: {event.get("description", "Not provided")}

Return a concise Markdown report with:

## Executive Summary
## Severity
## Why It Matters
## Business Impact
## MITRE ATT&CK Mapping
## Possible Cause
## Recommended Mitigation
"""

    last_error = None

    for model_name in MODEL_NAMES:
        for attempt in range(3):
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                )

                if response.text:
                    return response.text

                raise RuntimeError("Gemini returned an empty response.")

            except errors.ServerError as error:
                last_error = error

                if attempt < 2:
                    time.sleep(2 ** attempt)

            except errors.APIError as error:
                last_error = error
                break

    raise RuntimeError(
        "Gemini is temporarily unavailable after multiple attempts. "
        "Please wait a minute and try again."
    ) from last_error
