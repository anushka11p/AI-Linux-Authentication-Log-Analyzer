import re
from typing import Optional


def parse_log_line(line: str) -> Optional[dict]:
    """
    Parse a Linux auth.log line and return a structured event.
    Returns None when the line is not a supported authentication event.
    """

    timestamp_match = re.match(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})", line)
    timestamp = timestamp_match.group(1) if timestamp_match else None

    failed_match = re.search(
        r"Failed password for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+)",
        line,
    )
    if failed_match:
        return {
            "timestamp": timestamp,
            "event_type": "failed_login",
            "username": failed_match.group(1),
            "ip_address": failed_match.group(2),
            "outcome": "failure",
            "raw_log": line.strip(),
        }

    success_match = re.search(
        r"Accepted (?:password|publickey) for (\S+) from ([0-9a-fA-F:.]+)",
        line,
    )
    if success_match:
        return {
            "timestamp": timestamp,
            "event_type": "successful_login",
            "username": success_match.group(1),
            "ip_address": success_match.group(2),
            "outcome": "success",
            "raw_log": line.strip(),
        }

    invalid_match = re.search(
        r"Invalid user (\S+) from ([0-9a-fA-F:.]+)",
        line,
        re.IGNORECASE,
    )
    if invalid_match:
        return {
            "timestamp": timestamp,
            "event_type": "invalid_user",
            "username": invalid_match.group(1),
            "ip_address": invalid_match.group(2),
            "outcome": "failure",
            "raw_log": line.strip(),
        }

    sudo_match = re.search(r"sudo:\s+(\S+)\s+:", line)
    if sudo_match:
        return {
            "timestamp": timestamp,
            "event_type": "sudo_usage",
            "username": sudo_match.group(1),
            "ip_address": None,
            "outcome": "activity",
            "raw_log": line.strip(),
        }

    return None