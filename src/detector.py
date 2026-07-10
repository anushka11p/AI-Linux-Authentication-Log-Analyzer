from collections import Counter


def detect_brute_force(events: list[dict], threshold: int = 5) -> list[dict]:
    """
    Detect repeated failed login attempts from the same IP and username.
    """

    failed_attempts = Counter()

    for event in events:
        if event.get("event_type") != "failed_login":
            continue

        key = (
            event.get("ip_address"),
            event.get("username"),
        )
        failed_attempts[key] += 1

    alerts = []

    for (ip_address, username), count in failed_attempts.items():
        if count >= threshold:
            alerts.append(
                {
                    "event_type": "possible_brute_force",
                    "ip_address": ip_address,
                    "username": username,
                    "failed_attempts": count,
                    "severity": "HIGH",
                    "description": (
                        f"{count} failed login attempts detected for "
                        f"user '{username}' from IP {ip_address}."
                    ),
                }
            )

    return alerts