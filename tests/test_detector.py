from src.detector import detect_brute_force


def test_brute_force_detection():
    events = [
        {
            "event_type": "failed_login",
            "username": "admin",
            "ip_address": "192.168.1.50",
        }
        for _ in range(5)
    ]

    alerts = detect_brute_force(events, threshold=5)

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "HIGH"