from src.log_parser import parse_log_line


def test_failed_login_parsing():
    line = (
        "Jul 10 10:15:22 server sshd[1234]: "
        "Failed password for admin from 192.168.1.50 port 55221 ssh2"
    )

    event = parse_log_line(line)

    assert event is not None
    assert event["event_type"] == "failed_login"
    assert event["username"] == "admin"
    assert event["ip_address"] == "192.168.1.50"