"""Tests for header_anomalies.py."""

from __future__ import annotations

from phish_signals.header_anomalies import check_header_anomalies


def _base_auth(signals=None):
    return {
        "available": True,
        "passed": False,
        "signals": signals or [],
        "selectedAuthservId": None,
    }


def test_no_headers() -> None:
    result = check_header_anomalies(None, [], None, _base_auth())
    assert result == {"signals": [], "messageIdDomain": None, "mailer": None}


def test_missing_message_id_and_date() -> None:
    headers = {"from": "a@example.com"}
    result = check_header_anomalies(
        headers, [{"key": "from", "line": "From: a@example.com"}], None, _base_auth()
    )
    ids = {s["id"] for s in result["signals"]}
    assert "missing_message_id" in ids
    assert "missing_date_header" in ids


def test_message_id_domain_mismatch() -> None:
    headers = {"from": "a@example.com", "message-id": "<xyz@othercorp.com>"}
    lines = [
        {"key": "from", "line": "From: a@example.com"},
        {"key": "message-id", "line": "Message-Id: <xyz@othercorp.com>"},
    ]
    result = check_header_anomalies(headers, lines, None, _base_auth())
    ids = {s["id"] for s in result["signals"]}
    assert "message_id_domain_mismatch" in ids
    assert result["messageIdDomain"] == "othercorp.com"


def test_script_mailer_detected() -> None:
    headers = {"x-mailer": "PHPMailer 6.5"}
    lines = [{"key": "x-mailer", "line": "X-Mailer: PHPMailer 6.5"}]
    result = check_header_anomalies(headers, lines, None, _base_auth())
    ids = {s["id"] for s in result["signals"]}
    assert "script_generated_mail" in ids
    assert result["mailer"] == "PHPMailer 6.5"


def test_php_originating_script() -> None:
    headers = {}
    lines = [
        {
            "key": "x-php-originating-script",
            "line": "X-PHP-Originating-Script: 1000:x.php",
        }
    ]
    result = check_header_anomalies(headers, lines, None, _base_auth())
    ids = {s["id"] for s in result["signals"]}
    assert "php_originating_script" in ids


def test_bulk_sender_headers_benign() -> None:
    headers = {}
    lines = [
        {"key": "list-unsubscribe", "line": "List-Unsubscribe: <mailto:x@y.com>"},
        {"key": "message-id", "line": "Message-Id: <a@b.com>"},
    ]
    result = check_header_anomalies(headers, lines, None, _base_auth())
    signal = next(s for s in result["signals"] if s["id"] == "bulk_sender_headers")
    assert signal["benign"] is True


def test_thread_hijack_pattern() -> None:
    headers = {"subject": "Re: quarterly invoice"}
    lines = [
        {"key": "subject", "line": "Subject: Re: quarterly invoice"},
        {"key": "in-reply-to", "line": "In-Reply-To: <a@b.com>"},
        {"key": "message-id", "line": "Message-Id: <c@d.com>"},
        {"key": "date", "line": "Date: Mon, 1 Jan 2024 10:00:00 +0000"},
    ]
    auth = _base_auth(
        signals=[
            {
                "id": "dmarc_fail",
                "category": "authentication",
                "severity": "high",
                "label": "x",
                "detail": "x",
            }
        ]
    )
    result = check_header_anomalies(headers, lines, None, auth)
    ids = {s["id"] for s in result["signals"]}
    assert "thread_hijack_pattern" in ids


def test_authserv_id_mismatch() -> None:
    headers = {}
    chain = {
        "hops": [
            {
                "index": 0,
                "helo": None,
                "reverseDns": "mx.realcorp.com",
                "ip": "1.2.3.4",
                "by": None,
                "timestamp": None,
                "heloMismatch": False,
                "private": False,
            }
        ],
        "originIp": "1.2.3.4",
        "originHost": "mx.realcorp.com",
        "signals": [],
    }
    auth = _base_auth()
    auth["selectedAuthservId"] = "mx.attacker.com"
    result = check_header_anomalies(headers, [], chain, auth)
    ids = {s["id"] for s in result["signals"]}
    assert "authserv_id_mismatch" in ids
