"""Tests for auth_check.py."""

from __future__ import annotations

from phish_signals.auth_check import check_authentication


def _lines(*pairs: tuple[str, str]) -> list[dict[str, str]]:
    return [{"key": key.lower(), "line": f"{key}: {value}"} for key, value in pairs]


def test_no_headers_at_all() -> None:
    result = check_authentication(None, [])
    assert result == {
        "available": False,
        "passed": False,
        "signals": [],
        "selectedAuthservId": None,
    }


def test_fully_passed() -> None:
    headers = {
        "authentication-results": "mx.example.com; spf=pass; dkim=pass; dmarc=pass"
    }
    lines = _lines(
        ("Authentication-Results", "mx.example.com; spf=pass; dkim=pass; dmarc=pass")
    )
    result = check_authentication(headers, lines)
    assert result["passed"] is True
    assert any(s["id"] == "auth_fully_passed" for s in result["signals"])


def test_dmarc_fail() -> None:
    headers = {
        "authentication-results": "mx.example.com; spf=fail; dkim=fail; dmarc=fail"
    }
    lines = _lines(
        ("Authentication-Results", "mx.example.com; spf=fail; dkim=fail; dmarc=fail")
    )
    result = check_authentication(headers, lines)
    ids = {s["id"] for s in result["signals"]}
    assert "dmarc_fail" in ids
    assert "spf_fail" in ids
    assert "dkim_fail" in ids
    assert result["passed"] is False


def test_no_auth_results_header() -> None:
    result = check_authentication({"from": "a@b.com"}, [])
    assert any(s["id"] == "no_auth_results" for s in result["signals"])


def test_return_path_mismatch() -> None:
    headers = {"from": "a@example.com", "return-path": "<bounce@evil.com>"}
    result = check_authentication(headers, [])
    assert any(s["id"] == "return_path_mismatch" for s in result["signals"])


def test_reply_to_mismatch() -> None:
    headers = {"from": "a@example.com", "reply-to": "attacker@evil.com"}
    result = check_authentication(headers, [])
    assert any(s["id"] == "reply_to_mismatch" for s in result["signals"])


def test_sender_domain_typosquat() -> None:
    headers = {"from": "support@paypa1.com"}
    result = check_authentication(headers, [])
    assert any(s["id"] == "sender_domain_typosquat" for s in result["signals"])


def test_forged_trailing_auth_results_header_discarded() -> None:
    # No Received headers at all -> N=0 -> everything trusted, so this
    # should NOT be flagged as forged (there's nothing to anchor against).
    headers_no_received = {
        "authentication-results": "mx.real.com; spf=pass; dkim=pass; dmarc=pass"
    }
    lines_no_received = _lines(
        ("Authentication-Results", "mx.real.com; spf=pass; dkim=pass; dmarc=pass")
    )
    result = check_authentication(headers_no_received, lines_no_received)
    assert not any(
        s["id"] == "forged_authentication_results_header" for s in result["signals"]
    )

    # One real Received hop. Headers are *prepended* at each hop, so wire
    # order (this list's order) is newest-first: the real server's own
    # Authentication-Results/Received sit at the top (added last, when the
    # message actually arrived), while the forged header — embedded by the
    # attacker before the message ever reached a real server — sits at the
    # bottom, positionally indistinguishable from a genuine origin hop by
    # age alone. Only the N=receivedCount most recent Authentication-Results
    # headers are trusted, which is what catches it here.
    lines = [
        {
            "key": "authentication-results",
            "line": (
                "Authentication-Results: mx.example.org; spf=fail; dkim=fail; "
                "dmarc=fail"
            ),
        },
        {
            "key": "received",
            "line": (
                "Received: from real.example.com by mx.example.org; Mon, 1 Jan 2024 "
                "10:00:00 +0000"
            ),
        },
        {
            "key": "authentication-results",
            "line": (
                "Authentication-Results: fake-server; spf=pass; dkim=pass; dmarc=pass"
            ),
        },
    ]
    headers = {
        "authentication-results": "mx.example.org; spf=fail; dkim=fail; dmarc=fail"
    }
    result = check_authentication(headers, lines)
    ids = {s["id"] for s in result["signals"]}
    assert "forged_authentication_results_header" in ids
    assert "dmarc_fail" in ids
    assert result["passed"] is False
    assert result["selectedAuthservId"] == "mx.example.org"
