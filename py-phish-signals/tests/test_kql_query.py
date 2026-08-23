"""Tests for kql_query.py."""

from __future__ import annotations

from phish_signals.kql_query import build_kql_query


def _ioc(type_: str, value: str):
    return {"type": type_, "value": value, "defanged": value}


def test_empty_iocs() -> None:
    result = build_kql_query([])
    assert "No indicator here was concrete enough" in result


def test_domain_and_email_generate_email_events_block() -> None:
    result = build_kql_query([_ioc("domain", "evil.com"), _ioc("email", "a@evil.com")])
    assert "SuspectDomains" in result
    assert "SuspectSenders" in result
    assert "EmailEvents" in result
    assert "EmailUrlInfo" in result  # domains also drive the URL block


def test_hash_and_filename_generate_attachment_and_endpoint_blocks() -> None:
    result = build_kql_query([_ioc("hash", "a" * 64), _ioc("filename", "invoice.exe")])
    assert "EmailAttachmentInfo" in result
    assert "DeviceFileEvents" in result


def test_ip_generates_network_blocks() -> None:
    result = build_kql_query([_ioc("ip", "1.2.3.4")])
    assert "SuspectIPs" in result
    assert "DeviceNetworkEvents" in result


def test_lookback_days_option() -> None:
    result = build_kql_query([_ioc("domain", "evil.com")], lookback_days=7)
    assert "let Lookback = 7d;" in result


def test_string_escaping() -> None:
    result = build_kql_query([_ioc("filename", 'evil"name.exe')])
    assert '\\"' in result
