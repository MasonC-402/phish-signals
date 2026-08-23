"""Tests for received_chain.py."""

from __future__ import annotations

from phish_signals.received_chain import analyze_received_chain, is_private_ip


def _lines(*raw_lines: str) -> list[dict[str, str]]:
    return [{"key": "received", "line": line} for line in raw_lines]


def test_is_private_ip() -> None:
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("172.32.0.1") is False
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("::1") is True
    assert is_private_ip("fe80::1") is True


def test_no_received_headers() -> None:
    result = analyze_received_chain([])
    assert result == {"hops": [], "originIp": None, "originHost": None, "signals": []}


def test_single_hop_signal() -> None:
    lines = _lines(
        "Received: from mail.example.com (mail.example.com [1.2.3.4]) by "
        "mx.example.org; Mon, 1 Jan 2024 10:00:00 +0000"
    )
    result = analyze_received_chain(lines)
    assert len(result["hops"]) == 1
    assert result["originIp"] == "1.2.3.4"
    ids = {s["id"] for s in result["signals"]}
    assert "single_hop_delivery" in ids


def test_private_origin_ip_single_hop() -> None:
    lines = _lines(
        "Received: from internal.local (internal.local [10.0.0.5]) by mx.example.org; "
        "Mon, 1 Jan 2024 10:00:00 +0000"
    )
    result = analyze_received_chain(lines)
    ids = {s["id"] for s in result["signals"]}
    assert "origin_private_ip" in ids


def test_helo_rdns_mismatch() -> None:
    # HELO claims one domain, reverse DNS resolves to a totally different one.
    lines = _lines(
        "Received: from spoofed.attacker.net (real-host.otherdomain.com [5.6.7.8]) by "
        "mx.example.org; Mon, 1 Jan 2024 10:00:00 +0000",
        "Received: from mx.example.org (mx.example.org [9.9.9.9]) by "
        "final.example.org; Mon, 1 Jan 2024 10:05:00 +0000",
    )
    result = analyze_received_chain(lines)
    ids = {s["id"] for s in result["signals"]}
    assert "helo_rdns_mismatch" in ids


def test_helo_brand_impersonation() -> None:
    lines = _lines(
        "Received: from paypal.com (attacker-host.evil.net [5.6.7.8]) by "
        "mx.example.org; Mon, 1 Jan 2024 10:00:00 +0000",
        "Received: from mx.example.org (mx.example.org [9.9.9.9]) by "
        "final.example.org; Mon, 1 Jan 2024 10:05:00 +0000",
    )
    result = analyze_received_chain(lines)
    ids = {s["id"] for s in result["signals"]}
    assert "helo_brand_impersonation" in ids


def test_timestamp_regression_detected() -> None:
    # Input is wire order (newest hop first). The origin hop (last in this
    # list, first once reversed into origin->recipient order) is dated
    # *after* the next hop — impossible for a real delivery chain.
    lines = _lines(
        "Received: from b.example.com (b.example.com [2.2.2.2]) by c.example.com; Mon, "
        "1 Jan 2024 10:00:00 +0000",
        "Received: from a.example.com (a.example.com [1.1.1.1]) by b.example.com; Mon, "
        "1 Jan 2024 12:00:00 +0000",
    )
    result = analyze_received_chain(lines)
    ids = {s["id"] for s in result["signals"]}
    assert "received_timestamp_regression" in ids


def test_unknown_reverse_dns_not_recorded() -> None:
    lines = _lines(
        "Received: from mail.example.com (unknown [1.2.3.4]) by mx.example.org; Mon, 1 "
        "Jan 2024 10:00:00 +0000"
    )
    result = analyze_received_chain(lines)
    assert result["hops"][0]["reverseDns"] is None
