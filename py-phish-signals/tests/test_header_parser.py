"""Tests for header_parser.py."""

from __future__ import annotations

from phish_signals.header_parser import parse_header_text


def test_basic_headers() -> None:
    result = parse_header_text("From: a@b.com\r\nSubject: Hi\r\n")
    assert result["headers"]["from"] == "a@b.com"
    assert result["headers"]["subject"] == "Hi"
    assert len(result["headerLines"]) == 2


def test_folded_continuation_line() -> None:
    result = parse_header_text("Subject: Hello\r\n world\r\n")
    assert result["headers"]["subject"] == "Hello world"
    assert len(result["headerLines"]) == 1


def test_first_occurrence_wins_for_repeated_header() -> None:
    # Wire order is newest-first, so the first occurrence is the most recent.
    result = parse_header_text("Received: hop2\r\nReceived: hop1\r\n")
    assert result["headers"]["received"] == "hop2"
    assert len(result["headerLines"]) == 2


def test_ignores_blank_lines_and_malformed_lines() -> None:
    result = parse_header_text(
        "\r\nFrom: a@b.com\r\nnot a header line\r\n\r\nSubject: x\r\n"
    )
    keys = [h["key"] for h in result["headerLines"]]
    assert keys == ["from", "subject"]
