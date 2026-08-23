"""Tests for email_parser.py — the parsing layer that turns a raw .eml or
pasted message into the structured ParsedEmail shape the checks consume."""

from __future__ import annotations

from phish_signals.email_parser import (
    extract_hrefs,
    extract_urls,
    find_dangerous_schemes,
    find_link_mismatches,
    looks_like_raw_email,
    parse_email,
)


def test_extract_urls_strips_trailing_punctuation() -> None:
    text = "Visit http://example.com/path. Or (https://example.org/x), see!"
    assert extract_urls(text) == ["http://example.com/path", "https://example.org/x"]


def test_extract_urls_empty() -> None:
    assert extract_urls(None) == []
    assert extract_urls("") == []


def test_extract_hrefs() -> None:
    html = '<a href="https://example.com/a">click</a> <a href="https://example.com/b">b</a>'
    assert extract_hrefs(html) == ["https://example.com/a", "https://example.com/b"]


def test_find_dangerous_schemes_dedupes() -> None:
    html = (
        '<a href="javascript:alert(1)">x</a><a href="data:text/html,x">y</a>'
        '<a href="JAVASCRIPT:foo()">z</a>'
    )
    assert find_dangerous_schemes(html) == ["javascript", "data"]


def test_find_link_mismatches_detects_domain_swap() -> None:
    html = '<a href="http://evil.tk/login">https://paypal.com/account</a>'
    mismatches = find_link_mismatches(html)
    assert len(mismatches) == 1
    assert mismatches[0]["claimedDomain"] == "paypal.com"
    assert mismatches[0]["actualDomain"] == "evil.tk"


def test_find_link_mismatches_ignores_generic_text() -> None:
    html = '<a href="http://evil.tk/login">Click here</a>'
    assert find_link_mismatches(html) == []


def test_looks_like_raw_email_true_for_headers() -> None:
    raw = "From: a@b.com\r\nSubject: Hi\r\n\r\nBody text."
    assert looks_like_raw_email(raw) is True


def test_looks_like_raw_email_false_for_plain_paste() -> None:
    raw = "Dear customer, please verify your account now."
    assert looks_like_raw_email(raw) is False


def test_looks_like_raw_email_false_for_quoted_from_line() -> None:
    raw = 'He wrote "From: someone" in his reply, which is odd.'
    assert looks_like_raw_email(raw) is False


def test_parse_email_plain_paste() -> None:
    raw = "Please click http://evil.example.com/login now."
    parsed = parse_email(raw)
    assert parsed["isRawEmail"] is False
    assert parsed["from"] is None
    assert parsed["urls"] == ["http://evil.example.com/login"]
    assert parsed["textBody"] == raw


def test_parse_email_raw_eml_basic_fields() -> None:
    raw = (
        'From: "A Sender" <sender@example.com>\r\n'
        "To: victim@example.org\r\n"
        "Subject: Urgent: verify your account\r\n"
        "Date: Mon, 1 Jan 2024 10:00:00 +0000\r\n"
        "Received: from mail.example.com (mail.example.com [1.2.3.4]) by "
        "mx.example.org; Mon, 1 Jan 2024 10:00:05 +0000\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Please visit http://phish.example/login to verify.\r\n"
    )
    parsed = parse_email(raw)
    assert parsed["isRawEmail"] is True
    # stdlib's policy.default re-serializes the address, which drops
    # quoting around a display name that doesn't strictly need it per RFC
    # 5322 — a cosmetic difference from mailparser's own AddressObject.text
    # formatting, not a loss of information (the name and address are both
    # still present and unchanged).
    assert parsed["from"] == "A Sender <sender@example.com>"
    assert parsed["subject"] == "Urgent: verify your account"
    assert parsed["urls"] == ["http://phish.example/login"]
    assert len(parsed["headerLines"]) == 6
    assert parsed["headers"]["from"] == '"A Sender" <sender@example.com>'
    assert parsed["date"] == "2024-01-01T10:00:00.000Z"


def test_parse_email_html_body_and_link_mismatch() -> None:
    raw = (
        "From: a@b.com\r\n"
        "Subject: Test\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        '<html><body><a href="http://evil.tk/x">https://paypal.com/account</a></body></html>\r\n'
    )
    parsed = parse_email(raw)
    assert parsed["linkMismatches"] == [
        {
            "text": "https://paypal.com/account",
            "href": "http://evil.tk/x",
            "claimedDomain": "paypal.com",
            "actualDomain": "evil.tk",
        }
    ]
    assert "http://evil.tk/x" in parsed["urls"]


def test_parse_email_extra_attachments_override_mime_attachments() -> None:
    raw = 'From: "Sender" <a@b.com>\r\nSubject: test\r\n\r\nBody text here.'
    extra_attachments = [
        {
            "filename": "invoice.exe",
            "contentType": "application/x-msdownload",
            "size": 999,
        },
    ]
    parsed = parse_email(raw, extra_attachments)
    assert len(parsed["attachments"]) == 1
    assert parsed["attachments"][0]["filename"] == "invoice.exe"
    assert "sha256" not in parsed["attachments"][0]


def test_parse_email_regular_mime_attachment_is_hashed() -> None:
    raw = (
        "From: a@b.com\r\n"
        "Subject: test\r\n"
        "Content-Type: multipart/mixed; boundary=BOUND\r\n"
        "\r\n"
        "--BOUND\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Hello\r\n"
        "--BOUND\r\n"
        "Content-Type: application/octet-stream\r\n"
        'Content-Disposition: attachment; filename="notes.bin"\r\n'
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        "aGVsbG8gd29ybGQ=\r\n"
        "--BOUND--\r\n"
    )
    parsed = parse_email(raw)
    assert len(parsed["attachments"]) == 1
    att = parsed["attachments"][0]
    assert att["filename"] == "notes.bin"
    assert "sha256" in att
    assert att["size"] == len(b"hello world")
