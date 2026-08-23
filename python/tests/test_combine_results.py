"""Tests for combine_results.py — the assembly point that runs every check
and scores the result. Exercises the full pipeline end to end using the
real email_parser/auth_check/url_check outputs, not hand-built stubs,
since this module's whole job is wiring those together correctly."""

from __future__ import annotations

from phish_signals.auth_check import check_authentication
from phish_signals.combine_results import AnalysisInput, combine_results
from phish_signals.content_check import (
    check_content,
    check_dangerous_schemes,
    check_link_text,
)
from phish_signals.email_parser import parse_email
from phish_signals.header_anomalies import check_header_anomalies
from phish_signals.received_chain import analyze_received_chain
from phish_signals.url_check import check_qr_codes, check_urls, summarize_url_signals


def _run_pipeline(raw_email: str):
    parsed = parse_email(raw_email)
    auth = check_authentication(parsed["headers"], parsed["headerLines"])
    urls = check_urls(parsed["urls"])
    url_signals = summarize_url_signals(urls)
    content = check_content(parsed["textBody"], parsed["from"])
    link_text = check_link_text(parsed["linkMismatches"])
    dangerous_schemes = check_dangerous_schemes(parsed["dangerousSchemes"])
    qr_codes = check_qr_codes(parsed["qrCodeUrls"])
    from phish_signals.attachment_check import check_attachments

    attachments = check_attachments(parsed["attachments"])
    chain = (
        analyze_received_chain(parsed["headerLines"]) if parsed["isRawEmail"] else None
    )
    header_anomalies = check_header_anomalies(
        parsed["headers"], parsed["headerLines"], chain, auth
    )

    return combine_results(
        AnalysisInput(
            parsed=parsed,
            auth=auth,
            urls=urls,
            url_signals=url_signals,
            content=content,
            link_text=link_text,
            dangerous_schemes=dangerous_schemes,
            qr_codes=qr_codes,
            attachments=attachments,
            chain=chain,
            header_anomalies=header_anomalies,
        )
    )


def test_clean_plain_paste_is_low_risk() -> None:
    result = _run_pipeline("Hi, just checking in about tomorrow's meeting.")
    assert result["verdict"] == "Low Risk"
    assert result["authAvailable"] is False
    assert result["receivedChain"] is None


def test_phishing_style_message_scores_high() -> None:
    raw = (
        'From: "PayPal Security" <security@paypa1-secure.com>\r\n'
        "Reply-To: reply@paypa1-secure.com\r\n"
        "Subject: Urgent: Verify your account now\r\n"
        "Date: Mon, 1 Jan 2024 10:00:00 +0000\r\n"
        "Message-ID: <1@paypa1-secure.com>\r\n"
        "Received: from paypa1-secure.com (unknown [10.0.0.1]) by "
        "mx.example.org; Mon, 1 Jan 2024 10:00:05 +0000\r\n"
        "Authentication-Results: mx.example.org; spf=fail; dkim=fail; dmarc=fail\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<html><body>Dear customer, please verify your account urgently: "
        '<a href="http://paypa1-secure.com/verify">https://paypal.com/account</a>. '
        "CLICK NOW OR YOUR ACCOUNT WILL BE SUSPENDED IMMEDIATELY TODAY ONLY LAST "
        "CHANCE."
        "</body></html>\r\n"
    )
    result = _run_pipeline(raw)
    assert result["verdict"] == "High Risk"
    assert result["score"] >= 60
    assert result["authAvailable"] is True
    assert result["authPassed"] is False
    ids = {s["id"] for s in result["signals"]}
    assert "dmarc_fail" in ids
    assert len(result["mitre"]) > 0
    assert "No indicator" not in result["sigmaRule"] or result["score"] > 0
    assert isinstance(result["kqlQuery"], str)
    assert len(result["recommendations"]) > 0
    assert result["confidence"]["level"] in ("low", "medium", "high")


def test_iocs_and_categories_present_for_risky_message() -> None:
    raw = (
        "From: attacker@evil-domain.tk\r\n"
        "Subject: test\r\n"
        "\r\n"
        "Click http://evil-domain.tk/malware.exe now.\r\n"
    )
    result = _run_pipeline(raw)
    assert any(ioc["type"] == "url" for ioc in result["iocs"]) or any(
        ioc["type"] == "email" for ioc in result["iocs"]
    )
    assert (
        any(c["category"] == "payload" for c in result["categories"])
        or result["score"] == 0
    )
