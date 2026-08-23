"""Tests for url_check.py."""

from __future__ import annotations

from phish_signals.url_check import (
    analyze_url,
    brand_impersonation,
    check_qr_codes,
    check_typosquat,
    check_urls,
    is_ip_literal,
    levenshtein,
    summarize_url_signals,
)


def test_levenshtein_basic() -> None:
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("same", "same") == 0
    assert levenshtein("", "abc") == 3


def test_check_typosquat_detects_close_misspelling() -> None:
    assert check_typosquat("paypa1.com") == "paypal.com"


def test_check_typosquat_none_for_real_brand() -> None:
    assert check_typosquat("paypal.com") is None
    assert check_typosquat("www.paypal.com") is None
    assert check_typosquat("login.paypal.com") is None


def test_check_typosquat_none_for_unrelated_domain() -> None:
    assert check_typosquat("example.com") is None


def test_brand_impersonation_subdomain() -> None:
    assert brand_impersonation("paypal.com.evil.net") == "paypal.com"


def test_brand_impersonation_hyphenated() -> None:
    assert brand_impersonation("secure-paypal.com") == "paypal.com"


def test_brand_impersonation_none_for_regional_tld() -> None:
    # A single-token match on the registrable domain shouldn't fire —
    # otherwise paypal.co.uk-shaped legitimate regional domains would.
    assert brand_impersonation("paypal.co.uk") is None


def test_is_ip_literal() -> None:
    assert is_ip_literal("192.168.1.1") is True
    assert is_ip_literal("999.1.1.1") is False
    assert is_ip_literal("0x7f000001") is True
    assert is_ip_literal("example.com") is False
    assert is_ip_literal("::1") is True


def test_analyze_url_clean() -> None:
    result = analyze_url("https://example.com/page")
    assert result["risk"] == "clean"
    assert result["hostname"] == "example.com"


def test_analyze_url_typosquat_is_malicious() -> None:
    result = analyze_url("https://paypa1.com/login")
    assert result["risk"] == "malicious"
    assert "typosquat" in result["detail"]


def test_analyze_url_unparseable() -> None:
    result = analyze_url("not a url at all")
    assert result["risk"] == "unknown"
    assert "hostname" not in result


def test_analyze_url_ip_literal_and_dangerous_extension() -> None:
    result = analyze_url("http://192.168.1.1/malware.exe")
    assert result["risk"] in ("suspicious", "malicious")
    assert "IP address" in result["detail"]
    assert ".exe" in result["detail"]


def test_analyze_url_homograph_domain() -> None:
    # xn--pypal-4ve.com decodes to "pаypal.com" with a Cyrillic а — a mixed
    # Latin/Cyrillic homograph of paypal.com.
    result = analyze_url("https://xn--pypal-4ve.com/login")
    assert result["risk"] == "malicious"
    assert result["decodedHost"] is not None


def test_check_urls_bounds_to_max() -> None:
    from phish_signals.url_check import MAX_URLS_ANALYZED

    urls = [f"https://example{i}.com" for i in range(MAX_URLS_ANALYZED + 5)]
    result = check_urls(urls)
    assert len(result) == MAX_URLS_ANALYZED


def test_check_urls_empty() -> None:
    assert check_urls(None) == []
    assert check_urls([]) == []


def test_summarize_url_signals_malicious_and_suspicious() -> None:
    analyses = [
        analyze_url("https://paypa1.com/login"),
        analyze_url("http://bit.ly/xyz"),
    ]
    signals = summarize_url_signals(analyses)
    ids = {s["id"] for s in signals}
    assert "malicious_links" in ids
    assert "suspicious_links" in ids


def test_summarize_url_signals_no_links() -> None:
    signals = summarize_url_signals([])
    assert len(signals) == 1
    assert signals[0]["id"] == "no_links_present"
    assert signals[0]["benign"] is True


def test_check_qr_codes_empty() -> None:
    assert check_qr_codes(None) == {"signals": []}
    assert check_qr_codes([]) == {"signals": []}


def test_check_qr_codes_present() -> None:
    result = check_qr_codes(["https://example.com/a"])
    assert result["signals"][0]["id"] == "qr_code_link"
