"""Tests for sigma_rule.py."""

from __future__ import annotations

from phish_signals.sigma_rule import build_sigma_rule, subject_keywords


def test_subject_keywords_filters_stopwords_and_short_words() -> None:
    # "the"/"for"/"your"/"is" are stopwords or too short; "your" is both a
    # stopword *and* long enough, so this also confirms stopwords are
    # excluded regardless of length.
    assert subject_keywords("The urgent invoice for your account is overdue") == [
        "urgent",
        "invoice",
        "account",
        "overdue",
    ]


def test_subject_keywords_none() -> None:
    assert subject_keywords(None) == []


def test_subject_keywords_caps_at_six() -> None:
    subject = "alpha bravo charlie delta echo foxtrot golf hotel"
    assert len(subject_keywords(subject)) == 6


def test_build_sigma_rule_empty_when_nothing_distinctive() -> None:
    rule = build_sigma_rule(
        subject=None,
        sender_domain=None,
        reply_to_domain=None,
        urls=[],
        attachments=[],
        signals=[],
        verdict="Low Risk",
        score=0,
    )
    assert "No indicator in this message" in rule


def test_build_sigma_rule_includes_sender_domain_and_condition() -> None:
    rule = build_sigma_rule(
        subject="Urgent payment request",
        sender_domain="evil.com",
        reply_to_domain=None,
        urls=[],
        attachments=[],
        signals=[],
        verdict="High Risk",
        score=75,
    )
    assert "sender_domain" in rule
    assert "@evil.com" in rule
    assert (
        "condition: sender_domain" in rule
        or "sender_domain" in rule.split("condition:")[1]
    )
    assert "level: high" in rule


def test_build_sigma_rule_includes_attack_tags() -> None:
    rule = build_sigma_rule(
        subject=None,
        sender_domain="evil.com",
        reply_to_domain=None,
        urls=[],
        attachments=[],
        signals=[
            {
                "id": "x",
                "category": "payload",
                "severity": "high",
                "label": "x",
                "detail": "x",
                "mitre": ["T1566.002"],
            }
        ],
        verdict="High Risk",
        score=70,
    )
    assert "attack.t1566.002" in rule


def test_build_sigma_rule_skips_reply_to_if_same_as_sender() -> None:
    rule = build_sigma_rule(
        subject=None,
        sender_domain="evil.com",
        reply_to_domain="evil.com",
        urls=[],
        attachments=[],
        signals=[],
        verdict="High Risk",
        score=70,
    )
    assert "reply_to_domain" not in rule
