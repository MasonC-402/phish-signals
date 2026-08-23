"""Tests for recommendations.py."""

from __future__ import annotations

from phish_signals.recommendations import build_recommendations


def _sig(id_: str):
    return {
        "id": id_,
        "category": "payload",
        "severity": "high",
        "label": "x",
        "detail": "x",
    }


def test_low_risk_no_signals() -> None:
    recs = build_recommendations(verdict="Low Risk", signals=[], auth_available=True)
    urgencies = [r["urgency"] for r in recs]
    assert urgencies == ["context"]


def test_high_risk_credential_and_attachment_risk() -> None:
    recs = build_recommendations(
        verdict="High Risk",
        signals=[_sig("credential_request"), _sig("attachment_executable")],
        auth_available=True,
    )
    texts = [r["text"] for r in recs]
    assert any("Do not click" in t for t in texts)
    assert any("already entered a password" in t for t in texts)
    assert any("disconnect the machine" in t for t in texts)
    assert any("Report it" in t for t in texts)


def test_no_auth_available_adds_context_recommendation() -> None:
    recs = build_recommendations(
        verdict="Medium Risk", signals=[], auth_available=False
    )
    assert any("no message headers" in r["text"] for r in recs)


def test_reply_to_mismatch_recommendation() -> None:
    recs = build_recommendations(
        verdict="Medium Risk", signals=[_sig("reply_to_mismatch")], auth_available=True
    )
    assert any(
        "Replies to this message go to a different domain" in r["text"] for r in recs
    )
