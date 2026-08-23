"""Tests for mitre.py."""

from __future__ import annotations

from phish_signals.mitre import map_techniques, technique_url


def test_technique_url_parent() -> None:
    assert technique_url("T1566") == "https://attack.mitre.org/techniques/T1566/"


def test_technique_url_sub_technique() -> None:
    assert (
        technique_url("T1566.002") == "https://attack.mitre.org/techniques/T1566/002/"
    )


def test_map_techniques_dedupes_and_sorts() -> None:
    signals = [
        {
            "id": "a",
            "category": "payload",
            "severity": "high",
            "label": "A",
            "detail": "d",
            "mitre": ["T1566.002", "T1204.001"],
        },
        {
            "id": "b",
            "category": "payload",
            "severity": "high",
            "label": "B",
            "detail": "d",
            "mitre": ["T1566.002"],
        },
    ]
    result = map_techniques(signals)
    assert [t["id"] for t in result] == ["T1204.001", "T1566.002"]
    assert result[0]["name"] == "User Execution: Malicious Link"


def test_map_techniques_ignores_unknown_ids() -> None:
    signals = [
        {
            "id": "a",
            "category": "payload",
            "severity": "low",
            "label": "A",
            "detail": "d",
            "mitre": ["T9999.999"],
        }
    ]
    assert map_techniques(signals) == []


def test_map_techniques_no_mitre_key() -> None:
    signals = [
        {
            "id": "a",
            "category": "payload",
            "severity": "low",
            "label": "A",
            "detail": "d",
        }
    ]
    assert map_techniques(signals) == []
