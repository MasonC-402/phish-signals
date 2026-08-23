"""Tests for json_export.py."""

from __future__ import annotations

import json

from phish_signals.json_export import build_json_export


def test_excludes_json_report_field() -> None:
    result = {"score": 10, "verdict": "Low Risk", "jsonReport": "should not appear"}
    exported = build_json_export(result)
    parsed = json.loads(exported)
    assert "jsonReport" not in parsed
    assert parsed["score"] == 10


def test_pretty_printed_with_two_space_indent() -> None:
    result = {"score": 10}
    exported = build_json_export(result)
    assert exported == '{\n  "score": 10\n}'


def test_preserves_unicode_without_escaping() -> None:
    result = {"detail": "café"}
    exported = build_json_export(result)
    assert "café" in exported
