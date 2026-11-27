"""Tests for json_export.py."""

from __future__ import annotations

import json
from typing import cast

from phish_signals.json_export import build_json_export
from phish_signals.types import CombinedResult

# build_json_export only serializes whatever keys it is handed, so these tests
# pass deliberately partial results rather than a full CombinedResult.


def test_excludes_json_report_field() -> None:
    result = cast(
        "CombinedResult",
        {"score": 10, "verdict": "Low Risk", "jsonReport": "should not appear"},
    )
    exported = build_json_export(result)
    parsed = json.loads(exported)
    assert "jsonReport" not in parsed
    assert parsed["score"] == 10


def test_pretty_printed_with_two_space_indent() -> None:
    result = cast("CombinedResult", {"score": 10})
    exported = build_json_export(result)
    assert exported == '{\n  "score": 10\n}'


def test_preserves_unicode_without_escaping() -> None:
    result = cast("CombinedResult", {"detail": "café"})
    exported = build_json_export(result)
    assert "café" in exported
