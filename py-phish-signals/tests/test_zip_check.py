"""Tests for zip_check.py — round-tripped against Python's own zipfile
module rather than hand-built byte strings, so this validates against an
independent ZIP writer."""

from __future__ import annotations

import io
import zipfile

from phish_signals.zip_check import list_zip_entries, looks_like_zip


def _make_zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_looks_like_zip_true_for_real_zip() -> None:
    assert looks_like_zip(_make_zip({"a.txt": b"hello"})) is True


def test_looks_like_zip_false_for_other_bytes() -> None:
    assert looks_like_zip(b"not a zip file at all") is False
    assert looks_like_zip(b"") is False


def test_list_zip_entries_reads_names_and_sizes() -> None:
    data = _make_zip({"invoice.pdf": b"x" * 100, "readme.txt": b"y" * 10})
    result = list_zip_entries(data)
    assert result["status"] == "ok"
    names = {e["filename"]: e["uncompressedSize"] for e in result["entries"]}
    assert names == {"invoice.pdf": 100, "readme.txt": 10}


def test_list_zip_entries_finds_nested_executable() -> None:
    data = _make_zip({"backup/invoice.pdf.exe": b"MZ" + b"\x00" * 50})
    result = list_zip_entries(data)
    assert result["status"] == "ok"
    assert result["entries"][0]["filename"] == "backup/invoice.pdf.exe"


def test_not_zip_status() -> None:
    assert list_zip_entries(b"plain text content")["status"] == "not-zip"


def test_empty_zip() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w"):
        pass
    result = list_zip_entries(buf.getvalue())
    assert result["status"] == "ok"
    assert result["entries"] == []


def test_truncated_zip_is_unreadable_not_a_crash() -> None:
    data = _make_zip({"a.txt": b"hello"})
    truncated = data[: len(data) - 5]
    result = list_zip_entries(truncated)
    assert result["status"] == "unreadable"
