"""Tests for attachment_check.py."""

from __future__ import annotations

from phish_signals.attachment_check import (
    check_attachments,
    extname,
    has_double_extension,
    has_executable_mime_mismatch,
)


def test_extname_basic() -> None:
    assert extname("invoice.pdf") == ".pdf"
    assert extname("invoice.PDF") == ".pdf"
    assert extname("noextension") == ""


def test_extname_nul_truncation() -> None:
    assert extname("invoice.exe\x00.txt") == ".exe"


def test_extname_path_stripped() -> None:
    assert extname("folder/subfolder/invoice.exe") == ".exe"
    assert extname("folder\\subfolder\\invoice.exe") == ".exe"


def test_extname_trailing_dot_and_whitespace() -> None:
    assert extname("invoice.exe ") == ".exe"
    assert extname("invoice.exe.") == ".exe"


def test_extname_strips_rtlo() -> None:
    # U+202E (RTLO) inserted before the fake extension shouldn't hide the
    # real one from the trailing-anchored match.
    assert extname("invoice‮gnp.exe") == ".exe"


def test_has_double_extension() -> None:
    assert has_double_extension("invoice.pdf.exe", ".exe") is True
    assert has_double_extension("invoice.exe", ".exe") is False
    assert has_double_extension("invoice.exe", "") is False


def test_has_double_extension_ext_longer_than_remainder() -> None:
    # Regression guard: a naive `s[:len(s) - len(ext)]` (rather than
    # `s[:-len(ext)]`) mis-slices when `ext` is longer than what's left
    # after removing it, because Python re-applies negative-index wraparound
    # to an already-negative literal. ".exe" (4 chars) against a 2-char
    # filename exercises exactly that.
    assert has_double_extension("ab", ".exe") is False


def test_has_executable_mime_mismatch() -> None:
    assert has_executable_mime_mismatch(".jpg", "application/x-msdownload") is True
    assert has_executable_mime_mismatch(".exe", "application/x-msdownload") is False
    assert has_executable_mime_mismatch(".jpg", "image/jpeg") is False


def test_check_attachments_executable() -> None:
    result = check_attachments(
        [
            {
                "filename": "invoice.exe",
                "contentType": "application/octet-stream",
                "size": 100,
            }
        ]
    )
    assert result["signals"][0]["id"] == "attachment_executable"
    assert result["signals"][0]["severity"] == "critical"


def test_check_attachments_double_extension_takes_priority() -> None:
    result = check_attachments(
        [
            {
                "filename": "invoice.pdf.exe",
                "contentType": "application/octet-stream",
                "size": 100,
            }
        ]
    )
    assert result["signals"][0]["id"] == "attachment_double_extension"


def test_check_attachments_macro_document() -> None:
    result = check_attachments(
        [
            {
                "filename": "quarterly.docm",
                "contentType": "application/vnd.ms-word.document.macroEnabled.12",
                "size": 100,
            }
        ]
    )
    assert result["signals"][0]["id"] == "attachment_macro_document"


def test_check_attachments_archive_with_dangerous_inner() -> None:
    result = check_attachments(
        [
            {
                "filename": "backup.zip",
                "contentType": "application/zip",
                "size": 100,
                "zipEntries": [{"filename": "readme.pdf.exe", "uncompressedSize": 10}],
            }
        ]
    )
    assert result["signals"][0]["id"] == "attachment_archive_contains_executable"
    assert '"readme.pdf.exe"' in result["signals"][0]["detail"]


def test_check_attachments_renamed_archive_dangerous_inner_notes_it() -> None:
    result = check_attachments(
        [
            {
                "filename": "invoice.pdf",
                "contentType": "application/octet-stream",
                "size": 100,
                "zipEntries": [{"filename": "payload.exe", "uncompressedSize": 10}],
            }
        ]
    )
    assert "doesn't even indicate an archive" in result["signals"][0]["detail"]


def test_check_attachments_zip_unreadable() -> None:
    result = check_attachments(
        [
            {
                "filename": "backup.zip",
                "contentType": "application/zip",
                "size": 100,
                "zipUnreadable": True,
            }
        ]
    )
    assert result["signals"][0]["id"] == "attachment_archive_unreadable"


def test_check_attachments_benign_archive() -> None:
    result = check_attachments(
        [{"filename": "backup.zip", "contentType": "application/zip", "size": 100}]
    )
    assert result["signals"][0]["id"] == "attachment_archive"
    assert result["signals"][0]["severity"] == "low"


def test_check_attachments_benign_pdf_no_signal() -> None:
    result = check_attachments(
        [{"filename": "invoice.pdf", "contentType": "application/pdf", "size": 100}]
    )
    assert result["signals"] == []


def test_check_attachments_none_and_empty() -> None:
    assert check_attachments(None) == {"signals": []}
    assert check_attachments([]) == {"signals": []}
