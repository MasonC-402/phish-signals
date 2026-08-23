"""Attachment metadata analysis — filename, extension, and declared type only.

Port of ``typescript/src/attachmentCheck.ts``.

This module never touches content bytes itself; where a hash or a ZIP
directory listing is present on ``AttachmentSummary``, it was computed once,
upstream, in ``email_parser.py`` (the listing via ``zip_check.py``, reading
only the ZIP central directory — never decompressing an entry).
"""

from __future__ import annotations

import re

from .sanitize import strip_dangerous_unicode
from .types import AttachmentSummary, Signal, SignalResult, ZipEntry

EXECUTABLE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".com",
        ".pif",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".wsf",
        ".wsh",
        ".msi",
        ".msp",
        ".ps1",
        ".psm1",
        ".jar",
        ".hta",
        ".cpl",
        ".reg",
    }
)

MACRO_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".docm",
        ".xlsm",
        ".pptm",
        ".dotm",
        ".xltm",
        ".potm",
        ".xlam",
        ".xlsb",
    }
)

# Containers used to smuggle a payload past scanners that only look at the
# outermost file, and disk images that mount on double-click without the
# mark-of-the-web warning a downloaded executable would get.
ARCHIVE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".zip",
        ".rar",
        ".7z",
        ".cab",
        ".gz",
        ".tar",
        ".ace",
        ".arj",
    }
)
DISK_IMAGE_EXTENSIONS: frozenset[str] = frozenset(
    {".iso", ".img", ".vhd", ".vhdx", ".dmg"}
)
SCRIPT_SHORTCUT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".lnk",
        ".url",
        ".scf",
        ".inf",
        ".chm",
        ".one",
        ".xll",
        ".wll",
    }
)

# What's dangerous inside a ZIP is the same as what's dangerous as a
# top-level attachment. Disk images are left out: mounting a nested disk
# image straight out of an archive listing is a stretch two containers deep.
_DANGEROUS_INNER_EXTENSIONS: frozenset[str] = (
    EXECUTABLE_EXTENSIONS | MACRO_EXTENSIONS | SCRIPT_SHORTCUT_EXTENSIONS
)

# Extensions that read as an ordinary document or image. Declaring one of
# these as an executable MIME type below is a narrow, low-noise mismatch —
# plenty of legitimate mail clients declare ordinary attachments as
# application/octet-stream whenever they don't recognize the type, so that
# generic type is deliberately left out of the executable set.
_BENIGN_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".bmp",
        ".webp",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".txt",
        ".csv",
        ".rtf",
    }
)

_EXECUTABLE_MIME_TYPES: frozenset[str] = frozenset(
    {
        "application/x-msdownload",
        "application/x-dosexec",
        "application/x-executable",
        "application/vnd.microsoft.portable-executable",
        "application/x-ms-shortcut",
    }
)

_EXTENSION_RE = re.compile(r"\.[a-z0-9]+$", re.IGNORECASE)
_DOUBLE_EXTENSION_RE = re.compile(r"\.[a-z0-9]{2,4}$", re.IGNORECASE)
_TRAILING_DOT_WHITESPACE_RE = re.compile(r"[\s.]+$")


def extname(filename: str | None) -> str:
    """The lowercased extension of a filename, normalized against display
    tricks before the trailing match is anchored:

    - a NUL byte truncates what most systems and viewers ever actually
      render for the name, so only what's before the first one is considered.
    - zero-width and bidi-control characters (RTLO in particular) aren't
      whitespace, so a naive trailing-character trim leaves them in place;
      :func:`~phish_signals.sanitize.strip_dangerous_unicode` removes them
      before the extension regex, anchored to the end, looks past them.
    - only the basename (after the last / or \\) is considered, so an
      embedded path segment can't hide the real extension either.

    Trailing dots and whitespace are stripped after that normalization:
    "invoice.exe " and "invoice.exe." both resolve to .exe on Windows.
    """
    truncated_at_nul = (filename or "").split("\0")[0]
    normalized = strip_dangerous_unicode(truncated_at_nul)
    basename = re.split(r"[/\\]", normalized)[-1] or ""
    cleaned = _TRAILING_DOT_WHITESPACE_RE.sub("", basename)
    match = _EXTENSION_RE.search(cleaned)
    return match.group(0).lower() if match else ""


def has_double_extension(filename: str | None, ext: str) -> bool:
    """e.g. "invoice.pdf.exe" — a real extension immediately followed by a
    dangerous one, the classic disguise trick.
    """
    if not ext:
        return False
    without_final_ext = _TRAILING_DOT_WHITESPACE_RE.sub("", filename or "")[: -len(ext)]
    return bool(_DOUBLE_EXTENSION_RE.search(without_final_ext))


def has_executable_mime_mismatch(ext: str, content_type: str | None) -> bool:
    """ "photo.jpg" declared as application/x-msdownload — the filename says
    picture, the message's own metadata says Windows executable.
    """
    if ext not in _BENIGN_EXTENSIONS:
        return False
    mime_type = (content_type or "").lower().split(";")[0].strip()
    return mime_type in _EXECUTABLE_MIME_TYPES


def _find_dangerous_zip_entries(entries: list[ZipEntry]) -> list[str]:
    """Reuses :func:`extname` so a nested "readme.pdf.exe" inside the archive
    is caught by the same double-extension-shaped trick as a top-level one.
    """
    names = (strip_dangerous_unicode(e["filename"]) for e in entries)
    return [name for name in names if extname(name) in _DANGEROUS_INNER_EXTENSIONS]


def check_attachments(attachments: list[AttachmentSummary] | None) -> SignalResult:
    signals: list[Signal] = []

    for file in attachments or []:
        ext = extname(file["filename"])
        # Driven by whether the file content-sniffed as a ZIP
        # (zip_check.py), not by its extension.
        zip_entries = file.get("zipEntries")
        dangerous_inner = (
            _find_dangerous_zip_entries(zip_entries) if zip_entries else []
        )

        if has_executable_mime_mismatch(ext, file.get("contentType")):
            signals.append(
                {
                    "id": "attachment_mime_extension_mismatch",
                    "category": "payload",
                    "severity": "high",
                    "label": "Declared Type Contradicts the Filename",
                    "detail": (
                        f'"{file["filename"]}" has an extension that reads as an '
                        "ordinary document or image, but the message declares its type "
                        f'as "{file.get("contentType")}", which is an executable '
                        "format. The two disagree."
                    ),
                    "mitre": ["T1036.008", "T1566.001"],
                }
            )

        if ext in EXECUTABLE_EXTENSIONS and has_double_extension(file["filename"], ext):
            signals.append(
                {
                    "id": "attachment_double_extension",
                    "category": "payload",
                    "severity": "critical",
                    "label": "Disguised Executable Attachment",
                    "detail": (
                        f'"{file["filename"]}" uses a double extension to pass an '
                        "executable off as a document. This is deliberate deception, "
                        "not a misconfiguration."
                    ),
                    "mitre": ["T1566.001", "T1036.007", "T1204.002"],
                }
            )
        elif ext in EXECUTABLE_EXTENSIONS:
            signals.append(
                {
                    "id": "attachment_executable",
                    "category": "payload",
                    "severity": "critical",
                    "label": "Executable Attachment",
                    "detail": (
                        f'"{file["filename"]}" is a directly executable file type '
                        f"({ext}). Opening it runs code on your machine."
                    ),
                    "mitre": ["T1566.001", "T1204.002"],
                }
            )
        elif ext in MACRO_EXTENSIONS:
            signals.append(
                {
                    "id": "attachment_macro_document",
                    "category": "payload",
                    "severity": "high",
                    "label": "Macro-Enabled Document",
                    "detail": (
                        f'"{file["filename"]}" is a macro-enabled Office document '
                        f'({ext}). The macro runs on "Enable Content", which is what '
                        "the message body is usually written to talk you into."
                    ),
                    "mitre": ["T1566.001", "T1204.002"],
                }
            )
        elif ext in DISK_IMAGE_EXTENSIONS:
            signals.append(
                {
                    "id": "attachment_disk_image",
                    "category": "payload",
                    "severity": "high",
                    "label": "Disk Image Attachment",
                    "detail": (
                        f'"{file["filename"]}" is a disk image ({ext}). These mount on '
                        'double-click and their contents bypass the "downloaded from '
                        'the internet" warning an executable would trigger.'
                    ),
                    "mitre": ["T1566.001", "T1204.002"],
                }
            )
        elif ext in SCRIPT_SHORTCUT_EXTENSIONS:
            signals.append(
                {
                    "id": "attachment_shortcut",
                    "category": "payload",
                    "severity": "high",
                    "label": "Shortcut / Script Container Attachment",
                    "detail": (
                        f'"{file["filename"]}" is a shortcut or script container '
                        f"({ext}). It looks inert but can launch an arbitrary command "
                        "when opened."
                    ),
                    "mitre": ["T1566.001", "T1204.002"],
                }
            )
        elif dangerous_inner:
            shown = ", ".join(f'"{n}"' for n in dangerous_inner[:3])
            more = (
                f", and {len(dangerous_inner) - 3} more"
                if len(dangerous_inner) > 3
                else ""
            )
            # Called out explicitly when the filename doesn't even say .zip.
            renamed_note = (
                ""
                if ext == ".zip"
                else (
                    f" The filename doesn't even indicate an archive "
                    f'(extension: "{ext or "none"}"), which is itself worth noting.'
                )
            )
            signals.append(
                {
                    "id": "attachment_archive_contains_executable",
                    "category": "payload",
                    "severity": "critical",
                    "label": "Archive Contains a Disguised Executable",
                    "detail": (
                        f'"{file["filename"]}" is a ZIP archive (identified from its '
                        f"content, not just its name).{renamed_note} Its directory "
                        f"listing shows {shown}{more} — a directly executable or "
                        "macro-bearing file sitting inside what looks like an ordinary "
                        "archive. Its compressed bytes were never extracted or run; "
                        "only the directory listing was read."
                    ),
                    "mitre": ["T1566.001", "T1204.002", "T1027.001"],
                }
            )
        elif file.get("zipUnreadable"):
            # Distinct from both "nothing dangerous inside" and "not an
            # archive at all" — this content-sniffs as a ZIP but its
            # directory couldn't actually be read (most likely ZIP64).
            signals.append(
                {
                    "id": "attachment_archive_unreadable",
                    "category": "payload",
                    "severity": "low",
                    "label": "Archive Directory Could Not Be Read",
                    "detail": (
                        f'"{file["filename"]}" is a ZIP archive, but its central '
                        "directory could not be read (most likely a ZIP64 archive, "
                        "which isn't supported here). Its contents are unknown rather "
                        "than confirmed clean — this is not the same as having been "
                        "checked and found nothing dangerous."
                    ),
                    "mitre": ["T1566.001"],
                }
            )
        elif ext in ARCHIVE_EXTENSIONS:
            signals.append(
                {
                    "id": "attachment_archive",
                    "category": "payload",
                    "severity": "low",
                    "label": "Archive Attachment",
                    "detail": (
                        f'"{file["filename"]}" is an archive ({ext}). Not suspicious '
                        "alone, but archives are routinely used to hide an executable "
                        "from scanners that only inspect the outer file. Its contents "
                        "were not opened."
                    ),
                    "mitre": ["T1566.001"],
                }
            )

    return {"signals": signals}


__all__ = [
    "ARCHIVE_EXTENSIONS",
    "DISK_IMAGE_EXTENSIONS",
    "EXECUTABLE_EXTENSIONS",
    "MACRO_EXTENSIONS",
    "SCRIPT_SHORTCUT_EXTENSIONS",
    "check_attachments",
    "extname",
    "has_double_extension",
    "has_executable_mime_mismatch",
]
