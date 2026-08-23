"""Parses a pasted header block into headers plus ordered raw lines.

Port of ``typescript/src/headerParser.ts``.

Lightweight parser for a block of raw email headers pasted on their own —
not a full .eml message. Produces the same ``{headerLines, headers}`` shapes
``received_chain.analyze_received_chain`` and ``auth_check.check_authentication``
already consume, without doing any MIME/body parsing at all.
"""

from __future__ import annotations

import re
from typing import TypedDict

from .types import HeaderLine

# Header field-name per RFC 5322: printable US-ASCII excluding colon.
_HEADER_LINE = re.compile(r"^([!-9;-~]+):[ \t]?(.*)$")
_LEADING_WHITESPACE = re.compile(r"^[ \t]")


class ParsedHeaders(TypedDict):
    #: Raw header lines, unfolded, in original (wire) order.
    headerLines: list[HeaderLine]
    #: Lowercase header name -> first (i.e. most recent, since wire order is
    #: newest-first) value.
    headers: dict[str, object]


def parse_header_text(raw: str) -> ParsedHeaders:
    """Parse a block of raw header text. Mirrors ``parseHeaderText``."""
    normalized = raw.replace("\r\n", "\n")
    raw_lines = normalized.split("\n")

    # Unfold continuation lines (leading whitespace) into the header above them.
    lines: list[str] = []
    for line in raw_lines:
        if _LEADING_WHITESPACE.match(line) and lines:
            lines[-1] += " " + line.strip()
        elif line.strip() != "":
            lines.append(line)

    header_lines: list[HeaderLine] = []
    headers: dict[str, object] = {}

    for line in lines:
        match = _HEADER_LINE.match(line)
        if not match:
            continue
        key = match.group(1).lower()
        value = match.group(2)
        header_lines.append({"key": key, "line": line})
        # First occurrence wins: wire order is newest-first, so for a singular
        # header (From/Reply-To/Return-Path/Subject) the first instance is
        # the most recent one, matching what a real message would present.
        if key not in headers:
            headers[key] = value

    return {"headerLines": header_lines, "headers": headers}


__all__ = ["ParsedHeaders", "parse_header_text"]
