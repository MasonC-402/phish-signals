"""Input handling. Mirrors ``typescript/src/sanitize.ts``."""

from __future__ import annotations

import re
from typing import Any

DEFAULT_MAX_LENGTH = 50_000


class ValidationError(Exception):
    """An expected, caller-actionable input problem (bad length, wrong type).

    Safe to show verbatim to whoever submitted the input. Anything else raised
    during analysis should stay generic to the user and only be logged.
    """


# C0 controls minus tab (\x09), newline (\x0a) and carriage return (\x0d),
# which are ordinary in the message text this handles.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]")


def sanitize_input(raw: Any, max_length: int = DEFAULT_MAX_LENGTH) -> str:
    """Validate and normalize a submitted message body or header paste.

    Raises :class:`ValidationError` for non-strings, empty or whitespace-only
    input, and input over ``max_length``.
    """
    # An empty string is rejected as "Invalid input" rather than "cannot be
    # empty" — it fails the falsy check first, matching the reference
    # implementation's `!raw || typeof raw !== 'string'`.
    if not raw or not isinstance(raw, str):
        raise ValidationError("Invalid input")
    if len(raw.strip()) == 0:
        raise ValidationError("Input cannot be empty")
    if len(raw) > max_length:
        raise ValidationError(
            f"Content exceeds maximum length of {max_length:,} characters"
        )

    clean = _CONTROL_CHARS.sub("", raw)
    return clean.replace("\r\n", "\n")


# Codepoints commonly abused to spoof how text displays: zero-width characters
# (can split a brand name to dodge keyword matching), bidi marks/embedding/
# override/isolate controls (can visually reverse or hide part of a domain or
# filename), invisible math operators, and the BOM. Built from numeric code
# points rather than pasting the characters themselves, so this source file
# stays plain ASCII and the exact set being stripped is auditable at a glance.
_DANGEROUS_CODEPOINTS = (
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F,  # zero-width space/joiners, LRM/RLM
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # LRE/RLE/PDF/LRO/RLO
    0x2066, 0x2067, 0x2068, 0x2069,          # LRI/RLI/FSI/PDI
    0x2060, 0x2061, 0x2062, 0x2063, 0x2064,  # word joiner + invisible operators
    0xFEFF,                                  # BOM / zero-width no-break space
)

_DANGEROUS_UNICODE = re.compile(
    "[" + "".join(f"\\u{c:04x}" for c in _DANGEROUS_CODEPOINTS) + "]"
)


def strip_dangerous_unicode(value: Any) -> str:
    """Remove display-spoofing codepoints from header-derived text.

    Applied to anything header-derived (Subject, From, ...) before it is shown
    to an analyst. HTML-escaping alone prevents script injection but does not
    stop a crafted header from *visually* lying to the person reading it.
    Returns ``''`` for non-string input rather than raising.
    """
    if not isinstance(value, str):
        return ""
    return _DANGEROUS_UNICODE.sub("", value)


__all__ = [
    "DEFAULT_MAX_LENGTH",
    "ValidationError",
    "sanitize_input",
    "strip_dangerous_unicode",
]
