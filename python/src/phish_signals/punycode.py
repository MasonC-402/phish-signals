"""RFC 3492 punycode decoding, plus Unicode script identification.

Mirrors ``typescript/src/punycode.ts``.

A URL parser converts any non-ASCII hostname to its ``xn--`` form before this
package ever sees it, so a homograph domain arrives as an opaque string like
``xn--pypal-4ve.com``. Flagging that as "uses punycode" is true but useless —
the point of the attack is what it *looks* like. Decoding it back and naming
the scripts involved turns the finding into something a reader can act on:
they can see the Cyrillic character sitting in the middle of a word they
thought was Latin.

Written out rather than delegated to :mod:`encodings.idna`, matching the
TypeScript side's reasons and adding one of its own: stdlib IDNA decoding
raises on input that this analyzer must survive (over-long labels, malformed
trailers, labels that fail IDNA validity rules). Attacker-supplied hostnames
are exactly the input most likely to be malformed, and "the parser threw" must
never be indistinguishable from "nothing suspicious here" — so every failure
path below returns ``None`` and lets the caller carry on with the raw label.
"""

from __future__ import annotations

from .types import HostnameDescription

_BASE = 36
_T_MIN = 1
_T_MAX = 26
_SKEW = 38
_DAMP = 700
_INITIAL_BIAS = 72
_INITIAL_N = 128
_DELIMITER = "-"
_BASE_MINUS_T_MIN = _BASE - _T_MIN
_MAX_INT = 0x7FFFFFFF


def _digit_value(code_point: int) -> int:
    """Map a basic code point to its 0..35 digit value, or ``_BASE`` if it isn't one.

    Bounds are checked explicitly on both ends. The reference C implementation
    writes these as a single subtraction (``cp - 0x30 < 0x0a``) relying on
    unsigned wraparound, which does not hold in a language with signed or
    arbitrary-precision integers: any character below '0' would produce a
    negative number that passes the test and decodes as a bogus digit instead
    of being rejected.
    """
    if 0x30 <= code_point <= 0x39:
        return code_point - 0x30 + 26  # '0'-'9' => 26..35
    if 0x41 <= code_point <= 0x5A:
        return code_point - 0x41  # 'A'-'Z' => 0..25
    if 0x61 <= code_point <= 0x7A:
        return code_point - 0x61  # 'a'-'z' => 0..25
    return _BASE


def _adapt(delta: int, num_points: int, first_time: bool) -> int:
    scaled = delta // _DAMP if first_time else delta >> 1
    scaled += scaled // num_points

    k = 0
    while scaled > (_BASE_MINUS_T_MIN * _T_MAX) >> 1:
        scaled //= _BASE_MINUS_T_MIN
        k += _BASE
    # Integer division throughout: the reference uses Math.floor over float
    # division, which is the same value for the non-negative operands here but
    # loses precision on large deltas where Python's ints would not.
    return k + ((_BASE_MINUS_T_MIN + 1) * scaled) // (scaled + _SKEW)


def decode_label(value: str) -> str | None:
    """Decode one punycode label (without the ``xn--`` prefix).

    Returns ``None`` if the label is malformed or would overflow, rather than
    raising — see this module's docstring for why that distinction matters.
    """
    output: list[int] = []
    n = _INITIAL_N
    i = 0
    bias = _INITIAL_BIAS

    last_delimiter = value.rfind(_DELIMITER)
    for j in range(max(last_delimiter, 0)):
        code = ord(value[j])
        if code > 0x7F:
            return None  # the basic section must be ASCII
        output.append(code)

    index = last_delimiter + 1 if last_delimiter > 0 else 0

    while index < len(value):
        old_i = i

        w = 1
        k = _BASE
        while True:
            if index >= len(value):
                return None
            digit = _digit_value(ord(value[index]))
            index += 1
            if digit >= _BASE:
                return None
            if digit > (_MAX_INT - i) // w:
                return None  # overflow
            i += digit * w

            if k <= bias:
                t = _T_MIN
            elif k >= bias + _T_MAX:
                t = _T_MAX
            else:
                t = k - bias
            if digit < t:
                break

            if w > _MAX_INT // (_BASE - t):
                return None  # overflow
            w *= _BASE - t
            k += _BASE

        out_length = len(output) + 1
        bias = _adapt(i - old_i, out_length, old_i == 0)

        if i // out_length > _MAX_INT - n:
            return None  # overflow
        n += i // out_length
        i %= out_length

        output.insert(i, n)
        i += 1

    try:
        return "".join(chr(c) for c in output)
    except (ValueError, OverflowError):
        return None  # out-of-range code point


def decode_hostname(hostname: str) -> str | None:
    """Decode every ``xn--`` label in a hostname. ``None`` if none were present.

    A label that fails to decode is left in its raw ``xn--`` form rather than
    failing the whole hostname, so one malformed label does not blind the
    caller to the rest.
    """
    saw_punycode = False
    decoded_labels: list[str] = []

    for label in hostname.split("."):
        if label[:4].lower() != "xn--":
            decoded_labels.append(label)
            continue
        result = decode_label(label[4:])
        if result is None:
            decoded_labels.append(label)
            continue
        saw_punycode = True
        decoded_labels.append(result)

    return ".".join(decoded_labels) if saw_punycode else None


# Enough of the Unicode blocks to name what a lookalike domain is actually
# built from. Anything unlisted falls through as "Other", which is itself worth
# surfacing on a hostname.
_SCRIPT_RANGES: tuple[tuple[str, tuple[tuple[int, int], ...]], ...] = (
    ("Latin", ((0x41, 0x5A), (0x61, 0x7A), (0xC0, 0x24F), (0x1E00, 0x1EFF))),
    ("Greek", ((0x370, 0x3FF), (0x1F00, 0x1FFF))),
    ("Cyrillic", ((0x400, 0x52F), (0x2DE0, 0x2DFF), (0xA640, 0xA69F))),
    ("Armenian", ((0x530, 0x58F),)),
    ("Hebrew", ((0x590, 0x5FF),)),
    ("Arabic", ((0x600, 0x6FF), (0x750, 0x77F))),
    ("Devanagari", ((0x900, 0x97F),)),
    ("Thai", ((0xE00, 0xE7F),)),
    ("Han", ((0x4E00, 0x9FFF), (0x3400, 0x4DBF))),
    ("Hiragana", ((0x3040, 0x309F),)),
    ("Katakana", ((0x30A0, 0x30FF),)),
    ("Hangul", ((0xAC00, 0xD7AF), (0x1100, 0x11FF))),
)


def _is_common(code_point: int) -> bool:
    """Digits, hyphens, dots and underscores belong to every script.

    They appear in hostnames of every language and so carry no signal about
    which scripts a label actually draws on.
    """
    return (
        0x30 <= code_point <= 0x39
        or code_point == 0x2D
        or code_point == 0x2E
        or code_point == 0x5F
    )


def scripts_of(value: str) -> list[str]:
    """Name the Unicode scripts a string draws on, in order of first appearance.

    First-appearance order is part of the contract, not an accident: the
    reference implementation collects into a JS ``Set``, which iterates in
    insertion order, and conformance compares the resulting list by exact
    equality. A Python ``set`` would not preserve that, so this dedupes
    against a list instead.
    """
    found: list[str] = []

    for char in value:
        code_point = ord(char)
        if _is_common(code_point):
            continue

        name = "Other"
        for script_name, ranges in _SCRIPT_RANGES:
            if any(lo <= code_point <= hi for lo, hi in ranges):
                name = script_name
                break

        if name not in found:
            found.append(name)

    return found


# Non-Latin characters whose common renderings are visually indistinguishable
# from a Latin letter. A label built entirely from these is a "whole-script
# confusable": it isn't mixed-script at all, so a mixed-script test alone will
# never catch it. This is the mechanism behind the well-known "apple.com"
# demonstration domain, which is pure Cyrillic and renders identically.
_LATIN_CONFUSABLES = frozenset(
    # Cyrillic
    "авеёіјкмнор"
    "стухѕԁԛԝӏїә"
    "ғԃ"
    # Greek
    "αβγεζηικμνο"
    "ρστυχϲϳѵ"
    # Armenian
    "օոսցզգ"
)


def is_whole_script_confusable(label: str) -> bool:
    """True when every non-ASCII character in the label has a Latin lookalike.

    A label with no non-ASCII characters at all is not confusable — there is
    nothing being substituted.
    """
    non_ascii = [c for c in label if ord(c) > 0x7F]
    if not non_ascii:
        return False

    # Every non-ASCII character must be a known Latin lookalike, and so the
    # label must read as a Latin word overall — a genuine non-Latin word
    # contains characters with no Latin counterpart and falls out here.
    return all(c.lower() in _LATIN_CONFUSABLES for c in non_ascii)


def describe_hostname(hostname: str) -> HostnameDescription:
    """Describe a hostname's Unicode makeup.

    Reports two separate findings, because they are different attacks:

    ``mixed``
        One label draws on more than one script — Latin with a single Cyrillic
        character substituted in.
    ``confusable``
        One label is entirely non-Latin but every character has a Latin
        lookalike, so it renders as a Latin brand name.

    The confusable test is qualified by the TLD, because structurally a
    genuine non-Latin word is indistinguishable from a whole-script
    confusable: a Cyrillic place name is made entirely of Cyrillic letters
    with Latin lookalikes, exactly as a Cyrillic spelling of a Latin brand is.
    What separates them is where they live — a Cyrillic label under a Cyrillic
    TLD is an ordinary internationalized domain, whereas a Cyrillic label
    under .com is imitating something. Without this qualification the check
    flags the entire non-Latin-language internet.
    """
    decoded = decode_hostname(hostname)
    subject = decoded or hostname
    labels = subject.split(".")

    tld = labels[-1] if len(labels) > 1 else ""
    tld_is_ascii = bool(tld) and all(
        c.isascii() and (c.isalnum() or c == "-") for c in tld
    )

    return {
        "decoded": decoded,
        "scripts": scripts_of(subject),
        "mixed": any(len(scripts_of(label)) > 1 for label in labels),
        "confusable": tld_is_ascii
        and any(is_whole_script_confusable(label) for label in labels[:-1]),
    }


__all__ = [
    "decode_hostname",
    "decode_label",
    "describe_hostname",
    "is_whole_script_confusable",
    "scripts_of",
]
