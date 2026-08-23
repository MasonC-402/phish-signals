"""Indicator extraction and defanging. Mirrors ``typescript/src/iocs.ts``.

A verdict is where the analyst's job actually starts. Whoever is looking at
this needs to paste indicators into a ticket, a blocklist, or a note to a
colleague — and needs them defanged, so pasting a live phishing URL into a
chat client does not render a clickable link or trigger a preview fetch that
tips off the sender.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from .types import (
    AttachmentSummary,
    Ioc,
    IocType,
    ReceivedChainAnalysis,
    UrlAnalysis,
)


def defang(value: str) -> str:
    """Break a live indicator so no client will linkify or fetch it.

    Follows what SOC tooling generally emits: the scheme is broken so nothing
    auto-links, and every dot is bracketed so no client re-detects a hostname.
    Deliberately applied to the whole string rather than just the authority —
    chat and ticket systems will happily linkify a bare "evil.tk/login" out of
    a path too.
    """
    result = re.sub(r"^http", "hxxp", value, count=1, flags=re.IGNORECASE)
    return result.replace(".", "[.]").replace("@", "[@]")


def refang(value: str) -> str:
    """Restore a defanged indicator to its live form.

    Order matters: the bracketed dot has to be restored before the scheme,
    otherwise ``hxxp[://]`` would collapse its own brackets into the wrong
    thing first.

    Also accepts ``hxxp[://]`` — bracketed around the colon-slash-slash rather
    than just the scheme letters — even though :func:`defang` never produces
    that form itself. It is a common convention from other tools, and
    refanging it costs nothing: the pattern simply never matches text that
    does not contain it.
    """
    result = re.sub(r"\[://\]", "://", value, flags=re.IGNORECASE)
    result = re.sub(r"\[\.\]", ".", result, flags=re.IGNORECASE)
    result = re.sub(r"\[@\]", "@", result, flags=re.IGNORECASE)
    return re.sub(r"^hxxp", "http", result, count=1, flags=re.IGNORECASE)


def _ioc(ioc_type: IocType, value: str) -> Ioc:
    return {"type": ioc_type, "value": value, "defanged": defang(value)}


# ASCII-only \w, matching the reference implementation. Python's \w is
# Unicode-aware by default, which would let a Cyrillic lookalike address
# through a check written to accept only ASCII mail-safe characters — exactly
# backwards for this package's purposes.
_ADDRESS_PATTERN = re.compile(
    r"[\w.+-]+@[\w.-]+\.[a-z]{2,}", re.IGNORECASE | re.ASCII
)


def _address_of(header_value: str | None) -> str | None:
    if not header_value:
        return None
    match = _ADDRESS_PATTERN.search(str(header_value))
    return match.group(0).lower() if match else None


def extract_iocs(
    *,
    urls: Iterable[UrlAnalysis] = (),
    attachments: Iterable[AttachmentSummary] = (),
    chain: ReceivedChainAnalysis | None = None,
    from_address: str | None = None,
    reply_to: str | None = None,
    return_path: str | None = None,
) -> list[Ioc]:
    """Collect the indicators worth handing to another tool, de-duplicated.

    Keyword-only, unlike the TypeScript side's single options object: Python
    has keyword arguments natively, so an argument bag adds nothing here, and
    six same-typed positional strings would be trivially easy to transpose.
    """
    iocs: list[Ioc] = []
    seen: set[tuple[str, str]] = set()

    def push(candidate: Ioc | None) -> None:
        if not candidate:
            return
        key = (candidate["type"], candidate["value"])
        if key in seen:
            return
        seen.add(key)
        iocs.append(candidate)

    # Only links that actually raised something. A clean link is not an
    # indicator, and including it would make the list useless to paste
    # anywhere.
    for url in urls:
        if url["risk"] not in ("malicious", "suspicious"):
            continue
        push(_ioc("url", url["url"]))
        hostname = url.get("hostname")
        if hostname:
            push(_ioc("domain", hostname))

    for address in (from_address, reply_to, return_path):
        parsed = _address_of(address)
        if parsed:
            push(_ioc("email", parsed))

    if chain:
        origin_ip = chain.get("originIp")
        if origin_ip:
            push(_ioc("ip", origin_ip))
        origin_host = chain.get("originHost")
        if origin_host:
            push(_ioc("domain", origin_host))

    for file in attachments:
        push(_ioc("filename", file["filename"]))
        # Hex digests have no dots, scheme, or "@" to break, so defang() is a
        # harmless no-op on them — no special-casing needed. All three
        # algorithms are listed together, matching how most real IOC reports
        # do it, since different blocklists still index by different ones.
        for algorithm in ("sha256", "sha1", "md5"):
            digest = file.get(algorithm)
            if digest:
                push(_ioc("hash", digest))

    return iocs


# --- Freeform IOC parsing -------------------------------------------------
#
# For pasted indicators that don't come from an analyzed email at all, so
# there's no UrlAnalysis or AttachmentSummary to read structure from, just raw
# text. Every token is refanged first, so a paste straight out of a defang
# tool or a SOC ticket classifies the same as a live value would.

_HASH_PATTERN = re.compile(
    r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", re.IGNORECASE | re.ASCII
)
_EMAIL_PATTERN = re.compile(
    r"^[\w.+-]+@[\w-]+(\.[\w-]+)+$", re.IGNORECASE | re.ASCII
)
_IPV4_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$", re.ASCII)
_IPV6_PATTERN = re.compile(r"^[a-f0-9:]{2,}$", re.IGNORECASE | re.ASCII)
_SCHEME_PATTERN = re.compile(r"^https?://", re.IGNORECASE | re.ASCII)
_HOST_AND_PATH_PATTERN = re.compile(
    r"^([a-z0-9.-]+)(/\S*)$", re.IGNORECASE | re.ASCII
)
_EXTENSION_PATTERN = re.compile(r"\.[a-z0-9]+$", re.ASCII)
_SURROUNDING_PUNCTUATION = re.compile(r"^[\[<(]+|[\]>),.;:!?]+$")

# Extensions worth recognizing as "this token is a filename," not a hostname —
# broader than the dangerous-extension sets in the attachment checks, since
# this only needs to identify a filename, not judge its risk. Deliberately
# excludes '.com': a real legacy DOS executable extension, but negligible next
# to how overwhelmingly it means the TLD in any pasted text. '.zip' and '.one'
# are both real, if rare, gTLDs too (a lookalike ".zip" domain is itself a
# known phishing trick), so a bare "example.zip" pasted with no path still
# reads as a filename here — an accepted residual ambiguity, not a gap worth a
# heavier disambiguation pass for two rare TLDs.
_FILENAME_EXTENSIONS = frozenset({
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".pif", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".msi", ".msp", ".ps1", ".psm1", ".jar",
    ".hta", ".cpl", ".reg", ".lnk", ".iso", ".docm", ".xlsm", ".pptm",
    ".dotm", ".xltm", ".potm", ".xlam", ".xlsb", ".doc", ".docx", ".xls",
    ".xlsx", ".ppt", ".pptx", ".pdf", ".zip", ".rar", ".7z", ".rtf", ".one",
})

# A domain needs a plausible alphabetic TLD — this alone is what keeps
# "invoice.exe" from being misread as a two-label hostname once the filename
# check above has already had first refusal at it.
_DOMAIN_PATTERN = re.compile(
    r"^(?!\d+$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$",
    re.IGNORECASE | re.ASCII,
)

_TOKEN_SEPARATORS = re.compile(r"[\s,;|]+")


def _extname_of(value: str) -> str:
    match = _EXTENSION_PATTERN.search(value.lower())
    return match.group(0) if match else ""


def _is_valid_ipv4(host: str) -> bool:
    return bool(_IPV4_PATTERN.match(host)) and all(
        int(octet) <= 255 for octet in host.split(".")
    )


def _classify_token(raw_token: str) -> Ioc | None:
    # Surrounding punctuation a paste commonly carries along: brackets, angle
    # brackets, trailing sentence punctuation.
    token = _SURROUNDING_PUNCTUATION.sub("", refang(raw_token)).strip()
    if not token:
        return None

    if _HASH_PATTERN.match(token):
        return _ioc("hash", token.lower())
    if _EMAIL_PATTERN.match(token):
        return _ioc("email", token.lower())

    if _SCHEME_PATTERN.match(token):
        return _ioc("url", token)

    host_and_path = _HOST_AND_PATH_PATTERN.match(token)
    if (
        host_and_path
        and _DOMAIN_PATTERN.match(host_and_path.group(1))
        and _extname_of(host_and_path.group(1)) not in _FILENAME_EXTENSIONS
    ):
        return _ioc("url", f"http://{token}")

    if _is_valid_ipv4(token):
        return _ioc("ip", token)
    if ":" in token and _IPV6_PATTERN.match(token) and len(token.split(":")) > 2:
        return _ioc("ip", token.lower())

    extension = _extname_of(token)
    if extension and extension in _FILENAME_EXTENSIONS and "/" not in token:
        return _ioc("filename", token)

    if _DOMAIN_PATTERN.match(token):
        return _ioc("domain", token.lower())

    return None


def parse_ioc_text(text: str) -> list[Ioc]:
    """Parse freeform pasted text — any mix of live or defanged indicators,
    any separator — into a de-duplicated list."""
    iocs: list[Ioc] = []
    seen: set[tuple[str, str]] = set()

    for raw_token in _TOKEN_SEPARATORS.split(text):
        candidate = _classify_token(raw_token)
        if not candidate:
            continue
        key = (candidate["type"], candidate["value"])
        if key in seen:
            continue
        seen.add(key)
        iocs.append(candidate)

    return iocs


__all__ = ["defang", "extract_iocs", "parse_ioc_text", "refang"]
