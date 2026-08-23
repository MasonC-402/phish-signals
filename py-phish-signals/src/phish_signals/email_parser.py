"""Raw .eml and pasted-message parsing.

Port of ``typescript/src/emailParser.ts``.

Builds on the stdlib :mod:`email` package (with ``email.policy.default``)
for MIME structure, in place of the reference's ``mailparser``. Header
lines needed for the Received-chain/auth checks are read separately, from
:mod:`phish_signals.header_parser`, on the raw header block text — those
checks need the *original wire text* of each header line, not a
MIME-library's parsed/decoded representation of it.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from email import message_from_string, policy
from email.message import EmailMessage, MIMEPart
from email.utils import parsedate_to_datetime
from typing import cast
from urllib.parse import urlsplit

from .domains import registrable_domain
from .header_parser import parse_header_text
from .qr_check import DecodableImage, scan_images_for_qr_codes
from .sanitize import strip_dangerous_unicode
from .types import (
    AttachmentSummary,
    LinkMismatch,
    ParsedEmail,
    RawAttachmentMeta,
    ZipEntry,
)
from .zip_check import list_zip_entries

# The trailing character class deliberately excludes the punctuation that
# commonly *follows* a URL rather than belonging to it — an HTML-to-text
# rendering of a link as "[http://example.com]" would otherwise leave a
# trailing "]" glued to every extracted URL.
_URL_PATTERN = re.compile(r"\bhttps?://[^\s<>\"'`\])}]+", re.IGNORECASE)
_TRAILING_PUNCTUATION = re.compile(r"[.,;:!?'\")\]}>]+$")

_ANCHOR_PATTERN = re.compile(
    r"""<a\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>""",
    re.IGNORECASE | re.DOTALL,
)
_HREF_PATTERN = re.compile(r"""\bhref\s*=\s*["'](https?://[^"']+)["']""", re.IGNORECASE)

# href="data:...", href="javascript:...", href="vbscript:..." — schemes with
# no hostname at all. A data: URI can encode an entire fake login page
# inline; javascript:/vbscript: run code directly on click.
_DANGEROUS_SCHEME_PATTERN = re.compile(
    r"""\bhref\s*=\s*["'](data|javascript|vbscript):""", re.IGNORECASE
)


def _clean_url(url: str) -> str:
    return _TRAILING_PUNCTUATION.sub("", url)


def extract_urls(text: str | None) -> list[str]:
    if not text:
        return []
    return [u for u in (_clean_url(m) for m in _URL_PATTERN.findall(text)) if u]


def extract_hrefs(html: str | None) -> list[str]:
    """Links are pulled from the HTML part's href attributes as well as the
    plain text, since a benign plaintext part next to a malicious HTML part
    is the standard phishing layout.
    """
    if not html:
        return []
    return [_clean_url(m) for m in _HREF_PATTERN.findall(html)]


def find_dangerous_schemes(html: str | None) -> list[str]:
    if not html:
        return []
    found: list[str] = []
    for m in _DANGEROUS_SCHEME_PATTERN.findall(html):
        scheme = m.lower()
        if scheme not in found:
            found.append(scheme)
    return found


_TAG_RE = re.compile(r"<[^>]*>")
_NBSP_RE = re.compile(r"&nbsp;", re.IGNORECASE)
_WHITESPACE_RE = re.compile(r"\s+")


def _strip_tags(html: str) -> str:
    return _WHITESPACE_RE.sub(" ", _NBSP_RE.sub(" ", _TAG_RE.sub(" ", html))).strip()


_AMP_RE = re.compile(r"&amp;", re.IGNORECASE)
_LT_RE = re.compile(r"&lt;", re.IGNORECASE)
_GT_RE = re.compile(r"&gt;", re.IGNORECASE)
_QUOT_RE = re.compile(r"&quot;", re.IGNORECASE)
_APOS_RE = re.compile(r"&#0?39;|&apos;", re.IGNORECASE)


def _decode_entities(value: str) -> str:
    value = _AMP_RE.sub("&", value)
    value = _LT_RE.sub("<", value)
    value = _GT_RE.sub(">", value)
    value = _QUOT_RE.sub('"', value)
    return _APOS_RE.sub("'", value)


_TEXT_URL_MATCH = re.compile(
    r"^(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/?#]|$)", re.IGNORECASE
)
_HTTP_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)
_WWW_PREFIX_RE = re.compile(r"^www\.", re.IGNORECASE)


def _url_hostname(url: str) -> str | None:
    """The equivalent of ``new URL(href).hostname``, or ``None`` on failure.

    Only the hostname is needed here (unlike url_check.py's fuller parser),
    so this stays a minimal, local helper rather than reaching into that
    module's private parsing internals.
    """
    try:
        hostname = urlsplit(url).hostname
    except ValueError:
        return None
    return hostname or None


def find_link_mismatches(html: str | None) -> list[LinkMismatch]:
    """<a href="http://evil.tk/login">https://paypal.com/account</a> — the
    anchor text names one destination and the href points at another.
    """
    if not html:
        return []
    mismatches: list[LinkMismatch] = []

    for match in _ANCHOR_PATTERN.finditer(html):
        href = _decode_entities(match.group(1).strip())
        text = _decode_entities(_strip_tags(match.group(2)))
        if not _HTTP_SCHEME_RE.match(href):
            continue

        # Only compare when the anchor text is itself a URL or a bare
        # domain — "Click here" tells us nothing.
        text_url_match = _TEXT_URL_MATCH.match(text)
        if not text_url_match:
            continue

        href_host = _url_hostname(href)
        if not href_host:
            continue

        claimed = registrable_domain(_WWW_PREFIX_RE.sub("", text_url_match.group(1)))
        actual = registrable_domain(_WWW_PREFIX_RE.sub("", href_host))
        if claimed != actual:
            mismatches.append(
                {
                    "text": text[:120],
                    "href": href[:300],
                    "claimedDomain": claimed,
                    "actualDomain": actual,
                }
            )

    return mismatches


# Header-block detection. Walks the top of the input and requires an actual
# contiguous header block there, rather than testing for a single header
# line anywhere in the input (which would misfire on an ordinary pasted
# body that happens to quote a "From:" line).
_HEADER_LINE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{1,40}:\s*\S")
_TRANSPORT_HEADER_RE = re.compile(
    r"^(from|received|return-path|delivered-to|message-id|dkim-signature|authentication-results):",
    re.IGNORECASE,
)
_FOLDED_CONTINUATION_RE = re.compile(r"^[ \t]+\S")


def looks_like_raw_email(raw: str) -> bool:
    lines = raw[:8000].split("\n")
    header_count = 0
    saw_transport_header = False

    for line in lines:
        if line.strip() == "":
            break  # blank line ends the header block
        if _HEADER_LINE_RE.match(line):
            header_count += 1
            if _TRANSPORT_HEADER_RE.match(line):
                saw_transport_header = True
        elif _FOLDED_CONTINUATION_RE.match(line):
            continue  # folded continuation of the previous header
        else:
            break  # prose — not a header block

    # Two headers is enough on its own; a single one counts only if it's a
    # real transport header rather than something like "Note: ..." opening
    # a message.
    return header_count >= 2 or (header_count == 1 and saw_transport_header)


def _hash_attachment(content: bytes) -> dict[str, str]:
    """Digests only, never interpretation: the bytes are hashed as an
    opaque blob. MD5 and SHA-1 are included alongside SHA-256 despite both
    being broken for collision resistance, because they're still what a lot
    of existing hash-indexed threat intel keys on for this kind of
    "is this a known-bad file" lookup.
    """
    return {
        "md5": hashlib.md5(content).hexdigest(),
        "sha1": hashlib.sha1(content).hexdigest(),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _zip_fields(content: bytes | None) -> dict[str, list[ZipEntry] | bool]:
    """Attempted on every content-buffered attachment, regardless of
    filename or declared type — :func:`~phish_signals.zip_check.list_zip_entries`
    itself sniffs the actual bytes and returns 'not-zip' immediately for
    anything that isn't, so this is cheap for the common non-archive case
    and, unlike a filename check, isn't evaded by an attachment renamed to
    ".zipx" or given no extension at all.
    """
    if not content:
        return {}
    result = list_zip_entries(content)
    if result["status"] == "ok":
        return {"zipEntries": result["entries"]} if result["entries"] else {}
    if result["status"] == "unreadable":
        return {"zipUnreadable": True}
    return {}


def _summarize_attachments(
    attachments: list[RawAttachmentMeta] | None,
) -> tuple[list[AttachmentSummary], int]:
    items = attachments or []
    files: list[AttachmentSummary] = []
    for a in items:
        if a.get("contentDisposition") == "inline" or a.get("related"):
            continue
        summary: dict[str, object] = {
            "filename": a.get("filename") or "(unnamed)",
            "contentType": a.get("contentType") or "unknown",
            "size": a.get("size") or 0,
        }
        content = a.get("content")
        if content:
            summary.update(_hash_attachment(content))
        summary.update(_zip_fields(content))
        files.append(cast(AttachmentSummary, summary))

    image_count = sum(
        1 for a in items if (a.get("contentType") or "").startswith("image/")
    )
    return files, image_count


def _dedupe(values: list[str]) -> list[str]:
    seen: list[str] = []
    for v in values:
        if v not in seen:
            seen.append(v)
    return seen


def _scan_for_qr_code_urls(
    attachments: list[RawAttachmentMeta] | None,
) -> tuple[list[str], int]:
    """QR scanning runs over every image found — including inline ones —
    unlike :func:`_summarize_attachments`'s ``files`` list, since an inline
    embedded logo/banner-shaped image is exactly where a phishing kit hides
    a QR code meant to be seen, not downloaded.
    """
    images: list[DecodableImage] = [
        {"contentType": a.get("contentType") or "", "content": a["content"]}
        for a in (attachments or [])
        if (a.get("contentType") or "").lower().startswith("image/")
        and a.get("content")
    ]

    scanned = scan_images_for_qr_codes(images)
    urls = _dedupe(
        [u for payload in scanned["payloads"] for u in extract_urls(payload)]
    )
    return urls, scanned["scannedCount"]


def _iso_utc_millis(dt: datetime) -> str:
    utc = dt.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def _parsed_date(value: str | None) -> str | None:
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    return _iso_utc_millis(dt)


def _walk_parts(msg: MIMEPart, in_related: bool = False):
    if msg.is_multipart():
        subtype = msg.get_content_subtype()
        for part in msg.iter_parts():
            yield from _walk_parts(part, in_related or subtype == "related")
    else:
        yield msg, in_related


def _extract_raw_attachments(msg: EmailMessage) -> list[RawAttachmentMeta]:
    try:
        body_plain = msg.get_body(preferencelist=("plain",))
    except Exception:
        body_plain = None
    try:
        body_html = msg.get_body(preferencelist=("html",))
    except Exception:
        body_html = None
    body_ids = {id(p) for p in (body_plain, body_html) if p is not None}

    raw_attachments: list[RawAttachmentMeta] = []
    for part, in_related in _walk_parts(msg):
        if id(part) in body_ids:
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        raw_attachments.append(
            {
                "filename": part.get_filename() or "",
                "contentType": part.get_content_type(),
                "size": len(payload),
                "contentDisposition": part.get_content_disposition() or "",
                "related": in_related,
                "content": payload,
            }
        )
    return raw_attachments


def _get_text_body(msg: EmailMessage) -> str:
    try:
        part = msg.get_body(preferencelist=("plain",))
        if part is not None:
            return part.get_content()
    except Exception:
        pass
    # No plain part — fall back to a stripped-tags rendering of the HTML
    # part, the closest stdlib-only equivalent to the reference's
    # html-to-text conversion (mailparser always populates `.text` this way
    # when there is no separate text/plain part).
    html = _get_html_body(msg)
    return _strip_tags(html) if html else ""


def _get_html_body(msg: EmailMessage) -> str:
    try:
        part = msg.get_body(preferencelist=("html",))
        if part is not None:
            return part.get_content()
    except Exception:
        pass
    return ""


def parse_email(
    raw_content: str, extra_attachments: list[RawAttachmentMeta] | None = None
) -> ParsedEmail:
    if looks_like_raw_email(raw_content):
        msg = message_from_string(raw_content, policy=policy.default)

        text_body = _get_text_body(msg)
        html_body = _get_html_body(msg)

        # extra_attachments, not the message's own MIME attachments,
        # whenever the caller supplied it. Only msg_parser.py's caller ever
        # does — its reconstructed text (real preserved headers, or a
        # synthesized "From: ...\r\nSubject: ..." block) satisfies
        # looks_like_raw_email() above, landing in this branch, but that
        # reconstructed text has no real MIME attachment parts of its own
        # (there aren't any — it's headers plus body only), so a .msg's
        # attachments would otherwise silently vanish here.
        source_attachments = (
            extra_attachments
            if extra_attachments is not None
            else _extract_raw_attachments(msg)
        )
        files, image_count = _summarize_attachments(source_attachments)
        qr_code_urls, qr_images_scanned = _scan_for_qr_code_urls(source_attachments)

        from_header = msg.get("from")
        from_value = str(from_header) if from_header is not None else None
        reply_to_header = msg.get("reply-to")
        reply_to_value = str(reply_to_header) if reply_to_header is not None else None
        subject = msg.get("subject")
        subject_value = str(subject) if subject is not None else None
        date_value = _parsed_date(msg.get("date"))

        # Raw lines in wire order, from the header block only — needed
        # because the Received chain is only meaningful in the order the
        # servers wrote it, which a MIME-library's own header representation
        # doesn't preserve as plain text.
        normalized = raw_content.replace("\r\n", "\n")
        header_block = normalized.split("\n\n", 1)[0]
        parsed_headers = parse_header_text(header_block)

        return_path = parsed_headers["headers"].get("return-path")
        return_path_value = return_path if isinstance(return_path, str) else None

        return {
            "isRawEmail": True,
            "from": from_value,
            "returnPath": return_path_value,
            "replyTo": reply_to_value,
            "subject": subject_value,
            "date": date_value,
            "headers": parsed_headers["headers"],
            "headerLines": parsed_headers["headerLines"],
            "textBody": text_body,
            "htmlBody": html_body,
            # Subject line carries the urgency bait as often as the body
            # does, and the HTML part may hold text the plaintext
            # alternative deliberately omits. stripDangerousUnicode()
            # matters here because it's the one place this scan actually
            # happens — zero-width characters inserted mid-word must be
            # stripped before matching, not just before rendering.
            "scanText": strip_dangerous_unicode(
                "\n".join([subject_value or "", text_body, _strip_tags(html_body)])
            ),
            "urls": _dedupe(
                [
                    *extract_urls(text_body),
                    *extract_hrefs(html_body),
                    *extract_urls(_strip_tags(html_body)),
                    *qr_code_urls,
                ]
            ),
            "linkMismatches": find_link_mismatches(html_body),
            "dangerousSchemes": find_dangerous_schemes(html_body),
            "attachments": files,
            "imageCount": image_count,
            "qrCodeUrls": qr_code_urls,
            "qrImagesScanned": qr_images_scanned,
        }

    # Plain paste, or a .msg whose original MIME structure couldn't be
    # preserved — attachment metadata comes from the caller instead, since
    # it isn't part of the raw text itself.
    files, image_count = _summarize_attachments(extra_attachments)

    return {
        "isRawEmail": False,
        "from": None,
        "returnPath": None,
        "replyTo": None,
        "subject": None,
        "date": None,
        "headers": None,
        "headerLines": [],
        "textBody": raw_content,
        "htmlBody": None,
        "scanText": strip_dangerous_unicode(raw_content),
        "urls": _dedupe(extract_urls(raw_content)),
        "linkMismatches": [],
        "dangerousSchemes": [],
        "attachments": files,
        "imageCount": image_count,
        # Never populated on this path: a plain-text paste has no image
        # bytes at all, and a .msg's extra_attachments never carries
        # `content` — the same boundary the hash fields above respect.
        "qrCodeUrls": [],
        "qrImagesScanned": 0,
    }


__all__ = [
    "extract_hrefs",
    "extract_urls",
    "find_dangerous_schemes",
    "find_link_mismatches",
    "looks_like_raw_email",
    "parse_email",
]
