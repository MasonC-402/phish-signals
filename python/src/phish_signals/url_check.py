"""Pure structural/heuristic URL analysis — no external API calls.

Port of ``typescript/src/urlCheck.ts``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .domains import (
    KNOWN_BRAND_DOMAINS,
    brand_label,
    normalize_confusables,
    registrable_domain,
)
from .punycode import describe_hostname
from .types import Signal, SignalResult, UrlAnalysis, UrlRisk

SUSPICIOUS_TLDS: list[str] = [
    ".zip",
    ".mov",
    ".xyz",
    ".top",
    ".club",
    ".gq",
    ".tk",
    ".ml",
    ".cf",
    ".ga",
    ".work",
    ".click",
    ".link",
    ".support",
    ".icu",
    ".rest",
    ".quest",
    ".cam",
    ".sbs",
    ".cfd",
    ".bond",
    ".lol",
    ".beauty",
    ".autos",
    ".monster",
]

URL_SHORTENERS: list[str] = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "shorturl.at",
    "cutt.ly",
    "tiny.cc",
    "rb.gy",
    "shorte.st",
    "bl.ink",
    "lnkd.in",
    "trib.al",
    "tny.im",
    "s.id",
]

# Extensions that, delivered straight from a link in an email, are a payload
# rather than a document.
DANGEROUS_DOWNLOAD_EXTENSIONS: list[str] = [
    ".exe",
    ".scr",
    ".msi",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".jar",
    ".ps1",
    ".hta",
    ".iso",
    ".img",
    ".vhd",
    ".lnk",
    ".7z",
    ".rar",
    ".cab",
]

# Ports that aren't a normal way to reach a public web page.
EXPECTED_PORTS: frozenset[str] = frozenset({"", "80", "443", "8443"})

_CREDENTIAL_KEYWORDS = re.compile(
    r"\b(login|signin|sign-in|verify|verification|secure|account|update|"
    r"confirm|password|credential|authenticate|unlock|recover)\b",
    re.IGNORECASE,
)

_DEFAULT_PORTS: dict[str, str] = {
    "http": "80",
    "https": "443",
    "ws": "80",
    "wss": "443",
    "ftp": "21",
}

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
_CONTROL_OR_SPACE = re.compile(r"[\t\n\r]")


def levenshtein(a: str, b: str) -> int:
    matrix: list[list[int]] = [[i] + [0] * len(b) for i in range(len(a) + 1)]
    for j in range(len(b) + 1):
        matrix[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            matrix[i][j] = (
                matrix[i - 1][j - 1]
                if a[i - 1] == b[j - 1]
                else min(matrix[i - 1][j - 1], matrix[i][j - 1], matrix[i - 1][j]) + 1
            )
    return matrix[len(a)][len(b)]


def _is_known_brand(host: str) -> bool:
    """True when the host is the brand itself or a subdomain of it."""
    return any(
        host == brand or host.endswith("." + brand) for brand in KNOWN_BRAND_DOMAINS
    )


def check_typosquat(hostname: str) -> str | None:
    host = hostname.lower().removeprefix("www.").removesuffix(".")
    if _is_known_brand(host):
        return None

    # Compare the registrable domain, so login.paypa1.com is caught by way of
    # paypa1.com rather than being diluted by its subdomain.
    candidate = registrable_domain(host)
    if _is_known_brand(candidate):
        return None

    normalized_candidate = normalize_confusables(candidate)
    for brand in KNOWN_BRAND_DOMAINS:
        if normalized_candidate == normalize_confusables(brand):
            return brand

    for brand in KNOWN_BRAND_DOMAINS:
        # An edit distance of 1-2 is only meaningful between strings of similar
        # length; this also bounds the O(n*m) matrix below, which was otherwise
        # allocated against an attacker-controlled hostname up to the full input
        # length, 20 times per URL.
        if abs(len(candidate) - len(brand)) > 2:
            continue
        distance = levenshtein(candidate, brand)
        if 0 < distance <= 2:
            return brand

    return None


def brand_impersonation(hostname: str) -> str | None:
    """A brand name showing up as a subdomain label, or hyphenated into an
    unrelated registrable domain: paypal.com.secure-verify.net,
    secure-paypal.com, microsoft-account.login.xyz.
    """
    host = hostname.lower().removesuffix(".")
    if _is_known_brand(host):
        return None

    registrable = registrable_domain(host)
    if _is_known_brand(registrable):
        return None

    subdomain_part = host[: max(0, len(host) - len(registrable))]
    sub_labels = [label for label in subdomain_part.split(".") if label]
    registrable_tokens = registrable.split(".")[0].split("-")

    for brand in KNOWN_BRAND_DOMAINS:
        label = brand_label(brand)

        # In a subdomain: paypal.com.evil.net, login.microsoft.evil.net
        if any(sl == label or label in sl.split("-") for sl in sub_labels):
            return brand

        # Hyphenated into the registrable domain: secure-paypal.com. A bare
        # single-token match is skipped deliberately — that would flag
        # legitimate regional domains like paypal.co.uk that just aren't on
        # the brand list.
        if len(registrable_tokens) > 1 and label in registrable_tokens:
            return brand

    return None


_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_DECIMAL_RE = re.compile(r"^\d+$")
_HEX_RE = re.compile(r"^0x[0-9a-f]+$", re.IGNORECASE)
_OCTAL_RE = re.compile(r"^0[0-7]+$")
_IPV6_CHARS_RE = re.compile(r"^[a-f0-9:]+$", re.IGNORECASE)


def is_ip_literal(hostname: str) -> bool:
    host = hostname.removeprefix("[").removesuffix("]")
    # Dotted quad, with the octets actually validated.
    if _IPV4_RE.match(host):
        return all(int(octet) <= 255 for octet in host.split("."))
    # Bare decimal (http://3232235777/), hex (0x7f000001), and octal forms. The
    # WHATWG URL parser normalizes most of these to dotted quad before we see
    # them, but not every caller goes through it.
    if _DECIMAL_RE.match(host) or _HEX_RE.match(host) or _OCTAL_RE.match(host):
        return True
    return ":" in host and bool(_IPV6_CHARS_RE.match(host))


def _has_punycode(hostname: str) -> bool:
    return "xn--" in hostname.lower()


def _has_suspicious_tld(hostname: str) -> bool:
    host = hostname.lower()
    return any(host.endswith(tld) for tld in SUSPICIOUS_TLDS)


def _is_shortener(hostname: str) -> bool:
    host = hostname.lower()
    return any(host == s or host.endswith("." + s) for s in URL_SHORTENERS)


def _excessive_subdomains(hostname: str) -> bool:
    return len(hostname.split(".")) >= 5


def _credential_keyword_count(path_and_query: str) -> int:
    matches = _CREDENTIAL_KEYWORDS.findall(path_and_query)
    return len({m.lower() for m in matches})


def _has_dangerous_download(pathname: str) -> str | None:
    lower = pathname.lower()
    return next(
        (ext for ext in DANGEROUS_DOWNLOAD_EXTENSIONS if lower.endswith(ext)), None
    )


# http://real-looking-domain.com@evil.com/ — the browser goes to evil.com.
# Only the authority is examined: testing the whole remainder would score
# every unsubscribe link carrying the recipient's address in a query
# parameter as this trick.
_SCHEME_PREFIX_RE = re.compile(r"^https?://", re.IGNORECASE)
_AUTHORITY_END_RE = re.compile(r"[/?#]")


def _has_at_symbol_trick(url: str) -> bool:
    authority = _SCHEME_PREFIX_RE.sub("", url)
    authority = _AUTHORITY_END_RE.split(authority, maxsplit=1)[0]
    return "@" in authority


@dataclass(frozen=True)
class _ParsedUrl:
    hostname: str
    port: str
    pathname: str
    search: str


def _idna_encode_host(host: str) -> str | None:
    if host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _parse_url(url: str) -> _ParsedUrl | None:
    """A best-effort approximation of the WHATWG URL parser.

    Not a full implementation — this package has no runtime dependencies, so
    there is no bundled WHATWG-compliant parser to lean on, and stdlib's
    :mod:`urllib.parse` is a plain splitter rather than one. Handles what the
    checks below actually need: scheme validation, a lowercased/IDNA-encoded
    hostname (matching what a real ``new URL()`` call hands the TypeScript
    side before ``describeHostname`` ever sees it), a default-port-aware
    port string, and a pathname that always starts with ``/``. Returns
    ``None`` on anything that doesn't parse, the same as the reference's
    ``try { new URL(url) } catch { return null }``.
    """
    # WHATWG strips leading/trailing C0 control + space and removes all tab/
    # newline characters wherever they occur before parsing anything else.
    cleaned = _CONTROL_OR_SPACE.sub("", url.strip())
    if not _SCHEME_RE.match(cleaned):
        return None

    try:
        parts = urlsplit(cleaned)
    except ValueError:
        return None

    if not parts.netloc:
        return None

    try:
        hostname_raw = parts.hostname
        port_num = parts.port
    except ValueError:
        return None

    if not hostname_raw:
        return None

    if ":" in hostname_raw:
        # An IPv6 literal — no IDNA encoding applies.
        hostname = hostname_raw
    else:
        encoded = _idna_encode_host(hostname_raw)
        if encoded is None:
            return None
        hostname = encoded

    scheme = parts.scheme.lower()
    default_port = _DEFAULT_PORTS.get(scheme)
    if port_num is None or (default_port is not None and str(port_num) == default_port):
        port = ""
    else:
        port = str(port_num)

    pathname = parts.path or "/"
    search = f"?{parts.query}" if parts.query else ""

    return _ParsedUrl(hostname=hostname, port=port, pathname=pathname, search=search)


def analyze_url(url: str) -> UrlAnalysis:
    parsed = _parse_url(url)
    if not parsed:
        return {"url": url, "risk": "unknown", "detail": "Could not parse this URL."}

    hostname = parsed.hostname
    reasons: list[str] = []
    risk_score = 0

    typosquat_match = check_typosquat(hostname)
    if typosquat_match:
        reasons.append(f'Closely resembles "{typosquat_match}" (likely typosquat)')
        risk_score += 35

    # Mutually exclusive with the above — a lookalike domain and a
    # brand-bearing subdomain are the same intent, and scoring both would
    # double-count it.
    impersonated_brand = brand_impersonation(hostname) if not typosquat_match else None
    if impersonated_brand:
        reasons.append(
            f'Puts "{brand_label(impersonated_brand)}" in the hostname, but the '
            f'real domain is "{registrable_domain(hostname)}"'
        )
        risk_score += 35

    if _has_at_symbol_trick(url):
        reasons.append(
            'Contains "@" trick. The real destination differs from what appears before '
            "the @"
        )
        risk_score += 35

    if is_ip_literal(hostname):
        reasons.append("Uses a raw IP address instead of a domain name")
        risk_score += 25

    # Decoded rather than merely detected: "uses punycode" is true but
    # useless, whereas showing that xn--pypal-4ve.com reads as "pаypal.com"
    # with a Cyrillic 'а' is the whole finding. Mixed-script and whole-script
    # confusables are separate cases — аррӏе.com is not mixed at all, it is
    # uniformly Cyrillic, so a mixed-script test alone never catches it.
    unicode_desc = describe_hostname(hostname)
    if unicode_desc["mixed"]:
        scripts_joined = " with ".join(unicode_desc["scripts"])
        reasons.append(
            f'Hostname reads as "{unicode_desc["decoded"]}" and mixes {scripts_joined} '
            "characters in a single label, a homograph trick for faking a "
            "familiar domain"
        )
        risk_score += 35
    elif unicode_desc["confusable"]:
        non_latin = "/".join(s for s in unicode_desc["scripts"] if s != "Latin")
        reasons.append(
            f'Hostname reads as "{unicode_desc["decoded"]}" but is written entirely in '
            f"{non_latin} characters chosen to look like Latin letters"
        )
        risk_score += 35
    elif unicode_desc["decoded"]:
        scripts_joined = ", ".join(unicode_desc["scripts"])
        reasons.append(
            f'Internationalized domain, reads as "{unicode_desc["decoded"]}" '
            f"({scripts_joined}). Legitimate in itself, but verify it is the domain "
            "you expect"
        )
        risk_score += 10
    elif _has_punycode(hostname):
        reasons.append(
            "Uses punycode encoding that could not be decoded, often used to fake "
            "lookalike domains"
        )
        risk_score += 25

    dangerous_ext = _has_dangerous_download(parsed.pathname)
    if dangerous_ext:
        reasons.append(
            f"Links directly to a {dangerous_ext} file, an executable or archive "
            "payload rather than a document"
        )
        risk_score += 30

    if _excessive_subdomains(hostname):
        reasons.append(
            "Unusually long subdomain chain, possibly hiding the real domain"
        )
        risk_score += 15

    if parsed.port not in EXPECTED_PORTS:
        reasons.append(
            f"Served from a non-standard port ({parsed.port}), unusual for a "
            "legitimate public site"
        )
        risk_score += 15

    if _has_suspicious_tld(hostname):
        tld = hostname.rsplit(".", 1)[-1] if "." in hostname else hostname
        reasons.append(f"Uses a TLD ({tld}) commonly associated with abuse")
        risk_score += 10

    if _is_shortener(hostname):
        reasons.append("Uses a URL shortener, destination is hidden")
        risk_score += 10

    credential_words = _credential_keyword_count(parsed.pathname + parsed.search)
    if credential_words >= 2:
        reasons.append("URL path contains multiple login/verification keywords")
        risk_score += 10

    risk_score = min(risk_score, 100)

    risk: UrlRisk = "clean"
    if risk_score >= 30:
        risk = "malicious"
    elif risk_score >= 10:
        risk = "suspicious"

    return {
        "url": url,
        "hostname": hostname,
        "risk": risk,
        "detail": "; ".join(reasons)
        if reasons
        else "No structural red flags detected.",
        "riskScore": risk_score,
        "decodedHost": unicode_desc["decoded"],
        "scripts": unicode_desc["scripts"],
    }


MAX_URLS_ANALYZED = 25


def check_urls(urls: list[str] | None) -> list[UrlAnalysis]:
    if not urls:
        return []
    return [analyze_url(u) for u in urls[:MAX_URLS_ANALYZED]]


def summarize_url_signals(analyses: list[UrlAnalysis]) -> list[Signal]:
    """Turns the per-URL analysis into evidence for the scoring model.

    Emitted as one signal per severity band rather than one per URL: twenty
    links to the same malicious host is one finding, not twenty.
    """
    malicious = [a for a in analyses if a["risk"] == "malicious"]
    suspicious = [a for a in analyses if a["risk"] == "suspicious"]
    signals: list[Signal] = []

    def host_list(items: list[UrlAnalysis]) -> str:
        seen: list[str] = []
        for item in items:
            host = item.get("hostname")
            if host and host not in seen:
                seen.append(host)
        return ", ".join(seen[:3])

    if malicious:
        signals.append(
            {
                "id": "malicious_links",
                "category": "payload",
                "severity": "high",
                "label": "High-Risk Links",
                "detail": (
                    f"{len(malicious)} link{'' if len(malicious) == 1 else 's'} "
                    f"showed strong structural red flags ({host_list(malicious)}). "
                    "See the Links table for the specific reason on each."
                ),
                "mitre": ["T1566.002", "T1204.001"],
            }
        )

    if suspicious:
        signals.append(
            {
                "id": "suspicious_links",
                "category": "payload",
                "severity": "medium",
                "label": "Suspicious Links",
                "detail": (
                    f"{len(suspicious)} link{'' if len(suspicious) == 1 else 's'} "
                    f"showed weaker but notable red flags ({host_list(suspicious)})."
                ),
                "mitre": ["T1566.002"],
            }
        )

    # Explicitly stated rather than left implicit: a message with nothing to
    # click and nothing to open cannot deliver a payload directly, which is
    # genuine evidence toward it being benign.
    if len(analyses) == 0:
        signals.append(
            {
                "id": "no_links_present",
                "category": "payload",
                "severity": "info",
                "benign": True,
                "label": "No Links in the Message",
                "detail": (
                    "The message contains no links at all, so there is nothing to "
                    "click. It could still be a reply-to-me fraud attempt, which the "
                    "social-engineering checks cover."
                ),
            }
        )

    return signals


def check_qr_codes(qr_code_urls: list[str] | None) -> SignalResult:
    """A transparency signal that a QR code was found and followed.

    The decoded URL itself is already scored like any other link by
    :func:`summarize_url_signals`, since the parser folds it into the same
    ``urls`` list. Without this, a QR code resolving to an otherwise-
    unremarkable link would leave no trace at all that the tool found and
    followed it.
    """
    urls = qr_code_urls or []
    if not urls:
        return {"signals": []}

    examples = ", ".join(urls[:3])

    return {
        "signals": [
            {
                "id": "qr_code_link",
                "category": "payload",
                "severity": "low",
                "label": "QR Code Contains a Link",
                "detail": (
                    "An embedded image contains a QR code that decodes to "
                    f"{'a link' if len(urls) == 1 else f'{len(urls)} links'}: "
                    f"{examples}. It was analyzed the same as any other link in the "
                    "message — see the Links table for its risk assessment. Routing a "
                    "reader through a QR code is an increasingly common way to get a "
                    "link past text-based filtering and past someone glancing at "
                    "where a link actually points."
                ),
                "mitre": ["T1566.002"],
            }
        ],
    }


__all__ = [
    "DANGEROUS_DOWNLOAD_EXTENSIONS",
    "EXPECTED_PORTS",
    "MAX_URLS_ANALYZED",
    "SUSPICIOUS_TLDS",
    "URL_SHORTENERS",
    "analyze_url",
    "brand_impersonation",
    "check_qr_codes",
    "check_typosquat",
    "check_urls",
    "is_ip_literal",
    "levenshtein",
    "summarize_url_signals",
]
