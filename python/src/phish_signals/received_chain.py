"""Received-header chain analysis.

Port of ``typescript/src/receivedChain.ts``.

The chain is the one part of a message an attacker cannot fully forge — they
can prepend whatever they like, but every hop *after* the injection point is
written by servers they don't control, and those hops record what the
sending machine actually was as well as what it claimed to be. Comparing
those two is a real spoofing check that needs no network access.
"""

from __future__ import annotations

import re
from email.utils import parsedate_to_datetime

from .domains import KNOWN_BRAND_DOMAINS, brand_label, registrable_domain
from .types import HeaderLine, ReceivedChainAnalysis, ReceivedHop, Signal

_IPV4_10 = re.compile(r"^10\.")
_IPV4_127 = re.compile(r"^127\.")
_IPV4_192_168 = re.compile(r"^192\.168\.")
_IPV4_169_254 = re.compile(r"^169\.254\.")
_IPV4_172 = re.compile(r"^172\.(1[6-9]|2\d|3[01])\.")


def is_private_ip(ip: str) -> bool:
    """RFC 1918 / loopback / link-local / unique-local.

    A message whose *entry* hop is one of these was injected inside a
    network rather than arriving from the internet, which is normal for
    internal mail and notable for anything claiming to be from an outside
    brand.
    """
    if _IPV4_10.match(ip):
        return True
    if _IPV4_127.match(ip):
        return True
    if _IPV4_192_168.match(ip):
        return True
    if _IPV4_169_254.match(ip):
        return True
    if _IPV4_172.match(ip):
        return True
    lower = ip.lower()
    return (
        lower == "::1"
        or lower.startswith("fc")
        or lower.startswith("fd")
        or lower.startswith("fe80")
    )


_RECEIVED_PREFIX_RE = re.compile(r"^received:\s*", re.IGNORECASE)
_WHITESPACE_RE = re.compile(r"\s+")
_HELO_RE = re.compile(r"\bfrom\s+([^\s(;]+)", re.IGNORECASE)
_BY_RE = re.compile(r"\bby\s+([^\s(;]+)", re.IGNORECASE)
_FROM_PAREN_RE = re.compile(r"\bfrom\s+[^\s(;]+\s*\(([^)]*)\)", re.IGNORECASE)
_BRACKET_IP_RE = re.compile(r"\[([0-9a-fA-F.:]+)\]")
_BRACKETED_RE = re.compile(r"\[[^\]]*\]")
_UNKNOWN_RE = re.compile(r"^unknown$", re.IGNORECASE)
_HAS_ALPHA_RE = re.compile(r"[a-z]", re.IGNORECASE)
_DATE_RE = re.compile(r";\s*([^;]+)$")


def _parse_hop(line: str, index: int) -> ReceivedHop:
    # Strip the header name and unfold continuation lines into one string.
    value = _WHITESPACE_RE.sub(" ", _RECEIVED_PREFIX_RE.sub("", line)).strip()

    helo_match = _HELO_RE.search(value)
    by_match = _BY_RE.search(value)

    # The parenthesised group right after `from` is where the receiving
    # server records what it independently observed: "from CLAIMED (RDNS [IP])".
    paren_match = _FROM_PAREN_RE.search(value)
    paren = paren_match.group(1) if paren_match else ""

    ip_match = _BRACKET_IP_RE.search(paren) or _BRACKET_IP_RE.search(value)
    ip = ip_match.group(1) if ip_match else None

    reverse_dns: str | None = None
    if paren:
        cleaned_paren = _BRACKETED_RE.sub("", paren).strip()
        host = cleaned_paren.split()[0] if cleaned_paren else ""
        # Receivers write "unknown" when the reverse lookup failed.
        if host and not _UNKNOWN_RE.match(host) and _HAS_ALPHA_RE.search(host):
            reverse_dns = host.removesuffix(".").lower()

    date_match = _DATE_RE.search(value)
    timestamp = date_match.group(1).strip() if date_match else None

    helo = helo_match.group(1).removesuffix(".").lower() if helo_match else None

    # Only meaningful when both sides are real hostnames.
    helo_mismatch = bool(
        helo
        and reverse_dns
        and "." in helo
        and "." in reverse_dns
        and registrable_domain(helo) != registrable_domain(reverse_dns)
    )

    return {
        "index": index,
        "helo": helo,
        "reverseDns": reverse_dns,
        "ip": ip,
        "by": by_match.group(1).removesuffix(".").lower() if by_match else None,
        "timestamp": timestamp,
        "heloMismatch": helo_mismatch,
        "private": is_private_ip(ip) if ip else False,
    }


def _parse_date(value: str | None) -> float | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if parsed is None:
        return None
    return parsed.timestamp() * 1000


def analyze_received_chain(header_lines: list[HeaderLine]) -> ReceivedChainAnalysis:
    received = [h for h in header_lines if h["key"].lower() == "received"]

    if not received:
        return {"hops": [], "originIp": None, "originHost": None, "signals": []}

    # Received headers are *prepended* at each hop, so the last one in the
    # message is the first hop chronologically. Reversed here so the chain
    # reads origin -> recipient, which is the order an analyst thinks in.
    hops = [_parse_hop(h["line"], index) for index, h in enumerate(reversed(received))]

    signals: list[Signal] = []
    origin = hops[0]

    # A HELO announcing one organization while reverse DNS resolves to
    # another is the classic spoofed-sender shape. Weighted higher when the
    # claimed name is a brand, since that is a deliberate choice rather than
    # a misconfiguration.
    mismatched_hops = [h for h in hops if h["heloMismatch"]]
    if mismatched_hops:
        hop = mismatched_hops[0]
        claims_brand = any(
            hop["helo"] is not None and brand_label(brand) in hop["helo"].split(".")
            for brand in KNOWN_BRAND_DOMAINS
        )

        ip_suffix = f" ({hop['ip']})" if hop["ip"] else ""
        signals.append(
            {
                "id": "helo_brand_impersonation"
                if claims_brand
                else "helo_rdns_mismatch",
                "category": "infrastructure",
                "severity": "high" if claims_brand else "medium",
                "label": "Sending Server Impersonates a Brand"
                if claims_brand
                else "Sending Server Name Mismatch",
                "detail": (
                    f'A relay announced itself as "{hop["helo"]}" but the receiving '
                    "server resolved the connection back to "
                    f'"{hop["reverseDns"]}"{ip_suffix}. The sending machine is not '
                    "what it claimed to be."
                ),
                "mitre": ["T1656"],
            }
        )

    # Every hop rewrites the chain below it, but it cannot rewrite the
    # clocks of servers further along. Time running backwards means a hop
    # was fabricated.
    timestamps = [_parse_date(h["timestamp"]) for h in hops]
    for i in range(1, len(timestamps)):
        previous = timestamps[i - 1]
        current = timestamps[i]
        # 5 minutes of slack for ordinary clock skew between mail servers.
        if (
            previous is not None
            and current is not None
            and current < previous - 5 * 60 * 1000
        ):
            signals.append(
                {
                    "id": "received_timestamp_regression",
                    "category": "infrastructure",
                    "severity": "high",
                    "label": "Forged Delivery Path",
                    "detail": (
                        "Timestamps in the Received chain run backwards: a later hop "
                        "is dated before an earlier one. Servers cannot rewrite the "
                        "clocks of servers further down the path, so at least one of "
                        "these headers was fabricated."
                    ),
                    "mitre": ["T1656"],
                }
            )
            break

    if origin["private"] and len(hops) == 1:
        signals.append(
            {
                "id": "origin_private_ip",
                "category": "infrastructure",
                "severity": "low",
                "label": "Message Entered From a Private Address",
                "detail": (
                    f"The only recorded hop came from {origin['ip']}, a "
                    "private/internal address. For mail claiming to be from an outside "
                    "organization, that means it was injected inside a network rather "
                    "than delivered across the internet."
                ),
                "mitre": ["T1534"],
            }
        )

    if len(hops) == 1:
        signals.append(
            {
                "id": "single_hop_delivery",
                "category": "infrastructure",
                "severity": "low",
                "label": "Direct Delivery, No Relay Path",
                "detail": (
                    "The message records only one hop. Legitimate mail from an "
                    "established provider almost always shows several. A single hop is "
                    "typical of a script or host connecting straight to the recipient "
                    "mail server."
                ),
            }
        )

    return {
        "hops": hops,
        "originIp": origin["ip"],
        "originHost": origin["reverseDns"] or origin["helo"],
        "signals": signals,
    }


__all__ = ["analyze_received_chain", "is_private_ip"]
