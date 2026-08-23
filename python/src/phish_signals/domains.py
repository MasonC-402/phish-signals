"""Shared domain helpers. Mirrors ``typescript/src/domains.ts``.

Used by the URL checks (typosquat/impersonation detection) and the auth checks
(From vs Return-Path/Reply-To comparison), which need to compare at the
registrable-domain level — comparing full hostnames flags every legitimate
third-party sending service.
"""

from __future__ import annotations

import re

# Brands impersonated often enough in real phishing to be worth special-casing.
# Order is irrelevant: the whitelist pass in the URL checks runs over the whole
# list before any distance comparison starts. It did matter once — 'usps.com'
# sits before 'ups.com', and with the whitelist check nested inside the
# comparison loop, ups.com matched usps.com at edit distance 1 and got scored
# as a typosquat of a brand it actually is.
KNOWN_BRAND_DOMAINS: list[str] = [
    "paypal.com", "amazon.com", "microsoft.com", "apple.com", "google.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "irs.gov", "netflix.com",
    "docusign.com", "usps.com", "fedex.com", "ups.com", "facebook.com",
    "instagram.com", "linkedin.com", "dropbox.com", "office.com", "outlook.com",
    "adobe.com", "dhl.com", "citibank.com", "amex.com", "coinbase.com",
    "binance.com", "whatsapp.com", "icloud.com", "onedrive.com", "sharepoint.com",
    "zoom.us", "slack.com", "github.com", "stripe.com", "intuit.com",
]

# Multi-part public suffixes common enough to matter here. Deliberately a short
# hand-maintained list rather than a bundled copy of the full Public Suffix
# List — it only needs to be good enough to stop "mail.example.co.uk" from
# being read as registrable domain "co.uk", and a stale PSL snapshot is its own
# maintenance problem.
_MULTI_PART_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "co.za", "org.za", "gov.za",
    "com.mx", "com.sg", "com.hk", "com.tw", "com.cn", "com.tr", "com.ar",
    "co.in", "net.in", "org.in", "gov.in",
    "co.kr", "or.kr",
})


def registrable_domain(hostname: str) -> str:
    """Approximate eTLD+1.

    Returns the input unchanged when it has too few labels to reduce (a bare
    TLD, a single-label hostname). Note that it has no way to recognize an IP
    literal, so ``registrable_domain('192.168.1.1')`` returns ``'1.1'`` — a
    documented quirk, pinned by a conformance vector, not a bug to fix here
    alone. See ``../../conformance/README.md``.
    """
    host = hostname.lower()
    # `removesuffix`, not `rstrip('.')`: exactly one trailing dot (the DNS
    # root) comes off. `rstrip` would strip a whole run of them and diverge
    # from the reference implementation's single-match regex.
    host = host.removesuffix(".")

    parts = host.split(".")
    if len(parts) <= 2:
        return host

    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return last_two


# Substitutions applied in this exact order — each runs over the output of the
# previous one, so reordering them changes results.
_CONFUSABLE_SUBSTITUTIONS: tuple[tuple[str, str], ...] = (
    (r"rn", "m"),
    (r"vv", "w"),
    (r"[1|!]", "l"),
    (r"0", "o"),
    (r"5", "s"),
    (r"\$", "s"),
    (r"3", "e"),
    (r"4", "a"),
    (r"7", "t"),
)


def normalize_confusables(value: str) -> str:
    """Collapse characters routinely swapped to build a lookalike domain.

    paypa1.com, rnicrosoft.com, arnazon.com. Both the candidate and the brand
    go through this before comparison, so a pure substitution collapses to an
    exact match rather than relying on edit distance (which would also match
    plenty of innocent domains at the same threshold).

    Note that '1' maps to 'l', not 'i', so "netfl1x.com" normalizes to
    "netfllx.com" rather than "netflix.com" — a real quirk of the substitution
    table, pinned by a conformance vector.
    """
    result = value.lower()
    for pattern, replacement in _CONFUSABLE_SUBSTITUTIONS:
        result = re.sub(pattern, replacement, result)
    return result


def brand_label(brand_domain: str) -> str:
    """The brand's distinctive label — 'paypal' from 'paypal.com'.

    Used to spot a brand appearing somewhere it shouldn't: in a subdomain, or
    hyphenated into an unrelated registrable domain.
    """
    return brand_domain.split(".")[0]


__all__ = [
    "KNOWN_BRAND_DOMAINS",
    "brand_label",
    "normalize_confusables",
    "registrable_domain",
]
