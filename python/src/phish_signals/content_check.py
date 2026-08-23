"""Body heuristics — urgency and lure language, link text, dangerous schemes.

Port of ``typescript/src/contentCheck.ts``.

The four phrase-list rules (urgency, credential request, financial request,
authority impersonation) live in ``rules/data/content.json`` as declarative
rules. The remaining checks — generic greeting detection, display-name
spoofing, excessive capitalization — are code rules because they need
regex or structured logic that the declarative grammar deliberately excludes.

``check_link_text`` and ``check_dangerous_schemes`` are standalone functions
rather than rules: they operate on pre-parsed structured data
(``LinkMismatch`` and ``dangerousSchemes``) rather than scanning free text,
so the rule context adds nothing.
"""

from __future__ import annotations

import re
from pathlib import Path

from .domains import registrable_domain
from .rules import Rule, RuleContext, Ruleset, evaluate_ruleset, load_rule_file
from .types import LinkMismatch, ParsedEmail, Signal, SignalResult

# ── Known brand names for display-name spoofing detection ──────────────
# Mirrors KNOWN_BRAND_NAMES in typescript/src/contentCheck.ts.
KNOWN_BRAND_NAMES: list[str] = [
    "paypal", "amazon", "microsoft", "apple", "bank of america", "chase",
    "wells fargo", "irs", "netflix", "docusign", "google", "facebook",
    "linkedin", "dropbox", "adobe", "fedex", "ups", "usps", "dhl",
    "coinbase", "american express", "citibank", "office 365", "onedrive",
]

_IM = re.IGNORECASE | re.MULTILINE
_GENERIC_GREETING_PATTERNS = [
    re.compile(r"^dear (customer|user|member|valued customer|sir/madam)", _IM),
    re.compile(r"^dear [a-z]+@", _IM),
    re.compile(r"^(hello|hi) (customer|user|member)\b", _IM),
]

_DISPLAY_NAME_RE = re.compile(r'^"?([^"<]+)"?\s*<(.+)>$')
_DISPLAY_AS_EMAIL_RE = re.compile(r"[\w.+-]+@([\w.-]+\.[a-z]{2,})", re.IGNORECASE)
# ASCII word boundaries to match JavaScript's \b behavior — Python's \b
# treats Unicode letters as word characters, which would under-count.
_CAPS_WORD_RE = re.compile(r"(?<![A-Za-z0-9_])[A-Z]{4,}(?![A-Za-z0-9_])")

# ── Declarative phrase rules ──────────────────────────────────────────

_DATA_DIR = Path(__file__).parent / "rules" / "data"

_CONTENT_PHRASE_RULES: list[Rule] = load_rule_file(_DATA_DIR / "content.json")

# ── Code rules (need regex or structured logic) ───────────────────────


def _check_generic_greeting(context: RuleContext) -> list[Signal]:
    text = context.parsed.get("scanText") or ""
    if not text:
        return []
    if any(pattern.search(text) for pattern in _GENERIC_GREETING_PATTERNS):
        return [{
            "id": "generic_greeting",
            "category": "social",
            "severity": "low",
            "label": "Generic Greeting",
            "detail": (
                "Addresses you generically rather than by name. An organization "
                "that holds an account for you generally knows your name."
            ),
        }]
    return []


def _check_display_name_brand_spoof(context: RuleContext) -> list[Signal]:
    from_address = context.parsed.get("from")
    if not from_address:
        return []

    match = _DISPLAY_NAME_RE.match(from_address)
    if not match:
        return []

    display_name = match.group(1).strip().lower()
    actual_email = match.group(2).strip().lower()
    signals: list[Signal] = []

    # Brand name in display name but not in actual address
    for brand in KNOWN_BRAND_NAMES:
        if brand in display_name and brand.replace(" ", "") not in actual_email:
            signals.append({
                "id": "display_name_brand_spoof",
                "category": "identity",
                "severity": "high",
                "label": "Display Name Spoofing",
                "detail": (
                    f'The sender name says "{brand}" but the actual address is '
                    f"{actual_email}. Most mail clients show only the name, so "
                    "this is what the recipient sees."
                ),
                "mitre": ["T1656"],
            })
            break

    # Display name is itself an email address at a different domain
    display_email_match = _DISPLAY_AS_EMAIL_RE.search(display_name)
    if display_email_match:
        claimed_domain = registrable_domain(display_email_match.group(1))
        actual_part = actual_email.split("@")[1] if "@" in actual_email else ""
        actual_domain = registrable_domain(actual_part)
        if claimed_domain and actual_domain and claimed_domain != actual_domain:
            signals.append({
                "id": "display_name_address_spoof",
                "category": "identity",
                "severity": "high",
                "label": "Sender Address Spoofing",
                "detail": (
                    f'The display name shows an address at "{claimed_domain}", '
                    f'but the message was actually sent from "{actual_domain}".'
                ),
                "mitre": ["T1656"],
            })

    return signals


def _check_excessive_caps(context: RuleContext) -> list[Signal]:
    text = context.parsed.get("scanText") or ""
    if not text:
        return []
    caps_words = _CAPS_WORD_RE.findall(text)
    if len(caps_words) >= 5:
        return [{
            "id": "excessive_capitalization",
            "category": "social",
            "severity": "low",
            "label": "Excessive Capitalization",
            "detail": (
                "Unusually heavy use of all-caps words, typically used to "
                "manufacture alarm."
            ),
        }]
    return []


_CODE_RULES: tuple[Rule, ...] = (
    Rule(
        id="core.generic_greeting",
        emits=frozenset({"generic_greeting"}),
        evaluate=_check_generic_greeting,
        tags=frozenset({"content"}),
        description="Detects generic greetings (Dear Customer, etc.).",
    ),
    Rule(
        id="core.display_name_spoof",
        emits=frozenset({"display_name_brand_spoof", "display_name_address_spoof"}),
        evaluate=_check_display_name_brand_spoof,
        tags=frozenset({"identity"}),
        description="Detects display name impersonating a known brand.",
    ),
    Rule(
        id="core.excessive_caps",
        emits=frozenset({"excessive_capitalization"}),
        evaluate=_check_excessive_caps,
        tags=frozenset({"content"}),
        description="Flags heavy use of all-caps words as a pressure tactic.",
    ),
)

# ── The content ruleset ───────────────────────────────────────────────

CONTENT_RULESET: Ruleset = Ruleset(
    name="content",
    rules=tuple(_CONTENT_PHRASE_RULES) + _CODE_RULES,
)

# ── Standalone checks (structured data, not text scanning) ────────────

_SCHEME_EXPLANATIONS: dict[str, str] = {
    "data": (
        "a data: link can encode an entire fake page inline, with no hostname "
        "at all for a domain-based check to examine"
    ),
    "javascript": (
        "a javascript: link runs code the moment it is clicked, with no page "
        "navigation involved"
    ),
    "vbscript": (
        "a vbscript: link runs code the moment it is clicked, an old mechanism "
        "still occasionally abused"
    ),
}


def check_content(
    body_text: str | None = None,
    from_address: str | None = None,
) -> SignalResult:
    """Run the content heuristics. Mirrors ``checkContent`` in the TypeScript.

    Accepts the same inputs as the TypeScript version: the message body text
    and optionally the From address. Internally delegates to the content
    ruleset rather than reimplementing the phrase scanning inline.
    """
    # Build a minimal ParsedEmail with just the fields content rules need.
    parsed: ParsedEmail = {
        "isRawEmail": False,
        "from": from_address,
        "returnPath": None,
        "replyTo": None,
        "subject": None,
        "date": None,
        "headers": None,
        "headerLines": [],
        "textBody": body_text or "",
        "htmlBody": None,
        "scanText": body_text or "",
        "urls": [],
        "linkMismatches": [],
        "dangerousSchemes": [],
        "attachments": [],
        "imageCount": 0,
        "qrCodeUrls": [],
        "qrImagesScanned": 0,
    }

    context = RuleContext(parsed=parsed)
    result = evaluate_ruleset(CONTENT_RULESET, context)
    return {"signals": result["signals"]}


def check_link_text(mismatches: list[LinkMismatch] | None = None) -> SignalResult:
    """Flag links whose visible text names one domain but href points elsewhere.

    Mirrors ``checkLinkText`` in the TypeScript.
    """
    items = mismatches or []
    if not items:
        return {"signals": []}

    examples = "; ".join(
        f'"{m["claimedDomain"]}" actually goes to "{m["actualDomain"]}"'
        for m in items[:3]
    )
    count = len(items)
    plural = "" if count == 1 else "s"

    return {
        "signals": [{
            "id": "deceptive_link_text",
            "category": "payload",
            "severity": "high",
            "label": "Deceptive Link Text",
            "detail": (
                f"{count} link{plural} display one destination but point at "
                f"another: {examples}. There is no legitimate reason for a "
                "link to misstate where it goes."
            ),
            "mitre": ["T1566.002", "T1204.001"],
        }],
    }


def check_dangerous_schemes(schemes: list[str] | None = None) -> SignalResult:
    """Flag data:, javascript:, vbscript: links.

    Mirrors ``checkDangerousSchemes`` in the TypeScript.
    """
    items = schemes or []
    if not items:
        return {"signals": []}

    explanations = "; ".join(
        _SCHEME_EXPLANATIONS.get(
            s,
            f"a {s}: link is not a normal way for a link in an email to work",
        )
        for s in items
    )

    return {
        "signals": [{
            "id": "dangerous_link_scheme",
            "category": "payload",
            "severity": "high",
            "label": "Link Uses a Non-Web Scheme",
            "detail": (
                f"The message contains a link using {'/'.join(items)} instead "
                f"of http(s). {explanations}. There is no legitimate reason "
                "for this to appear in an email."
            ),
            "mitre": ["T1566.002", "T1204.001"],
        }],
    }


__all__ = [
    "CONTENT_RULESET",
    "KNOWN_BRAND_NAMES",
    "check_content",
    "check_dangerous_schemes",
    "check_link_text",
]
