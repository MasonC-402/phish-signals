"""SPF/DKIM/DMARC evaluation from Authentication-Results headers.

Port of ``typescript/src/authCheck.ts``.
"""

from __future__ import annotations

import re

from .domains import brand_label, registrable_domain
from .types import AuthCheckResult, HeaderLine, Signal
from .url_check import brand_impersonation, check_typosquat

_AT_DOMAIN_RE = re.compile(r"@([^\s>,;]+)")


def _as_text(value: object) -> str | None:
    """Header values vary by header: plain strings, lists (repeated headers),
    or an address-object shape with a ``text`` key. Only the shapes actually
    seen on the headers read here are handled; anything else degrades to
    "no value" rather than raising.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = [t for v in value if (t := _as_text(v))]
        return "; ".join(parts) if parts else None
    if isinstance(value, dict) and isinstance(value.get("text"), str):
        return value["text"]
    return None


def _extract_domain(address_string: str | None) -> str | None:
    if not address_string:
        return None
    match = _AT_DOMAIN_RE.search(str(address_string))
    if not match:
        return None
    return match.group(1).lower().removesuffix(".")


# Multiple Authentication-Results headers happen whenever the message passed
# through more than one authenticating hop. Headers are prepended at each
# hop, so headerLines' wire order runs newest-hop-first; the OLDEST
# Authentication-Results header is the one stamped by the first real server
# to receive the message from the internet — see the TypeScript source for
# the full reasoning on why this selection exists and what it defends
# against (a forged trailing Authentication-Results header).
_AUTHSERV_ID_PATTERN = re.compile(r"^([^\s;]+)")


class _AuthoritativeAuthResults:
    __slots__ = ("authserv_id", "discarded_forged_header", "text")

    def __init__(
        self, text: str, authserv_id: str | None, discarded_forged_header: bool
    ) -> None:
        self.text = text
        self.authserv_id = authserv_id
        self.discarded_forged_header = discarded_forged_header


def _select_authoritative_auth_results(
    header_lines: list[HeaderLine],
) -> _AuthoritativeAuthResults:
    received_count = sum(1 for h in header_lines if h["key"].lower() == "received")

    # Wire order is newest-first, so this is already sorted newest-to-oldest.
    all_candidates = [
        h for h in header_lines if h["key"].lower() == "authentication-results"
    ]

    # The N most recent — i.e. everything a real hop could plausibly have
    # added, discarding only whatever's left over (necessarily older than all
    # of those).
    trusted_candidates = (
        all_candidates if received_count == 0 else all_candidates[:received_count]
    )

    discarded_forged_header = received_count > 0 and len(trusted_candidates) < len(
        all_candidates
    )

    if not trusted_candidates:
        return _AuthoritativeAuthResults("", None, discarded_forged_header)

    oldest = trusted_candidates[-1]
    text = re.sub(
        r"^authentication-results:\s*", "", oldest["line"], flags=re.IGNORECASE
    )
    authserv_id_match = _AUTHSERV_ID_PATTERN.match(text)
    authserv_id = (
        authserv_id_match.group(1).removesuffix(".") if authserv_id_match else None
    )

    return _AuthoritativeAuthResults(text, authserv_id, discarded_forged_header)


def _check_domain_impersonation(
    domain: str | None, field: str, header_label: str
) -> list[Signal]:
    """checkTyposquat/brandImpersonation were written for URL hostnames, but
    both reduce to a registrable-domain comparison against the same brand
    list internally, which is exactly what a bare From/Reply-To domain
    string already is.
    """
    if not domain:
        return []

    typosquat_match = check_typosquat(domain)
    if typosquat_match:
        return [
            {
                "id": f"{field}_domain_typosquat",
                "category": "identity",
                "severity": "high",
                "label": f"{header_label} Domain Resembles a Known Brand",
                "detail": (
                    f'The message\'s {header_label} is "{domain}", which closely '
                    f'resembles "{typosquat_match}" — a likely typosquat rather than '
                    "the real domain. This is an actual identity in the message, "
                    "not just a link destination."
                ),
                "mitre": ["T1656"],
            }
        ]

    # Mutually exclusive with the typosquat check, same reasoning url_check.py
    # uses for the equivalent link-hostname check.
    impersonated_brand = brand_impersonation(domain)
    if impersonated_brand:
        return [
            {
                "id": f"{field}_domain_brand_impersonation",
                "category": "identity",
                "severity": "high",
                "label": (
                    f"{header_label} Domain Puts a Brand Name Where It Doesn't Belong"
                ),
                "detail": (
                    f'The message\'s {header_label} is "{domain}", which puts '
                    f'"{brand_label(impersonated_brand)}" in the hostname while the '
                    "real domain is unrelated. Same trick as a lookalike link, but in "
                    "the message's own identity."
                ),
                "mitre": ["T1656"],
            }
        ]

    return []


def check_authentication(
    headers: dict[str, object] | None, header_lines: list[HeaderLine]
) -> AuthCheckResult:
    # An empty-but-present dict (a real header block with no relevant
    # headers) must not be treated the same as "no headers at all" — only
    # `None` (a plain-text paste) means that.
    if headers is None:
        return {
            "available": False,
            "passed": False,
            "signals": [],
            "selectedAuthservId": None,
        }

    signals: list[Signal] = []
    selection = _select_authoritative_auth_results(header_lines)
    auth_results = selection.text

    # The header itself being present at all — more Authentication-Results
    # headers than the message has real hops to have stamped them — is
    # meaningful evidence independent of whatever the extra one claims.
    if selection.discarded_forged_header:
        signals.append(
            {
                "id": "forged_authentication_results_header",
                "category": "authentication",
                "severity": "high",
                "label": "Authentication-Results Header Predates Real Delivery",
                "detail": (
                    "The message carries more Authentication-Results headers than it "
                    "has Received headers to have stamped them — meaning at least one "
                    "could not have been added by a real mail server relaying the "
                    "message, and was instead already present in the content as sent. "
                    "A real server only ever adds this header at the moment it "
                    "performs the check, never earlier. The extra header was ignored "
                    "when determining SPF/DKIM/DMARC status below."
                ),
                "mitre": ["T1656"],
            }
        )

    # DMARC is the authoritative result and carries the highest severity of
    # the three: it is precisely the check that asks "is this message
    # authorized by the domain in the From header".
    if re.search(r"dmarc=fail", auth_results, re.IGNORECASE):
        signals.append(
            {
                "id": "dmarc_fail",
                "category": "authentication",
                "severity": "high",
                "label": "DMARC Failure",
                "detail": (
                    "The message failed DMARC. It is not authorized by the domain it "
                    "claims to come from — the strongest single indicator of sender "
                    "spoofing available from headers alone."
                ),
                "mitre": ["T1656"],
            }
        )
    elif re.search(r"dmarc=(quarantine|reject)", auth_results, re.IGNORECASE):
        signals.append(
            {
                "id": "dmarc_enforced",
                "category": "authentication",
                "severity": "high",
                "label": "DMARC Enforcement Applied",
                "detail": (
                    "The receiving server applied the sending domain's DMARC "
                    "enforcement policy, which means alignment failed and the domain "
                    "owner asked for exactly this to be treated as suspect."
                ),
                "mitre": ["T1656"],
            }
        )
    elif re.search(r"dmarc=none", auth_results, re.IGNORECASE):
        signals.append(
            {
                "id": "dmarc_none",
                "category": "authentication",
                "severity": "low",
                "label": "No DMARC Policy",
                "detail": (
                    "The sending domain publishes no DMARC policy, so nothing prevents "
                    "another server from spoofing it and nothing here can confirm the "
                    "sender either way."
                ),
            }
        )

    if re.search(r"spf=fail", auth_results, re.IGNORECASE):
        signals.append(
            {
                "id": "spf_fail",
                "category": "authentication",
                "severity": "medium",
                "label": "SPF Failure",
                "detail": (
                    "The sending server is not on the list of servers authorized to "
                    "send for this domain."
                ),
                "mitre": ["T1656"],
            }
        )
    elif re.search(r"spf=(softfail|neutral)", auth_results, re.IGNORECASE):
        signals.append(
            {
                "id": "spf_softfail",
                "category": "authentication",
                "severity": "low",
                "label": "SPF Softfail",
                "detail": (
                    "SPF returned a soft failure or neutral result, so the sending "
                    "server is only weakly authorized for this domain."
                ),
            }
        )
    elif re.search(r"spf=none", auth_results, re.IGNORECASE):
        signals.append(
            {
                "id": "spf_none",
                "category": "authentication",
                "severity": "low",
                "label": "SPF Not Set Up",
                "detail": (
                    "The sending domain doesn't publish an SPF policy at all, so this "
                    "check couldn't confirm anything either way."
                ),
            }
        )

    if re.search(r"dkim=fail", auth_results, re.IGNORECASE):
        signals.append(
            {
                "id": "dkim_fail",
                "category": "authentication",
                "severity": "medium",
                "label": "DKIM Failure",
                "detail": (
                    "The cryptographic signature did not validate. The message content "
                    "or its headers were altered after signing, or the signature was "
                    "forged outright."
                ),
                "mitre": ["T1656"],
            }
        )
    elif re.search(r"dkim=none", auth_results, re.IGNORECASE):
        signals.append(
            {
                "id": "dkim_none",
                "category": "authentication",
                "severity": "low",
                "label": "No DKIM Signature",
                "detail": (
                    "The message was not signed with DKIM, so there is no "
                    "cryptographic evidence tying it to the sending domain."
                ),
            }
        )

    if auth_results.strip() == "":
        signals.append(
            {
                "id": "no_auth_results",
                "category": "authentication",
                "severity": "low",
                "label": "No Authentication Results",
                "detail": (
                    "This message carries no Authentication-Results header, so "
                    "SPF/DKIM/DMARC couldn't be checked at all. Common for mail that "
                    "bypassed normal filtering, and it means the checks below are "
                    "working with less to go on."
                ),
            }
        )

    from_domain = _extract_domain(_as_text(headers.get("from")))
    return_path_domain = _extract_domain(_as_text(headers.get("return-path")))

    # Compared at the registrable-domain level: bounce.example.com vs
    # example.com is one organization using a subdomain for bounce handling.
    if (
        from_domain
        and return_path_domain
        and registrable_domain(from_domain) != registrable_domain(return_path_domain)
    ):
        signals.append(
            {
                "id": "return_path_mismatch",
                "category": "identity",
                "severity": "low",
                "label": "Return-Path Mismatch",
                "detail": (
                    f'Bounces for this message go to "{return_path_domain}" while it '
                    f'claims to be from "{from_domain}". Normal for mail sent through '
                    "a newsletter tool or CRM, so weigh it alongside the other "
                    "findings rather than on its own."
                ),
            }
        )

    reply_to_domain = _extract_domain(_as_text(headers.get("reply-to")))
    if (
        from_domain
        and reply_to_domain
        and registrable_domain(reply_to_domain) != registrable_domain(from_domain)
    ):
        signals.append(
            {
                "id": "reply_to_mismatch",
                "category": "identity",
                "severity": "medium",
                "label": "Replies Go to a Different Domain",
                "detail": (
                    f'Hitting reply sends your response to "{reply_to_domain}", not '
                    f'"{from_domain}". This is how a conversation gets quietly '
                    "redirected to the attacker, and it is the standard setup for "
                    "business email compromise."
                ),
                "mitre": ["T1656"],
            }
        )

    signals.extend(_check_domain_impersonation(from_domain, "sender", "From"))

    # Reply-To can carry the same trick as From, and it's the address a
    # reply actually goes to — checked independently of from_domain above
    # rather than only when it already disagrees with from_domain.
    if reply_to_domain and (
        not from_domain
        or registrable_domain(reply_to_domain) != registrable_domain(from_domain)
    ):
        signals.extend(
            _check_domain_impersonation(reply_to_domain, "reply_to", "Reply-To")
        )

    passed = bool(
        re.search(r"spf=pass", auth_results, re.IGNORECASE)
        and re.search(r"dkim=pass", auth_results, re.IGNORECASE)
        and re.search(r"dmarc=pass", auth_results, re.IGNORECASE)
    )

    if passed:
        signals.append(
            {
                "id": "auth_fully_passed",
                "category": "authentication",
                "severity": "info",
                "benign": True,
                "label": "Sender Authentication Passed",
                "detail": (
                    "SPF, DKIM and DMARC all passed, so the message genuinely came "
                    "from the domain it claims. That confirms the sender, not their "
                    "intent — a compromised account passes every one of these."
                ),
            }
        )

    return {
        "available": True,
        "passed": passed,
        "signals": signals,
        "selectedAuthservId": selection.authserv_id,
    }


__all__ = ["check_authentication"]
