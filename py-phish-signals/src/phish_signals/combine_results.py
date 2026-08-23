"""Aggregation — takes the output of every check, scores it, and builds the
analyst-facing artifacts (IOCs, ATT&CK mapping, Sigma rule, recommendations).

Port of ``typescript/src/combineResults.ts``.

The scoring itself lives in :mod:`phish_signals.signals` — this module's job
is only to gather evidence and hand it over, so that how findings are
weighed stays in one place and independent of where they came from.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .domains import registrable_domain
from .iocs import extract_iocs
from .kql_query import build_kql_query
from .mitre import map_techniques
from .recommendations import build_recommendations
from .sigma_rule import build_sigma_rule
from .signals import assess_confidence, score_signals
from .types import (
    AuthCheckResult,
    CombinedResult,
    HeaderAnomalyResult,
    ParsedEmail,
    ReceivedChainAnalysis,
    Signal,
    SignalResult,
    UrlAnalysis,
)

_ADDRESS_DOMAIN_RE = re.compile(r"@([\w.-]+\.[a-z]{2,})", re.IGNORECASE)


def _domain_of(address: str | None) -> str | None:
    if not address:
        return None
    match = _ADDRESS_DOMAIN_RE.search(address)
    return registrable_domain(match.group(1).lower()) if match else None


@dataclass(frozen=True)
class AnalysisInput:
    """Grouped output of every individual check, ready to be scored and
    assembled into a :class:`~phish_signals.types.CombinedResult`.

    A dataclass rather than a TypedDict: this never crosses the conformance
    boundary (it is an argument, not a return value compared by deep
    equality), and never will — the shapes inside it already are TypedDicts.
    """

    parsed: ParsedEmail
    auth: AuthCheckResult
    urls: list[UrlAnalysis]
    url_signals: list[Signal]
    content: SignalResult
    link_text: SignalResult
    dangerous_schemes: SignalResult
    qr_codes: SignalResult
    attachments: SignalResult
    chain: ReceivedChainAnalysis | None
    header_anomalies: HeaderAnomalyResult


def combine_results(input: AnalysisInput) -> CombinedResult:
    parsed, auth, chain = input.parsed, input.auth, input.chain

    all_signals: list[Signal] = [
        *auth["signals"],
        *input.content["signals"],
        *input.link_text["signals"],
        *input.dangerous_schemes["signals"],
        *input.qr_codes["signals"],
        *input.attachments["signals"],
        *input.url_signals,
        *input.header_anomalies["signals"],
        *(chain["signals"] if chain else []),
    ]

    scored = score_signals(all_signals)

    confidence = assess_confidence(
        {
            "headers": parsed["isRawEmail"],
            "authResults": auth["available"]
            and not any(s["id"] == "no_auth_results" for s in auth["signals"]),
            "receivedChain": bool(chain and len(chain["hops"]) > 0),
            "htmlPart": bool(parsed.get("htmlBody")),
            # Whether we had structural visibility into attachments at all, not
            # whether any were actually found — see the TypeScript source for
            # why this is isRawEmail rather than "any attachments/images found".
            "attachmentMetadata": parsed["isRawEmail"],
        }
    )

    sender_domain = _domain_of(parsed.get("from"))
    reply_to_domain = _domain_of(parsed.get("replyTo"))

    iocs = extract_iocs(
        urls=input.urls,
        attachments=parsed.get("attachments") or [],
        chain=chain,
        from_address=parsed.get("from"),
        reply_to=parsed.get("replyTo"),
        return_path=parsed.get("returnPath"),
    )

    return {
        "score": scored["score"],
        "verdict": scored["verdict"],
        "confidence": confidence,
        "signals": scored["signals"],
        "benignSignals": scored["benignSignals"],
        "categories": scored["categories"],
        "urls": input.urls,
        "recommendations": build_recommendations(
            verdict=scored["verdict"],
            signals=scored["signals"],
            auth_available=auth["available"],
        ),
        "mitre": map_techniques(scored["signals"]),
        "iocs": iocs,
        "sigmaRule": build_sigma_rule(
            subject=parsed.get("subject"),
            sender_domain=sender_domain,
            reply_to_domain=reply_to_domain,
            urls=input.urls,
            attachments=parsed.get("attachments") or [],
            signals=scored["signals"],
            verdict=scored["verdict"],
            score=scored["score"],
        ),
        "kqlQuery": build_kql_query(iocs),
        "authAvailable": auth["available"],
        "authPassed": auth["passed"],
        "receivedChain": chain,
    }


__all__ = ["AnalysisInput", "combine_results"]
