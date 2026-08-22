"""The scoring engine. Mirrors ``typescript/src/signals.ts``.

An earlier model summed a hand-picked weight per finding and capped the total
at 100. That had three problems worth naming, because the shape of this module
is a direct response to each:

1. Correlated findings were summed as independent evidence. SPF fail (25) +
   DKIM fail (25) + DMARC fail (25) = 75, but DMARC failing *is* SPF and DKIM
   failing to align — one fact counted three times. An unauthenticated message
   hit "High Risk" before exhibiting any phishing behavior at all.
2. Nothing could lower a score. There was no way to express that a finding
   argues the message is legitimate.
3. A bare 0-100 number implied a calibration that hand-picked weights do not
   have, and said nothing about how much of the message was actually visible.

So: signals carry a category and a severity instead of a raw number. Within a
category the strongest signal counts in full and the rest contribute at a steep
discount — they corroborate, they are not new information. Categories are
treated as the independent axes, so breadth across categories moves the score
far more than depth inside one, which matches how phishing actually presents.
"""

from __future__ import annotations

import math
import unicodedata
from collections.abc import Iterable
from typing import Literal

from .types import (
    CATEGORY_LABELS,
    Availability,
    CategoryScore,
    Confidence,
    EvidenceCategory,
    ScoredEvidence,
    Severity,
    Signal,
    Verdict,
)

SEVERITY_POINTS: dict[Severity, int] = {
    "critical": 45,
    "high": 28,
    "medium": 14,
    "low": 6,
    "info": 0,
}

SEVERITY_RANK: dict[Severity, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

# Corroborating signals within a category contribute at this rate. Not zero
# (three independent spoofing indicators is worse than one) but nowhere near
# full value.
CORROBORATION_RATE = 0.25

# No single category can max out the score on its own. Reaching "High Risk"
# requires evidence on more than one axis.
MAX_CATEGORY_SCORE = 55

_CATEGORY_ORDER: tuple[EvidenceCategory, ...] = (
    "authentication",
    "identity",
    "infrastructure",
    "payload",
    "social",
)


def _round_half_up(value: float) -> int:
    """Round halves away from zero's convention and toward positive infinity.

    Python's built-in :func:`round` is banker's rounding — ``round(2.5)`` is 2,
    not 3 — while the reference implementation uses JavaScript's ``Math.round``,
    which rounds a half upward. Category scores land on exact halves routinely
    (28 + 14 * 0.25 = 31.5), so using the built-in here would silently disagree
    with the TypeScript side on real inputs.
    """
    return math.floor(value + 0.5)


def _severity_rank_of(signal: Signal) -> int:
    return SEVERITY_RANK.get(signal["severity"], 0)


def _label_sort_key(label: str) -> tuple[str, str]:
    """Approximate ``String.prototype.localeCompare`` for label ordering.

    The reference breaks a severity tie with ``localeCompare``, which is not
    what a plain codepoint comparison does, in two ways that both reorder
    real output:

    - It compares case-insensitively at the primary level, so "apple" sorts
      before "Banana" there but after "Zebra" under codepoint ordering.
    - It sorts an accented letter next to its unaccented base, so "Ápple"
      sorts before "Banana"; by codepoint U+00C1 lands after "Z".

    Casefolding after stripping combining marks handles both. The second
    element of the key handles strings equal apart from case, where collation
    puts lowercase first: swapping case inverts the codepoint comparison, so
    "apple" precedes "Apple" as it does in the reference.

    This is an approximation, not ICU collation, and it is chosen over a real
    collator because pulling an ICU dependency into a package that otherwise
    has no runtime dependencies is not worth it for a tie-break. The known
    residual gap is punctuation: ICU gives characters like "_" and "-" their
    own primary weights, so a label *starting* with punctuation can still
    order differently here. No signal this package emits has such a label —
    they are all alphanumeric with spaces and hyphens — so nothing currently
    reaches that gap. Worth re-checking if that ever stops being true.
    """
    primary = "".join(
        c
        for c in unicodedata.normalize("NFD", label)
        if not unicodedata.combining(c)
    )
    return (primary.lower(), label.swapcase())


def _sorted_by_severity(signals: Iterable[Signal]) -> list[Signal]:
    """Worst first, then alphabetically by label for a stable order."""
    return sorted(
        signals, key=lambda s: (-_severity_rank_of(s), _label_sort_key(s["label"]))
    )


def _score_category(
    category: EvidenceCategory, signals: list[Signal]
) -> CategoryScore:
    ordered = _sorted_by_severity(signals)
    points = [SEVERITY_POINTS.get(s["severity"], 0) for s in ordered]

    strongest = points[0] if points else 0
    corroboration = sum(points[1:]) * CORROBORATION_RATE

    return {
        "category": category,
        "label": CATEGORY_LABELS[category],
        "score": _round_half_up(min(strongest + corroboration, MAX_CATEGORY_SCORE)),
        "signals": ordered,
    }


def _benign_adjustment(benign_signals: list[Signal], worst_severity_rank: int) -> int:
    """Benign evidence reduces the score, but only when nothing high-severity fired.

    A message carrying an executable should not be able to talk its way down
    because its SPF was valid; plenty of real phishing is sent from correctly
    configured infrastructure the attacker controls outright.
    """
    if worst_severity_rank >= SEVERITY_RANK["high"]:
        return 0
    return len(benign_signals) * -6


def score_signals(all_signals: list[Signal]) -> ScoredEvidence:
    """Combine raw signals into a score, verdict, and per-category breakdown.

    Signals are passed through into the result by reference, never rebuilt.
    That is deliberate: a signal without a ``mitre`` key must not acquire one
    set to ``None`` on the way out, since conformance compares the result by
    exact deep equality and an absent key is not the same value as a null one.
    """
    # The same id twice (two attachments both executable, say) counts once —
    # the second adds no new information about whether this is a phish.
    seen: set[str] = set()
    deduped: list[Signal] = []
    for signal in all_signals:
        if signal["id"] in seen:
            continue
        seen.add(signal["id"])
        deduped.append(signal)

    benign_signals = [s for s in deduped if s.get("benign")]
    suspicious = [s for s in deduped if not s.get("benign")]

    categories = [
        scored
        for scored in (
            _score_category(
                category, [s for s in suspicious if s["category"] == category]
            )
            for category in _CATEGORY_ORDER
        )
        if scored["signals"]
    ]

    worst_severity_rank = max(
        (_severity_rank_of(s) for s in suspicious), default=0
    )
    raw = sum(c["score"] for c in categories) + _benign_adjustment(
        benign_signals, worst_severity_rank
    )

    score = max(0, min(_round_half_up(raw), 100))

    verdict: Verdict = "Low Risk"
    if score >= 60:
        verdict = "High Risk"
    elif score >= 30:
        verdict = "Medium Risk"

    return {
        "score": score,
        "verdict": verdict,
        "categories": categories,
        "signals": _sorted_by_severity(suspicious),
        "benignSignals": benign_signals,
    }


def assess_confidence(available: Availability) -> Confidence:
    """Report how much of the message was actually visible to the checks.

    Kept separate from the score on purpose: a low score on a pasted body with
    no headers means something very different from the same score on a full
    ``.eml``, and collapsing the two into one number hides that.
    """
    gaps: list[str] = []
    if not available.get("headers"):
        gaps.append(
            "No message headers — this looks like pasted body text, so sender "
            "and routing checks could not run."
        )
    if not available.get("authResults"):
        gaps.append(
            "No Authentication-Results header, so SPF, DKIM and DMARC results "
            "are unknown."
        )
    if not available.get("receivedChain"):
        gaps.append(
            "No Received headers, so the delivery path and originating server "
            "could not be traced."
        )
    if not available.get("htmlPart"):
        gaps.append(
            "No HTML part, so link text could not be compared against link "
            "destinations."
        )
    if not available.get("attachmentMetadata"):
        gaps.append("No attachment metadata was present in what was submitted.")

    checks = list(available.values())
    completeness = (
        sum(1 for check in checks if check) / len(checks) if checks else 0.0
    )

    level: Literal["high", "medium", "low"] = "low"
    if completeness >= 0.8:
        level = "high"
    elif completeness >= 0.5:
        level = "medium"

    return {
        "level": level,
        "completeness": completeness,
        "gaps": gaps,
    }


__all__ = [
    "CORROBORATION_RATE",
    "MAX_CATEGORY_SCORE",
    "SEVERITY_POINTS",
    "SEVERITY_RANK",
    "assess_confidence",
    "score_signals",
]
