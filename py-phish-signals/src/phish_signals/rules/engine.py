"""Runs a ruleset against a context and collects the signals it produced.

The engine is deliberately thin. It does not score, rank, or dedupe — that all
lives in :mod:`phish_signals.signals` and stays there, so that how findings are
weighed is decided in one place regardless of where they came from. What the
engine adds over ``[s for rule in ruleset for s in rule.evaluate(ctx)]`` is
three things that a library accepting third-party rules cannot do without:

1. **Fault isolation.** A rule that raises must not take the analysis with it.
   Somebody triaging a live phish should get the other forty findings plus a
   note that one rule broke, not a traceback and nothing. Failures are
   reported as :class:`RuleDiagnostic` entries rather than swallowed.

2. **Emission checking.** A signal whose id the rule never declared in
   ``emits`` is dropped, because an undeclared id is exactly the case the
   ruleset-level collision check could not see coming — it would sail past
   validation and then silently suppress a built-in via ``score_signals``'
   first-one-wins dedupe.

3. **Severity overrides.** Applied here rather than inside each rule, so a
   consumer can retune a signal without touching the rule that emits it.

Determinism: rules run in ruleset order, and signals come back in the order
they were produced. Nothing is sorted here — ``score_signals`` does its own
ordering, and re-sorting first would only hide the fact that ruleset order is
what decides which of two same-id signals wins.
"""

from __future__ import annotations

import traceback
from typing import Literal, TypedDict

from ..types import Severity, Signal
from .types import _VALID_CATEGORIES, _VALID_SEVERITIES, Rule, RuleContext, Ruleset

#: Why a rule contributed nothing, or contributed less than it tried to.
DiagnosticKind = Literal["error", "undeclared_signal", "malformed_signal"]


class RuleDiagnostic(TypedDict):
    """A rule that misbehaved, in JSON-able form.

    This one is meant to reach the caller — folded into a result, logged, or
    surfaced in a report's footer — so it is a TypedDict and its keys are
    camelCase like every other key in this package that crosses the language
    boundary.
    """

    ruleId: str
    kind: DiagnosticKind
    #: Human-readable, safe to show. Never contains message content.
    message: str


class RuleRunResult(TypedDict):
    """What a ruleset produced: the evidence, and anything that went wrong."""

    signals: list[Signal]
    diagnostics: list[RuleDiagnostic]


def _looks_like_signal(value: object) -> bool:
    """Cheap structural check for the five required Signal keys.

    Worth doing because a rule is third-party code and a malformed dict does
    not fail here — it fails much later, inside scoring or JSON export, with a
    KeyError that names neither the rule nor the message that triggered it.

    Also validates that category, severity, and id are within the allowed
    values — an invalid severity silently scores zero points, and an invalid
    category silently drops the signal from every category bucket, so both
    produce evidence that is not reflected in the verdict.
    """
    if not isinstance(value, dict):
        return False
    if not all(
        isinstance(value.get(key), str)
        for key in ("id", "category", "severity", "label", "detail")
    ):
        return False
    return (
        bool(value.get("id"))
        and value.get("category") in _VALID_CATEGORIES
        and value.get("severity") in _VALID_SEVERITIES
    )


def _apply_override(signal: Signal, severity: Severity) -> Signal:
    """Return a copy of ``signal`` at a new severity.

    Spread-and-replace rather than field assignment: it copies exactly the
    keys present and no others, so a signal without ``mitre`` does not come
    back with ``mitre`` set to ``None``. Under the deep equality conformance
    uses, those are different values.
    """
    return {**signal, "severity": severity}


def _run_rule(
    rule: Rule,
    context: RuleContext,
    overrides: dict[str, Severity],
    *,
    strict: bool,
) -> tuple[list[Signal], list[RuleDiagnostic]]:
    signals: list[Signal] = []
    diagnostics: list[RuleDiagnostic] = []

    try:
        produced = rule.evaluate(context)
        # Materialize the result inside fault isolation so a generator
        # that raises during iteration is caught the same way as a rule
        # that raises during evaluate().
        if produced is None:
            return signals, diagnostics
        items = list(produced)
    except Exception as exc:
        if strict:
            raise
        diagnostics.append(
            {
                "ruleId": rule.id,
                "kind": "error",
                # Type name only — str(exc) can contain attacker-controlled
                # message content lifted from the email being analyzed, and
                # diagnostics are documented as safe to display and log.
                "message": f"{type(exc).__name__}",
            }
        )
        return signals, diagnostics

    for item in items:
        if not _looks_like_signal(item):
            diagnostics.append(
                {
                    "ruleId": rule.id,
                    "kind": "malformed_signal",
                    "message": (
                        "rule returned a value that is not a Signal "
                        f"({type(item).__name__}); a Signal needs string "
                        "'id', 'category', 'severity', 'label' and 'detail'"
                    ),
                }
            )
            continue

        signal: Signal = item
        signal_id = signal["id"]

        if signal_id not in rule.emits:
            diagnostics.append(
                {
                    "ruleId": rule.id,
                    "kind": "undeclared_signal",
                    "message": (
                        f"emitted signal id {signal_id!r}, which is not in the "
                        f"rule's declared emits {sorted(rule.emits)!r}; dropped "
                        "because an undeclared id bypasses the ruleset's "
                        "collision check and can suppress another rule's finding"
                    ),
                }
            )
            continue

        override = overrides.get(signal_id)
        signals.append(
            _apply_override(signal, override) if override else signal
        )

    return signals, diagnostics


def evaluate_ruleset(
    ruleset: Ruleset, context: RuleContext, *, strict: bool = False
) -> RuleRunResult:
    """Run every rule in ``ruleset`` against ``context``.

    :param strict: Re-raise instead of isolating a failing rule. Off by
        default, because in production one broken rule losing the whole
        analysis is worse than one broken rule losing its own finding. Turn it
        on in tests and CI, where a rule raising is a defect you want to see
        as a failure rather than as a diagnostic nobody reads.
    """
    overrides = dict(ruleset.severity_overrides)
    signals: list[Signal] = []
    diagnostics: list[RuleDiagnostic] = []

    for rule in ruleset:
        rule_signals, rule_diagnostics = _run_rule(
            rule, context, overrides, strict=strict
        )
        signals.extend(rule_signals)
        diagnostics.extend(rule_diagnostics)

    return {"signals": signals, "diagnostics": diagnostics}


def format_diagnostics(diagnostics: list[RuleDiagnostic]) -> str:
    """One line per diagnostic, for logging. Empty string when there are none."""
    return "\n".join(
        f"[{d['kind']}] {d['ruleId']}: {d['message']}" for d in diagnostics
    )


def rule_traceback(exc: BaseException) -> str:
    """Full traceback for a rule failure, for a debugger rather than a log.

    Kept out of :class:`RuleDiagnostic` on purpose — a traceback can contain
    message content lifted from the email being analyzed, and diagnostics are
    designed to be safe to display and ship. Call this yourself, under
    ``strict=True``, when you are debugging a rule and know where the output
    is going.
    """
    return "".join(
        traceback.format_exception(type(exc), exc, exc.__traceback__)
    )


__all__ = [
    "DiagnosticKind",
    "RuleDiagnostic",
    "RuleRunResult",
    "evaluate_ruleset",
    "format_diagnostics",
    "rule_traceback",
]
