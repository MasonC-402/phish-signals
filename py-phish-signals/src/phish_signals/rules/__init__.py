"""Rule layer — named detection units, and the machinery to run and extend them.

The public surface of everything under ``phish_signals.rules``. Three modules
sit behind it:

:mod:`~phish_signals.rules.types`
    :class:`Rule`, :class:`RuleContext`, :class:`Ruleset` — what a rule is,
    what it may look at, and how a collection of them is assembled and
    derived from.

:mod:`~phish_signals.rules.engine`
    Runs a ruleset, isolates a rule that raises, applies severity overrides.
    Does not score: that stays in :mod:`phish_signals.signals`, so how
    evidence is weighed is decided in one place no matter where it came from.

:mod:`~phish_signals.rules.loader`
    The declarative JSON format, for the large share of content rules that
    are a phrase list and a severity. Data rather than code so that a shared
    loader can eventually eliminate per-implementation drift. Currently
    loaded by the Python side; the TypeScript side still uses inline arrays.

Writing a code rule::

    from phish_signals.rules import Rule, RuleContext, Ruleset
    from phish_signals.types import Signal

    def check_vendor_lookalike(context: RuleContext) -> list[Signal]:
        if "acme-payments" not in (context.sender_domain or ""):
            return []
        return [{
            "id": "acme_vendor_lookalike",
            "category": "identity",
            "severity": "high",
            "label": "Vendor Lookalike Domain",
            "detail": f"Sender domain {context.sender_domain} imitates our vendor.",
        }]

    my_rules = Ruleset(
        name="acme",
        rules=(Rule(
            id="acme.vendor_lookalike",
            emits=frozenset({"acme_vendor_lookalike"}),
            evaluate=check_vendor_lookalike,
            tags=frozenset({"identity"}),
        ),),
    )

Then run it and score the result::

    from phish_signals.rules import evaluate_ruleset
    from phish_signals import score_signals

    run = evaluate_ruleset(my_rules, RuleContext(parsed=parsed))
    scored = score_signals(run["signals"])

Two things worth knowing before writing a rule, both consequences of how
:func:`~phish_signals.signals.score_signals` already works rather than of
anything in this layer:

- **Signal ids are the namespace that matters.** Scoring deduplicates by
  ``Signal.id``, keeping the first. A custom rule emitting a built-in's id
  suppresses it. :class:`Ruleset` refuses to be built when two rules claim one
  signal id — use :meth:`Ruleset.replace_rule` when the override is intended.

- **One rule cannot swing a verdict alone.** A category's score is capped at
  55 and "High Risk" starts at 60, so even a rule firing ``critical`` reaches
  Medium Risk on its own. Getting to High Risk takes evidence on two
  independent categories. A miscalibrated custom rule has a bounded blast
  radius by construction.
"""

from __future__ import annotations

from .engine import (
    DiagnosticKind,
    RuleDiagnostic,
    RuleRunResult,
    evaluate_ruleset,
    format_diagnostics,
    rule_traceback,
)
from .loader import (
    FORMAT_VERSION,
    TEXT_FIELDS,
    RuleLoadError,
    load_rule_file,
    load_ruleset,
    parse_rule,
    parse_rule_file,
    quote_hits,
    render_detail,
)
from .types import (
    CORE_NAMESPACE,
    RULE_ID_PATTERN,
    Rule,
    RuleContext,
    RuleError,
    RuleFn,
    RuleInfo,
    Ruleset,
    RulesetError,
)

__all__ = [
    # What a rule is
    "CORE_NAMESPACE",
    "RULE_ID_PATTERN",
    "Rule",
    "RuleContext",
    "RuleFn",
    "RuleInfo",
    "Ruleset",
    # Running rules
    "DiagnosticKind",
    "RuleDiagnostic",
    "RuleRunResult",
    "evaluate_ruleset",
    "format_diagnostics",
    "rule_traceback",
    # Declarative rules
    "FORMAT_VERSION",
    "TEXT_FIELDS",
    "load_rule_file",
    "load_ruleset",
    "parse_rule",
    "parse_rule_file",
    "quote_hits",
    "render_detail",
    # Errors
    "RuleError",
    "RuleLoadError",
    "RulesetError",
]
