"""Core shapes for the rule layer: rules, rule context, and rulesets.

A rule is not a new concept in this package — it is the thing that already
exists inline inside every check. ``checkContent``'s ``if urgencyHits.length >
0 → signals.push({...})`` block is a rule; it just has no name, cannot be
listed, disabled, or replaced, and cannot be written by anybody who is not
editing this repository. This module gives that unit a name so all three
become possible.

Note the split from :mod:`phish_signals.types`, which is TypedDicts only for
conformance reasons. That constraint applies to *data crossing the language
boundary*. A ``Rule`` never does — it is behavior, it is never serialized into
a JSON export, and no conformance vector compares one by deep equality — so it
is an ordinary frozen dataclass. What a rule *emits* is still a plain
:class:`~phish_signals.types.Signal` dict, and the rules there apply in full:
never add an optional key set to ``None``, because an absent ``mitre`` and a
``mitre`` of ``None`` are different values under the deep equality the
conformance harness uses.

Two identifiers, deliberately distinct:

``Rule.id``
    Namespaced (``core.urgency_language``, ``acme.vendor_lookalike``) and
    unique within a ruleset. This is registry identity — what you disable,
    replace, or filter on. It never appears in output.

``Rule.emits``
    The set of ``Signal.id`` values the rule may produce. These *do* appear in
    output, and they are the ones that must stay stable across the TypeScript
    and Python implementations because conformance vectors name them.

Keeping them separate is what makes the collision check meaningful.
:func:`phish_signals.signals.score_signals` deduplicates by ``Signal.id`` with
first-one-wins, so two rules that both emit ``urgency_language`` do not both
count — whichever ran second is silently discarded, and which one that is
depends on ruleset order. That is a genuinely nasty failure mode for someone
writing a custom rule against a library they did not write: they get no error,
they get a rule that does nothing, or worse, they get a rule that suppresses a
built-in. :class:`Ruleset` rejects it at construction time instead.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field, replace
from functools import cached_property
from typing import TypedDict

from ..domains import registrable_domain
from ..types import (
    AuthCheckResult,
    HeaderAnomalyResult,
    ParsedEmail,
    ReceivedChainAnalysis,
    Severity,
    Signal,
    UrlAnalysis,
)

#: A rule id must be ``<namespace>.<name>``, both lowercase identifiers. The
#: namespace is not decoration: it is what stops a custom rule from colliding
#: with a built-in by accident, and what makes ``without_namespace('acme')``
#: possible for someone debugging whether their own rules caused a verdict.
RULE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")

#: Namespace reserved for rules shipped by this package.
CORE_NAMESPACE = "core"

_ADDRESS_DOMAIN = re.compile(r"@([\w.-]+\.[a-z]{2,})", re.IGNORECASE)


class RuleError(Exception):
    """Base class for every error this layer raises."""


class RulesetError(RuleError):
    """A ruleset could not be assembled — bad id, or two rules claiming one signal."""


def _domain_of(address: str | None) -> str | None:
    """Registrable domain of an email address, or None.

    Mirrors ``domainOf`` in ``typescript/src/combineResults.ts`` exactly,
    including its tolerance of a bare hostname with no local part.
    """
    if not address:
        return None
    match = _ADDRESS_DOMAIN.search(address)
    if not match:
        return None
    return registrable_domain(match.group(1).lower())


@dataclass(frozen=True)
class RuleContext:
    """Everything a rule is allowed to look at, plus cached derivations of it.

    This is the part of the design that actually earns its keep. The protocol
    around it is four lines; the reason a rule layer is worth having at all is
    that fifty rules can share one parse instead of each lowercasing the body
    and re-deriving the sender domain. The cached properties below exist
    because they were about to be duplicated across rules, not speculatively.

    **Derived data only.** A context is assembled once, before any rule runs,
    from work the pipeline has already done. Nothing here performs I/O, and
    nothing here should ever be allowed to: it is what keeps the "no external
    API calls, no cost" property of this package true no matter what rules a
    consumer loads, and it is what makes a rule testable by handing it a
    literal instead of a fixture and a network mock.

    Fields other than ``parsed`` default to empty, so a content rule can be
    written and unit-tested against a bare context without standing up the
    whole pipeline.

    Frozen, but read it as "no rule may mutate this" rather than as a deep
    immutability guarantee — the ``parsed`` dict underneath is still a dict.
    :func:`~phish_signals.rules.engine.evaluate_ruleset` does not defensively
    copy it on every rule call, because doing that per rule on every message
    costs more than the class of bug it prevents. A rule that mutates its
    context is a bug in that rule.
    """

    parsed: ParsedEmail
    urls: list[UrlAnalysis] = field(default_factory=list)
    auth: AuthCheckResult | None = None
    chain: ReceivedChainAnalysis | None = None
    header_anomalies: HeaderAnomalyResult | None = None

    # --- text ------------------------------------------------------------
    # Lowercased once here rather than in each rule. `scan_text` is the field
    # content heuristics should normally match against: it is subject + text
    # part + de-tagged HTML, so a lure that appears only in the subject line or
    # only inside HTML markup is still seen.

    @cached_property
    def scan_text_lower(self) -> str:
        return (self.parsed.get("scanText") or "").lower()

    @cached_property
    def body_text_lower(self) -> str:
        return (self.parsed.get("textBody") or "").lower()

    @cached_property
    def html_body_lower(self) -> str:
        return (self.parsed.get("htmlBody") or "").lower()

    @cached_property
    def subject_lower(self) -> str:
        return (self.parsed.get("subject") or "").lower()

    # --- addresses -------------------------------------------------------

    @cached_property
    def sender_domain(self) -> str | None:
        return _domain_of(self.parsed.get("from"))

    @cached_property
    def reply_to_domain(self) -> str | None:
        return _domain_of(self.parsed.get("replyTo"))

    @cached_property
    def return_path_domain(self) -> str | None:
        return _domain_of(self.parsed.get("returnPath"))

    # --- links -----------------------------------------------------------

    @cached_property
    def link_hostnames(self) -> frozenset[str]:
        """Every hostname a URL check managed to resolve, lowercased.

        Built from the analyzed URLs rather than from ``parsed['urls']``
        because the analyzer is what knows how to get a hostname out of a
        string that may not be a well-formed URL at all.
        """
        return frozenset(
            hostname.lower()
            for url in self.urls
            if (hostname := url.get("hostname"))
        )

    @cached_property
    def link_domains(self) -> frozenset[str]:
        """Registrable domains of :attr:`link_hostnames`."""
        return frozenset(
            domain
            for hostname in self.link_hostnames
            if (domain := registrable_domain(hostname))
        )


#: What a rule's callable must look like. Returning a list rather than a single
#: optional signal is deliberate: a rule that finds three lookalike domains
#: reports three findings, and flattening that into one signal would lose the
#: per-finding detail that makes the output actionable.
RuleFn = Callable[[RuleContext], list[Signal]]


@dataclass(frozen=True)
class Rule:
    """One named piece of detection logic.

    ``emits`` is not redundant with what :attr:`evaluate` returns. It is a
    declaration checked against reality: it lets a ruleset detect a signal-id
    collision between two rules *before* either has run, which is the only
    point at which the problem can still be reported as an error rather than
    as a silently missing finding.
    """

    id: str
    #: Signal ids this rule may produce. Every signal it actually emits must
    #: be one of these; the engine drops anything else as a diagnostic rather
    #: than letting an undeclared id reach the score.
    emits: frozenset[str]
    evaluate: RuleFn
    #: Free-form labels for selection — 'content', 'header', 'experimental'.
    #: Not part of scoring; purely how a consumer picks a subset.
    tags: frozenset[str] = frozenset()
    #: One line on what this looks for. Shown when listing a ruleset.
    description: str = ""

    def __post_init__(self) -> None:
        if not RULE_ID_PATTERN.match(self.id):
            raise RulesetError(
                f"invalid rule id {self.id!r}: expected '<namespace>.<name>', "
                "lowercase letters, digits and underscores only "
                "(e.g. 'acme.vendor_lookalike')"
            )
        if not self.emits:
            raise RulesetError(
                f"rule {self.id!r} declares no signal ids in 'emits'; a rule "
                "that can never produce a signal cannot affect a verdict"
            )

    @property
    def namespace(self) -> str:
        return self.id.split(".", 1)[0]


class RuleInfo(TypedDict):
    """Serializable description of a rule, for listing a ruleset.

    A TypedDict rather than a dataclass because this one *is* meant to be
    JSON-dumped — into a report's "what ran" section, or a CLI listing.
    """

    id: str
    emits: list[str]
    tags: list[str]
    description: str


@dataclass(frozen=True)
class Ruleset:
    """An ordered, immutable collection of rules.

    Immutable and explicitly passed, never a global registry populated by
    import-time decorators. Two reasons, both learned the hard way elsewhere:
    which rules ran would otherwise depend on which modules happened to be
    imported, and tests could not run a custom ruleset without leaking it into
    every other test in the process.

    Order is preserved and is the order rules run in. That matters more than
    it looks: ``score_signals`` deduplicates by signal id first-one-wins, so
    order decides which of two same-id signals survives. The collision check
    in :meth:`validate` exists so that situation cannot arise by accident, but
    it can still be reached deliberately via :meth:`replace_rule`.

    Every derivation returns a new ruleset. Nothing mutates in place, so a
    consumer narrowing the default set for one message cannot affect the next.
    """

    name: str
    rules: tuple[Rule, ...] = ()
    #: Severity to force for a given signal id, overriding whatever the rule
    #: emitted. Tuning knob for a consumer whose environment disagrees with a
    #: default — an org that genuinely does send gift-card requests by email
    #: can turn that signal down without forking the rule or losing it
    #: entirely. Applied by the engine.
    severity_overrides: Mapping[str, Severity] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        """Raise :class:`RulesetError` on a duplicate rule id or signal id.

        The signal-id half is the one that matters. A duplicate rule id is an
        obvious mistake that would surface quickly; a duplicate *signal* id
        produces a ruleset that loads cleanly, runs cleanly, and quietly drops
        one of the two rules' findings at scoring time.
        """
        seen_rule_ids: dict[str, Rule] = {}
        emitters: dict[str, Rule] = {}

        for rule in self.rules:
            if rule.id in seen_rule_ids:
                raise RulesetError(
                    f"ruleset {self.name!r} contains rule id {rule.id!r} twice; "
                    "rule ids must be unique (use Ruleset.replace_rule to "
                    "substitute one deliberately)"
                )
            seen_rule_ids[rule.id] = rule

            for signal_id in sorted(rule.emits):
                owner = emitters.get(signal_id)
                if owner is not None:
                    raise RulesetError(
                        f"ruleset {self.name!r}: rules {owner.id!r} and "
                        f"{rule.id!r} both emit signal id {signal_id!r}. "
                        "score_signals() deduplicates by signal id and keeps "
                        "only the first, so one of these rules would be "
                        "silently discarded. Rename the signal, or use "
                        f"Ruleset.replace_rule({owner.id!r}, ...) if you meant "
                        "to override it."
                    )
                emitters[signal_id] = rule

        for signal_id in self.severity_overrides:
            if signal_id not in emitters:
                raise RulesetError(
                    f"ruleset {self.name!r}: severity override for signal id "
                    f"{signal_id!r}, which no rule in this ruleset emits"
                )

    # --- lookup ----------------------------------------------------------

    def __iter__(self) -> Iterator[Rule]:
        return iter(self.rules)

    def __len__(self) -> int:
        return len(self.rules)

    def get(self, rule_id: str) -> Rule | None:
        return next((r for r in self.rules if r.id == rule_id), None)

    def describe(self) -> list[RuleInfo]:
        """List what is in this ruleset, in run order, as plain JSON-able data."""
        return [
            {
                "id": rule.id,
                "emits": sorted(rule.emits),
                "tags": sorted(rule.tags),
                "description": rule.description,
            }
            for rule in self.rules
        ]

    # --- derivation ------------------------------------------------------

    def with_rules(self, extra: Iterable[Rule], *, name: str | None = None) -> Ruleset:
        """Append rules. Raises if any collides with what is already here."""
        return replace(
            self,
            name=name or self.name,
            rules=self.rules + tuple(extra),
        )

    def replace_rule(self, rule_id: str, new_rule: Rule) -> Ruleset:
        """Swap one rule for another, in place, keeping run order.

        The supported way to override a built-in with something that emits the
        same signal id — an org-specific version of ``urgency_language`` with
        a tuned phrase list, say. Doing it this way rather than appending
        keeps the collision check honest: exactly one rule owns a signal id at
        any time, so the override genuinely replaces the original instead of
        racing it.
        """
        if self.get(rule_id) is None:
            raise RulesetError(
                f"ruleset {self.name!r} has no rule {rule_id!r} to replace"
            )
        return replace(
            self,
            rules=tuple(new_rule if r.id == rule_id else r for r in self.rules),
        )

    def without(self, rule_ids: Iterable[str]) -> Ruleset:
        """Drop rules by id.

        Unknown ids are ignored — this is a filter, not a lookup.
        """
        drop = frozenset(rule_ids)
        kept = tuple(r for r in self.rules if r.id not in drop)
        return self._rebuild(kept)

    def without_tags(self, tags: Iterable[str]) -> Ruleset:
        """Drop every rule carrying any of these tags."""
        drop = frozenset(tags)
        kept = tuple(r for r in self.rules if not (r.tags & drop))
        return self._rebuild(kept)

    def with_tags(self, tags: Iterable[str]) -> Ruleset:
        """Keep only rules carrying at least one of these tags."""
        keep = frozenset(tags)
        kept = tuple(r for r in self.rules if r.tags & keep)
        return self._rebuild(kept)

    def with_severity_overrides(
        self, overrides: Mapping[str, Severity]
    ) -> Ruleset:
        """Return a ruleset with these signal-id severity overrides merged in."""
        return replace(
            self, severity_overrides={**self.severity_overrides, **overrides}
        )

    def _rebuild(self, kept: tuple[Rule, ...]) -> Ruleset:
        """Rebuild after a filter, dropping overrides that no longer apply.

        Filtering out a rule leaves any override for its signal ids dangling,
        and ``validate()`` treats a dangling override as an error — correctly,
        since a typo'd override should not fail silently. So a filter prunes
        them rather than making every ``without_tags`` call a landmine.
        """
        still_emitted = {sid for rule in kept for sid in rule.emits}
        return replace(
            self,
            rules=kept,
            severity_overrides={
                sid: sev
                for sid, sev in self.severity_overrides.items()
                if sid in still_emitted
            },
        )


__all__ = [
    "CORE_NAMESPACE",
    "RULE_ID_PATTERN",
    "Rule",
    "RuleContext",
    "RuleError",
    "RuleFn",
    "RuleInfo",
    "Ruleset",
    "RulesetError",
]
