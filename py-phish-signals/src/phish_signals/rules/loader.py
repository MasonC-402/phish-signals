"""The declarative rule format: phishing rules as JSON data rather than code.

Most of what this engine looks for in message *content* is a phrase list and a
severity. ``checkContent`` in the TypeScript reference is four such lists and
four near-identical blocks of code around them. Written as code, each of those
has to be written twice — once per implementation — and every phrase added to
one side is drift until somebody adds it to the other. Written as data,
both implementations load the same file and there is nothing to keep in sync.

That is the whole argument for this module. It is not about making rules
prettier; it is about deleting a category of divergence that the
``conformance/`` suite otherwise exists to catch after the fact.

**What is deliberately not here: regular expressions.** This library feeds
attacker-controlled text into whatever matcher a rule declares. Python's
:mod:`re` has no timeout and its engine backtracks, so a user-supplied pattern
plus a crafted body is a denial of service in a library whose entire job is
parsing hostile input — and the person who wrote the rule is usually not the
person running it. So the declarative grammar is a closed set of matchers with
bounded cost, and free-form patterns are only available in code rules, where
whoever wrote the pattern is whoever ships it and owns the risk. Substring
scanning covers the overwhelming majority of real content rules; the handful
that genuinely need a pattern (generic-greeting detection, for instance) are
worth the few lines of Python.

Format — one JSON file per group of rules::

    {
      "version": 1,
      "namespace": "core",
      "rules": [
        {
          "id": "urgency_language",
          "category": "social",
          "label": "Urgency / Pressure Language",
          "severity": {
            "base": "low", "escalate_to": "medium", "when_hits_at_least": 3
          },
          "match": {
            "type": "phrases", "field": "scan_text", "any_of": ["act now"]
          },
          "detail": "Contains phrases designed to rush you: {hits}.",
          "mitre": ["T1566"],
          "tags": ["content"]
        }
      ]
    }

Validation is strict and unknown keys are an error, not a warning. A typo'd
``"severty"`` that loads quietly gives you a rule running at the wrong weight
with nothing to indicate it, which is worse than a file that refuses to load.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, cast

from ..types import EvidenceCategory, Severity, Signal
from .types import Rule, RuleContext, RuleError, Ruleset

#: Format version understood by this loader. A file declaring anything else is
#: rejected rather than best-effort parsed, so that adding a matcher type later
#: cannot make an old loader silently ignore it.
FORMAT_VERSION = 1

_VALID_CATEGORIES: frozenset[str] = frozenset(
    {"authentication", "identity", "infrastructure", "payload", "social"}
)
_VALID_SEVERITIES: frozenset[str] = frozenset(
    {"critical", "high", "medium", "low", "info"}
)

#: Text a ``phrases`` matcher can scan, mapped to the pre-lowercased
#: :class:`~phish_signals.rules.types.RuleContext` property that provides it.
#: ``scan_text`` is the usual choice — subject plus text part plus de-tagged
#: HTML — so a lure that appears only in the subject or only inside markup is
#: still caught.
TEXT_FIELDS: dict[str, str] = {
    "scan_text": "scan_text_lower",
    "body_text": "body_text_lower",
    "html_body": "html_body_lower",
    "subject": "subject_lower",
}

_RULE_KEYS = frozenset(
    {
        "id",
        "signal_id",
        "category",
        "label",
        "severity",
        "match",
        "detail",
        "mitre",
        "benign",
        "tags",
        "description",
    }
)
_REQUIRED_RULE_KEYS = frozenset(
    {"id", "category", "label", "severity", "match", "detail"}
)
_FILE_KEYS = frozenset({"version", "namespace", "rules"})
_SEVERITY_KEYS = frozenset({"base", "escalate_to", "when_hits_at_least"})
_PHRASES_KEYS = frozenset({"type", "field", "any_of"})


class RuleLoadError(RuleError):
    """A rule file was malformed. Names the file and the rule where possible."""


def _fail(where: str, message: str) -> RuleLoadError:
    return RuleLoadError(f"{where}: {message}")


def _require_mapping(value: object, where: str, what: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail(where, f"{what} must be an object, got {type(value).__name__}")
    return value


def _check_keys(
    data: Mapping[str, Any], allowed: frozenset[str], where: str, what: str
) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise _fail(
            where,
            f"unknown {what} key(s) {unknown!r}; allowed keys are "
            f"{sorted(allowed)!r}. Unknown keys are rejected rather than "
            "ignored so a typo cannot silently change what a rule does",
        )


def _string_list(value: object, where: str, what: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise _fail(where, f"{what} must be a list of strings")
    return list(value)


def quote_hits(hits: list[str]) -> str:
    """Render matched phrases the way the reference implementation does.

    Mirrors ``quote()`` in ``typescript/src/contentCheck.ts`` — first three
    hits, double-quoted, comma-separated — because this string lands in
    ``Signal.detail``, which conformance vectors compare verbatim.
    """
    return '"' + '", "'.join(hits[:3]) + '"'


def render_detail(template: str, hits: list[str]) -> str:
    """Substitute ``{hits}`` and ``{hit_count}`` into a detail template.

    Plain replacement rather than :meth:`str.format`. Two reasons: ``format``
    on a template loaded from a file exposes attribute and index traversal
    (``{0.__class__}``), and a literal brace anywhere in a detail string —
    entirely plausible in security copy — would raise. Replacement is also
    trivially identical to port to TypeScript, which matters for a string that
    ends up under deep-equality comparison.
    """
    return template.replace("{hits}", quote_hits(hits)).replace(
        "{hit_count}", str(len(hits))
    )


def _parse_severity(value: object, where: str) -> tuple[Severity, Severity, int]:
    """Return ``(base, escalated, threshold)``.

    Severity scaling with hit count is in the format because it is the pattern
    the existing content checks already use, and for a good reason: one
    "urgent" is a word, four pressure phrases in one message is a technique.
    A plain string means no escalation, expressed as a threshold no hit count
    can reach.
    """
    if isinstance(value, str):
        if value not in _VALID_SEVERITIES:
            raise _fail(
                where, f"severity {value!r} is not one of {sorted(_VALID_SEVERITIES)!r}"
            )
        severity = cast(Severity, value)
        return severity, severity, 1 << 30

    spec = _require_mapping(value, where, "severity")
    _check_keys(spec, _SEVERITY_KEYS, where, "severity")

    base_raw = spec.get("base")
    if not isinstance(base_raw, str) or base_raw not in _VALID_SEVERITIES:
        raise _fail(
            where,
            f"severity.base {base_raw!r} is not one of {sorted(_VALID_SEVERITIES)!r}",
        )
    base = cast(Severity, base_raw)

    if "escalate_to" not in spec:
        if "when_hits_at_least" in spec:
            raise _fail(
                where,
                "severity.when_hits_at_least is set but escalate_to is "
                "absent; a threshold without an escalation target has no "
                "effect and is likely a mistake",
            )
        return base, base, 1 << 30

    escalate_raw = spec.get("escalate_to")
    if not isinstance(escalate_raw, str) or escalate_raw not in _VALID_SEVERITIES:
        raise _fail(
            where,
            f"severity.escalate_to {escalate_raw!r} is not one of "
            f"{sorted(_VALID_SEVERITIES)!r}",
        )
    escalated = cast(Severity, escalate_raw)

    threshold = spec.get("when_hits_at_least")
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        raise _fail(
            where,
            "severity.when_hits_at_least must be an integer >= 1 when "
            "escalate_to is set",
        )
    return base, escalated, threshold


def _build_phrases_matcher(
    spec: Mapping[str, Any], where: str
) -> tuple[str, tuple[str, ...]]:
    """Validate a ``phrases`` matcher and return ``(context_attr, phrases)``."""
    _check_keys(spec, _PHRASES_KEYS, where, "match")

    field_name = spec.get("field", "scan_text")
    if not isinstance(field_name, str) or field_name not in TEXT_FIELDS:
        raise _fail(
            where,
            f"match.field {field_name!r} is not one of {sorted(TEXT_FIELDS)!r}",
        )

    phrases = _string_list(spec.get("any_of"), where, "match.any_of")
    if not phrases:
        raise _fail(where, "match.any_of must contain at least one phrase")

    lowered: list[str] = []
    for phrase in phrases:
        if phrase != phrase.lower():
            raise _fail(
                where,
                f"match.any_of entry {phrase!r} contains uppercase; phrases are "
                "matched against pre-lowercased text, so an uppercase phrase "
                "can never match. Write it lowercase",
            )
        if not phrase.strip():
            raise _fail(where, "match.any_of contains an empty phrase")
        lowered.append(phrase)

    # Order is preserved, not sorted: the reference filters the declared list
    # in declaration order, and the first three survivors are what `{hits}`
    # renders. Sorting here would change the detail string.
    return TEXT_FIELDS[field_name], tuple(lowered)


def parse_rule(
    data: Mapping[str, Any], namespace: str, *, where: str = "<rule>"
) -> Rule:
    """Build one :class:`Rule` from its declarative form.

    Exposed separately from file loading so a consumer can define data rules
    inline — from a database row, a config service, or a test — without
    writing a file first.
    """
    _check_keys(data, _RULE_KEYS, where, "rule")

    missing = sorted(_REQUIRED_RULE_KEYS - set(data))
    if missing:
        raise _fail(where, f"missing required rule key(s) {missing!r}")

    local_id = data["id"]
    if not isinstance(local_id, str):
        raise _fail(where, "rule id must be a string")
    where = f"{where} (rule {local_id!r})"

    signal_id = data.get("signal_id", local_id)
    if not isinstance(signal_id, str) or not signal_id:
        raise _fail(where, "signal_id must be a non-empty string")

    category = data["category"]
    if not isinstance(category, str) or category not in _VALID_CATEGORIES:
        raise _fail(
            where, f"category {category!r} is not one of {sorted(_VALID_CATEGORIES)!r}"
        )

    label = data["label"]
    detail_template = data["detail"]
    if not isinstance(label, str) or not isinstance(detail_template, str):
        raise _fail(where, "label and detail must be strings")

    base, escalated, threshold = _parse_severity(data["severity"], where)

    match_spec = _require_mapping(data["match"], where, "match")
    match_type = match_spec.get("type")
    if match_type != "phrases":
        raise _fail(
            where,
            f"match.type {match_type!r} is not supported; the declarative "
            "format currently supports 'phrases' only. Matchers with "
            "unbounded cost (regular expressions) are intentionally excluded "
            "— write those as a code rule",
        )
    attr, phrases = _build_phrases_matcher(match_spec, where)

    mitre = _string_list(data.get("mitre", []), where, "mitre")
    tags = frozenset(_string_list(data.get("tags", []), where, "tags"))

    benign = data.get("benign", False)
    if not isinstance(benign, bool):
        raise _fail(where, "benign must be a boolean")

    description = data.get("description", "")
    if not isinstance(description, str):
        raise _fail(where, "description must be a string")

    evaluate = _make_phrase_evaluator(
        signal_id=signal_id,
        category=cast(EvidenceCategory, category),
        label=label,
        detail_template=detail_template,
        attr=attr,
        phrases=phrases,
        base=base,
        escalated=escalated,
        threshold=threshold,
        mitre=tuple(mitre),
        benign=benign,
    )

    return Rule(
        id=f"{namespace}.{local_id}",
        emits=frozenset({signal_id}),
        evaluate=evaluate,
        tags=tags,
        description=description,
    )


def _make_phrase_evaluator(
    *,
    signal_id: str,
    category: EvidenceCategory,
    label: str,
    detail_template: str,
    attr: str,
    phrases: tuple[str, ...],
    base: Severity,
    escalated: Severity,
    threshold: int,
    mitre: tuple[str, ...],
    benign: bool,
):
    """Close over a validated spec and return the rule's callable.

    Everything is validated and bound once at load time so the per-message
    path is a substring scan and nothing else — no dict lookups into the spec,
    no re-validation, no branching on format details.
    """

    def evaluate(context: RuleContext) -> list[Signal]:
        text: str = getattr(context, attr)
        if not text:
            return []

        # Declaration order, matching the reference's `phraseList.filter(...)`.
        # `{hits}` renders the first three, so a different order here would
        # produce a different detail string for the same message.
        hits = [phrase for phrase in phrases if phrase in text]
        if not hits:
            return []

        signal: Signal = {
            "id": signal_id,
            "category": category,
            "severity": escalated if len(hits) >= threshold else base,
            "label": label,
            "detail": render_detail(detail_template, hits),
        }
        # Optional keys are added only when they carry something. An absent
        # `mitre` and a `mitre` of None are different values under the deep
        # equality the conformance harness uses, so a key must never be set
        # just to keep the shape uniform.
        if mitre:
            signal["mitre"] = list(mitre)
        if benign:
            signal["benign"] = True
        return [signal]

    return evaluate


def parse_rule_file(data: Mapping[str, Any], *, where: str = "<file>") -> list[Rule]:
    """Build the rules described by one already-parsed rule file."""
    _check_keys(data, _FILE_KEYS, where, "file")

    version = data.get("version")
    is_valid_version = (
        isinstance(version, int) and not isinstance(version, bool)
        and version == FORMAT_VERSION
    )
    if not is_valid_version:
        raise _fail(
            where,
            f"unsupported format version {version!r}; this loader understands "
            f"version {FORMAT_VERSION}",
        )

    namespace = data.get("namespace")
    if not isinstance(namespace, str) or not namespace:
        raise _fail(where, "'namespace' must be a non-empty string")

    rules_raw = data.get("rules")
    if not isinstance(rules_raw, list):
        raise _fail(where, "'rules' must be a list")

    return [
        parse_rule(
            _require_mapping(entry, where, f"rules[{index}]"),
            namespace,
            where=f"{where} rules[{index}]",
        )
        for index, entry in enumerate(rules_raw)
    ]


def load_rule_file(path: str | Path) -> list[Rule]:
    """Read and parse one ``.json`` rule file."""
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise _fail(str(path), f"invalid JSON: {exc}") from exc
    except OSError as exc:
        raise _fail(str(path), f"could not be read: {exc}") from exc

    return parse_rule_file(
        _require_mapping(raw, str(path), "rule file"), where=str(path)
    )


def load_ruleset(
    directory: str | Path, *, name: str, extra: Iterable[Rule] = ()
) -> Ruleset:
    """Load every ``*.json`` under ``directory`` into one ruleset.

    Files are read in sorted filename order and rules keep their in-file
    order, so the resulting ruleset is identical run to run and machine to
    machine. That matters because ruleset order decides which of two same-id
    signals survives ``score_signals``' dedupe — a ruleset whose order depends
    on filesystem iteration order would be a verdict that changes between
    machines for no visible reason.

    Not recursive. Subdirectories are for grouping files you load separately,
    not a hierarchy this flattens behind your back.
    """
    directory = Path(directory)
    if not directory.is_dir():
        raise _fail(str(directory), "is not a directory")

    rules: list[Rule] = []
    for path in sorted(directory.glob("*.json")):
        rules.extend(load_rule_file(path))
    rules.extend(extra)

    # Ruleset.__post_init__ validates — a signal id claimed by two files
    # surfaces here, as an error naming both rules.
    return Ruleset(name=name, rules=tuple(rules))


__all__ = [
    "FORMAT_VERSION",
    "TEXT_FIELDS",
    "RuleLoadError",
    "load_rule_file",
    "load_ruleset",
    "parse_rule",
    "parse_rule_file",
    "quote_hits",
    "render_detail",
]
