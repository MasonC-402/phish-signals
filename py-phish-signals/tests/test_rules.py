"""Tests for the rule layer.

Grouped by the property each one is defending, because most of these exist to
pin down a specific failure mode that is silent rather than loud — a rule that
quietly suppresses another rule's finding, an optional key that acquires a
``None`` and breaks deep equality, a ruleset whose order depends on filesystem
iteration. None of those show up as an exception if the guard is removed; they
show up as a wrong verdict.
"""

from __future__ import annotations

import json
from typing import Any, cast

import pytest

from phish_signals import score_signals
from phish_signals.rules import (
    Rule,
    RuleContext,
    Ruleset,
    RulesetError,
    evaluate_ruleset,
    load_rule_file,
    load_ruleset,
    parse_rule,
    quote_hits,
    render_detail,
)
from phish_signals.rules.loader import RuleLoadError
from phish_signals.types import ParsedEmail, Signal


def make_parsed(**overrides: object) -> ParsedEmail:
    """A ParsedEmail with every key present, so rules see a realistic shape."""
    parsed: ParsedEmail = {
        "isRawEmail": True,
        "from": None,
        "returnPath": None,
        "replyTo": None,
        "subject": None,
        "date": None,
        "headers": None,
        "headerLines": [],
        "textBody": "",
        "htmlBody": None,
        "scanText": "",
        "urls": [],
        "linkMismatches": [],
        "dangerousSchemes": [],
        "attachments": [],
        "imageCount": 0,
        "qrCodeUrls": [],
        "qrImagesScanned": 0,
    }
    # Cast rather than update(): overrides are deliberately loosely typed so a
    # test can set one key without restating the other sixteen.
    return cast(ParsedEmail, {**parsed, **overrides})


def static_rule(rule_id: str, signal_id: str, **signal_overrides: object) -> Rule:
    """A rule that always fires one signal.

    For exercising the machinery, not detection logic.
    """

    def evaluate(context: RuleContext) -> list[Signal]:
        signal: Signal = {
            "id": signal_id,
            "category": "social",
            "severity": "low",
            "label": f"Label for {signal_id}",
            "detail": "detail",
        }
        return [cast(Signal, {**signal, **signal_overrides})]

    return Rule(id=rule_id, emits=frozenset({signal_id}), evaluate=evaluate)


EMPTY_CONTEXT = RuleContext(parsed=make_parsed())


# --------------------------------------------------------------------------
# Rule identity
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_id",
    [
        "urgency_language",  # no namespace
        "Core.Urgency",  # uppercase
        "core.",  # empty name
        ".urgency",  # empty namespace
        "core.sub.rule",  # two dots
        "1core.rule",  # leading digit
    ],
)
def test_rule_id_must_be_namespaced(bad_id: str) -> None:
    with pytest.raises(RulesetError, match="invalid rule id"):
        static_rule(bad_id, "sig")


def test_rule_must_declare_at_least_one_emitted_signal() -> None:
    with pytest.raises(RulesetError, match="declares no signal ids"):
        Rule(id="acme.dead", emits=frozenset(), evaluate=lambda ctx: [])


def test_namespace_property() -> None:
    assert static_rule("acme.vendor_lookalike", "sig").namespace == "acme"


# --------------------------------------------------------------------------
# Ruleset validation — the collision guard is the reason this layer exists
# --------------------------------------------------------------------------


def test_two_rules_emitting_one_signal_id_is_rejected() -> None:
    """The silent failure this whole design is built around.

    score_signals dedupes by signal id first-one-wins, so without this guard
    the second rule runs, produces a signal, and has it dropped at scoring
    time with no error anywhere.
    """
    with pytest.raises(RulesetError, match="both emit signal id 'urgency_language'"):
        Ruleset(
            name="test",
            rules=(
                static_rule("core.urgency", "urgency_language"),
                static_rule("acme.urgency", "urgency_language"),
            ),
        )


def test_duplicate_rule_id_is_rejected() -> None:
    with pytest.raises(RulesetError, match="twice"):
        Ruleset(
            name="test",
            rules=(
                static_rule("acme.dup", "sig_a"),
                static_rule("acme.dup", "sig_b"),
            ),
        )


def test_severity_override_for_unemitted_signal_is_rejected() -> None:
    """A typo'd override must not fail silently."""
    with pytest.raises(RulesetError, match="which no rule in this ruleset emits"):
        Ruleset(
            name="test",
            rules=(static_rule("acme.one", "sig_a"),),
            severity_overrides={"sig_typo": "high"},
        )


def test_replace_rule_is_the_supported_override_path() -> None:
    base = Ruleset(
        name="core", rules=(static_rule("core.urgency", "urgency_language"),)
    )
    tuned = base.replace_rule(
        "core.urgency", static_rule("acme.urgency", "urgency_language")
    )

    assert [r.id for r in tuned] == ["acme.urgency"]
    # Derivation returns a new ruleset; the original is untouched.
    assert base.get("core.urgency") is not None


def test_replace_unknown_rule_raises() -> None:
    base = Ruleset(name="core", rules=(static_rule("core.a", "sig_a"),))
    with pytest.raises(RulesetError, match="has no rule"):
        base.replace_rule("core.nope", static_rule("core.b", "sig_b"))


def test_with_rules_rejects_a_colliding_addition() -> None:
    base = Ruleset(name="core", rules=(static_rule("core.a", "sig_a"),))
    with pytest.raises(RulesetError, match="both emit signal id"):
        base.with_rules([static_rule("acme.a", "sig_a")])


# --------------------------------------------------------------------------
# Ruleset derivation
# --------------------------------------------------------------------------


def tagged(rule_id: str, signal_id: str, *tags: str) -> Rule:
    rule = static_rule(rule_id, signal_id)
    return Rule(
        id=rule.id, emits=rule.emits, evaluate=rule.evaluate, tags=frozenset(tags)
    )


def test_tag_filters() -> None:
    ruleset = Ruleset(
        name="core",
        rules=(
            tagged("core.a", "sig_a", "content"),
            tagged("core.b", "sig_b", "header"),
            tagged("core.c", "sig_c", "content", "experimental"),
        ),
    )

    assert [r.id for r in ruleset.with_tags(["content"])] == ["core.a", "core.c"]
    assert [r.id for r in ruleset.without_tags(["experimental"])] == [
        "core.a",
        "core.b",
    ]
    assert [r.id for r in ruleset.without(["core.b"])] == ["core.a", "core.c"]


def test_filtering_prunes_now_dangling_severity_overrides() -> None:
    """Otherwise every without_tags() call is a landmine.

    validate() rejects an override for a signal nobody emits — correct, since
    a typo should be loud. But that would make filtering out the rule the
    override targets raise, which is not a mistake at all.
    """
    ruleset = Ruleset(
        name="core",
        rules=(
            tagged("core.a", "sig_a", "content"),
            tagged("core.b", "sig_b", "header"),
        ),
        severity_overrides={"sig_a": "high", "sig_b": "info"},
    )
    filtered = ruleset.without_tags(["header"])

    assert dict(filtered.severity_overrides) == {"sig_a": "high"}


def test_describe_is_json_serializable_and_in_run_order() -> None:
    ruleset = Ruleset(
        name="core",
        rules=(tagged("core.b", "sig_b", "x"), tagged("core.a", "sig_a")),
    )
    described = ruleset.describe()

    assert [r["id"] for r in described] == ["core.b", "core.a"]
    json.dumps(described)


# --------------------------------------------------------------------------
# RuleContext
# --------------------------------------------------------------------------


def test_context_derives_and_caches_address_domains() -> None:
    context = RuleContext(
        parsed=make_parsed(
            **{
                "from": "Billing <billing@mail.example.co.uk>",
                "replyTo": "attacker@evil.test",
            }
        )
    )

    assert context.sender_domain == "example.co.uk"
    assert context.reply_to_domain is None or context.reply_to_domain.endswith("test")
    # cached_property on a frozen dataclass writes straight into __dict__,
    # bypassing the frozen __setattr__ — worth pinning, since adding
    # slots=True to RuleContext would break it with no other visible symptom.
    assert "sender_domain" in context.__dict__


def test_context_text_fields_are_lowercased_and_none_safe() -> None:
    context = RuleContext(
        parsed=make_parsed(subject="URGENT Action", scanText="ACT NOW", htmlBody=None)
    )

    assert context.subject_lower == "urgent action"
    assert context.scan_text_lower == "act now"
    assert context.html_body_lower == ""


def test_context_link_domains_come_from_analyzed_urls() -> None:
    context = RuleContext(
        parsed=make_parsed(),
        urls=[
            {
                "url": "https://a.evil.test/x",
                "hostname": "A.Evil.Test",
                "risk": "suspicious",
                "detail": "",
            },
            {"url": "https://no-hostname", "risk": "unknown", "detail": ""},
        ],
    )

    assert context.link_hostnames == frozenset({"a.evil.test"})
    assert context.link_domains == frozenset({"evil.test"})


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------


def test_a_raising_rule_is_isolated_not_fatal() -> None:
    def boom(context: RuleContext) -> list[Signal]:
        raise ValueError("bad regex or whatever")

    ruleset = Ruleset(
        name="test",
        rules=(
            Rule(id="acme.boom", emits=frozenset({"sig_boom"}), evaluate=boom),
            static_rule("core.ok", "sig_ok"),
        ),
    )
    run = evaluate_ruleset(ruleset, EMPTY_CONTEXT)

    assert [s["id"] for s in run["signals"]] == ["sig_ok"]
    assert run["diagnostics"] == [
        {
            "ruleId": "acme.boom",
            "kind": "error",
            "message": "ValueError",
        }
    ]


def test_strict_mode_reraises() -> None:
    def boom(context: RuleContext) -> list[Signal]:
        raise ValueError("nope")

    ruleset = Ruleset(
        name="test",
        rules=(Rule(id="acme.boom", emits=frozenset({"s"}), evaluate=boom),),
    )
    with pytest.raises(ValueError, match="nope"):
        evaluate_ruleset(ruleset, EMPTY_CONTEXT, strict=True)


def test_undeclared_signal_id_is_dropped() -> None:
    """An undeclared id is exactly what the ruleset collision check cannot see."""

    def sneaky(context: RuleContext) -> list[Signal]:
        return [
            {
                "id": "urgency_language",
                "category": "social",
                "severity": "critical",
                "label": "Hijacked",
                "detail": "",
            }
        ]

    ruleset = Ruleset(
        name="test",
        rules=(Rule(id="acme.sneaky", emits=frozenset({"acme_sig"}), evaluate=sneaky),),
    )
    run = evaluate_ruleset(ruleset, EMPTY_CONTEXT)

    assert run["signals"] == []
    assert run["diagnostics"][0]["kind"] == "undeclared_signal"


def test_malformed_return_value_is_reported_not_raised() -> None:
    ruleset = Ruleset(
        name="test",
        rules=(
            Rule(
                id="acme.bad",
                emits=frozenset({"sig"}),
                # Neither entry is a Signal: one is not a dict at all, the
                # other is missing four of the five required keys. Being
                # malformed is the point, so the type error here is expected.
                evaluate=lambda ctx: cast(
                    "list[Signal]", ["not a signal", {"id": "sig"}]
                ),
            ),
        ),
    )
    run = evaluate_ruleset(ruleset, EMPTY_CONTEXT)

    assert run["signals"] == []
    assert [d["kind"] for d in run["diagnostics"]] == [
        "malformed_signal",
        "malformed_signal",
    ]


def test_rules_run_in_ruleset_order() -> None:
    ruleset = Ruleset(
        name="test",
        rules=(
            static_rule("core.b", "sig_b"),
            static_rule("core.a", "sig_a"),
            static_rule("core.c", "sig_c"),
        ),
    )
    run = evaluate_ruleset(ruleset, EMPTY_CONTEXT)

    assert [s["id"] for s in run["signals"]] == ["sig_b", "sig_a", "sig_c"]


def test_severity_override_is_applied_without_adding_absent_keys() -> None:
    """The deep-equality constraint from types.py, enforced at the engine level.

    An override rebuilds a signal. If it rebuilt it field-by-field, a signal
    with no `mitre` would come back with `mitre: None`, which is a different
    value under the comparison conformance uses.
    """
    ruleset = Ruleset(
        name="test",
        rules=(static_rule("core.a", "sig_a"),),
        severity_overrides={"sig_a": "critical"},
    )
    run = evaluate_ruleset(ruleset, EMPTY_CONTEXT)

    assert run["signals"][0]["severity"] == "critical"
    assert "mitre" not in run["signals"][0]
    assert "benign" not in run["signals"][0]


def test_override_preserves_present_optional_keys() -> None:
    ruleset = Ruleset(
        name="test",
        rules=(static_rule("core.a", "sig_a", mitre=["T1566"], benign=True),),
        severity_overrides={"sig_a": "info"},
    )
    run = evaluate_ruleset(ruleset, EMPTY_CONTEXT)

    assert run["signals"][0]["mitre"] == ["T1566"]
    assert run["signals"][0]["benign"] is True


def test_engine_output_feeds_score_signals_directly() -> None:
    ruleset = Ruleset(
        name="test",
        rules=(static_rule("core.a", "sig_a"), static_rule("core.b", "sig_b")),
    )
    scored = score_signals(evaluate_ruleset(ruleset, EMPTY_CONTEXT)["signals"])

    assert scored["verdict"] == "Low Risk"
    assert len(scored["signals"]) == 2


def test_one_critical_rule_cannot_reach_high_risk_alone() -> None:
    """Documented blast-radius property of a miscalibrated custom rule.

    A category caps at MAX_CATEGORY_SCORE (55) and High Risk starts at 60, so
    a single rule firing `critical` lands at Medium. Reaching High takes
    evidence on two independent categories.
    """
    ruleset = Ruleset(
        name="test",
        rules=(static_rule("acme.loud", "acme_sig", severity="critical"),),
    )
    scored = score_signals(evaluate_ruleset(ruleset, EMPTY_CONTEXT)["signals"])

    assert scored["score"] == 45
    assert scored["verdict"] == "Medium Risk"


# --------------------------------------------------------------------------
# Declarative loader
# --------------------------------------------------------------------------

URGENCY_RULE: dict[str, object] = {
    "id": "urgency_language",
    "category": "social",
    "label": "Urgency / Pressure Language",
    "severity": {"base": "low", "escalate_to": "medium", "when_hits_at_least": 3},
    "match": {
        "type": "phrases",
        "field": "scan_text",
        "any_of": ["act now", "urgent", "final notice", "last warning"],
    },
    "detail": "Contains phrases designed to rush you: {hits}. ({hit_count} total)",
    "mitre": ["T1566"],
    "tags": ["content"],
}


def run_one(rule: Rule, **parsed_overrides: object) -> list[Signal]:
    ruleset = Ruleset(name="test", rules=(rule,))
    context = RuleContext(parsed=make_parsed(**parsed_overrides))
    run = evaluate_ruleset(ruleset, context, strict=True)
    assert run["diagnostics"] == []
    return run["signals"]


def test_declarative_rule_fires_and_renders_detail() -> None:
    rule = parse_rule(URGENCY_RULE, "core")
    assert rule.id == "core.urgency_language"

    signals = run_one(rule, scanText="Please ACT NOW, this is your final notice.")

    assert signals[0]["id"] == "urgency_language"
    assert signals[0]["severity"] == "low"
    assert signals[0]["detail"] == (
        'Contains phrases designed to rush you: "act now", "final notice". (2 total)'
    )
    assert signals[0]["mitre"] == ["T1566"]


def test_declarative_rule_escalates_at_the_declared_threshold() -> None:
    rule = parse_rule(URGENCY_RULE, "core")
    signals = run_one(rule, scanText="act now urgent final notice")

    assert signals[0]["severity"] == "medium"


def test_declarative_rule_omits_absent_optional_keys() -> None:
    spec = {k: v for k, v in URGENCY_RULE.items() if k != "mitre"}
    signals = run_one(parse_rule(spec, "core"), scanText="urgent")

    assert "mitre" not in signals[0]
    assert "benign" not in signals[0]


def test_benign_rule_sets_the_flag_and_lowers_the_score() -> None:
    spec = {**URGENCY_RULE, "benign": True, "severity": "info"}
    signals = run_one(parse_rule(spec, "core"), scanText="urgent")

    assert signals[0]["benign"] is True
    assert score_signals(signals)["benignSignals"] == signals


def test_hits_follow_declaration_order_not_occurrence_order() -> None:
    """`{hits}` renders the first three, so this decides the detail string."""
    rule = parse_rule(URGENCY_RULE, "core")
    signals = run_one(rule, scanText="last warning ... urgent ... act now")

    assert signals[0]["detail"].startswith(
        'Contains phrases designed to rush you: "act now", "urgent", "last warning"'
    )


def test_match_field_selects_which_text_is_scanned() -> None:
    match_spec = dict(cast("dict[str, Any]", URGENCY_RULE["match"]))
    match_spec["field"] = "subject"
    spec = {**URGENCY_RULE, "match": match_spec}
    rule = parse_rule(spec, "core")

    assert run_one(rule, scanText="act now", subject="hello") == []
    assert len(run_one(rule, subject="Act Now")) == 1


def test_quote_and_render_helpers_match_the_reference() -> None:
    assert quote_hits(["a", "b", "c", "d"]) == '"a", "b", "c"'
    assert quote_hits(["a"]) == '"a"'
    assert render_detail("saw {hits} ({hit_count})", ["a", "b"]) == 'saw "a", "b" (2)'


def test_render_detail_tolerates_literal_braces() -> None:
    """str.format would raise here, and would also expose {0.__class__}."""
    assert render_detail("a {literal} brace, {hits}", ["x"]) == 'a {literal} brace, "x"'


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ({"severty": "low"}, "unknown rule key"),
        ({"category": "nonsense"}, "category 'nonsense' is not one of"),
        ({"severity": "urgent"}, "is not one of"),
        ({"severity": {"base": "low", "escalate_to": "medium"}}, "when_hits_at_least"),
        (
            {
                "severity": {
                    "base": "low",
                    "escalate_to": "medium",
                    "when_hits_at_least": 0,
                }
            },
            "integer >= 1",
        ),
        ({"match": {"type": "regex", "pattern": "a+"}}, "is not supported"),
        (
            {"match": {"type": "phrases", "field": "nope", "any_of": ["x"]}},
            "match.field",
        ),
        ({"match": {"type": "phrases", "any_of": []}}, "at least one phrase"),
        ({"match": {"type": "phrases", "any_of": ["Act Now"]}}, "contains uppercase"),
        ({"benign": "yes"}, "benign must be a boolean"),
        ({"mitre": "T1566"}, "must be a list of strings"),
    ],
)
def test_loader_rejects_malformed_rules(mutation: dict, expected: str) -> None:
    spec = {**URGENCY_RULE, **mutation}
    with pytest.raises(RuleLoadError, match=expected):
        parse_rule(spec, "core")


def test_loader_reports_missing_required_keys() -> None:
    spec = {k: v for k, v in URGENCY_RULE.items() if k != "detail"}
    with pytest.raises(
        RuleLoadError, match=r"missing required rule key\(s\) \['detail'\]"
    ):
        parse_rule(spec, "core")


def test_regex_rejection_explains_why() -> None:
    with pytest.raises(RuleLoadError) as excinfo:
        parse_rule({**URGENCY_RULE, "match": {"type": "regex"}}, "core")

    assert "unbounded cost" in str(excinfo.value)


# --------------------------------------------------------------------------
# File and directory loading
# --------------------------------------------------------------------------


def write_rule_file(
    directory, filename: str, rules: list[dict], namespace: str = "core"
):
    path = directory / filename
    path.write_text(
        json.dumps({"version": 1, "namespace": namespace, "rules": rules}),
        encoding="utf-8",
    )
    return path


def test_load_rule_file(tmp_path) -> None:
    path = write_rule_file(tmp_path, "content.json", [URGENCY_RULE])
    rules = load_rule_file(path)

    assert [r.id for r in rules] == ["core.urgency_language"]
    assert rules[0].tags == frozenset({"content"})


def test_load_ruleset_is_deterministic_across_files(tmp_path) -> None:
    """Sorted filename order, not filesystem iteration order.

    Ruleset order decides which of two same-id signals survives scoring, so a
    ruleset whose order varied by machine would be a verdict that varied by
    machine.
    """
    write_rule_file(tmp_path, "b_second.json", [{**URGENCY_RULE, "id": "b_rule"}])
    write_rule_file(tmp_path, "a_first.json", [{**URGENCY_RULE, "id": "a_rule"}])

    ruleset = load_ruleset(tmp_path, name="core")

    assert [r.id for r in ruleset] == ["core.a_rule", "core.b_rule"]


def test_collision_across_two_files_is_caught_at_load(tmp_path) -> None:
    write_rule_file(tmp_path, "a.json", [URGENCY_RULE])
    # Different namespace and different rule id, so nothing collides until you
    # look at signal_id — which is exactly the case that would otherwise load
    # cleanly and lose one rule's findings at scoring time.
    write_rule_file(
        tmp_path,
        "b.json",
        [{**URGENCY_RULE, "id": "pressure", "signal_id": "urgency_language"}],
        namespace="acme",
    )

    with pytest.raises(RulesetError, match="both emit signal id 'urgency_language'"):
        load_ruleset(tmp_path, name="core")


def test_signal_id_can_differ_from_rule_id(tmp_path) -> None:
    rules = load_rule_file(
        write_rule_file(
            tmp_path,
            "a.json",
            [{**URGENCY_RULE, "id": "pressure", "signal_id": "urgency_language"}],
        )
    )

    assert rules[0].id == "core.pressure"
    assert rules[0].emits == frozenset({"urgency_language"})


def test_load_ruleset_accepts_extra_code_rules(tmp_path) -> None:
    write_rule_file(tmp_path, "a.json", [URGENCY_RULE])
    ruleset = load_ruleset(
        tmp_path, name="core", extra=[static_rule("core.coded", "coded_sig")]
    )

    assert [r.id for r in ruleset] == ["core.urgency_language", "core.coded"]


def test_bad_json_names_the_file(tmp_path) -> None:
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(RuleLoadError, match=r"broken\.json: invalid JSON"):
        load_rule_file(path)


def test_unsupported_format_version_is_rejected(tmp_path) -> None:
    path = tmp_path / "future.json"
    path.write_text(
        json.dumps({"version": 2, "namespace": "core", "rules": []}), encoding="utf-8"
    )

    with pytest.raises(RuleLoadError, match="unsupported format version"):
        load_rule_file(path)


def test_missing_directory_is_rejected(tmp_path) -> None:
    with pytest.raises(RuleLoadError, match="is not a directory"):
        load_ruleset(tmp_path / "nope", name="core")


def test_empty_directory_loads_an_empty_ruleset(tmp_path) -> None:
    assert len(load_ruleset(tmp_path, name="core")) == 0


# --------------------------------------------------------------------------
# Review-driven hardening — each test pins a fix from the code review
# --------------------------------------------------------------------------


def test_bool_version_is_rejected(tmp_path) -> None:
    """True == 1 in Python, so version: true must not sneak past."""
    path = tmp_path / "sneaky.json"
    path.write_text(
        json.dumps({"version": True, "namespace": "core", "rules": []}),
        encoding="utf-8",
    )
    with pytest.raises(RuleLoadError, match="unsupported format version"):
        load_rule_file(path)


def test_when_hits_without_escalate_to_is_rejected() -> None:
    spec = {
        **URGENCY_RULE,
        "severity": {"base": "low", "when_hits_at_least": 3},
    }
    with pytest.raises(RuleLoadError, match="escalate_to is absent"):
        parse_rule(spec, "core")


def test_unhashable_category_raises_load_error() -> None:
    """A list or dict in 'category' must raise RuleLoadError, not TypeError."""
    spec = {**URGENCY_RULE, "category": ["social"]}
    with pytest.raises(RuleLoadError, match="is not one of"):
        parse_rule(spec, "core")


def test_unhashable_severity_base_raises_load_error() -> None:
    spec = {**URGENCY_RULE, "severity": {"base": []}}
    with pytest.raises(RuleLoadError, match="is not one of"):
        parse_rule(spec, "core")


def test_unhashable_field_raises_load_error() -> None:
    spec = {
        **URGENCY_RULE,
        "match": {"type": "phrases", "field": [], "any_of": ["x"]},
    }
    with pytest.raises(RuleLoadError, match=r"match\.field"):
        parse_rule(spec, "core")


def test_invalid_severity_override_is_rejected() -> None:
    with pytest.raises(RulesetError, match="invalid severity"):
        Ruleset(
            name="test",
            rules=(static_rule("core.a", "sig_a"),),
            severity_overrides={"sig_a": "urgent"},
        )


def test_severity_overrides_are_defensively_copied() -> None:
    overrides: dict = {"sig_a": "high"}
    ruleset = Ruleset(
        name="test",
        rules=(static_rule("core.a", "sig_a"),),
        severity_overrides=overrides,
    )
    # Mutating the original dict must not affect the ruleset
    overrides["sig_a"] = "critical"
    assert ruleset.severity_overrides["sig_a"] == "high"


def test_invalid_signal_category_is_reported_as_malformed() -> None:
    """A signal with category='other' must not slip through."""

    def bad_category(ctx: RuleContext) -> list[Signal]:
        return [cast(Signal, {
            "id": "sig",
            "category": "other",
            "severity": "low",
            "label": "Bad",
            "detail": "x",
        })]

    ruleset = Ruleset(
        name="test",
        rules=(Rule(
            id="acme.bad",
            emits=frozenset({"sig"}),
            evaluate=bad_category,
        ),),
    )
    run = evaluate_ruleset(ruleset, EMPTY_CONTEXT)
    assert run["signals"] == []
    assert run["diagnostics"][0]["kind"] == "malformed_signal"


def test_generator_rule_that_raises_is_isolated() -> None:
    """Fault isolation must cover iteration, not just the evaluate call."""

    def gen_boom(ctx: RuleContext) -> list[Signal]:
        def _gen():
            yield cast(Signal, {
                "id": "sig",
                "category": "social",
                "severity": "low",
                "label": "L",
                "detail": "d",
            })
            raise RuntimeError("mid-iteration failure")
        return list(_gen())  # type: ignore[return-value]

    ruleset = Ruleset(
        name="test",
        rules=(
            Rule(id="acme.gen", emits=frozenset({"sig"}), evaluate=gen_boom),
            static_rule("core.ok", "sig_ok"),
        ),
    )
    run = evaluate_ruleset(ruleset, EMPTY_CONTEXT)
    assert any(d["kind"] == "error" for d in run["diagnostics"])
    assert any(s["id"] == "sig_ok" for s in run["signals"])


def test_diagnostic_message_does_not_leak_exception_text() -> None:
    """Diagnostics are documented as safe to display; no attacker content."""

    def leak(ctx: RuleContext) -> list[Signal]:
        raise ValueError("SECRET email body content here")

    ruleset = Ruleset(
        name="test",
        rules=(Rule(id="acme.leak", emits=frozenset({"s"}), evaluate=leak),),
    )
    run = evaluate_ruleset(ruleset, EMPTY_CONTEXT)
    msg = run["diagnostics"][0]["message"]
    assert msg == "ValueError"
    assert "SECRET" not in msg
