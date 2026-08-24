# Rule engine concepts

What a `Rule`, a `RuleContext`, a `Ruleset`, and the engine that runs them
mean — language-neutral, because both implementations model them identically
and conformance vectors pin the parts of this that cross the language
boundary (signal ids, categories, severities). For the JSON rule *format*
(the data a rule file is written as), see [README.md](README.md) instead;
this file is about the engine that runs rules, not the format one kind of
rule happens to be declared in.

Each implementation's own docs — [python/docs/rules.md](../python/docs/rules.md),
[typescript/docs/rules.md](../typescript/docs/rules.md) — cover the API
surface and code examples for that language and link back here for the
"why."

## Rule

One named piece of detection logic. Five fields:

| Field | Purpose |
| --- | --- |
| `id` | Namespaced identifier, e.g. `"core.urgency_language"`. Must match `<namespace>.<name>`, lowercase letters/digits/underscores only. |
| `emits` | The `Signal.id` values this rule may produce. Declared up front so a ruleset can detect two rules claiming the same signal id *before* either has run. |
| `evaluate` | The detection logic: a function from a `RuleContext` to a list of signals. |
| `tags` | Free-form labels for selection — `"content"`, `"header"`, `"experimental"`. Not part of scoring. |
| `description` | One-line summary shown when listing a ruleset. |

**`id` and `emits` are deliberately distinct identifiers**, not a redundant
pair:

- `id` is registry identity — what you disable, replace, or filter on. It
  never appears in output, and two rules may point at the same signal id
  through it (see `Ruleset.replaceRule`/`replace_rule` below).
- `emits` is what *does* appear in output, and it is what must stay stable
  across implementations, because conformance vectors name signal ids
  directly.

A rule is not a new concept the engine invents — it is the thing that
already exists inline inside every check. An `if urgencyHits.length > 0 →
signals.push({...})` block *is* a rule; giving it a name is what makes it
listable, disableable, and replaceable, and what lets someone who isn't
editing this repository write one.

## RuleContext

Everything a rule is allowed to look at, plus cached derivations of it.
Assembled once, before any rule runs, from work the pipeline has already
done. Nothing here performs I/O, and nothing here should ever be allowed to —
that is what keeps "no network calls" true no matter what rules a consumer
loads, and what makes a rule testable by handing it a literal instead of a
fixture.

Only the parsed email is required; everything else defaults to empty, so a
content rule can be constructed and unit-tested without standing up the
whole analysis pipeline.

| Field/property | What it is |
| --- | --- |
| the parsed email | Required. Everything below is derived from this plus the optional analyses. |
| analyzed URLs | Optional, defaults to empty. |
| auth check result | Optional, defaults to absent. |
| received-chain analysis | Optional, defaults to absent. |
| header-anomaly result | Optional, defaults to absent. |
| scan-text, lowercased | Subject + text part + de-tagged HTML — the field content heuristics should normally match against. |
| body-text, lowercased | Text part only. |
| html-body, lowercased | HTML part only. |
| subject, lowercased | Subject line only. |
| sender domain | Registrable domain of the From address, or none. |
| reply-to domain | Registrable domain of the Reply-To address, or none. |
| return-path domain | Registrable domain of the Return-Path address, or none. |
| link hostnames | Every hostname a URL check managed to resolve, lowercased. |
| link domains | Registrable domains of the link hostnames. |

Each of the derived properties is computed once and cached (Python's
`@functools.cached_property`; TypeScript's `RuleContext` hand-rolls the same
memoization, since the language has no built-in equivalent) — the reason
this class earns its keep at all is that fifty rules can share one parse
instead of each lowercasing the body and re-deriving the sender domain
independently.

## Ruleset

An ordered, immutable collection of rules. Every derivation returns a *new*
ruleset — nothing mutates in place, so narrowing the default set for one
message cannot affect the next.

**Validated at construction**, not lazily:

- A duplicate rule id is rejected.
- Two rules claiming the same signal id are rejected. This is the failure
  mode the whole design exists to prevent: without this guard, both rules
  would load and run cleanly, and one of them would simply have its finding
  discarded at scoring time (`scoreSignals`/`score_signals` deduplicates by
  signal id, first-one-wins) with nothing anywhere indicating it happened.
- A severity override naming a signal id nobody in the ruleset emits is
  rejected.

**Order matters** for the same reason the collision check exists: it decides
which of two same-id signals a dedupe keeps, in the one case that check
cannot see coming (`replaceRule`/`replace_rule`, below, deliberately
re-introduces a same-id situation on purpose).

**Derivation methods** (same operations, named per each language's
convention):

| Operation | What it does |
| --- | --- |
| add rules | Appends rules, keeping run order. Throws/raises if any collides with what's already there. |
| replace a rule | Swaps one rule for another *by rule id*, keeping run order — the supported way to override a built-in with something that emits the same signal id, since a plain "add" would trip the collision check. |
| filter by id | Drops rules by id. Unknown ids are ignored — this is a filter, not a lookup. |
| filter by tag (exclude) | Drops every rule carrying any of the given tags. |
| filter by tag (include) | Keeps only rules carrying at least one of the given tags. |
| retune severity | Returns a ruleset with the given signal-id → severity overrides merged in, without touching the rule that emits them. |

Filtering prunes any severity override that no longer applies afterward —
otherwise construction-time validation would reject the *result* of your own
filter for a dangling override the filter itself caused.

## Engine

Running a ruleset is not just `rules.flatMap(rule => rule.evaluate(context))`
— that one-liner is what the engine replaces, and it adds three things a
library that accepts third-party rules cannot do without:

1. **Fault isolation.** A rule that raises must not take the whole analysis
   with it. The other rules still run; the failure is reported as a
   diagnostic instead of an exception. (Tests and CI should opt into
   `strict` mode instead, which re-raises — a rule throwing during
   development is a defect you want to see as a failure, not a diagnostic
   nobody reads.)
2. **Emission checking.** A signal whose id the rule never declared in
   `emits` is dropped rather than accepted. An undeclared id is exactly the
   case the ruleset-level collision check could not see coming — it would
   sail past validation and then silently suppress a built-in via scoring's
   dedupe.
3. **Severity overrides.** Applied here, centrally, rather than inside each
   rule, so a consumer can retune a signal's severity without forking the
   rule that emits it.

Running a ruleset produces two lists: the **signals** actually produced (in
ruleset order), and **diagnostics** — one entry per rule that misbehaved,
each naming the offending rule id, a kind (`error` / `undeclared_signal` /
`malformed_signal`), and a message that is always safe to log or display,
because it is deliberately never built from the message content a rule was
looking at.

## Scoring interaction

The rule engine does not score anything — it produces signals, and scoring
is a separate, single-owner concern (`scoreSignals`/`score_signals`) that
stays that way regardless of where a signal came from. Two properties worth
knowing when writing or tuning rules:

1. **Signal ids are the namespace that matters for scoring.** Scoring
   deduplicates by `Signal.id`, keeping the first. A custom rule that emits a
   built-in's signal id suppresses it — which is exactly why `Ruleset`
   refuses to be constructed with two rules claiming one signal id, and why
   overriding one is a deliberate `replaceRule`/`replace_rule` call rather
   than something that can happen by accident.
2. **One rule cannot swing a verdict alone.** A single category's score caps
   at 55 (`MAX_CATEGORY_SCORE`), and "High Risk" starts at 60 — so even a
   rule firing at `critical` severity, alone, tops out at "Medium Risk".
   Reaching "High Risk" requires corroborating evidence across more than one
   category. A single miscalibrated custom rule has a bounded blast radius by
   construction.
