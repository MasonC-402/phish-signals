# Rules Engine

The rules engine gives the detection logic in phish-signals a name, so it can
be listed, disabled, replaced, or extended by consumers of the library.

**Where it lives:** `phish_signals.rules` — three modules behind one
`__init__.py`:

| Module | Role |
|--------|------|
| `types` | `Rule`, `RuleContext`, `Ruleset` — what a rule is, what it may look at, how a collection is assembled |
| `engine` | Runs a ruleset, isolates failures, applies severity overrides |
| `loader` | Declarative JSON format for phrase-list rules (data, not code) |

## Quick start

### Running the built-in content rules

```python
from phish_signals import check_content, score_signals

result = check_content("ACT NOW or your account will be suspended!")
scored = score_signals(result["signals"])

print(scored["verdict"])   # "Medium Risk"
print(scored["score"])     # 14
for signal in scored["signals"]:
    print(f"  [{signal['severity']}] {signal['label']}: {signal['detail']}")
```

### Writing a custom code rule

```python
from phish_signals.rules import Rule, RuleContext, Ruleset, evaluate_ruleset
from phish_signals import score_signals
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

# Run and score
run = evaluate_ruleset(my_rules, RuleContext(parsed=parsed))
scored = score_signals(run["signals"])
```

### Writing a declarative JSON rule

Most content rules are a phrase list and a severity. Write them as data
instead of code so both the Python and TypeScript implementations can load
the same file:

```json
{
  "version": 1,
  "namespace": "acme",
  "rules": [
    {
      "id": "internal_transfer_lure",
      "category": "social",
      "label": "Internal Transfer Lure",
      "severity": { "base": "low", "escalate_to": "medium", "when_hits_at_least": 2 },
      "match": {
        "type": "phrases",
        "field": "scan_text",
        "any_of": ["internal transfer", "departmental budget", "expense reimbursement"]
      },
      "detail": "Contains phrases related to internal transfers: {hits}.",
      "mitre": ["T1566"],
      "tags": ["content"]
    }
  ]
}
```

Load it:

```python
from phish_signals.rules import load_rule_file, load_ruleset

# Single file
rules = load_rule_file("path/to/rules.json")

# Entire directory (sorted filename order, deterministic)
ruleset = load_ruleset("path/to/rules/", name="acme")
```

## Concepts

### Rule

A frozen dataclass with five fields:

| Field | Type | Purpose |
|-------|------|---------|
| `id` | `str` | Namespaced identifier, e.g. `"core.urgency_language"`. Must match `<namespace>.<name>`, lowercase. |
| `emits` | `frozenset[str]` | Signal IDs this rule may produce. Declared up front for collision detection. |
| `evaluate` | `Callable[[RuleContext], list[Signal]]` | The detection logic. |
| `tags` | `frozenset[str]` | Free-form labels for filtering — `"content"`, `"header"`, `"experimental"`. |
| `description` | `str` | One-line summary shown when listing a ruleset. |

**Two identifiers, deliberately distinct:**

- `Rule.id` — registry identity. What you disable, replace, or filter on. Never appears in output.
- `Rule.emits` — the `Signal.id` values the rule may produce. These appear in output and must stay stable across implementations because conformance vectors name them.

### RuleContext

Everything a rule is allowed to look at. Assembled once before any rule runs
from work the pipeline has already done. Nothing here performs I/O.

```python
@dataclass(frozen=True)
class RuleContext:
    parsed: ParsedEmail
    urls: list[UrlAnalysis] = field(default_factory=list)
    auth: AuthCheckResult | None = None
    chain: ReceivedChainAnalysis | None = None
    header_anomalies: HeaderAnomalyResult | None = None
```

Cached properties provide derived data rules commonly need:

| Property | Type | What it is |
|----------|------|------------|
| `scan_text_lower` | `str` | Subject + text body + de-tagged HTML, lowercased |
| `body_text_lower` | `str` | Text body only, lowercased |
| `html_body_lower` | `str` | HTML body, lowercased |
| `subject_lower` | `str` | Subject line, lowercased |
| `sender_domain` | `str \| None` | Registrable domain of the From address |
| `reply_to_domain` | `str \| None` | Registrable domain of Reply-To |
| `return_path_domain` | `str \| None` | Registrable domain of Return-Path |
| `link_hostnames` | `frozenset[str]` | Hostnames from analyzed URLs |
| `link_domains` | `frozenset[str]` | Registrable domains of link hostnames |

### Ruleset

An ordered, immutable collection of rules. Order matters: `score_signals()`
deduplicates by signal ID first-one-wins, so ruleset order decides which of
two same-ID signals survives.

**Validation** runs at construction time:

- Duplicate rule IDs are rejected
- Two rules claiming the same signal ID are rejected (this is the silent
  failure the whole design is built around — without this guard, the second
  rule would run, produce a signal, and have it dropped at scoring time with
  no error anywhere)
- Severity overrides for signals nobody emits are rejected

**Derivation** — every method returns a new ruleset:

```python
# Add rules
extended = ruleset.with_rules([my_custom_rule])

# Override a built-in
tuned = ruleset.replace_rule("core.urgency_language", my_version)

# Filter
headers_only = ruleset.with_tags(["header"])
no_experimental = ruleset.without_tags(["experimental"])
selective = ruleset.without(["core.generic_greeting"])

# Retune severity without touching the rule
quieter = ruleset.with_severity_overrides({"urgency_language": "info"})
```

### Engine

`evaluate_ruleset()` runs every rule in a ruleset against a context and
collects the signals. It adds three things over a bare list comprehension:

1. **Fault isolation** — a rule that raises produces a diagnostic, not a
   crash. The other rules still run.
2. **Emission checking** — a signal whose ID the rule never declared in
   `emits` is dropped. An undeclared ID would bypass the collision check
   and could silently suppress another rule's finding.
3. **Severity overrides** — applied here so a consumer can retune a signal
   without touching the rule that emits it.

```python
from phish_signals.rules import evaluate_ruleset, format_diagnostics

run = evaluate_ruleset(ruleset, context)
# run["signals"]      — list[Signal], in ruleset order
# run["diagnostics"]  — list[RuleDiagnostic], rules that misbehaved

if run["diagnostics"]:
    print(format_diagnostics(run["diagnostics"]))
```

Use `strict=True` in tests and CI to turn rule failures into exceptions
rather than diagnostics.

## Declarative rule format

### File structure

```json
{
  "version": 1,
  "namespace": "core",
  "rules": [...]
}
```

- `version` — must be `1`. A file declaring anything else is rejected.
- `namespace` — prefixed to each rule's ID: a rule with `"id": "foo"` in
  namespace `"core"` becomes `core.foo`.

### Rule fields

| Field | Required | Type | Notes |
|-------|----------|------|-------|
| `id` | yes | `string` | Local ID, namespaced automatically |
| `signal_id` | no | `string` | Defaults to `id`. Use when the signal ID differs from the rule ID. |
| `category` | yes | `string` | One of: `authentication`, `identity`, `infrastructure`, `payload`, `social` |
| `label` | yes | `string` | Human-readable name shown in reports |
| `severity` | yes | `string \| object` | See below |
| `match` | yes | `object` | See below |
| `detail` | yes | `string` | Template with `{hits}` and `{hit_count}` placeholders |
| `mitre` | no | `string[]` | MITRE ATT&CK technique IDs |
| `tags` | no | `string[]` | Free-form labels for filtering |
| `benign` | no | `boolean` | `true` if this argues the message is legitimate |
| `description` | no | `string` | One-line summary |

**Severity** — either a plain string (`"medium"`) or an object with
escalation:

```json
{ "base": "low", "escalate_to": "medium", "when_hits_at_least": 3 }
```

**Match** — currently supports `phrases` only:

```json
{
  "type": "phrases",
  "field": "scan_text",
  "any_of": ["act now", "urgent", "final notice"]
}
```

- `field` — which text to scan: `scan_text` (default, subject + text +
  de-tagged HTML), `body_text`, `html_body`, `subject`
- `any_of` — phrases must be lowercase (they're matched against
  pre-lowercased text)

**Regular expressions are deliberately excluded.** Python's `re` has no
timeout and its engine backtracks, so a user-supplied pattern plus crafted
input is a denial of service. Patterns are only available in code rules,
where whoever wrote the pattern is whoever ships it and owns the risk.

### Validation

Strict by design — unknown keys are errors, not warnings. A typo'd
`"severty"` that loads quietly gives you a rule running at the wrong weight
with nothing to indicate it.

### Detail templates

Two substitutions:

- `{hits}` — first three matched phrases, double-quoted: `"act now", "urgent", "final notice"`
- `{hit_count}` — total number of matched phrases

Uses plain string replacement (not `str.format()`) to avoid attribute
traversal attacks (`{0.__class__}`) and to match the TypeScript behavior
exactly.

## Scoring interaction

The rules engine **does not score**. It produces signals; scoring lives in
`phish_signals.signals.score_signals()` and stays there.

Two properties worth knowing:

1. **Signal IDs are the namespace that matters.** Scoring deduplicates by
   `Signal.id`, keeping the first. A custom rule emitting a built-in's ID
   suppresses it. `Ruleset` refuses to be built when two rules claim one
   signal ID — use `Ruleset.replace_rule()` when the override is intended.

2. **One rule cannot swing a verdict alone.** A category's score caps at
   55 and "High Risk" starts at 60, so even a rule firing `critical`
   reaches Medium Risk on its own. Getting to High Risk takes evidence on
   two independent categories. A miscalibrated custom rule has a bounded
   blast radius by construction.

## Built-in content rules

The `CONTENT_RULESET` in `content_check.py` assembles all built-in content
detection rules:

### Declarative rules (from `rules/data/content.json`)

| Rule ID | Signal ID | Category | Severity | What it detects |
|---------|-----------|----------|----------|-----------------|
| `core.urgency_language` | `urgency_language` | social | low → medium (≥3 hits) | Pressure phrases: "act now", "account suspended", etc. |
| `core.credential_request` | `credential_request` | social | medium | Password/credential requests |
| `core.financial_request` | `financial_request` | social | medium | Wire transfer, gift card, invoice fraud language |
| `core.authority_impersonation` | `authority_impersonation` | social | medium | CEO impersonation, IT department claims, secrecy requests |

### Code rules

| Rule ID | Signal ID(s) | Category | Severity | What it detects |
|---------|--------------|----------|----------|-----------------|
| `core.generic_greeting` | `generic_greeting` | social | low | "Dear Customer", "Hello user", etc. |
| `core.display_name_spoof` | `display_name_brand_spoof`, `display_name_address_spoof` | identity | high | Display name claims a brand or shows a fake email |
| `core.excessive_caps` | `excessive_capitalization` | social | low | ≥5 all-caps words (4+ letters each) |

### Standalone functions (not rules)

| Function | Signal ID | Category | Severity | What it detects |
|----------|-----------|----------|----------|-----------------|
| `check_link_text()` | `deceptive_link_text` | payload | high | Link text claims one domain, href goes to another |
| `check_dangerous_schemes()` | `dangerous_link_scheme` | payload | high | `data:`, `javascript:`, `vbscript:` links |

## Extending the engine

### Adding a custom ruleset alongside the built-in one

```python
from phish_signals.content_check import CONTENT_RULESET
from phish_signals.rules import Rule, RuleContext, evaluate_ruleset

my_rule = Rule(
    id="acme.custom_check",
    emits=frozenset({"acme_custom_signal"}),
    evaluate=my_check_function,
    tags=frozenset({"content"}),
)

# Combine with the built-in rules
combined = CONTENT_RULESET.with_rules([my_rule], name="acme_extended")
run = evaluate_ruleset(combined, context)
```

### Replacing a built-in rule

```python
tuned_urgency = Rule(
    id="acme.urgency",
    emits=frozenset({"urgency_language"}),
    evaluate=my_urgency_check,
)

# Same signal ID, different logic — replace_rule keeps the collision check honest
tuned = CONTENT_RULESET.replace_rule("core.urgency_language", tuned_urgency)
```

### Loading custom declarative rules from a directory

```python
from phish_signals.rules import load_ruleset

custom = load_ruleset("path/to/custom/rules/", name="acme")
combined = CONTENT_RULESET.with_rules(list(custom))
```

### Tuning severity without changing rules

```python
# Gift-card language is normal in our org
quieter = CONTENT_RULESET.with_severity_overrides({
    "financial_request": "info",
})
```

## Testing rules

```python
from phish_signals.rules import RuleContext, Ruleset, evaluate_ruleset

# Use strict=True in tests so rule failures are exceptions, not diagnostics
run = evaluate_ruleset(ruleset, context, strict=True)
assert run["diagnostics"] == []
```

The test suite in `tests/test_rules.py` pins every failure mode the engine
guards against. `tests/test_content_check.py` tests each content rule
against realistic inputs.
