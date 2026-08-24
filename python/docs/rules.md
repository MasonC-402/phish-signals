# Rules Engine

The rules engine gives the detection logic in phish-signals a name, so it can
be listed, disabled, replaced, or extended by consumers of the library.

This page is the Python API surface — imports, class signatures, code
examples. For what a `Rule`/`RuleContext`/`Ruleset` actually mean, why `id`
and `emits` are separate, and what the engine guarantees beyond a bare loop
over rules, see [`../../rules/CONCEPTS.md`](../../rules/CONCEPTS.md), which
covers both implementations at once since the concepts are identical. For the
declarative JSON rule format, see
[`../../rules/README.md`](../../rules/README.md).

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

print(scored["verdict"])   # "Low Risk"
print(scored["score"])     # 6
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
instead of code so the phrase lists are defined once — the TypeScript rule
layer (`typescript/src/rules/`) now has a matching loader, verified to
produce byte-identical signals from the same rule file, though
`checkContent` isn't wired to load from one yet:

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

## Concepts, in Python

See [`../../rules/CONCEPTS.md`](../../rules/CONCEPTS.md) for what each of
these means and guarantees. This section is just the Python signatures.

### Rule

```python
@dataclass(frozen=True)
class Rule:
    id: str
    emits: frozenset[str]
    evaluate: Callable[[RuleContext], list[Signal]]
    tags: frozenset[str] = frozenset()
    description: str = ""
```

### RuleContext

```python
@dataclass(frozen=True)
class RuleContext:
    parsed: ParsedEmail
    urls: list[UrlAnalysis] = field(default_factory=list)
    auth: AuthCheckResult | None = None
    chain: ReceivedChainAnalysis | None = None
    header_anomalies: HeaderAnomalyResult | None = None
```

Cached properties: `scan_text_lower`, `body_text_lower`, `html_body_lower`,
`subject_lower` (all `str`); `sender_domain`, `reply_to_domain`,
`return_path_domain` (all `str | None`); `link_hostnames`, `link_domains`
(both `frozenset[str]`).

### Ruleset

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

The JSON format itself (file structure, rule field reference, the
severity/match schema, validation rules, detail-template substitution, and
why regular expressions are deliberately excluded from it) is fully
documented once, language-neutrally, in
[`../../rules/README.md`](../../rules/README.md) — it's the same format
whichever implementation is loading it. This page only shows the Python
loading calls, above.

## Scoring interaction

Fully covered in [`../../rules/CONCEPTS.md`](../../rules/CONCEPTS.md#scoring-interaction)
— it's identical in both implementations. In short: the rules engine does
not score anything itself; that stays in `phish_signals.signals.score_signals()`.

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
