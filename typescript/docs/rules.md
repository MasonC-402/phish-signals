# Rules Engine

The rules engine gives the detection logic in phish-signals a name, so it can
be listed, disabled, replaced, or extended by consumers of the library.

This page is the TypeScript API surface — imports, class signatures, code
examples. For what a `Rule`/`RuleContext`/`Ruleset` actually mean, why `id`
and `emits` are separate, and what the engine guarantees beyond a bare loop
over rules, see [`rules/CONCEPTS.md`](https://github.com/MasonC-402/phish-signals/blob/main/rules/CONCEPTS.md), which
covers both implementations at once since the concepts are identical. For the
declarative JSON rule format, see
[`rules/README.md`](https://github.com/MasonC-402/phish-signals/blob/main/rules/README.md).

**Not yet part of the published package's public API.** Everything below
works if you're building against this repo directly, but
`@farksecurity/phish-signals`'s `package.json` only exposes its top-level
entry point (`"."` → `dist/index.js`) — there is no `./rules` subpath export,
and `index.ts` doesn't re-export `Rule`/`RuleContext`/`Ruleset`/
`evaluateRuleset`/`loadRuleFile`/`loadRuleset` either. So
`import { Rule } from '@farksecurity/phish-signals'` does not work today for
someone who only `npm install`ed the package — the examples below import
from `../src/rules/...`, which is correct for this repo's own test suite and
for anyone building from source, but is not yet installable API. Making it
one is a real decision (what to name the subpath, whether these are ready to
commit to as public API) rather than something to do silently as part of
writing this page.

**Where it lives:** `typescript/src/rules/` — three modules:

| Module | Role |
| --- | --- |
| `types.ts` | `Rule`, `RuleContext`, `Ruleset` — what a rule is, what it may look at, how a collection is assembled |
| `engine.ts` | Runs a ruleset, isolates failures, applies severity overrides |
| `loader.ts` | Declarative JSON format for phrase-list rules (data, not code) |

## Quick start

### Running the built-in content rules

```ts
import { checkContent, scoreSignals } from '@farksecurity/phish-signals';

const result = checkContent('ACT NOW or your account will be suspended!', null);
const scored = scoreSignals(result.signals);

console.log(scored.verdict); // 'Low Risk'
console.log(scored.score);   // 6
for (const signal of scored.signals) {
  console.log(`  [${signal.severity}] ${signal.label}: ${signal.detail}`);
}
```

### Writing a custom code rule

```ts
import { Rule, RuleContext, Ruleset } from '../src/rules/types';
import { evaluateRuleset } from '../src/rules/engine';
import { scoreSignals } from '@farksecurity/phish-signals';
import type { Signal } from '@farksecurity/phish-signals';

function checkVendorLookalike(context: RuleContext): Signal[] {
  if (!context.senderDomain?.includes('acme-payments')) return [];
  return [{
    id: 'acme_vendor_lookalike',
    category: 'identity',
    severity: 'high',
    label: 'Vendor Lookalike Domain',
    detail: `Sender domain ${context.senderDomain} imitates our vendor.`,
  }];
}

const myRules = new Ruleset('acme', [
  new Rule('acme.vendor_lookalike', ['acme_vendor_lookalike'], checkVendorLookalike, ['identity']),
]);

// Run and score
const run = evaluateRuleset(myRules, new RuleContext(parsed));
const scored = scoreSignals(run.signals);
```

### Writing a declarative JSON rule

Most content rules are a phrase list and a severity. Write them as data
instead of code so the phrase lists are defined once — the same file loads
in either language:

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

```ts
import { loadRuleFile, loadRuleset } from '../src/rules/loader';

// Single file
const rules = loadRuleFile('path/to/rules.json');

// Entire directory (sorted filename order, deterministic)
const ruleset = loadRuleset('path/to/rules/', 'acme');
```

## Concepts, in TypeScript

See [`rules/CONCEPTS.md`](https://github.com/MasonC-402/phish-signals/blob/main/rules/CONCEPTS.md) for what each of
these means and guarantees. This section is just the TypeScript signatures.

### Rule

```ts
class Rule {
  readonly id: string;
  readonly emits: ReadonlySet<string>;
  readonly evaluate: RuleFn;
  readonly tags: ReadonlySet<string>;
  readonly description: string;

  constructor(
    id: string,
    emits: Iterable<string>,
    evaluate: RuleFn,
    tags: Iterable<string> = [],
    description = '',
  ) { /* ... */ }
}
```

### RuleContext

```ts
class RuleContext {
  constructor(
    public readonly parsed: ParsedEmail,
    public readonly urls: UrlAnalysis[] = [],
    public readonly auth: AuthCheckResult | null = null,
    public readonly chain: ReceivedChainAnalysis | null = null,
    public readonly headerAnomalies: HeaderAnomalyResult | null = null,
  ) {}
}
```

Cached getters: `scanTextLower`, `bodyTextLower`, `htmlBodyLower`,
`subjectLower` (all `string`); `senderDomain`, `replyToDomain`,
`returnPathDomain` (all `string | null`); `linkHostnames`, `linkDomains`
(both `ReadonlySet<string>`). TypeScript has no built-in equivalent to
Python's `@functools.cached_property`, so `RuleContext` hand-rolls the same
memoization with a private backing field per getter.

### Ruleset

```ts
// Add rules
const extended = ruleset.withRules([myCustomRule]);

// Override a built-in
const tuned = ruleset.replaceRule('core.urgency_language', myVersion);

// Filter
const headersOnly = ruleset.withTags(['header']);
const noExperimental = ruleset.withoutTags(['experimental']);
const selective = ruleset.without(['core.generic_greeting']);

// Retune severity without touching the rule
const quieter = ruleset.withSeverityOverrides({ urgency_language: 'info' });
```

### Engine

```ts
import { evaluateRuleset, formatDiagnostics } from '../src/rules/engine';

const run = evaluateRuleset(ruleset, context);
// run.signals      — Signal[], in ruleset order
// run.diagnostics  — RuleDiagnostic[], rules that misbehaved

if (run.diagnostics.length > 0) {
  console.log(formatDiagnostics(run.diagnostics));
}
```

Use `{ strict: true }` in tests and CI to turn rule failures into exceptions
rather than diagnostics.

## Declarative rule format

The JSON format itself (file structure, rule field reference, the
severity/match schema, validation rules, detail-template substitution, and
why regular expressions are deliberately excluded from it) is fully
documented once, language-neutrally, in
[`rules/README.md`](https://github.com/MasonC-402/phish-signals/blob/main/rules/README.md) — it's the same format
whichever implementation is loading it. This page only shows the TypeScript
loading calls, above.

## Scoring interaction

Fully covered in [`rules/CONCEPTS.md`](https://github.com/MasonC-402/phish-signals/blob/main/rules/CONCEPTS.md#scoring-interaction)
— it's identical in both implementations. In short: the rules engine does
not score anything itself; that stays in `scoreSignals()`.

## Built-in content rules

Unlike Python, **none of `contentCheck.ts`'s rules are routed through
`Rule`/`Ruleset` yet** — they're inline logic in one function, same as before
the rule engine existed (see [`rules/README.md`](https://github.com/MasonC-402/phish-signals/blob/main/rules/README.md)
for that gap). The signal ids, categories, and severities below are still
guaranteed identical to Python's by conformance vectors; there just isn't a
`Rule.id` or a built-in `Ruleset` object for any of these to filter,
disable, or replace yet.

| Signal ID | Category | Severity | What it detects |
| --- | --- | --- | --- |
| `urgency_language` | social | low → medium (≥3 hits) | Pressure phrases: "act now", "account suspended", etc. |
| `credential_request` | social | medium | Password/credential requests |
| `financial_request` | social | medium | Wire transfer, gift card, invoice fraud language |
| `authority_impersonation` | social | medium | CEO impersonation, IT department claims, secrecy requests |
| `generic_greeting` | social | low | "Dear Customer", "Hello user", etc. |
| `display_name_brand_spoof`, `display_name_address_spoof` | identity | high | Display name claims a brand or shows a fake email |
| `excessive_capitalization` | social | low | ≥5 all-caps words (4+ letters each) |
| `deceptive_link_text` (`checkLinkText`) | payload | high | Link text claims one domain, href goes to another |
| `dangerous_link_scheme` (`checkDangerousSchemes`) | payload | high | `data:`, `javascript:`, `vbscript:` links |

## Extending the engine

Because `contentCheck.ts` doesn't expose a built-in `Ruleset` yet, there's no
`CONTENT_RULESET.withRules(...)` equivalent to hook into today — that becomes
possible once `contentCheck.ts` itself is ported onto `Rule`/`Ruleset` (the
open item in [`rules/README.md`](https://github.com/MasonC-402/phish-signals/blob/main/rules/README.md)). Until then,
run your own ruleset alongside the built-in check and merge the signals
yourself:

```ts
import { checkContent } from '@farksecurity/phish-signals';
import { Rule, RuleContext, Ruleset } from '../src/rules/types';
import { evaluateRuleset } from '../src/rules/engine';
import type { ParsedEmail, SignalResult } from '@farksecurity/phish-signals';

const myRules = new Ruleset('acme', [myCustomRule]);

function checkContentExtended(parsed: ParsedEmail, context: RuleContext): SignalResult {
  const builtin = checkContent(parsed.textBody, parsed.from);
  const custom = evaluateRuleset(myRules, context);
  return { signals: [...builtin.signals, ...custom.signals] };
}
```

### Loading custom declarative rules from a directory

```ts
import { loadRuleset } from '../src/rules/loader';

const custom = loadRuleset('path/to/custom/rules/', 'acme');
```

## Testing rules

```ts
import { evaluateRuleset } from '../src/rules/engine';
import assert from 'node:assert/strict';

// Use { strict: true } in tests so rule failures are exceptions, not diagnostics
const run = evaluateRuleset(ruleset, context, { strict: true });
assert.deepStrictEqual(run.diagnostics, []);
```
