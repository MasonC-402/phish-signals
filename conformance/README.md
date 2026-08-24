# Conformance suite

Both implementations of phish-signals are independently written, so nothing
stops them from silently drifting apart on *what a given input is judged to
be* — the same URL scoring `malicious` in TypeScript and `suspicious` in
Python, say, with no test in either language catching it, because each
language's own test suite only tests itself.

This directory is the fix: language-neutral vectors of `input → expected
output`, checked into the repo once, run by a thin test harness in each
implementation. A vector that only one language's harness satisfies is a
failing test, not a surprise discovered in production.

## What this is not

Not a replacement for either implementation's own test suite.
`typescript/test/*.test.ts` covers edge cases, malformed input handling, and
things specific to that implementation (a truncated ZIP central directory not
raising, for instance) that don't need a Python-side opinion at all. This
directory covers only the shared, language-neutral contract: given this
input, every implementation must agree on this output.

## Vector format

One JSON file per function under `vectors/<module>/<function-name>.json`,
mirroring the TypeScript source layout (`vectors/domains/registrable-domain.json`
tests `registrableDomain` from `typescript/src/domains.ts`, and so on).

```json
{
  "module": "domains",
  "function": "registrableDomain",
  "cases": [
    { "name": "human-readable description of what this case exercises", "input": "mail.example.com", "expect": "example.com" }
  ]
}
```

- `input` is the single argument passed to the function under test. (Nothing
  currently vectored takes more than one argument. If that changes, use
  `"args": [...]` — an array of positional arguments — instead of `input`,
  and update this doc.)
- `expect` is compared against the actual return value by **exact deep
  equality**, not a partial/subset match. This is deliberate: partial
  matching hides drift instead of catching it. If a vector only checks
  `score` and `verdict` on a function that also returns `categories`, an
  implementation that gets `categories` wrong passes anyway — better to
  fully specify the expected value once (see
  `vectors/signals/score-signals.json` for a worked example with a rich
  return type) than to under-specify every vector to keep them short.
- Object/array key order in `expect` doesn't matter; the harness does a
  structural comparison, not a string comparison.
- Where a case documents a real quirk rather than an idealized result (e.g.
  `registrableDomain('192.168.1.1')` returning `'1.1'`, because the function
  has no way to know an IP literal isn't a domain), the case `name` says so
  explicitly. Vectors capture actual behavior. If a port "fixes" a quirk
  like that, it's the vector that's wrong now, not the implementation — either
  update the vector deliberately (and fix the same thing in both languages)
  or match the existing behavior.

## Running it

Each language's own test suite loads and runs every vector as part of its
normal test run — there's no separate command.

- **TypeScript**: `typescript/test/conformance.test.ts`, run via `npm test`
  from `typescript/`. Reads every `vectors/**/*.json` file, dispatches by
  `module`/`function` to the matching export from `typescript/src/`, and
  fails the specific case (not the whole file) on a mismatch. Every vector
  here already has a matching TS export — a missing one is a real bug, so
  the harness fails hard rather than skipping.
- **Python**: `python/tests/test_conformance.py`, run via
  `uv run pytest` from `python/` (see `python/README.md`
  for setup). Reads the same files, converting each vector's camelCase
  `module` and `function` names to snake_case (`urlCheck` →
  `phish_signals.url_check`, `registrableDomain` → `registrable_domain`) to
  find them. Every module vectored so far is a single lowercase word, where
  that conversion is the identity; it starts mattering with the checks layer.
  Unlike the TypeScript side, a vector whose module or function doesn't exist
  yet is **skipped, not failed** — the Python port is in progress, and "not
  implemented yet" isn't the same failure as "implemented and wrong." A vector
  whose function exists but returns the wrong value still fails normally.

  One consequence worth knowing before writing Python-side code: because
  `expect` is compared by exact deep equality against parsed JSON, anything a
  vectored function returns has to *be* JSON-shaped data — dicts and lists,
  not class instances, which never compare equal to a `dict`. The Python
  implementation uses `TypedDict` for exactly this reason. Vectors are
  therefore also the thing that pins **data key spelling** across the two
  languages: `benignSignals` stays camelCase on the Python side, because the
  key is part of the contract rather than an internal style choice.

## Coverage

The pure, zero-runtime-dependency layer is vectored — `domains`, `punycode`,
`iocs`, and `signals`'s `scoreSignals` — plus `contentCheck`'s `checkContent`
(the first vector into the checks layer, and the first to use the multi-arg
`args` form) and the rule loader's `quoteHits`/`renderDetail` helpers. The
rest of the checks layer (`urlCheck`, `authCheck`, `attachmentCheck`,
`combineResults`, the parsers, ...) has no vectors yet, and neither does the
rule engine's own internals (`Rule`, `RuleContext`, `Ruleset`,
`evaluateRuleset`) — see this directory's git history for why those aren't
vectorable directly: they hold or take a live callable, not JSON-shaped data.
Both implementations satisfy every vector here.

Coverage is thinner than the passing count suggests, and it is worth being
precise about that: 42 cases is enough to pin the documented quirks and one
real slice of the checks layer, not
enough to catch a subtly wrong port. Two areas where the languages differ by
default, both found by differential-testing the Python port against the
TypeScript one rather than by any vector here, are worth vectors of their own
when someone next touches this directory:

- **Half-way rounding.** `Math.round(31.5)` is 32; Python's built-in
  `round(31.5)` is 32 too, but `round(2.5)` is 2 where JavaScript gives 3 —
  banker's rounding versus half-up. Category scores land on exact halves
  routinely (28 + 14 × 0.25), so this is reachable, not theoretical.
- **String collation.** `localeCompare` — which `scoreSignals` uses to break a
  severity tie — is case-insensitive at the primary level and sorts accented
  letters next to their base letter. Codepoint comparison, the default in most
  other languages, does neither: it sorts `"apple"` after `"Zebra"`, and `"Á"`
  after `"Z"`. Every signal label this package emits is ASCII and title-cased,
  so nothing currently reaches the disagreement, which is exactly why a vector
  should pin it before someone adds a label that does. Add them as the Python port reaches each
module, generating the `expect` value from the TypeScript implementation
(the reference) rather than hand-deriving it — see the git history of this
directory for how the existing vectors were produced.
