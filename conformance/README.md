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

- `input` is the single argument passed to the function under test. A
  function taking more than one argument uses `"args": [...]` — an array of
  positional arguments — instead of `input`.
- JSON has no `Map`, but `checkAuthentication` and `checkHeaderAnomalies`
  take their headers as one (mailparser's shape). Write such an argument as
  `{"$map": {"from": "...", ...}}`: the TypeScript harness builds a `Map`
  from it, the Python harness a plain `dict`. Any object whose only key is
  `$map` is decoded this way, at any depth.
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
  find them. As on the TypeScript side, a vector whose module or function
  can't be found fails rather than skipping.

  One consequence worth knowing before writing Python-side code: because
  `expect` is compared by exact deep equality against parsed JSON, anything a
  vectored function returns has to *be* JSON-shaped data — dicts and lists,
  not class instances, which never compare equal to a `dict`. The Python
  implementation uses `TypedDict` for exactly this reason. Vectors are
  therefore also the thing that pins **data key spelling** across the two
  languages: `benignSignals` stays camelCase on the Python side, because the
  key is part of the contract rather than an internal style choice.

## Writing a vector

Don't hand-derive `expect`. Write each case with `name` and `input`/`args`
only, then fill it from the TypeScript implementation (the reference):

```sh
(cd typescript && npm run pretest)   # compiles src/ in place
node conformance/fill-expect.js      # fills only cases with no `expect`
```

Then **read the diff**. A filled value that doesn't match the case's `name`
is a finding, not a formality: either the name is wrong, or the reference
has a bug or a gap. Where the vector pins a quirk or gap rather than an
endorsed result, the `name` says so. Finally, run both test suites; a Python
failure is a parity bug. `--force` regenerates every case, for a deliberate
behaviour change only.

## Coverage

127 cases across:

- **Pure helpers:** `domains`, `punycode`, `iocs`, and the rule loader's
  `quoteHits`/`renderDetail`.
- **Scoring:** `scoreSignals`, including the two cross-language traps below.
- **Checks layer:** `checkContent`; `urlCheck` (`checkUrls`,
  `checkTyposquat`, `brandImpersonation`, `levenshtein`, `isIpLiteral`,
  `checkQrCodes`); `checkAttachments`; `receivedChain`
  (`analyzeReceivedChain`, `isPrivateIp`); `checkAuthentication`, including
  the forged-Authentication-Results defence and its documented limit;
  `checkHeaderAnomalies`; and `mapTechniques`.

Not yet vectored: `combineResults`, the output builders (`buildSigmaRule`,
`buildKqlQuery`, `buildRecommendations`, `extractIocs`), and the parsers
(`parseEmail`, `parseMsg`), whose inputs are raw messages rather than
JSON-shaped data. The rule engine's own internals (`Rule`, `RuleContext`,
`Ruleset`, `evaluateRuleset`) aren't vectorable directly, because they hold
or take a live callable. Both implementations satisfy every vector here.

Two places where the languages differ by default. Both were found by
differential-testing the Python port against the TypeScript one, and both
are now pinned by `vectors/signals/score-signals-rounding-and-collation.json`:

- **Half-way rounding.** JavaScript's `Math.round` rounds a half up; Python's
  built-in `round` is banker's rounding (`round(2.5)` is 2). Category scores
  land on exact halves (28 + 3 × 6 × 0.25 = 32.5), so the Python port uses an
  explicit half-up helper.
- **String collation.** `localeCompare`, which `scoreSignals` uses to break a
  severity tie, is case-insensitive at the primary level, sorts accented
  letters next to their base letter, and puts lowercase before uppercase when
  that is the only difference. Codepoint comparison does none of these. Every
  label this package emits today is ASCII and title-cased, so the vectors
  exist to catch the day one isn't.
