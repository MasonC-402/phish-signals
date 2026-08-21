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
  fails the specific case (not the whole file) on a mismatch.
- **Python**: not wired up yet — see `python/README.md`. It should follow
  the same shape: read the same JSON files unmodified, dispatch to the
  matching function, assert equality.

## Coverage

Only the pure, zero-runtime-dependency layer is vectored so far —
`domains`, `punycode`, `iocs`, and `signals`'s `scoreSignals`. The larger
surface (`urlCheck`, `authCheck`, `attachmentCheck`, `combineResults`, the
parsers, ...) has no vectors yet. Add them as the Python port reaches each
module, generating the `expect` value from the TypeScript implementation
(the reference) rather than hand-deriving it — see the git history of this
directory for how the existing vectors were produced.
