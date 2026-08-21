# phish-signals (Python)

Not started yet — this is scaffolding, not an implementation. This will be an
independent Python implementation of the same detection engine as
[`../typescript/`](../typescript/) — not a binding or wrapper around it, a
second implementation held to the same behavior via
[`../conformance/`](../conformance/).

## Layout

Standard modern Python packaging: a [src layout](https://packaging.python.org/en/latest/discussions/src-layout-vs-flat-layout/)
(forces tests to run against the installed package rather than accidentally
importing from the working directory) plus [pytest](https://docs.pytest.org/)'s
conventional `tests/` directory.

```text
python/
├── pyproject.toml
├── LICENSE
├── src/
│   └── phish_signals/
│       └── __init__.py      # public API surface — mirrors typescript/src/index.ts's role
└── tests/
    └── test_conformance.py  # runs ../../conformance/vectors against whatever's implemented
```

The PyPI distribution name is `phish-signals` (hyphenated, like the repo);
the import name is `phish_signals` (underscored — Python import names can't
contain hyphens). `import phish_signals`, not `import phish-signals`.

## Setup

```bash
cd python
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
pytest
```

Right now every test in `pytest`'s output will be `SKIPPED`, not failed —
that's correct. `tests/test_conformance.py` skips a vector whose module or
function doesn't exist yet rather than failing on it; see that file's
docstring. As modules get implemented, their vectors flip from skip to pass
(or fail, if the port doesn't match — that's the point).

## Porting order

Leaves-first, so each layer is verifiable before anything depends on it:

1. Zero-dependency primitives: `domains`, `punycode`, `sanitize`, `signals`
   (scoring), `iocs`
2. Checks over plain data: `urlCheck`, `authCheck`, `headerAnomalies`,
   `contentCheck`, `attachmentCheck`, `receivedChain`
3. Aggregation/output: `combineResults`, `sigmaRule`, `kqlQuery`, `mitre`,
   `recommendations`, `jsonExport`
4. Parsing last, where the runtime dependencies get swapped for Python
   equivalents: `mailparser` → stdlib `email`, `@kenjiuno/msgreader` →
   `extract-msg`, `jsqr`/`pngjs`/`jpeg-js` → `pyzbar`/Pillow or
   `opencv-python`

Do not port `zipCheck` onto Python's `zipfile` module as-is: the TypeScript
version deliberately degrades gracefully on a truncated or forged central
directory (see `typescript/test/zipcheck.test.ts`) rather than raising, which
matters for detection — an attacker-crafted ZIP that makes the parser throw
must not be indistinguishable from "nothing suspicious found." `zipfile` is
stricter than that; either handle its exceptions to match the TypeScript
behavior, or port the hand-rolled central-directory parse directly.

## Function naming

Vectors name functions the way the TypeScript source does (camelCase, e.g.
`registrableDomain`) since that's the reference implementation. Write the
Python side with ordinary Python naming (`registrable_domain`) — the
conformance harness converts camelCase to snake_case to find it. See
`../conformance/README.md`.

## Adding a module

1. Implement it under `src/phish_signals/<name>.py`, matching
   `typescript/src/<name>.ts`'s public functions and behavior (including its
   quirks — see `../conformance/README.md`'s note on that).
2. If `../conformance/vectors/<name>/` already has vectors (seeded from the
   TypeScript side for the zero-dependency layer), `pytest` will pick them up
   automatically — no wiring needed.
3. If it doesn't yet, add vectors there once both implementations exist, so
   coverage grows with the port rather than trailing behind it.
4. Re-export the new public functions from `src/phish_signals/__init__.py`,
   same grouping as `typescript/src/index.ts`.
