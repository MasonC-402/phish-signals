# phish-signals (Python)

An independent Python implementation of the same detection engine as
[`../typescript/`](../typescript/) — not a binding or wrapper around it, a
second implementation held to the same behavior via
[`../conformance/`](../conformance/).

**Status: the zero-dependency primitives are ported; the rest is stubbed.**
`types`, `domains`, `punycode`, `sanitize`, `signals`, and `iocs` are
implemented and pass every conformance vector currently in the suite. The
checks, aggregation, and parsing layers exist as documented placeholder
modules that export nothing yet — each names the TypeScript functions it owes
and any porting hazard specific to it. `phish_signals.IMPLEMENTED_MODULES` is
the machine-readable version of that split.

Managed with [uv](https://docs.astral.sh/uv/).

## Layout

Standard modern Python packaging: a [src layout](https://packaging.python.org/en/latest/discussions/src-layout-vs-flat-layout/)
(forces tests to run against the installed package rather than accidentally
importing from the working directory) plus [pytest](https://docs.pytest.org/)'s
conventional `tests/` directory.

```text
py-phish-signals/
├── pyproject.toml
├── LICENSE
├── .python-version          # 3.14, pins the interpreter uv uses locally
├── src/
│   └── phish_signals/
│       ├── __init__.py      # public API surface — mirrors typescript/src/index.ts's role
│       ├── py.typed         # PEP 561 marker: this package ships inline types
│       ├── types.py         # shared shapes, as TypedDicts — see the note below
│       ├── domains.py       # ported
│       ├── punycode.py      # ported
│       ├── sanitize.py      # ported
│       ├── signals.py       # ported
│       ├── iocs.py          # ported
│       └── *.py             # everything else: documented stubs, export nothing yet
└── tests/
    └── test_conformance.py  # runs ../../conformance/vectors against whatever's implemented
```

Note that `.python-version` (3.14, what uv uses locally) and
`requires-python` in `pyproject.toml` (>=3.10, what the package claims to
support) are deliberately different numbers. Developing on the newest
interpreter while supporting an older floor is the normal arrangement, but it
means local green does not by itself prove the floor still holds — check it
with `uv run --python 3.10 --isolated --with pytest --with . pytest`.

## Shared shapes are TypedDicts, not dataclasses

This is load-bearing rather than stylistic, and it is the first thing to know
before adding a type. The conformance harness compares `func(input) ==
expect`, where `expect` is JSON parsed off disk, by exact deep equality. A
dataclass instance never compares equal to a `dict`, so every vectored
function would fail no matter how correct its logic was; a TypedDict *is* a
plain `dict` at runtime, so one value satisfies both the type checker and the
vector.

The corollary is that a TypedDict body may contain **annotations only**.
Methods written inside one are silently discarded — the class is not really a
class, `TypedDict(...)` returns a bare `dict` whose `__init__` never ran, and
`hasattr(value, "your_method")` is `False` with no error anywhere to say so.
Behavior belongs in module-level functions taking and returning these dicts,
which is how the TypeScript side is written too.

The directory is `py-phish-signals/` (sits clearly alongside `typescript/` in
the repo listing), but the **PyPI distribution name is the plain
`phish-signals`** (confirmed available), so `pip install phish-signals`
matches the repo's own name without a redundant `py-` prefix. Either way, the
**import name is `phish_signals`** — underscored, since Python import names
can't contain hyphens: `import phish_signals`, not `import phish-signals` or
`import py_phish_signals`.

## Setup

```bash
cd py-phish-signals
uv sync                # creates .venv, installs the package + dev dependencies
uv run pytest
```

Every vector in the suite currently passes. `tests/test_conformance.py` skips
a vector whose module or function doesn't exist yet rather than failing on it
(see that file's docstring), so as the remaining modules land their vectors
flip from skip to pass — or to fail, if the port doesn't match, which is the
point.

To add a runtime dependency once parsing needs one (`extract-msg`, `pyzbar`,
...): `uv add extract-msg`. To add a dev-only one: `uv add --dev <package>`.

## Porting order

Leaves-first, so each layer is verifiable before anything depends on it:

1. ~~Zero-dependency primitives: `domains`, `punycode`, `sanitize`, `signals`
   (scoring), `iocs`~~ — **done**, plus `types` underneath them
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

Vectors name modules and functions the way the TypeScript source does
(camelCase, e.g. `urlCheck` / `registrableDomain`) since that's the reference
implementation. Write the Python side with ordinary Python naming
(`url_check.registrable_domain`) — the conformance harness converts camelCase
to snake_case in both positions to find it. See `../conformance/README.md`.

That applies to *function and module names*. It deliberately does not apply to
**data keys inside the values these functions return** — `benignSignals`,
`originIp`, `uncompressedSize` and the like stay camelCase, because those
cross the language boundary in JSON exports and in the conformance vectors'
`expect` values, where the exact spelling is part of the contract rather than
an internal style choice. Renaming one to snake_case is a behavior change that
breaks conformance, not a cleanup.

## Adding a module

1. Implement it under `src/phish_signals/<name>.py`, matching
   `typescript/src/<name>.ts`'s public functions and behavior (including its
   quirks — see `../conformance/README.md`'s note on that).
2. If `../conformance/vectors/<name>/` already has vectors (seeded from the
   TypeScript side for the zero-dependency layer), `uv run pytest` will pick
   them up automatically — no wiring needed.
3. If it doesn't yet, add vectors there once both implementations exist, so
   coverage grows with the port rather than trailing behind it.
4. Re-export the new public functions from `src/phish_signals/__init__.py`,
   same grouping as `typescript/src/index.ts`.

## Publishing

`.github/workflows/publish-pypi.yml` (repo root) is tag-driven: bump
`version` in `pyproject.toml`, commit, push a matching `pypi-vX.Y.Z` tag. It
won't succeed until a trusted publisher is configured on PyPI's side for a
project named `phish-signals` — see that workflow file's comment.
