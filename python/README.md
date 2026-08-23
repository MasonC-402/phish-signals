# phish-signals (Python)

An independent Python implementation of the same detection engine as
[`../typescript/`](../typescript/) — not a binding or wrapper around it, a
second implementation held to the same behavior via
[`../conformance/`](../conformance/).

**Status: fully ported.** Every module in `typescript/src/` has a Python
counterpart under `src/phish_signals/`, passing every conformance vector
currently in the suite (see `../conformance/`, which only vectors the pure,
zero-dependency layer so far — the larger surface has no vectors yet on
either side). `phish_signals.IMPLEMENTED_MODULES` is the machine-readable
list of what's behind it, which at this point is everything.

Managed with [uv](https://docs.astral.sh/uv/).

## Layout

Standard modern Python packaging: a [src layout](https://packaging.python.org/en/latest/discussions/src-layout-vs-flat-layout/)
(forces tests to run against the installed package rather than accidentally
importing from the working directory) plus [pytest](https://docs.pytest.org/)'s
conventional `tests/` directory.

```text
python/
├── pyproject.toml
├── LICENSE
├── .python-version          # 3.14, pins the interpreter uv uses locally
├── src/
│   └── phish_signals/
│       ├── __init__.py         # public API surface — mirrors typescript/src/index.ts's role
│       ├── py.typed            # PEP 561 marker: this package ships inline types
│       ├── types.py            # shared shapes, as TypedDicts — see the note below
│       ├── domains.py          # registrable-domain / brand-list helpers
│       ├── punycode.py         # punycode decode + homograph/confusable detection
│       ├── sanitize.py         # input validation, dangerous-unicode stripping
│       ├── header_parser.py    # raw header-block -> headers + ordered lines
│       ├── signals.py          # scoring engine
│       ├── iocs.py             # IOC extraction, defang/refang
│       ├── url_check.py        # typosquat/homograph/structural URL analysis
│       ├── auth_check.py       # SPF/DKIM/DMARC from Authentication-Results
│       ├── received_chain.py   # Received-header chain / HELO-RDNS spoofing
│       ├── header_anomalies.py # everything else header-shaped
│       ├── content_check.py    # body phrase heuristics + rule engine wiring
│       ├── attachment_check.py # filename/extension/MIME-type heuristics
│       ├── zip_check.py        # ZIP central-directory listing, no decompression
│       ├── mitre.py            # ATT&CK technique lookup
│       ├── rules/              # named detection units + declarative loader
│       ├── recommendations.py  # scored evidence -> analyst actions
│       ├── sigma_rule.py       # Sigma detection-rule generation
│       ├── kql_query.py        # Defender/Sentinel Advanced Hunting KQL
│       ├── json_export.py      # machine-readable export of a CombinedResult
│       ├── combine_results.py  # the assembly point — runs and scores everything
│       ├── email_parser.py     # raw .eml / pasted-message -> ParsedEmail
│       ├── msg_parser.py       # Outlook .msg -> raw email text (extract_msg)
│       └── qr_check.py         # QR decoding from embedded/attached images
└── tests/
    ├── test_conformance.py     # runs ../../conformance/vectors against this port
    └── test_*.py               # one file per module, plus test_rules.py / test_combine_results.py
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

The directory is `python/` (sits alongside `typescript/` in the repo
listing), but the **PyPI distribution name is the plain `phish-signals`**
(confirmed available), so `pip install phish-signals` matches the repo's own
name. Either way, the **import name is `phish_signals`** — underscored,
since Python import names can't contain hyphens: `import phish_signals`, not
`import phish-signals`.

## Setup

```bash
cd python
uv sync                # creates .venv, installs the package + dev dependencies
uv run pytest
```

Every vector in the suite currently passes. `tests/test_conformance.py` skips
a vector whose module or function doesn't exist — a state that shouldn't
occur any more now that every module is ported, but the harness stays
skip-not-fail for whichever side of the two implementations a future vector
lands on first.

Three runtime dependencies exist for exactly two modules: `extract-msg`
(`msg_parser.py`, built on `olefile` — reads an Outlook `.msg`'s compound-file
structure and MAPI properties) and `pillow` + `opencv-python-headless`
(`qr_check.py` — image decoding and QR detection). `pyzbar`, this package's
other originally-considered QR option, was tried and rejected: it fails at
*import* time on any machine without the system `zbar` library already
installed, which would break the whole package rather than just QR scanning;
`opencv-python-headless` needs nothing beyond `pip`/`uv`. Every other module
is stdlib-only — see each module's own docstring for why that boundary is
where it is.

`zip_check.py` is a from-scratch port of the TypeScript central-directory
parser, not a wrapper around Python's `zipfile` module: the TypeScript
version deliberately degrades gracefully on a truncated or forged central
directory (see `typescript/test/zipcheck.test.ts`) rather than raising, which
matters for detection — an attacker-crafted ZIP that makes the parser throw
must not be indistinguishable from "nothing suspicious found." `zipfile` is
stricter than that, so this port reads the same signature/EOCD/central-directory
bytes directly, the same way the TypeScript side does.

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
