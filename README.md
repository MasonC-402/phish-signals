# phish-signals

Heuristic phishing-detection engine: URL/domain typosquat and homograph
checks, SPF/DKIM/DMARC-aware header analysis, Received-chain spoofing checks,
IOC defang/refang, MITRE ATT&CK mapping, Sigma rule generation, and parsing
for raw `.eml`/`.msg` messages plus embedded QR codes. No network calls, no
external API keys — everything runs locally on data you already have.

Extracted from [farksecurity.com's phish-report tool](https://farksecurity.com/phish-report).

## Implementations

| Implementation | Status |
| --------------- | ------ |
| [`typescript/`](typescript/) | Published — `npm install @farksecurity/phish-signals` |
| [`python/`](python/) | Published — `pip install phish-signals` |

The two are independent implementations of the same detection logic, not a
core-plus-binding — each is a complete, standalone package you can install and
use on its own. They are expected to agree on *what* a given input is: the
same signal ids, categories, and severities for the same input. They are not
expected to version in lockstep, and each ships its own release process:
`.github/workflows/publish.yml` publishes to npm on an `npm-v*` tag, and
`publish-pypi.yml` publishes to PyPI on a `pypi-v*` tag. Both use trusted
publishing (OIDC), so no registry token is stored in the repo.
`.github/workflows/ci.yml` runs both test suites, the conformance vectors,
the static checks and a rule-data sync check on every push and pull request.

## Shared rules

[`rules/`](rules/) holds detection rules written as data. Both
implementations load the same rule files, so a phrase list is written once.
See [rules/README.md](rules/README.md).

## Conformance

[`conformance/`](conformance/) holds the thing that actually keeps two
independent implementations from silently drifting apart: language-neutral
JSON vectors of `input → expected output`, checked into the repo and run by a
small test-suite harness in each language. A vector that only one language's
harness satisfies is a failing test, not a surprise discovered later. See
[conformance/README.md](conformance/README.md) for the vector format and
which modules currently have coverage.

## License

MIT
