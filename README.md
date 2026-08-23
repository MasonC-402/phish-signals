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
| [`python/`](python/) | Fully ported and conformant; `pip install phish-signals` once released |

The two are independent implementations of the same detection logic, not a
core-plus-binding — each is a complete, standalone package you can install and
use on its own. They are expected to agree on *what* a given input is: the
same signal ids, categories, and severities for the same input. They are not
expected to version in lockstep, and each ships its own release process:
`.github/workflows/publish.yml` builds and tags npm releases as `npm-v*`,
`publish-pypi.yml` does the same for PyPI as `pypi-v*`. The PyPI workflow
exists but is dormant until a trusted publisher is configured on PyPI's side
(see that file's comment) and there's an actual release to cut.

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
