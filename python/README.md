# phish-signals (Python)

Not started yet. This will be an independent Python implementation of the
same detection engine as [`../typescript/`](../typescript/) — not a binding
or wrapper around it, a second implementation held to the same behavior via
[`../conformance/`](../conformance/).

## Suggested starting point

Port leaves-first, so each layer is verifiable before anything depends on it:

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

As each module lands, add its conformance vectors under
`../conformance/vectors/` (or fill in expected values for ones already
seeded by the TypeScript side) and wire a Python harness that reads them —
see `../conformance/README.md`.
