// Runs the language-neutral conformance vectors under ../../conformance/vectors
// against this implementation. See ../../conformance/README.md for the vector
// format and why this exists: it's what catches this implementation and the
// Python one silently disagreeing on what a given input means, which neither
// language's own test suite (this file's siblings) can catch on its own.
//
// An ordinary node:test file, picked up by `npm test` like everything else —
// no separate command, nothing extra to remember to run.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

import * as domains from '../src/domains';
import * as punycode from '../src/punycode';
import * as iocs from '../src/iocs';
import * as signals from '../src/signals';
import * as contentCheck from '../src/contentCheck';
import * as rulesLoader from '../src/rules/loader';

// One entry per module a vector file's "module" field can name. Extend this
// as more modules gain conformance coverage — see the "Coverage" section of
// conformance/README.md, and update it alongside this list.
//
// Typed as `unknown` per export, not `(input: unknown) => unknown`: these
// modules also export plain constants (KNOWN_BRAND_DOMAINS,
// SEVERITY_POINTS, ...) that aren't callable at all. Whether a given export
// is actually a function is checked at dispatch time below, not here.
//
// "rules" maps to rules/loader.ts rather than a single rules.ts: the rule
// layer is a directory of modules (types/engine/loader), and quoteHits /
// renderDetail — the only pieces of it that are pure JSON-in/JSON-out
// functions, as opposed to something holding a live Rule callable — live in
// loader.ts. See conformance/README.md and rules/README.md for why the rest
// of the rule layer (Rule, RuleContext, Ruleset, evaluateRuleset) isn't
// vectored directly.
const MODULES: Record<string, Record<string, unknown>> = {
  domains,
  punycode,
  iocs,
  signals,
  contentCheck,
  rules: rulesLoader,
};

interface VectorCase {
  name: string;
  // Most vectored functions take one argument, expressed as "input"; a few
  // (checkContent, ...) take more than one and use "args" instead — see
  // conformance/README.md's vector format.
  input?: unknown;
  args?: unknown[];
  expect: unknown;
}

interface VectorFile {
  module: string;
  function: string;
  cases: VectorCase[];
}

const VECTORS_DIR = join(__dirname, '..', '..', 'conformance', 'vectors');

function findVectorFiles(dir: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) files.push(...findVectorFiles(full));
    else if (entry.name.endsWith('.json')) files.push(full);
  }
  return files;
}

for (const path of findVectorFiles(VECTORS_DIR)) {
  const vectorFile: VectorFile = JSON.parse(readFileSync(path, 'utf8'));
  const target = MODULES[vectorFile.module]?.[vectorFile.function];

  test(`conformance: ${vectorFile.module}.${vectorFile.function}`, async (t) => {
    assert.equal(
      typeof target,
      'function',
      `${path}: '${vectorFile.function}' on module '${vectorFile.module}' is not a callable export — ` +
        `is it re-exported from src/index.ts, and listed in this file's MODULES map?`,
    );
    const fn = target as (...args: unknown[]) => unknown;
    for (const c of vectorFile.cases) {
      await t.test(c.name, () => {
        const args = c.args ?? [c.input];
        assert.deepStrictEqual(fn(...args), c.expect);
      });
    }
  });
}
