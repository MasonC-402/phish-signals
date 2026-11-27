#!/usr/bin/env node
// Fills in missing `expect` values in conformance vectors by running the
// TypeScript implementation, which is the reference. Hand-deriving expected
// output is how vectors end up encoding what someone *thought* the code does;
// generating it from the reference and then reviewing the diff is how they
// end up encoding what it actually does.
//
// Workflow for a new vector:
//   1. Write the case with `name` and `input`/`args`, and no `expect`.
//   2. cd typescript && npm run pretest     (compiles src/ in place)
//   3. node conformance/fill-expect.js      (only fills cases lacking `expect`)
//   4. Read the diff. A surprising `expect` is a finding, not a formality.
//   5. Run both test suites; a Python mismatch is a parity bug to fix.
//
// `--force` regenerates every case, for a deliberate behaviour change. Never
// use it to make a failing vector pass without understanding why it failed.

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const VECTORS = path.join(__dirname, 'vectors');
const TS_SRC = path.join(ROOT, 'typescript', 'src');
const force = process.argv.includes('--force');

// Mirrors decodeArg() in typescript/test/conformance.test.ts.
function decodeArg(value) {
  if (Array.isArray(value)) return value.map(decodeArg);
  if (value && typeof value === 'object') {
    const keys = Object.keys(value);
    if (keys.length === 1 && keys[0] === '$map') return new Map(Object.entries(value.$map));
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, decodeArg(v)]));
  }
  return value;
}

function loadModule(name) {
  const file = path.join(TS_SRC, name === 'rules' ? path.join('rules', 'loader.js') : `${name}.js`);
  if (!fs.existsSync(file)) {
    throw new Error(`${file} not found — run \`npm run pretest\` in typescript/ first`);
  }
  return require(file);
}

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const full = path.join(dir, e.name);
    return e.isDirectory() ? walk(full) : e.name.endsWith('.json') ? [full] : [];
  });
}

let filled = 0;
for (const file of walk(VECTORS).sort()) {
  const vector = JSON.parse(fs.readFileSync(file, 'utf8'));
  const fn = loadModule(vector.module)[vector.function];
  if (typeof fn !== 'function') throw new Error(`${file}: ${vector.module}.${vector.function} is not a function`);

  let changed = false;
  vector.cases = vector.cases.map((c) => {
    if ('expect' in c && !force) return c;
    const args = (c.args ?? [c.input]).map(decodeArg);
    // Round-trip through JSON so the stored value is exactly what a harness
    // will parse back (undefined-valued keys dropped, and so on).
    const expect = JSON.parse(JSON.stringify(fn(...args)) ?? 'null');
    changed = true;
    filled += 1;
    const { expect: _old, ...rest } = c;
    return { ...rest, expect };
  });

  if (changed) {
    fs.writeFileSync(file, `${JSON.stringify(vector, null, 2)}\n`);
    console.log(`filled ${path.relative(ROOT, file)}`);
  }
}
console.log(`${filled} case(s) filled`);
