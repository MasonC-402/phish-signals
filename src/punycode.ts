// RFC 3492 punycode decoding, plus Unicode script identification.
//
// The URL parser converts any non-ASCII hostname to its "xn--" form before we
// ever see it, so a homograph domain reaches the analyzer as an opaque string
// like "xn--pypal-4ve.com". Flagging that as "uses punycode" is true but
// useless — the point of the attack is what it *looks* like. Decoding it back
// and naming the scripts involved turns the finding into something a reader can
// act on: they can see the Cyrillic character sitting in the middle of a word
// they thought was Latin.
//
// Written out rather than pulled in as a dependency: Node's own `punycode`
// module has been deprecated since v7, and the algorithm is small, fully
// specified, and exercised by a round-trip test against the URL parser.

const BASE = 36;
const T_MIN = 1;
const T_MAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;
const DELIMITER = '-';
const BASE_MINUS_T_MIN = BASE - T_MIN;

/**
 * Maps a basic code point to its 0..35 digit value, or BASE if it isn't one.
 *
 * Bounds are checked explicitly on both ends. The reference C implementation
 * writes these as a single subtraction (`cp - 0x30 < 0x0a`) which relies on
 * unsigned wraparound; in JavaScript that arithmetic is signed, so any
 * character below '0' produces a negative number that passes the test and
 * decodes as a bogus digit instead of being rejected.
 */
function digitValue(codePoint: number): number {
  if (codePoint >= 0x30 && codePoint <= 0x39) return codePoint - 0x30 + 26; // '0'-'9' => 26..35
  if (codePoint >= 0x41 && codePoint <= 0x5a) return codePoint - 0x41; // 'A'-'Z' => 0..25
  if (codePoint >= 0x61 && codePoint <= 0x7a) return codePoint - 0x61; // 'a'-'z' => 0..25
  return BASE;
}

function adapt(delta: number, numPoints: number, firstTime: boolean): number {
  let scaled = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  scaled += Math.floor(scaled / numPoints);

  let k = 0;
  while (scaled > (BASE_MINUS_T_MIN * T_MAX) >> 1) {
    scaled = Math.floor(scaled / BASE_MINUS_T_MIN);
    k += BASE;
  }
  return Math.floor(k + ((BASE_MINUS_T_MIN + 1) * scaled) / (scaled + SKEW));
}

/** Decodes one punycode label (without the "xn--" prefix). Null if malformed. */
function decodeLabel(input: string): string | null {
  const output: number[] = [];
  let n = INITIAL_N;
  let i = 0;
  let bias = INITIAL_BIAS;

  const lastDelimiter = input.lastIndexOf(DELIMITER);
  for (let j = 0; j < lastDelimiter; j++) {
    const code = input.charCodeAt(j);
    if (code > 0x7f) return null; // basic section must be ASCII
    output.push(code);
  }

  let index = lastDelimiter > 0 ? lastDelimiter + 1 : 0;

  while (index < input.length) {
    const oldi = i;

    for (let w = 1, k = BASE; ; k += BASE) {
      if (index >= input.length) return null;
      const digit = digitValue(input.charCodeAt(index++));
      if (digit >= BASE) return null;
      if (digit > Math.floor((0x7fffffff - i) / w)) return null; // overflow
      i += digit * w;

      const t = k <= bias ? T_MIN : (k >= bias + T_MAX ? T_MAX : k - bias);
      if (digit < t) break;

      if (w > Math.floor(0x7fffffff / (BASE - t))) return null; // overflow
      w *= BASE - t;
    }

    const outLength = output.length + 1;
    bias = adapt(i - oldi, outLength, oldi === 0);

    if (Math.floor(i / outLength) > 0x7fffffff - n) return null; // overflow
    n += Math.floor(i / outLength);
    i %= outLength;

    output.splice(i, 0, n);
    i++;
  }

  try {
    return String.fromCodePoint(...output);
  } catch {
    return null; // out-of-range code point
  }
}

/** Decodes every xn-- label in a hostname. Returns null if none were present. */
function decodeHostname(hostname: string): string | null {
  const labels = hostname.split('.');
  let sawPunycode = false;

  const decoded = labels.map((label) => {
    if (!/^xn--/i.test(label)) return label;
    const result = decodeLabel(label.slice(4));
    if (result === null) return label;
    sawPunycode = true;
    return result;
  });

  return sawPunycode ? decoded.join('.') : null;
}

// Enough of the Unicode blocks to name what a lookalike domain is actually
// built from. Anything unlisted falls through as "Other", which is itself worth
// surfacing on a hostname.
const SCRIPT_RANGES: { name: string; ranges: [number, number][] }[] = [
  { name: 'Latin', ranges: [[0x41, 0x5a], [0x61, 0x7a], [0xc0, 0x24f], [0x1e00, 0x1eff]] },
  { name: 'Greek', ranges: [[0x370, 0x3ff], [0x1f00, 0x1fff]] },
  { name: 'Cyrillic', ranges: [[0x400, 0x52f], [0x2de0, 0x2dff], [0xa640, 0xa69f]] },
  { name: 'Armenian', ranges: [[0x530, 0x58f]] },
  { name: 'Hebrew', ranges: [[0x590, 0x5ff]] },
  { name: 'Arabic', ranges: [[0x600, 0x6ff], [0x750, 0x77f]] },
  { name: 'Devanagari', ranges: [[0x900, 0x97f]] },
  { name: 'Thai', ranges: [[0xe00, 0xe7f]] },
  { name: 'Han', ranges: [[0x4e00, 0x9fff], [0x3400, 0x4dbf]] },
  { name: 'Hiragana', ranges: [[0x3040, 0x309f]] },
  { name: 'Katakana', ranges: [[0x30a0, 0x30ff]] },
  { name: 'Hangul', ranges: [[0xac00, 0xd7af], [0x1100, 0x11ff]] },
];

/** Digits, hyphens and dots belong to every script and carry no signal. */
function isCommon(codePoint: number): boolean {
  return (codePoint >= 0x30 && codePoint <= 0x39)
    || codePoint === 0x2d
    || codePoint === 0x2e
    || codePoint === 0x5f;
}

function scriptsOf(value: string): string[] {
  const found = new Set<string>();

  for (const char of value) {
    const codePoint = char.codePointAt(0);
    if (codePoint === undefined || isCommon(codePoint)) continue;

    const script = SCRIPT_RANGES.find((s) => s.ranges.some(([lo, hi]) => codePoint >= lo && codePoint <= hi));
    found.add(script ? script.name : 'Other');
  }

  return [...found];
}

// Non-Latin characters whose common renderings are visually indistinguishable
// from a Latin letter. A label built entirely from these is a "whole-script
// confusable": it isn't mixed-script at all, so a mixed-script test alone will
// never catch it. This is the mechanism behind the well-known "аррӏе.com"
// demonstration, which is pure Cyrillic and renders identically to "apple.com".
const LATIN_CONFUSABLES = new Set([
  // Cyrillic
  'а', 'в', 'е', 'ё', 'і', 'ј', 'к', 'м', 'н', 'о', 'р', 'с', 'т', 'у', 'х',
  'ѕ', 'ԁ', 'ԛ', 'ԝ', 'ӏ', 'ї', 'ә', 'ғ', 'ԃ',
  // Greek
  'α', 'β', 'γ', 'ε', 'ζ', 'η', 'ι', 'κ', 'μ', 'ν', 'ο', 'ρ', 'σ', 'τ', 'υ',
  'χ', 'ϲ', 'ϳ', 'ѵ',
  // Armenian
  'օ', 'ո', 'ս', 'ց', 'զ', 'գ',
]);

/** True when every non-ASCII character in the label has a Latin lookalike. */
function isWholeScriptConfusable(label: string): boolean {
  const chars = [...label];
  const nonAscii = chars.filter((c) => (c.codePointAt(0) || 0) > 0x7f);
  if (nonAscii.length === 0) return false;

  // Every non-ASCII character must be a known Latin lookalike, and the label
  // must read as a Latin word overall — a genuine Cyrillic word contains
  // characters with no Latin counterpart and so falls out here.
  return nonAscii.every((c) => LATIN_CONFUSABLES.has(c.toLowerCase()));
}

/**
 * Describes a hostname's Unicode makeup.
 *
 * Two separate findings, because they are different attacks:
 *  - `mixed`: one label draws on more than one script ("pаypal" — Latin with a
 *    single Cyrillic 'а' substituted in).
 *  - `confusable`: one label is entirely non-Latin but every character has a
 *    Latin lookalike ("аррӏе" — all Cyrillic, renders as "apple").
 *
 * The confusable test is qualified by the TLD, because structurally a genuine
 * Cyrillic word is indistinguishable from a whole-script confusable — "москва"
 * is made entirely of Cyrillic letters that have Latin lookalikes, exactly like
 * "аррӏе" does. What separates them is where they live: a Cyrillic label under
 * a Cyrillic TLD (москва.рф) is an ordinary internationalized domain, whereas
 * a Cyrillic label under .com is imitating something. Without this the checker
 * flags the entire Russian-language internet.
 */
function describeHostname(hostname: string): {
  decoded: string | null;
  scripts: string[];
  mixed: boolean;
  confusable: boolean;
} {
  const decoded = decodeHostname(hostname);
  const subject = decoded || hostname;
  const labels = subject.split('.');

  const tld = labels.length > 1 ? labels[labels.length - 1] : '';
  const tldIsAscii = /^[a-z0-9-]+$/i.test(tld);

  return {
    decoded,
    scripts: scriptsOf(subject),
    mixed: labels.some((label) => scriptsOf(label).length > 1),
    confusable: tldIsAscii && labels.slice(0, -1).some(isWholeScriptConfusable),
  };
}

export { decodeLabel, decodeHostname, scriptsOf, describeHostname, isWholeScriptConfusable };
