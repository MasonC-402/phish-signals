const DEFAULT_MAX_LENGTH = 50000;

// Thrown for expected, user-actionable input problems (bad length, wrong file
// type, etc.) — safe to show verbatim to the visitor. Anything else thrown
// during analysis should stay generic to the user and only get logged server-side.
export class ValidationError extends Error {}

export function sanitizeInput(raw: unknown, maxLength: number = DEFAULT_MAX_LENGTH): string {
  if (!raw || typeof raw !== 'string') {
    throw new ValidationError('Invalid input');
  }
  if (raw.trim().length === 0) {
    throw new ValidationError('Input cannot be empty');
  }
  if (raw.length > maxLength) {
    throw new ValidationError(`Content exceeds maximum length of ${maxLength.toLocaleString()} characters`);
  }

  let clean = raw.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');
  clean = clean.replace(/\r\n/g, '\n');

  return clean;
}

// Codepoints commonly abused to spoof how text displays: zero-width chars
// (can split up a brand name to dodge keyword matching), bidi
// marks/embedding/override/isolate controls (can visually reverse or hide
// part of a domain/filename), invisible math operators, and the BOM / a
// stray zero-width no-break space. Built from numeric code points (rather
// than pasting the characters themselves) so the source file stays plain
// ASCII and the exact set being stripped is auditable at a glance.
const DANGEROUS_CODEPOINTS = [
  0x200b, 0x200c, 0x200d, 0x200e, 0x200f, // zero-width space/joiners, LRM/RLM
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e, // LRE/RLE/PDF/LRO/RLO
  0x2066, 0x2067, 0x2068, 0x2069, // LRI/RLI/FSI/PDI
  0x2060, 0x2061, 0x2062, 0x2063, 0x2064, // word joiner + invisible operators
  0xfeff, // BOM / zero-width no-break space
];

const DANGEROUS_UNICODE_PATTERN = new RegExp(
  '[' + DANGEROUS_CODEPOINTS.map((c) => '\\u' + c.toString(16).padStart(4, '0')).join('') + ']',
  'g'
);

// Applied to any header-derived text (Subject/From/etc.) before it's shown in
// the UI — HTML-escaping alone (which Pug already does by default) prevents
// script injection, but doesn't stop a crafted header from *visually* lying
// to the analyst reading the report.
export function stripDangerousUnicode(str: unknown): string {
  if (typeof str !== 'string') return '';
  return str.replace(DANGEROUS_UNICODE_PATTERN, '');
}
