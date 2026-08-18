// Advanced Hunting KQL generation (src/kqlQuery.ts) and freeform IOC parsing
// for the standalone builder (src/iocs.ts's parseIocText).

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildKqlQuery } from '../src/kqlQuery';
import { parseIocText, defang } from '../src/iocs';
import type { Ioc } from '../src/types';

function ioc(type: Ioc['type'], value: string): Ioc {
  return { type, value, defanged: defang(value) };
}

test('no query is emitted when there is nothing concrete to hunt on', () => {
  const query = buildKqlQuery([]);
  assert.match(query, /No indicator here was concrete enough/);
  assert.doesNotMatch(query, /^union/m);
});

test('a domain IOC produces sender, URL, and network blocks referencing only SuspectDomains', () => {
  const query = buildKqlQuery([ioc('domain', 'evil.tk')]);

  assert.match(query, /let SuspectDomains = dynamic\(\["evil\.tk"\]\);/);
  assert.match(query, /EmailEvents/);
  assert.match(query, /SenderFromAddress has_any \(SuspectDomains\)/);
  assert.match(query, /EmailUrlInfo/);
  assert.match(query, /UrlClickEvents/);
  assert.match(query, /DeviceNetworkEvents/);
  assert.match(query, /RemoteUrl has_any \(SuspectDomains\)/);

  // Nothing here should reference a let-binding for a type that wasn't
  // provided — a stray reference would be a runtime KQL error, not just
  // dead code.
  assert.doesNotMatch(query, /SuspectHashes/);
  assert.doesNotMatch(query, /SuspectIPs/);
  assert.doesNotMatch(query, /SuspectSenders/);
});

test('a hash IOC produces attachment and endpoint file blocks, nothing email/network-specific', () => {
  const hash = 'c'.repeat(64);
  const query = buildKqlQuery([ioc('hash', hash)]);

  assert.match(query, new RegExp(`let SuspectHashes = dynamic\\(\\["${hash}"\\]\\);`));
  assert.match(query, /EmailAttachmentInfo/);
  assert.match(query, /SHA256 in \(SuspectHashes\)/);
  assert.match(query, /DeviceFileEvents/);
  assert.doesNotMatch(query, /SuspectDomains/);
  assert.doesNotMatch(query, /SuspectUrls/);
});

test('every subquery is a syntactically closed union member — no malformed comma splicing', () => {
  const query = buildKqlQuery([
    ioc('domain', 'evil.tk'),
    ioc('url', 'http://evil.tk/login'),
    ioc('ip', '203.0.113.5'),
    ioc('hash', 'a'.repeat(64)),
    ioc('filename', 'invoice.exe'),
    ioc('email', 'attacker@evil.tk'),
  ]);

  // The bug this guards against: joining an array of individual lines with
  // ',\n' instead of joining whole subqueries produced "(,", trailing
  // commas after every clause, and an unclosed leading "(".
  assert.doesNotMatch(query, /\(,/);
  assert.doesNotMatch(query, /,\s*\n\s*\|/);

  const openParens = (query.match(/^\(/gm) || []).length;
  const closeParens = (query.match(/^\)/gm) || []).length;
  assert.equal(openParens, closeParens);
  assert.ok(openParens >= 6, 'expected at least one subquery per IOC type present');

  assert.match(query, /\| sort by Timestamp desc/);
});

test('the lookback option is honored', () => {
  const query = buildKqlQuery([ioc('domain', 'evil.tk')], { lookbackDays: 7 });
  assert.match(query, /let Lookback = 7d;/);
});

test('a value that could break out of a KQL string is quoted safely', () => {
  const query = buildKqlQuery([ioc('domain', 'evil".tk\\x')]);
  assert.match(query, /dynamic\(\["evil\\"\.tk\\\\x"\]\)/);
});

// ── parseIocText ─────────────────────────────────────────────────────────

test('parseIocText classifies each IOC type from a live-value paste', () => {
  const hash = 'a'.repeat(64);
  const iocs = parseIocText(`evil.tk http://evil.tk/login 203.0.113.5 ${hash} attacker@evil.tk invoice.exe`);

  const byType = Object.fromEntries(iocs.map((i) => [i.type, i.value]));
  assert.equal(byType.domain, 'evil.tk');
  assert.equal(byType.url, 'http://evil.tk/login');
  assert.equal(byType.ip, '203.0.113.5');
  assert.equal(byType.hash, hash);
  assert.equal(byType.email, 'attacker@evil.tk');
  assert.equal(byType.filename, 'invoice.exe');
});

test('parseIocText refangs both this site\'s own defang style and the bracketed-scheme style', () => {
  const iocs = parseIocText('evil[.]tk hxxp://evil[.]tk/a hxxp[://]evil[.]tk/b attacker[@]evil[.]tk');
  const values = iocs.map((i) => `${i.type}:${i.value}`);

  assert.ok(values.includes('domain:evil.tk'));
  assert.ok(values.includes('url:http://evil.tk/a'));
  assert.ok(values.includes('url:http://evil.tk/b'));
  assert.ok(values.includes('email:attacker@evil.tk'));
});

test('an invalid-length hex string is not misread as a hash', () => {
  const iocs = parseIocText('c'.repeat(63));
  assert.equal(iocs.length, 0);
});

test('a bare domain ending in .com is never misread as a filename', () => {
  const iocs = parseIocText('plain-domain.example.com');
  assert.deepEqual(iocs, [{ type: 'domain', value: 'plain-domain.example.com', defanged: 'plain-domain[.]example[.]com' }]);
});

test('duplicate indicators collapse to one entry', () => {
  const iocs = parseIocText('evil.tk, evil.tk\nevil[.]tk');
  assert.equal(iocs.length, 1);
});

test('prose and bare numbers are silently skipped, not misclassified', () => {
  const iocs = parseIocText('please review this message from the vendor 12345 asap');
  assert.equal(iocs.length, 0);
});
