// Unit tests for the URL heuristics. Nothing under lib/ had any test coverage
// at all, which is how three separate false-positive bugs shipped and stayed
// shipped — the smoke test only ever asserted that the results page rendered.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { checkUrls, checkTyposquat, brandImpersonation, isIpLiteral } from '../src/urlCheck';

function analyze(url: string) {
  const [result] = checkUrls([url]);
  return result;
}

test('a brand that is also near another brand is not flagged as its own typosquat', () => {
  // Regression: the exact-match whitelist used to live *inside* the brand loop,
  // and 'usps.com' is checked before 'ups.com' is reached. ups.com therefore
  // matched usps.com at edit distance 1 and every real UPS tracking link came
  // back "malicious".
  assert.equal(checkTyposquat('ups.com'), null);
  assert.equal(checkTyposquat('www.ups.com'), null);
  assert.equal(checkTyposquat('usps.com'), null);

  const result = analyze('https://www.ups.com/track?tracknum=1Z999AA10123456784');
  assert.equal(result.risk, 'clean');
});

test('genuine lookalike domains are still caught', () => {
  assert.equal(checkTyposquat('paypa1.com'), 'paypal.com');
  assert.equal(checkTyposquat('rnicrosoft.com'), 'microsoft.com');
  assert.equal(checkTyposquat('arnazon.com'), 'amazon.com');
  assert.equal(checkTyposquat('netflx.com'), 'netflix.com');
  // Caught via the registrable domain rather than the full hostname.
  assert.equal(checkTyposquat('login.paypa1.com'), 'paypal.com');
});

test('subdomains of a real brand are left alone', () => {
  assert.equal(checkTyposquat('accounts.google.com'), null);
  assert.equal(checkTyposquat('mail.chase.com'), null);
  assert.equal(analyze('https://accounts.google.com/signin').risk, 'clean');
});

test('an email address in a query string is not an "@" trick', () => {
  // Regression: hasAtSymbolTrick stripped only the scheme and tested the whole
  // remainder for '@', so every unsubscribe link carrying the recipient's
  // address — which is most bulk mail — scored 35 and came back "malicious".
  const result = analyze('https://news.example.com/unsubscribe?email=jane.doe@example.com');
  assert.equal(result.risk, 'clean');
  assert.doesNotMatch(result.detail, /@/);
});

test('a real userinfo "@" trick is still caught', () => {
  const result = analyze('http://www.paypal.com@evil.tk/login');
  assert.equal(result.risk, 'malicious');
  assert.match(result.detail, /"@" trick/);
});

test('a brand name in a subdomain of an unrelated domain is caught', () => {
  // The exact spelling means this is not a typosquat, and four labels is under
  // the excessive-subdomain threshold — so this scored zero before.
  assert.equal(brandImpersonation('paypal.com.secure-verify.net'), 'paypal.com');
  assert.equal(brandImpersonation('login.microsoft.evil.tk'), 'microsoft.com');
  assert.equal(brandImpersonation('secure-paypal.com'), 'paypal.com');

  const result = analyze('https://paypal.com.secure-verify.net/account');
  assert.equal(result.risk, 'malicious');
  assert.match(result.detail, /secure-verify\.net/);
});

test('brand impersonation does not fire on the brand itself or a regional domain', () => {
  assert.equal(brandImpersonation('paypal.com'), null);
  assert.equal(brandImpersonation('www.paypal.com'), null);
  assert.equal(brandImpersonation('mail.google.com'), null);
  // Not on the brand list, but a bare single-token registrable domain — the
  // deliberate carve-out that keeps legitimate regional domains quiet.
  assert.equal(brandImpersonation('paypal.co.uk'), null);
});

test('IP literals are detected across their notations, and octets are validated', () => {
  assert.equal(isIpLiteral('192.168.1.1'), true);
  assert.equal(isIpLiteral('3232235777'), true);
  assert.equal(isIpLiteral('0x7f000001'), true);
  assert.equal(isIpLiteral('::1'), true);
  // 999 is not a valid octet, so this is a hostname, not an IP.
  assert.equal(isIpLiteral('999.999.999.999'), false);
  assert.equal(isIpLiteral('example.com'), false);

  assert.match(analyze('http://192.168.1.50/login').detail, /raw IP address/);
});

test('a link straight to an executable payload is flagged', () => {
  const result = analyze('https://files.example.com/invoice.exe');
  assert.equal(result.risk, 'malicious');
  assert.match(result.detail, /\.exe/);
});

test('ordinary links come back clean', () => {
  for (const url of [
    'https://github.com/MasonC-402/farkwebsite',
    'https://en.wikipedia.org/wiki/Phishing',
    'https://example.com/blog/2026/some-post',
    'https://www.fedex.com/fedextrack/?trknbr=123456789012',
  ]) {
    assert.equal(analyze(url).risk, 'clean', `expected ${url} to be clean, got: ${analyze(url).detail}`);
  }
});

test('typosquat comparison is bounded against a very long hostname', () => {
  // The Levenshtein matrix was allocated against an attacker-controlled
  // hostname (up to the full 500k input length) 20 times per URL, with no
  // length guard. The guard makes this constant-time to reject.
  const longHost = 'a'.repeat(60000) + '.com';
  const started = Date.now();
  assert.equal(checkTyposquat(longHost), null);
  assert.ok(Date.now() - started < 500, 'typosquat check should short-circuit on length');
});
