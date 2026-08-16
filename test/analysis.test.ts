// The scoring engine and the individual checks that feed it.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { scoreSignals, assessConfidence } from '../src/signals';
import { checkAuthentication } from '../src/authCheck';
import { checkAttachments } from '../src/attachmentCheck';
import { checkContent, checkLinkText, checkDangerousSchemes } from '../src/contentCheck';
import { checkQrCodes } from '../src/urlCheck';
import { sanitizeInput, stripDangerousUnicode, ValidationError } from '../src/sanitize';
import type { Severity, EvidenceCategory, Signal } from '../src/types';

function signal(id: string, category: EvidenceCategory, severity: Severity, benign = false): Signal {
  return { id, category, severity, label: id, detail: '', benign };
}

// checkAuthentication reads Authentication-Results from headerLines (wire
// order), not from the headers Map, so single-header tests need a matching
// headerLines entry alongside the Map.
function authResultsLine(value: string): { key: string; line: string }[] {
  return [{ key: 'authentication-results', line: `authentication-results: ${value}` }];
}

test('correlated findings in one category do not stack like independent evidence', () => {
  // The regression this whole model exists for: SPF + DKIM + DMARC failing is
  // one fact (the message is not authenticated), and the old additive model
  // scored it 25+25+25 = 75, reaching High Risk on authentication alone.
  const authOnly = scoreSignals([
    signal('dmarc_fail', 'authentication', 'high'),
    signal('spf_fail', 'authentication', 'medium'),
    signal('dkim_fail', 'authentication', 'medium'),
  ]);

  // Strongest (28) + the other two at the corroboration rate (28*0.25).
  assert.equal(authOnly.score, 35);
  assert.equal(authOnly.verdict, 'Medium Risk');
});

test('evidence spread across categories outweighs the same volume in one', () => {
  const concentrated = scoreSignals([
    signal('a', 'authentication', 'medium'),
    signal('b', 'authentication', 'medium'),
    signal('c', 'authentication', 'medium'),
    signal('d', 'authentication', 'medium'),
  ]);

  const spread = scoreSignals([
    signal('a', 'authentication', 'medium'),
    signal('b', 'identity', 'medium'),
    signal('c', 'payload', 'medium'),
    signal('d', 'social', 'medium'),
  ]);

  assert.ok(
    spread.score > concentrated.score * 2,
    `expected breadth to dominate depth, got spread=${spread.score} concentrated=${concentrated.score}`
  );
});

test('no single category can reach High Risk on its own', () => {
  const oneCategory = scoreSignals([
    signal('a', 'payload', 'critical'),
    signal('b', 'payload', 'critical'),
    signal('c', 'payload', 'critical'),
    signal('d', 'payload', 'high'),
  ]);

  assert.ok(oneCategory.score <= 55, `category cap not applied, got ${oneCategory.score}`);
  assert.notEqual(oneCategory.verdict, 'High Risk');
});

test('duplicate signal ids count once', () => {
  const once = scoreSignals([signal('attachment_executable', 'payload', 'critical')]);
  const twice = scoreSignals([
    signal('attachment_executable', 'payload', 'critical'),
    signal('attachment_executable', 'payload', 'critical'),
  ]);
  assert.equal(once.score, twice.score);
});

test('benign evidence lowers the score, but cannot excuse a serious finding', () => {
  const weakOnly = scoreSignals([
    signal('minor', 'identity', 'low'),
    signal('auth_fully_passed', 'authentication', 'info', true),
  ]);
  const withoutBenign = scoreSignals([signal('minor', 'identity', 'low')]);
  assert.ok(weakOnly.score < withoutBenign.score, 'benign signal should reduce a weak score');

  // A message carrying an executable does not get talked down by valid SPF.
  const serious = scoreSignals([
    signal('attachment_executable', 'payload', 'critical'),
    signal('auth_fully_passed', 'authentication', 'info', true),
  ]);
  const seriousAlone = scoreSignals([signal('attachment_executable', 'payload', 'critical')]);
  assert.equal(serious.score, seriousAlone.score);
});

test('a clean message scores zero', () => {
  assert.equal(scoreSignals([]).score, 0);
  assert.equal(scoreSignals([]).verdict, 'Low Risk');
});

test('confidence reflects how much of the message was visible', () => {
  const full = assessConfidence({ headers: true, authResults: true, receivedChain: true, htmlPart: true, attachmentMetadata: true });
  assert.equal(full.level, 'high');
  assert.equal(full.gaps.length, 0);

  const paste = assessConfidence({ headers: false, authResults: false, receivedChain: false, htmlPart: false, attachmentMetadata: false });
  assert.equal(paste.level, 'low');
  assert.ok(paste.gaps.length >= 4);
  assert.match(paste.gaps.join(' '), /pasted body text/);
});

test('DMARC outranks SPF and DKIM', () => {
  const headers = new Map<string, unknown>([
    ['authentication-results', 'mx.example.com; spf=fail; dkim=fail; dmarc=fail'],
  ]);
  const byId = new Map(checkAuthentication(headers, authResultsLine('mx.example.com; spf=fail; dkim=fail; dmarc=fail')).signals.map((s) => [s.id, s]));

  assert.equal(byId.get('dmarc_fail')?.severity, 'high');
  assert.equal(byId.get('spf_fail')?.severity, 'medium');
  assert.equal(byId.get('dkim_fail')?.severity, 'medium');
});

test('a third-party sending service is not flagged for Return-Path mismatch', () => {
  const headers = new Map<string, unknown>([
    ['authentication-results', 'mx.google.com; spf=pass; dkim=pass; dmarc=pass'],
    ['from', 'news@example.com'],
    ['return-path', 'bounces-123@bounce.example.com'],
  ]);
  const result = checkAuthentication(headers, authResultsLine('mx.google.com; spf=pass; dkim=pass; dmarc=pass'));

  assert.equal(result.passed, true);
  assert.equal(result.signals.filter((s) => !s.benign).length, 0);
  assert.ok(result.signals.some((s) => s.id === 'auth_fully_passed' && s.benign));
});

test('DMARC enforcement and absent policy are distinguished', () => {
  const quarantined = checkAuthentication(
    new Map<string, unknown>([['authentication-results', 'mx.example.com; spf=pass; dkim=pass; dmarc=quarantine']]),
    authResultsLine('mx.example.com; spf=pass; dkim=pass; dmarc=quarantine')
  );
  assert.ok(quarantined.signals.some((s) => s.id === 'dmarc_enforced'));
  assert.equal(quarantined.passed, false);

  const none = checkAuthentication(
    new Map<string, unknown>([['authentication-results', 'mx.example.com; spf=pass; dkim=pass; dmarc=none']]),
    authResultsLine('mx.example.com; spf=pass; dkim=pass; dmarc=none')
  );
  assert.ok(none.signals.some((s) => s.id === 'dmarc_none'));
});

test('no headerLines means no Authentication-Results to read, same as an absent header', () => {
  const headers = new Map<string, unknown>([['authentication-results', 'mx.example.com; spf=pass; dkim=pass; dmarc=pass']]);
  const result = checkAuthentication(headers, []);
  assert.ok(result.signals.some((s) => s.id === 'no_auth_results'));
  assert.equal(result.passed, false);
});

test('the oldest Authentication-Results header (closest to the true original sender) is authoritative, not a later re-stamp', () => {
  const headers = new Map<string, unknown>([
    ['authentication-results', ['internal-gateway.example.com; spf=fail; dkim=pass; dmarc=fail', 'mx.google.com; spf=pass; dkim=pass; dmarc=pass']],
  ]);
  // Wire order: newest hop first. A corporate gateway re-stamped its own
  // (failing) check for the internal forward *after* the true original
  // receiving server (Google, at the bottom/oldest position) had already
  // authenticated the actual sender cleanly.
  const headerLines = [
    { key: 'authentication-results', line: 'authentication-results: internal-gateway.example.com; spf=fail; dkim=pass; dmarc=fail' },
    { key: 'authentication-results', line: 'authentication-results: mx.google.com; spf=pass; dkim=pass; dmarc=pass' },
  ];

  const result = checkAuthentication(headers, headerLines);

  assert.equal(result.passed, true, 'the original delivering hop passed, so the message should read as authenticated');
  assert.equal(result.signals.some((s) => s.id === 'dmarc_fail'), false, 'a later re-stamp failing should not override the original pass');
  assert.ok(result.signals.some((s) => s.id === 'auth_fully_passed' && s.benign));
});

test('a forged old header cannot hide a real failure at the newest hop, when there is only one to trust', () => {
  // With a single Authentication-Results header, "oldest" and "newest" are
  // the same header — this just confirms a straightforward single-hop
  // failure is still reported.
  const value = 'mx.example.com; spf=fail; dkim=fail; dmarc=fail';
  const result = checkAuthentication(new Map<string, unknown>([['authentication-results', value]]), authResultsLine(value));
  assert.ok(result.signals.some((s) => s.id === 'dmarc_fail'));
});

test('a From domain that closely resembles a known brand is flagged, even with no links in the message', () => {
  const headers = new Map<string, unknown>([
    ['authentication-results', 'mx.example.com; spf=pass; dkim=pass; dmarc=pass'],
    ['from', 'support@paypa1.com'],
  ]);
  const result = checkAuthentication(headers, authResultsLine('mx.example.com; spf=pass; dkim=pass; dmarc=pass'));
  const found = result.signals.find((s) => s.id === 'sender_domain_typosquat');
  assert.ok(found, 'expected a sender-domain typosquat signal');
  assert.equal(found?.severity, 'high');
  assert.equal(found?.category, 'identity');
});

test('a From domain hyphenating a brand into an unrelated domain is flagged as impersonation, not typosquat', () => {
  const headers = new Map<string, unknown>([
    ['authentication-results', 'mx.example.com; spf=pass; dkim=pass; dmarc=pass'],
    ['from', 'security@secure-paypal-alerts.tk'],
  ]);
  const result = checkAuthentication(headers, authResultsLine('mx.example.com; spf=pass; dkim=pass; dmarc=pass'));
  assert.ok(result.signals.some((s) => s.id === 'sender_domain_brand_impersonation'));
  assert.equal(result.signals.some((s) => s.id === 'sender_domain_typosquat'), false, 'the two should be mutually exclusive');
});

test('a Reply-To that typosquats a brand is flagged even when From is unrelated and clean', () => {
  const headers = new Map<string, unknown>([
    ['authentication-results', 'mx.example.com; spf=pass; dkim=pass; dmarc=pass'],
    ['from', 'billing@acme-corp.com'],
    ['reply-to', 'support@paypa1.com'],
  ]);
  const result = checkAuthentication(headers, authResultsLine('mx.example.com; spf=pass; dkim=pass; dmarc=pass'));
  assert.ok(result.signals.some((s) => s.id === 'reply_to_domain_typosquat'));
});

test('a legitimate brand domain is never flagged as its own typosquat via From', () => {
  const headers = new Map<string, unknown>([
    ['authentication-results', 'mx.paypal.com; spf=pass; dkim=pass; dmarc=pass'],
    ['from', 'service@paypal.com'],
  ]);
  const result = checkAuthentication(headers, authResultsLine('mx.paypal.com; spf=pass; dkim=pass; dmarc=pass'));
  assert.equal(result.signals.some((s) => s.id === 'sender_domain_typosquat' || s.id === 'sender_domain_brand_impersonation'), false);
});

test('QR-derived links are reported as their own signal, distinct from the underlying URL risk', () => {
  const found = checkQrCodes(['https://evil-example.tk/pay']);
  assert.equal(found.signals[0].id, 'qr_code_link');
  assert.equal(found.signals[0].severity, 'low');
  assert.match(found.signals[0].detail, /evil-example\.tk/);

  assert.equal(checkQrCodes([]).signals.length, 0);
  assert.equal(checkQrCodes(undefined).signals.length, 0);
});

test('attachment extensions survive trailing dots and spaces', () => {
  for (const filename of ['invoice.exe', 'invoice.exe ', 'invoice.exe.']) {
    const signals = checkAttachments([{ filename, contentType: 'application/octet-stream', size: 1 }]).signals;
    assert.equal(signals.length, 1, `expected a signal for "${filename}"`);
    assert.equal(signals[0].severity, 'critical');
  }
});

test('attachment extensions survive a NUL byte, RTLO/zero-width characters, and an embedded path', () => {
  // \s never matches NUL/RTLO/zero-width characters, so any of these sitting
  // after the real extension used to make the trailing-character trim leave
  // them in place and the extension regex (anchored to the end of the
  // string) find nothing at all — silently dropping a critical finding down
  // to no finding whatsoever.
  // Built with String.fromCharCode rather than a literal embedded NUL byte,
  // so this source file itself stays plain text (a raw NUL makes some tools,
  // e.g. grep without -a, treat the whole file as binary).
  const cases = [
    'invoice.exe' + String.fromCharCode(0) + '.txt', // NUL then a benign extension — must resolve to what's *before* the NUL
    'payload.exe‮', // trailing RTLO
    'invoice.exe​', // trailing zero-width space
    'some/embedded/path/invoice.exe',
    'some\\windows\\path\\invoice.exe',
  ];
  for (const filename of cases) {
    const signals = checkAttachments([{ filename, contentType: 'application/octet-stream', size: 1 }]).signals;
    assert.equal(signals.length, 1, `expected a signal for ${JSON.stringify(filename)}`);
    assert.equal(signals[0].severity, 'critical', `expected critical severity for ${JSON.stringify(filename)}`);
  }
});

test('attachment types are categorized with proportionate severity', () => {
  const check = (filename: string) =>
    checkAttachments([{ filename, contentType: 'application/octet-stream', size: 1 }]).signals[0];

  assert.equal(check('invoice.pdf.exe').id, 'attachment_double_extension');
  assert.equal(check('setup.iso').id, 'attachment_disk_image');
  assert.equal(check('invoice.lnk').id, 'attachment_shortcut');
  assert.equal(check('budget.xlsm').id, 'attachment_macro_document');
  // An archive alone is weak evidence, not a finding on its own.
  assert.equal(check('documents.zip').severity, 'low');
  assert.equal(checkAttachments([{ filename: 'report.pdf', contentType: 'application/pdf', size: 1 }]).signals.length, 0);
});

test('dangerous attachments carry ATT&CK technique mappings', () => {
  const signals = checkAttachments([{ filename: 'invoice.pdf.exe', contentType: 'application/octet-stream', size: 1 }]).signals;
  assert.ok(signals[0].mitre?.includes('T1566.001'));
  assert.ok(signals[0].mitre?.includes('T1036.007'));
});

test('a benign extension declared as an executable MIME type is flagged', () => {
  const signals = checkAttachments([
    { filename: 'photo.jpg', contentType: 'application/x-msdownload', size: 1 },
  ]).signals;
  assert.ok(signals.some((s) => s.id === 'attachment_mime_extension_mismatch' && s.severity === 'high'));
});

test('an ordinary octet-stream declaration is not flagged as a mismatch', () => {
  // application/octet-stream is deliberately excluded from the executable set:
  // mail clients declare it constantly for attachments they don't recognize,
  // and treating it as suspicious would false-positive on routine mail.
  const signals = checkAttachments([
    { filename: 'photo.jpg', contentType: 'application/octet-stream', size: 1 },
  ]).signals;
  assert.equal(signals.filter((s) => s.id === 'attachment_mime_extension_mismatch').length, 0);
});

test('a genuinely image-typed attachment is not flagged', () => {
  const signals = checkAttachments([
    { filename: 'photo.jpg', contentType: 'image/jpeg', size: 1 },
  ]).signals;
  assert.equal(signals.filter((s) => s.id === 'attachment_mime_extension_mismatch').length, 0);
});

test('a file actually named .exe is caught by the executable check, not the mismatch check', () => {
  // BENIGN_EXTENSIONS and EXECUTABLE_EXTENSIONS never overlap by construction —
  // this proves the two checks don't double-fire on the same file.
  const signals = checkAttachments([
    { filename: 'invoice.exe', contentType: 'application/x-msdownload', size: 1 },
  ]).signals;
  assert.equal(signals.length, 1);
  assert.equal(signals[0].id, 'attachment_executable');
});

test('a ZIP whose directory listing names an executable is upgraded from a flat archive flag to critical', () => {
  const dangerous = checkAttachments([
    { filename: 'documents.zip', contentType: 'application/zip', size: 1, zipEntries: [{ filename: 'invoice.pdf.exe', uncompressedSize: 100 }] },
  ]).signals;
  assert.equal(dangerous.length, 1);
  assert.equal(dangerous[0].id, 'attachment_archive_contains_executable');
  assert.equal(dangerous[0].severity, 'critical');
  assert.match(dangerous[0].detail, /invoice\.pdf\.exe/);

  // No dangerous entries — falls back to the ordinary flat, low-severity flag.
  const clean = checkAttachments([
    { filename: 'documents.zip', contentType: 'application/zip', size: 1, zipEntries: [{ filename: 'readme.txt', uncompressedSize: 50 }] },
  ]).signals;
  assert.equal(clean[0].id, 'attachment_archive');
  assert.equal(clean[0].severity, 'low');

  // No listing at all (e.g. unreadable, or the .msg boundary) — same flat flag.
  const noListing = checkAttachments([{ filename: 'documents.zip', contentType: 'application/zip', size: 1 }]).signals;
  assert.equal(noListing[0].id, 'attachment_archive');
});

test('a disk image inside a ZIP is not treated as dangerous on its own', () => {
  // Two containers deep is a stretch — flagging "backup.zip contains
  // backup.dmg" would misfire on ordinary archives.
  const signals = checkAttachments([
    { filename: 'backup.zip', contentType: 'application/zip', size: 1, zipEntries: [{ filename: 'backup.dmg', uncompressedSize: 100 }] },
  ]).signals;
  assert.equal(signals[0].id, 'attachment_archive');
});

test('a ZIP entry name carrying an RTLO character is sanitized before it reaches the finding text', () => {
  // Real bytes: "invoice" + RTLO + "gnp.exe" — the classic trick: RTLO
  // reverses everything after it for *display* (making this render as
  // something ending in .png), while the underlying logical bytes actually
  // end in ".exe". extname() already correctly reads ".exe" off the logical
  // bytes regardless of the RTLO (it normalizes its own input), but the raw
  // name previously reached the signal's detail text unsanitized, where the
  // RTLO character would still visually reverse how it renders on screen.
  // This only tests that the detail text itself is clean, not the
  // (already-correct) detection.
  const rtloName = 'invoice‮gnp.exe';
  const signals = checkAttachments([
    { filename: 'documents.zip', contentType: 'application/zip', size: 1, zipEntries: [{ filename: rtloName, uncompressedSize: 10 }] },
  ]).signals;
  assert.equal(signals[0].id, 'attachment_archive_contains_executable');
  assert.doesNotMatch(signals[0].detail, /‮/, 'the RTLO character should not reach the detail text');
  assert.match(signals[0].detail, /invoicegnp\.exe/);
});

test('urgency severity scales with how many distinct phrases hit', () => {
  const one = checkContent('This is urgent.', null).signals.find((s) => s.id === 'urgency_language');
  assert.equal(one?.severity, 'low');

  const many = checkContent(
    'This is urgent. Your account will be suspended. Final notice. Act immediately.',
    null
  ).signals.find((s) => s.id === 'urgency_language');
  assert.equal(many?.severity, 'medium');
});

test('display name showing a different address than the real sender is flagged', () => {
  const signals = checkContent('Hello there.', '"support@paypal.com" <attacker@evil.tk>').signals;
  const spoof = signals.find((s) => s.id === 'display_name_address_spoof');
  assert.equal(spoof?.severity, 'high');
  assert.equal(spoof?.category, 'identity');
});

test('deceptive link text is high severity and empty input is silent', () => {
  const found = checkLinkText([
    { text: 'paypal.com', href: 'http://evil.tk', claimedDomain: 'paypal.com', actualDomain: 'evil.tk' },
  ]);
  assert.equal(found.signals[0].severity, 'high');
  assert.equal(checkLinkText([]).signals.length, 0);
  assert.equal(checkLinkText(undefined).signals.length, 0);
});

test('data:/javascript: link schemes are flagged, and absence is silent', () => {
  const dataLink = checkDangerousSchemes(['data']);
  assert.equal(dataLink.signals[0].id, 'dangerous_link_scheme');
  assert.equal(dataLink.signals[0].severity, 'high');
  assert.match(dataLink.signals[0].detail, /no hostname at all/);

  const both = checkDangerousSchemes(['data', 'javascript']);
  assert.equal(both.signals.length, 1, 'multiple schemes collapse into one signal');
  assert.match(both.signals[0].detail, /data\/javascript/);

  assert.equal(checkDangerousSchemes([]).signals.length, 0);
  assert.equal(checkDangerousSchemes(undefined).signals.length, 0);
});

test('sanitizeInput enforces its contract', () => {
  assert.throws(() => sanitizeInput('', 100), ValidationError);
  assert.throws(() => sanitizeInput('   ', 100), ValidationError);
  assert.throws(() => sanitizeInput(null, 100), ValidationError);
  assert.throws(() => sanitizeInput('x'.repeat(101), 100), ValidationError);
  assert.equal(sanitizeInput('a\x00b\r\nc', 100), 'ab\nc');
});

test('stripDangerousUnicode removes invisible and bidi-control characters', () => {
  assert.equal(stripDangerousUnicode('pay​pal.com'), 'paypal.com');
  assert.equal(stripDangerousUnicode('invoice‮gnp.exe'), 'invoicegnp.exe');
  assert.equal(stripDangerousUnicode(null), '');
});
