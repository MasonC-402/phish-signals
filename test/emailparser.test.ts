import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import QRCode from 'qrcode';
import { PNG } from 'pngjs';
import { encode as encodeJpeg } from 'jpeg-js';

import { parseEmail, findLinkMismatches, findDangerousSchemes, looksLikeRawEmail } from '../src/emailParser';

const MULTIPART = [
  'From: "PayPal Service" <service@paypa1-secure.tk>',
  'To: victim@example.com',
  'Subject: Your account has been limited',
  'MIME-Version: 1.0',
  'Content-Type: multipart/alternative; boundary="BOUND"',
  '',
  '--BOUND',
  'Content-Type: text/plain; charset=utf-8',
  '',
  'Hello, nothing to see here.',
  '',
  '--BOUND',
  'Content-Type: text/html; charset=utf-8',
  '',
  '<html><body><p>Please <a href="http://evil-paypa1.tk/login/verify">https://www.paypal.com/account</a> now.</p></body></html>',
  '',
  '--BOUND--',
  '',
].join('\r\n');

test('data: and javascript: link schemes are found and deduplicated', () => {
  const html = '<a href="data:text/html;base64,AAAA">click</a><a href="javascript:alert(1)">go</a><a href="data:text/html;base64,BBBB">again</a>';
  const schemes = findDangerousSchemes(html);
  assert.deepEqual(new Set(schemes), new Set(['data', 'javascript']));
});

test('ordinary http(s) links do not trip the dangerous-scheme check', () => {
  assert.deepEqual(findDangerousSchemes('<a href="https://example.com">a link</a>'), []);
  assert.deepEqual(findDangerousSchemes(null), []);
});

test('zero-width characters inserted mid-word no longer evade phrase matching', async () => {
  // Regression: scanText used to reach checkContent() completely unfiltered,
  // so an attacker inserting U+200B between letters defeated the plain
  // substring matching every content signal depends on.
  const salted = 'Please ver​ify your acc​ount immediately or it will be susp​ended.';
  const raw = `From: a@b.com\r\nSubject: Notice\r\n\r\n${salted}`;
  const parsed = await parseEmail(raw);

  assert.doesNotMatch(parsed.scanText, /​/);
  assert.match(parsed.scanText, /verify your account/);
  assert.match(parsed.scanText, /suspended/);
});

test('zero-width evasion is stripped on the plain-paste path too', async () => {
  const salted = 'ver​ify your acc​ount now';
  const parsed = await parseEmail(salted);
  assert.equal(parsed.isRawEmail, false);
  assert.doesNotMatch(parsed.scanText, /​/);
  assert.match(parsed.scanText, /verify your account/);
});

test('links present only in the HTML part are extracted', async () => {
  // Regression: extractUrls(textBody || htmlBody) meant that for any multipart
  // message with both parts — nearly all real mail — the HTML was never read.
  // A benign plaintext decoy beside a malicious HTML payload is the standard
  // phishing layout, and it scored zero.
  const parsed = await parseEmail(MULTIPART);
  assert.ok(parsed.isRawEmail);
  assert.ok(
    parsed.urls.some((u) => u.includes('evil-paypa1.tk')),
    `expected the HTML-only link to be extracted, got: ${JSON.stringify(parsed.urls)}`
  );
});

test('extracted URLs carry no trailing punctuation', async () => {
  const raw = [
    'From: sender@example.com',
    'Subject: Links',
    '',
    'See [http://example.com/a] and (http://example.com/b), plus http://example.com/c.',
    '',
  ].join('\r\n');

  const parsed = await parseEmail(raw);
  for (const url of parsed.urls) {
    assert.doesNotMatch(url, /[.,;:!?'")\]}>]$/, `trailing punctuation left on ${url}`);
  }
});

test('the subject line is included in the text scanned for phrases', async () => {
  const parsed = await parseEmail(MULTIPART);
  assert.match(parsed.scanText, /account has been limited/);
});

test('anchor text claiming one domain while linking to another is detected', () => {
  const mismatches = findLinkMismatches(
    '<a href="http://evil.tk/login">https://www.paypal.com/account</a>'
  );
  assert.equal(mismatches.length, 1);
  assert.equal(mismatches[0].claimedDomain, 'paypal.com');
  assert.equal(mismatches[0].actualDomain, 'evil.tk');
});

test('anchors are not flagged when text and href agree, or when text is not a URL', () => {
  assert.equal(findLinkMismatches('<a href="https://www.paypal.com/x">paypal.com</a>').length, 0);
  assert.equal(findLinkMismatches('<a href="https://mail.example.com/x">example.com</a>').length, 0);
  // "Click here" claims nothing, so there is nothing to contradict.
  assert.equal(findLinkMismatches('<a href="http://evil.tk/login">Click here</a>').length, 0);
});

test('header-block detection handles blocks that do not start with From', () => {
  // The old single-regex test only anchored on From/Received/Return-Path, so a
  // paste beginning with Delivered-To or Subject skipped every auth check.
  assert.equal(looksLikeRawEmail('Delivered-To: a@b.com\nSubject: Hi\n\nBody'), true);
  assert.equal(looksLikeRawEmail('Subject: Hi\nTo: a@b.com\n\nBody'), true);
  assert.equal(looksLikeRawEmail('From: a@b.com\n\nBody'), true);
});

test('a prose body that merely quotes a From: line is not treated as headers', async () => {
  const prose = 'Hi, I got this weird message today.\n\nFrom: someone@example.com\nIt looked fake.';
  assert.equal(looksLikeRawEmail(prose), false);

  const parsed = await parseEmail(prose);
  assert.equal(parsed.isRawEmail, false);
  assert.equal(parsed.headers, null);
});

// ── Attachment metadata and hashing ───────────────────────────────────────

function buildAttachmentEml(filename: string, payload: Buffer): string {
  return [
    'From: sender@example.com',
    'Subject: Attachment test',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="BOUND"',
    '',
    '--BOUND',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'See attached.',
    '',
    '--BOUND',
    `Content-Type: application/octet-stream; name="${filename}"`,
    `Content-Disposition: attachment; filename="${filename}"`,
    'Content-Transfer-Encoding: base64',
    '',
    payload.toString('base64'),
    '',
    '--BOUND--',
    '',
  ].join('\r\n');
}

test('attachment hashes are computed correctly for the .eml path', async () => {
  const payload = Buffer.from('hello world');
  const parsed = await parseEmail(buildAttachmentEml('greeting.txt', payload));

  assert.equal(parsed.attachments.length, 1);
  const file = parsed.attachments[0];

  // Computed independently here, rather than hardcoding expected hex digests,
  // so this can't pass on a transcription error matching a transcription error.
  assert.equal(file.md5, createHash('md5').update(payload).digest('hex'));
  assert.equal(file.sha1, createHash('sha1').update(payload).digest('hex'));
  assert.equal(file.sha256, createHash('sha256').update(payload).digest('hex'));
});

test('.msg-sourced attachments carry no hash, by design', async () => {
  // Regression guard for the property this whole feature depends on: .msg
  // attachment bytes are never read (see lib/msgParser.ts), so there must
  // never be a `content` buffer to hash for them, however this text gets
  // routed internally.
  const synthesized = 'From: "Sender" <a@b.com>\r\nSubject: test\r\n\r\nBody text here.';
  const extraAttachments = [{ filename: 'invoice.doc', contentType: 'application/msword', size: 1234 }];
  const parsed = await parseEmail(synthesized, extraAttachments);

  assert.equal(parsed.attachments.length, 1);
  assert.equal(parsed.attachments[0].sha256, undefined);
  assert.equal(parsed.attachments[0].md5, undefined);
  assert.equal(parsed.attachments[0].sha1, undefined);
});

test('regression: .msg attachment metadata reaches the output instead of vanishing', async () => {
  // msgToRawEmail's reconstructed text (real preserved headers, or a
  // synthesized From:/Subject: block) virtually always satisfies
  // looksLikeRawEmail(), which used to mean mailparser's own (always-empty,
  // for this synthetic text) attachment list silently replaced whatever
  // msgParser had actually found in the real .msg structure — every .msg
  // attachment disappeared before it ever reached the analyzer.
  const synthesized = 'From: "Sender" <a@b.com>\r\nSubject: test\r\n\r\nBody text here.';
  assert.equal(looksLikeRawEmail(synthesized), true, 'precondition: this text must look like a raw email for the regression to be meaningful');

  const extraAttachments = [
    { filename: 'invoice.exe', contentType: 'application/x-msdownload', size: 999 },
  ];
  const parsed = await parseEmail(synthesized, extraAttachments);
  assert.equal(parsed.attachments.length, 1);
  assert.equal(parsed.attachments[0].filename, 'invoice.exe');
});

test('the plain .eml/paste path is unaffected by the extraAttachments fallback', async () => {
  // No caller ever passes a second argument for this path, so it must keep
  // reading attachments from mailparser's own parse, same as always.
  const parsed = await parseEmail(buildAttachmentEml('report.txt', Buffer.from('data')));
  assert.equal(parsed.attachments.length, 1);
  assert.equal(parsed.attachments[0].filename, 'report.txt');
});

// ── QR code decoding ───────────────────────────────────────────────────────

function buildInlineImageEml(contentType: string, cid: string, payload: Buffer): string {
  return [
    'From: sender@example.com',
    'Subject: QR test',
    'MIME-Version: 1.0',
    'Content-Type: multipart/related; boundary="BOUND"',
    '',
    '--BOUND',
    'Content-Type: text/html; charset=utf-8',
    '',
    `<html><body><p>Scan to view your invoice.</p><img src="cid:${cid}"></body></html>`,
    '',
    '--BOUND',
    `Content-Type: ${contentType}`,
    `Content-Disposition: inline; filename="code.png"`,
    `Content-ID: <${cid}>`,
    'Content-Transfer-Encoding: base64',
    '',
    payload.toString('base64'),
    '',
    '--BOUND--',
    '',
  ].join('\r\n');
}

test('a QR code in an inline embedded image is decoded to a URL and folded into urls', async () => {
  const png = await QRCode.toBuffer('https://evil-qr-example.tk/pay?invoice=1', { type: 'png' });
  const parsed = await parseEmail(buildInlineImageEml('image/png', 'logo123', png));

  assert.equal(parsed.qrImagesScanned, 1);
  assert.deepEqual(parsed.qrCodeUrls, ['https://evil-qr-example.tk/pay?invoice=1']);
  assert.ok(parsed.urls.includes('https://evil-qr-example.tk/pay?invoice=1'), 'expected the QR URL to also appear in the general urls list');
});

test('a JPEG QR code is decoded too, not just PNG', async () => {
  // qrcode only encodes PNG/SVG directly, so build the JPEG by round-tripping
  // the same QR pixels through pngjs (decode) and jpeg-js (encode) — both
  // already project dependencies, and JPEG is lossy but a QR code's stark
  // black/white blocks survive it without issue.
  const png = await QRCode.toBuffer('https://example.com/jpeg-qr-test', { type: 'png' });
  const decoded = PNG.sync.read(png);
  const jpeg = encodeJpeg({ width: decoded.width, height: decoded.height, data: decoded.data }, 90).data;

  const parsed = await parseEmail(buildInlineImageEml('image/jpeg', 'pic1', jpeg));

  assert.equal(parsed.qrImagesScanned, 1);
  assert.deepEqual(parsed.qrCodeUrls, ['https://example.com/jpeg-qr-test']);
});

test('an ordinary image with no QR code scans clean, without error', async () => {
  // A genuine, valid, blank 4x4 white PNG — no QR content at all, built with
  // the same decoder library the tool ships (pngjs) rather than a hand-rolled
  // byte blob, so this can't accidentally test against a malformed fixture.
  const blank = new PNG({ width: 4, height: 4 });
  blank.data.fill(255);
  const png = PNG.sync.write(blank);

  const parsed = await parseEmail(buildInlineImageEml('image/png', 'plain1', png));

  assert.equal(parsed.qrImagesScanned, 1);
  assert.deepEqual(parsed.qrCodeUrls, []);
});

test('.msg-sourced images are never scanned for QR codes, same boundary as hashing', async () => {
  const synthesized = 'From: "Sender" <a@b.com>\r\nSubject: test\r\n\r\nBody text here.';
  const extraAttachments = [{ filename: 'photo.png', contentType: 'image/png', size: 500 }];
  const parsed = await parseEmail(synthesized, extraAttachments);

  assert.equal(parsed.qrImagesScanned, 0);
  assert.deepEqual(parsed.qrCodeUrls, []);
});

test('QR image scanning is bounded and does not run on a plain-text paste', async () => {
  const parsed = await parseEmail('Just some pasted prose with no headers at all in it.');
  assert.equal(parsed.isRawEmail, false);
  assert.equal(parsed.qrImagesScanned, 0);
  assert.deepEqual(parsed.qrCodeUrls, []);
});
