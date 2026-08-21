// The detection-engineering modules: delivery-path analysis, header anomalies,
// homograph decoding, and the analyst artifacts (IOCs, ATT&CK, Sigma).

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyzeReceivedChain, isPrivateIp } from '../src/receivedChain';
import { checkHeaderAnomalies } from '../src/headerAnomalies';
import { decodeHostname, decodeLabel, describeHostname, isWholeScriptConfusable } from '../src/punycode';
import { extractIocs, defang } from '../src/iocs';
import { mapTechniques } from '../src/mitre';
import { buildSigmaRule } from '../src/sigmaRule';
import { buildRecommendations } from '../src/recommendations';
import { buildJsonExport } from '../src/jsonExport';
import type { AuthCheckResult, CombinedResult, Signal, UrlAnalysis } from '../src/types';

const NO_AUTH: AuthCheckResult = { available: false, passed: false, signals: [], selectedAuthservId: null };

function authWith(...ids: string[]): AuthCheckResult {
  return {
    available: true,
    passed: false,
    signals: ids.map((id) => ({ id, category: 'authentication', severity: 'medium', label: id, detail: '' })),
    selectedAuthservId: null,
  };
}

// authserv_id_mismatch now reads auth.selectedAuthservId directly (the exact
// header authCheck.ts selected), rather than independently re-deriving it
// from headerLines — see lib/headerAnomalies.ts's comment on that check.
function authWithAuthservId(authservId: string | null): AuthCheckResult {
  return { available: true, passed: false, signals: [], selectedAuthservId: authservId };
}

function received(line: string) {
  return { key: 'received', line };
}

// ── Delivery path ──────────────────────────────────────────────────────────

test('the chain is ordered oldest hop first', () => {
  // Received headers are prepended at each hop, so the last one in the message
  // is chronologically the first.
  const chain = analyzeReceivedChain([
    received('Received: from relay2.example.com (relay2.example.com [2.2.2.2]) by mx.final.com; Mon, 10 Aug 2026 10:02:00 +0000'),
    received('Received: from origin.example.com (origin.example.com [1.1.1.1]) by relay2.example.com; Mon, 10 Aug 2026 10:00:00 +0000'),
  ]);

  assert.equal(chain.hops.length, 2);
  assert.equal(chain.hops[0].ip, '1.1.1.1');
  assert.equal(chain.originIp, '1.1.1.1');
  assert.equal(chain.originHost, 'origin.example.com');
});

test('a HELO name that disagrees with reverse DNS is flagged', () => {
  const chain = analyzeReceivedChain([
    received('Received: from paypal.com (evil-host.attacker.tk [45.9.1.2]) by mx.example.com; Mon, 10 Aug 2026 10:00:00 +0000'),
  ]);

  const mismatch = chain.signals.find((s) => s.id === 'helo_brand_impersonation');
  assert.ok(mismatch, 'expected a brand impersonation signal');
  assert.equal(mismatch.severity, 'high');
  assert.match(mismatch.detail, /evil-host\.attacker\.tk/);
  assert.equal(chain.hops[0].heloMismatch, true);
});

test('a non-brand HELO mismatch is weaker evidence than a brand one', () => {
  const chain = analyzeReceivedChain([
    received('Received: from mail.somehost.com (other.example.net [3.3.3.3]) by mx.example.com; Mon, 10 Aug 2026 10:00:00 +0000'),
  ]);
  const signal = chain.signals.find((s) => s.id === 'helo_rdns_mismatch');
  assert.equal(signal?.severity, 'medium');
});

test('a matching HELO and reverse DNS produces no mismatch', () => {
  const chain = analyzeReceivedChain([
    received('Received: from mail.example.com (mail.example.com [1.2.3.4]) by mx.google.com; Mon, 10 Aug 2026 10:00:00 +0000'),
    received('Received: from sender.example.com (out.example.com [1.2.3.5]) by mail.example.com; Mon, 10 Aug 2026 09:59:00 +0000'),
  ]);
  assert.equal(chain.signals.filter((s) => s.id.startsWith('helo_')).length, 0);
});

test('timestamps running backwards through the chain are flagged as forged', () => {
  const chain = analyzeReceivedChain([
    // Topmost (latest hop) is dated *before* the hop below it.
    received('Received: from b.example.com (b.example.com [2.2.2.2]) by mx.example.com; Mon, 10 Aug 2026 08:00:00 +0000'),
    received('Received: from a.example.com (a.example.com [1.1.1.1]) by b.example.com; Mon, 10 Aug 2026 12:00:00 +0000'),
  ]);

  const forged = chain.signals.find((s) => s.id === 'received_timestamp_regression');
  assert.ok(forged, 'expected a timestamp regression signal');
  assert.equal(forged.severity, 'high');
});

test('small clock skew between servers is tolerated', () => {
  const chain = analyzeReceivedChain([
    received('Received: from b.example.com (b.example.com [2.2.2.2]) by mx.example.com; Mon, 10 Aug 2026 10:00:00 +0000'),
    received('Received: from a.example.com (a.example.com [1.1.1.1]) by b.example.com; Mon, 10 Aug 2026 10:01:00 +0000'),
  ]);
  assert.equal(chain.signals.filter((s) => s.id === 'received_timestamp_regression').length, 0);
});

test('an empty or headerless message yields an empty chain, not an error', () => {
  const chain = analyzeReceivedChain([]);
  assert.deepEqual(chain.hops, []);
  assert.equal(chain.originIp, null);
  assert.equal(chain.signals.length, 0);
});

test('private address ranges are recognized', () => {
  for (const ip of ['10.0.0.1', '192.168.1.1', '172.16.5.4', '127.0.0.1', '169.254.1.1', '::1']) {
    assert.equal(isPrivateIp(ip), true, `${ip} should be private`);
  }
  for (const ip of ['8.8.8.8', '45.9.1.2', '172.32.0.1']) {
    assert.equal(isPrivateIp(ip), false, `${ip} should be public`);
  }
});

// ── Header anomalies ───────────────────────────────────────────────────────

test('a script-generated mailer is flagged', () => {
  const headers = new Map<string, unknown>([['x-mailer', 'PHPMailer 6.1.4']]);
  const result = checkHeaderAnomalies(headers, [{ key: 'x-mailer', line: 'X-Mailer: PHPMailer 6.1.4' }], null, NO_AUTH);
  assert.ok(result.signals.some((s) => s.id === 'script_generated_mail'));
});

test('a backdated Date header is caught against the delivery timestamps', () => {
  const chain = analyzeReceivedChain([
    received('Received: from a.example.com (a.example.com [1.1.1.1]) by mx.example.com; Mon, 10 Aug 2026 10:00:00 +0000'),
  ]);
  const headers = new Map<string, unknown>([
    ['from', 'a@example.com'],
    ['date', 'Mon, 01 Aug 2026 10:00:00 +0000'],
  ]);
  const result = checkHeaderAnomalies(headers, [{ key: 'date', line: 'Date: Mon, 01 Aug 2026 10:00:00 +0000' }], chain, NO_AUTH);
  assert.ok(result.signals.some((s) => s.id === 'date_header_skew'));
});

test('bulk-sender headers register as benign evidence', () => {
  const headers = new Map<string, unknown>([['from', 'news@example.com'], ['message-id', '<x@example.com>']]);
  const lines = [
    { key: 'list-unsubscribe', line: 'List-Unsubscribe: <mailto:x@example.com>' },
    { key: 'message-id', line: 'Message-ID: <x@example.com>' },
    { key: 'date', line: 'Date: Mon, 10 Aug 2026 10:00:00 +0000' },
  ];
  const result = checkHeaderAnomalies(headers, lines, null, NO_AUTH);
  const benign = result.signals.find((s) => s.id === 'bulk_sender_headers');
  assert.ok(benign?.benign);
});

test('a reply with real thread headers that fails authentication is flagged as hijacked', () => {
  // In-Reply-To/References are technical headers a real mail client generates
  // from an actual prior message. Plain phishing has no reason to fake thread
  // continuity, which is what makes this combination distinct from a bare
  // auth failure — reserved for HARD auth failures specifically (see below).
  const headers = new Map<string, unknown>([['subject', 'Re: Q3 budget numbers']]);
  const lines = [
    { key: 'subject', line: 'Subject: Re: Q3 budget numbers' },
    { key: 'in-reply-to', line: 'In-Reply-To: <abc123@example.com>' },
  ];
  const result = checkHeaderAnomalies(headers, lines, null, authWith('dmarc_fail'));
  assert.ok(result.signals.some((s) => s.id === 'thread_hijack_pattern' && s.severity === 'high'));
});

test('references header alone is enough, and fwd is recognized too', () => {
  const headers = new Map<string, unknown>([['subject', 'Fwd: Invoice']]);
  const lines = [
    { key: 'subject', line: 'Subject: Fwd: Invoice' },
    { key: 'references', line: 'References: <abc123@example.com> <def456@example.com>' },
  ];
  const result = checkHeaderAnomalies(headers, lines, null, authWith('spf_fail'));
  assert.ok(result.signals.some((s) => s.id === 'thread_hijack_pattern'));
});

test('a reply with thread headers that authenticates cleanly is not flagged', () => {
  // The whole point: this is not "replies are suspicious," it's "a message
  // claiming thread continuity that also fails to authenticate is."
  const headers = new Map<string, unknown>([['subject', 'Re: Q3 budget numbers']]);
  const lines = [
    { key: 'subject', line: 'Subject: Re: Q3 budget numbers' },
    { key: 'in-reply-to', line: 'In-Reply-To: <abc123@example.com>' },
  ];
  const result = checkHeaderAnomalies(headers, lines, null, NO_AUTH);
  assert.equal(result.signals.filter((s) => s.id === 'thread_hijack_pattern').length, 0);

  const passing = checkHeaderAnomalies(headers, lines, null, authWith('auth_fully_passed'));
  assert.equal(passing.signals.filter((s) => s.id === 'thread_hijack_pattern').length, 0);
});

test('a reply-looking subject with no thread headers is not flagged, even if auth fails', () => {
  // Someone can type "Re:" by hand with nothing behind it. Without the
  // technical headers a real client generates, this is indistinguishable from
  // ordinary phishing and shouldn't get the stronger "hijacked thread" label.
  const headers = new Map<string, unknown>([['subject', 'Re: your invoice']]);
  const lines = [{ key: 'subject', line: 'Subject: Re: your invoice' }];
  const result = checkHeaderAnomalies(headers, lines, null, authWith('dmarc_fail'));
  assert.equal(result.signals.filter((s) => s.id === 'thread_hijack_pattern').length, 0);
});

test('thread headers on a non-reply subject are not flagged', () => {
  const headers = new Map<string, unknown>([['subject', 'New quarterly numbers']]);
  const lines = [
    { key: 'subject', line: 'Subject: New quarterly numbers' },
    { key: 'references', line: 'References: <abc123@example.com>' },
  ];
  const result = checkHeaderAnomalies(headers, lines, null, authWith('dmarc_fail'));
  assert.equal(result.signals.filter((s) => s.id === 'thread_hijack_pattern').length, 0);
});

test('a soft auth signal alone does not trigger the thread-hijack pattern', () => {
  // SPF softfail / no-DMARC-policy are common on ordinary mail and would make
  // this fire constantly if they counted; only the hard-failure ids do.
  const headers = new Map<string, unknown>([['subject', 'Re: Q3 budget numbers']]);
  const lines = [
    { key: 'subject', line: 'Subject: Re: Q3 budget numbers' },
    { key: 'in-reply-to', line: 'In-Reply-To: <abc123@example.com>' },
  ];
  const result = checkHeaderAnomalies(headers, lines, null, authWith('spf_softfail', 'dmarc_none'));
  assert.equal(result.signals.filter((s) => s.id === 'thread_hijack_pattern').length, 0);
});

test('an Authentication-Results claiming a different server than actually delivered it is flagged', () => {
  // selectedAuthservId is what authCheck.ts actually selected, not something
  // this check re-derives from headerLines itself — see its own comment.
  const chain = analyzeReceivedChain([
    received('Received: from sender.example.com (sender.example.com [1.1.1.1]) by mail.corp-example.com; Mon, 10 Aug 2026 10:00:00 +0000'),
  ]);
  const result = checkHeaderAnomalies(new Map(), [], chain, authWithAuthservId('totally-unrelated-host.tk'));
  const signal = result.signals.find((s) => s.id === 'authserv_id_mismatch');
  assert.ok(signal, 'expected an authserv-id mismatch signal');
  assert.equal(signal.severity, 'medium');
  assert.match(signal.detail, /totally-unrelated-host\.tk/);
  assert.match(signal.detail, /mail\.corp-example\.com/);
});

test('an Authentication-Results header matching the actual delivering server is not flagged', () => {
  const chain = analyzeReceivedChain([
    received('Received: from sender.example.com (sender.example.com [1.1.1.1]) by mx.google.com; Mon, 10 Aug 2026 10:00:00 +0000'),
  ]);
  const result = checkHeaderAnomalies(new Map(), [], chain, authWithAuthservId('mx.google.com'));
  assert.equal(result.signals.filter((s) => s.id === 'authserv_id_mismatch').length, 0);
});

test('authserv-id at the same organization, different internal hostname, is not flagged', () => {
  // Comparison is at the registrable-domain level specifically so ordinary
  // internal routing-hostname differences within one organization don't misfire.
  const chain = analyzeReceivedChain([
    received('Received: from sender.example.com (sender.example.com [1.1.1.1]) by mail-sor-f41.google.com; Mon, 10 Aug 2026 10:00:00 +0000'),
  ]);
  const result = checkHeaderAnomalies(new Map(), [], chain, authWithAuthservId('mx.google.com'));
  assert.equal(result.signals.filter((s) => s.id === 'authserv_id_mismatch').length, 0);
});

test('the mismatch check validates the origin hop, not the most recent one, since selectedAuthservId represents the oldest surviving header', () => {
  // Two real hops: Google received it first (origin), an internal gateway
  // relayed it onward second (most recent). The selected authserv-id
  // corresponds to Google's own stamp, so it must be checked against
  // Google's hop specifically — checking it against the internal gateway
  // instead would misfire on every ordinary multi-hop forward.
  const chain = analyzeReceivedChain([
    received('Received: from mail-gateway.corp-example.com (mail-gateway.corp-example.com [10.10.4.12]) by mx.corp-example.com; Mon, 10 Aug 2026 15:31:00 +0000'),
    received('Received: from sender.example.com (sender.example.com [1.1.1.1]) by mx.google.com; Mon, 10 Aug 2026 15:30:00 +0000'),
  ]);
  const result = checkHeaderAnomalies(new Map(), [], chain, authWithAuthservId('mx.google.com'));
  assert.equal(result.signals.filter((s) => s.id === 'authserv_id_mismatch').length, 0);
});

test('no delivery chain to cross-reference against means no mismatch signal', () => {
  // A partial paste with headers but no Received lines shouldn't be treated
  // as evidence of forgery — there is nothing here to corroborate against,
  // which is a different (and already-covered, via confidence) situation
  // than an actual contradiction.
  const result = checkHeaderAnomalies(new Map(), [], null, authWithAuthservId('totally-unrelated-host.tk'));
  assert.equal(result.signals.filter((s) => s.id === 'authserv_id_mismatch').length, 0);
});

// ── Homograph decoding ─────────────────────────────────────────────────────

test('punycode decoding round-trips against the URL parser', () => {
  for (const unicodeHost of ['pаypal.com', 'аррӏе.com', 'münchen.de', '日本語.jp', 'москва.рф']) {
    const puny = new URL(`https://${unicodeHost}`).hostname;
    assert.equal(decodeHostname(puny), unicodeHost.normalize('NFC'), `round-trip failed for ${unicodeHost}`);
  }
});

test('malformed punycode is rejected rather than decoded to nonsense', () => {
  // Bounds have to be checked on both ends: the reference C implementation
  // relies on unsigned wraparound, which in JS lets characters below '0'
  // through as negative digit values.
  for (const bad of ['!!!!', '$$', 'ab!!cd', ' ']) {
    assert.equal(decodeLabel(bad), null, `expected null for ${JSON.stringify(bad)}`);
  }
});

test('mixed-script and whole-script confusables are both detected', () => {
  // One Cyrillic character substituted into a Latin word.
  const mixed = describeHostname('xn--pypal-4ve.com');
  assert.equal(mixed.decoded, 'pаypal.com');
  assert.equal(mixed.mixed, true);

  // Entirely Cyrillic, so not mixed at all — a mixed-script test alone would
  // miss this, and it is the best-known homograph demonstration there is.
  const whole = describeHostname('xn--80ak6aa92e.com');
  assert.equal(whole.decoded, 'аррӏе.com');
  assert.equal(whole.mixed, false);
  assert.equal(whole.confusable, true);
});

test('legitimate internationalized domains are not flagged', () => {
  for (const host of ['xn--mnchen-3ya.de', 'xn--wgv71a119e.jp', 'xn--80adxhks.xn--p1ai']) {
    const described = describeHostname(host);
    assert.equal(described.mixed, false, `${host} should not be mixed-script`);
    assert.equal(described.confusable, false, `${host} should not be confusable`);
  }
  assert.equal(isWholeScriptConfusable('münchen'), false);
});

// ── Analyst artifacts ──────────────────────────────────────────────────────

test('indicators are defanged so nothing pasted becomes a live link', () => {
  assert.equal(defang('http://evil.tk/login'), 'hxxp://evil[.]tk/login');
  assert.equal(defang('https://a.b.com/x'), 'hxxps://a[.]b[.]com/x');
  assert.equal(defang('user@evil.tk'), 'user[@]evil[.]tk');
  assert.equal(defang('45.9.1.2'), '45[.]9[.]1[.]2');
});

test('only risky links become indicators', () => {
  const urls: UrlAnalysis[] = [
    { url: 'http://evil.tk/login', hostname: 'evil.tk', risk: 'malicious', detail: '' },
    { url: 'https://www.google.com/', hostname: 'www.google.com', risk: 'clean', detail: '' },
  ];
  const iocs = extractIocs({
    urls,
    attachments: [{ filename: 'invoice.exe', contentType: 'application/octet-stream', size: 1 }],
    chain: null,
    from: '"Evil" <sender@evil.tk>',
    replyTo: null,
    returnPath: null,
  });

  const values = iocs.map((i) => i.value);
  assert.ok(values.includes('http://evil.tk/login'));
  assert.ok(values.includes('sender@evil.tk'));
  assert.ok(values.includes('invoice.exe'));
  assert.ok(!values.includes('https://www.google.com/'), 'clean links are not indicators');
});

test('attachment hashes become indicators, one per algorithm present', () => {
  const iocs = extractIocs({
    urls: [],
    attachments: [{
      filename: 'invoice.pdf.exe',
      contentType: 'application/octet-stream',
      size: 1,
      md5: 'aaaa', sha1: 'bbbb', sha256: 'cccc',
    }],
    chain: null,
    from: null,
    replyTo: null,
    returnPath: null,
  });

  const hashes = iocs.filter((i) => i.type === 'hash').map((i) => i.value);
  assert.deepEqual(new Set(hashes), new Set(['aaaa', 'bbbb', 'cccc']));
  // A hex digest has no dots/scheme/@ to break, so defanging it is a no-op —
  // confirms that behavior rather than assuming it.
  for (const h of iocs.filter((i) => i.type === 'hash')) {
    assert.equal(h.defanged, h.value);
  }
});

test('an attachment with no hash (the .msg path) produces no hash indicator', () => {
  const iocs = extractIocs({
    urls: [],
    attachments: [{ filename: 'invoice.doc', contentType: 'application/msword', size: 1 }],
    chain: null,
    from: null,
    replyTo: null,
    returnPath: null,
  });
  assert.equal(iocs.filter((i) => i.type === 'hash').length, 0);
});

test('ATT&CK techniques are deduplicated and resolved to names and links', () => {
  const signals: Signal[] = [
    { id: 'a', category: 'payload', severity: 'high', label: 'a', detail: '', mitre: ['T1566.002', 'T1204.001'] },
    { id: 'b', category: 'payload', severity: 'high', label: 'b', detail: '', mitre: ['T1566.002'] },
    { id: 'c', category: 'social', severity: 'low', label: 'c', detail: '', mitre: ['T9999'] },
  ];
  const techniques = mapTechniques(signals);

  assert.equal(techniques.length, 2, 'unknown technique ids are dropped');
  const link = techniques.find((t) => t.id === 'T1566.002');
  assert.equal(link?.name, 'Phishing: Spearphishing Link');
  // Sub-techniques live under /TXXXX/YYY/, not /TXXXX.YYY/.
  assert.equal(link?.url, 'https://attack.mitre.org/techniques/T1566/002/');
});

test('the Sigma rule contains the observed indicators and is labelled experimental', () => {
  const rule = buildSigmaRule({
    subject: 'Overdue invoice payment required',
    senderDomain: 'invoice-update.tk',
    replyToDomain: null,
    urls: [{ url: 'http://invoice-update.tk/login', hostname: 'invoice-update.tk', risk: 'malicious', detail: '' }],
    attachments: [{ filename: 'invoice.pdf.exe', contentType: 'application/octet-stream', size: 1 }],
    signals: [{ id: 'x', category: 'payload', severity: 'critical', label: 'x', detail: '', mitre: ['T1566.001'] }],
    verdict: 'High Risk',
    score: 88,
  });

  assert.match(rule, /status: experimental/);
  assert.match(rule, /STARTING POINT, NOT A FINISHED RULE/);
  assert.match(rule, /'@invoice-update\.tk'/);
  assert.match(rule, /'invoice-update\.tk'/);
  assert.match(rule, /'\.exe'/);
  assert.match(rule, /attack\.t1566\.001/);
  assert.match(rule, /level: high/);
  assert.match(rule, /condition: .*sender_domain/);
});

test('an attachment hash produces a high-confidence Sigma selection', () => {
  const rule = buildSigmaRule({
    subject: null,
    senderDomain: null,
    replyToDomain: null,
    urls: [],
    attachments: [{
      filename: 'invoice.pdf.exe',
      contentType: 'application/octet-stream',
      size: 1,
      md5: 'aaaa', sha1: 'bbbb',
      sha256: 'c'.repeat(64),
    }],
    signals: [],
    verdict: 'High Risk',
    score: 90,
  });

  assert.match(rule, /attachment_hash\|contains:/);
  assert.match(rule, new RegExp(`'${'c'.repeat(64)}'`));
  assert.match(rule, /condition: .*attachment_hash/);
});

test('no attachment_hash selection appears when no attachment has one', () => {
  const rule = buildSigmaRule({
    subject: null,
    senderDomain: 'evil.tk',
    replyToDomain: null,
    urls: [],
    attachments: [{ filename: 'invoice.exe', contentType: 'application/octet-stream', size: 1 }],
    signals: [],
    verdict: 'High Risk',
    score: 90,
  });
  // "attachment_hash" as a word still appears in the boilerplate header
  // comment (it's always listed as a mappable field name); what must be
  // absent is the actual selection block and its entry in the condition.
  assert.doesNotMatch(rule, /attachment_hash\|contains:/);
  assert.doesNotMatch(rule, /condition: .*attachment_hash/);
});

test('no rule is emitted when nothing distinctive was observed', () => {
  const rule = buildSigmaRule({
    subject: null,
    senderDomain: null,
    replyToDomain: null,
    urls: [],
    attachments: [],
    signals: [],
    verdict: 'Low Risk',
    score: 0,
  });
  assert.match(rule, /No indicator in this message was distinctive enough/);
  assert.doesNotMatch(rule, /^title:/m);
});

test('a YAML-breaking subject cannot escape the generated rule', () => {
  const rule = buildSigmaRule({
    subject: "quote' and\nnewline: injected",
    senderDomain: "evil'.tk",
    replyToDomain: null,
    urls: [],
    attachments: [],
    signals: [],
    verdict: 'High Risk',
    score: 70,
  });

  // Single quotes are doubled, per YAML's own escaping rule.
  assert.match(rule, /'@evil''\.tk'/);

  // The newline is collapsed rather than carried into the document, so the
  // attacker-controlled text cannot start a line that reads as a new YAML key.
  const titleLine = rule.split('\n').find((line) => line.startsWith('title:'));
  assert.ok(titleLine, 'expected a title line');
  // Quoted scalar with the inner quote doubled, and the newline collapsed, so
  // the attacker-controlled subject can neither start a new line that reads as
  // a YAML key nor make the title itself parse as a nested mapping.
  assert.match(titleLine, /^title: '.*quote'' and newline: injected.*'$/);
  assert.equal(rule.split('\n').filter((line) => /^newline:/.test(line)).length, 0);
});

test('the generated rule is parseable YAML for every field we control', () => {
  const rule = buildSigmaRule({
    subject: 'Re: URGENT: wire transfer: confirm now',
    senderDomain: 'evil.tk',
    replyToDomain: 'other.tk',
    urls: [{ url: 'http://evil.tk/a', hostname: 'evil.tk', risk: 'malicious', detail: '' }],
    attachments: [{ filename: 'x.exe', contentType: 'application/octet-stream', size: 1 }],
    signals: [],
    verdict: 'High Risk',
    score: 90,
  });

  // Every top-level key sits at column 0 and every value line is indented;
  // a subject full of colons must not produce a stray top-level key.
  const topLevelKeys = rule
    .split('\n')
    .filter((line) => /^[a-z_]+:/.test(line))
    .map((line) => line.split(':')[0]);

  assert.deepEqual(
    topLevelKeys,
    ['title', 'id', 'status', 'description', 'author', 'date', 'logsource', 'detection', 'falsepositives', 'level']
  );
});

// ── Recommendations ────────────────────────────────────────────────────────

test('credential-phishing findings produce the password-reset action first', () => {
  const actions = buildRecommendations({
    verdict: 'High Risk',
    signals: [{ id: 'credential_request', category: 'social', severity: 'medium', label: '', detail: '' }],
    authAvailable: true,
  });

  assert.equal(actions[0].urgency, 'now');
  assert.match(actions[0].text, /Do not click/);
  assert.ok(actions.some((a) => /change that password now/.test(a.text)));
  assert.ok(actions.some((a) => /multi-factor/.test(a.text)));
});

test('an attachment finding produces the disconnect-the-machine action', () => {
  const actions = buildRecommendations({
    verdict: 'High Risk',
    signals: [{ id: 'attachment_executable', category: 'payload', severity: 'critical', label: '', detail: '' }],
    authAvailable: true,
  });
  assert.ok(actions.some((a) => /disconnect the machine/i.test(a.text)));
});

test('a clean result still tells the reader what the tool cannot know', () => {
  const actions = buildRecommendations({ verdict: 'Low Risk', signals: [], authAvailable: true });
  assert.ok(actions.every((a) => a.urgency === 'context'));
  assert.ok(actions.some((a) => /verify it through a second channel/.test(a.text)));
});

test('a headerless submission is told how to get a better answer', () => {
  const actions = buildRecommendations({ verdict: 'Low Risk', signals: [], authAvailable: false });
  assert.ok(actions.some((a) => /Show original/.test(a.text)));
});

// ── JSON export ────────────────────────────────────────────────────────────

function minimalResult(): CombinedResult {
  return {
    score: 42,
    verdict: 'Medium Risk',
    confidence: { level: 'high', completeness: 1, gaps: [] },
    signals: [{ id: 'x', category: 'payload', severity: 'high', label: 'X', detail: 'detail' }],
    benignSignals: [],
    categories: [],
    urls: [],
    recommendations: [{ urgency: 'now', text: 'do a thing' }],
    mitre: [],
    iocs: [{ type: 'domain', value: 'evil.tk', defanged: 'evil[.]tk' }],
    sigmaRule: 'title: x\n',
    kqlQuery: 'union isfuzzy=true\n',
    authAvailable: true,
    authPassed: false,
  };
}

test('the JSON export round-trips through JSON.parse with the same values', () => {
  const result = minimalResult();
  const parsed = JSON.parse(buildJsonExport(result));

  assert.equal(parsed.score, 42);
  assert.equal(parsed.verdict, 'Medium Risk');
  assert.equal(parsed.signals[0].id, 'x');
  assert.equal(parsed.iocs[0].value, 'evil.tk');
});

test('the JSON export does not embed itself', () => {
  // jsonReport is assigned onto `result` by the caller only *after* this
  // function runs (see routes/phish-report.ts) — this proves the export
  // produced here never ends up nesting a copy of itself regardless of when
  // it's called relative to that assignment.
  const result = minimalResult();
  result.jsonReport = 'PLACEHOLDER';
  const parsed = JSON.parse(buildJsonExport(result));
  assert.equal('jsonReport' in parsed, false);
});
