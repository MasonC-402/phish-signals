// End-to-end tests for combineResults — the assembly point that runs every
// check's output through scoring and builds the analyst artifacts — plus the
// package's "no network calls" guarantee, enforced rather than just stated.
//
// Mirrors python/tests/test_combine_results.py, which exercises the same
// pipeline through real parser and check outputs rather than hand-built
// stubs, since this module's whole job is wiring those together correctly.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';

import {
  analyzeReceivedChain,
  checkAttachments,
  checkAuthentication,
  checkContent,
  checkDangerousSchemes,
  checkHeaderAnomalies,
  checkLinkText,
  checkQrCodes,
  checkUrls,
  combineResults,
  parseEmail,
  summarizeUrlSignals,
} from '../src/index';
import type { CombinedResult } from '../src/index';

// ── No network: any attempt during this file's tests throws ──────────────
// node --test runs each file in its own process, so patching these globals
// here can't leak into the other test files.
const networkAttempts: string[] = [];
const restore: (() => void)[] = [];

function block(target: object, key: string, label: string): void {
  const holder = target as Record<string, unknown>;
  const original = holder[key];
  holder[key] = (...args: unknown[]) => {
    networkAttempts.push(`${label}(${String(args[0])})`);
    throw new Error(`network access attempted: ${label}`);
  };
  restore.push(() => {
    holder[key] = original;
  });
}

before(() => {
  block(net.Socket.prototype, 'connect', 'net.Socket.connect');
  block(net, 'connect', 'net.connect');
  block(net, 'createConnection', 'net.createConnection');
  block(tls, 'connect', 'tls.connect');
  block(dns, 'lookup', 'dns.lookup');
  block(dns, 'resolve', 'dns.resolve');
  block(dns.promises, 'lookup', 'dns.promises.lookup');
  block(dns.promises, 'resolve', 'dns.promises.resolve');
  block(http, 'request', 'http.request');
  block(http, 'get', 'http.get');
  block(https, 'request', 'https.request');
  block(https, 'get', 'https.get');
  block(globalThis, 'fetch', 'fetch');
});

after(() => {
  for (const undo of restore.reverse()) undo();
});

async function runPipeline(raw: string): Promise<CombinedResult> {
  const parsed = await parseEmail(raw);
  const auth = checkAuthentication(parsed.headers, parsed.headerLines);
  const urls = checkUrls(parsed.urls);
  const chain = parsed.isRawEmail ? analyzeReceivedChain(parsed.headerLines) : null;
  return combineResults({
    parsed,
    auth,
    urls,
    urlSignals: summarizeUrlSignals(urls),
    content: checkContent(parsed.textBody, parsed.from),
    linkText: checkLinkText(parsed.linkMismatches),
    dangerousSchemes: checkDangerousSchemes(parsed.dangerousSchemes),
    qrCodes: checkQrCodes(parsed.qrCodeUrls),
    attachments: checkAttachments(parsed.attachments),
    chain,
    headerAnomalies: checkHeaderAnomalies(parsed.headers, parsed.headerLines, chain, auth),
  });
}

const PHISH = [
  'From: "PayPal Security" <security@paypa1-secure.com>',
  'Reply-To: reply@paypa1-secure.com',
  'Subject: Urgent: Verify your account now',
  'Date: Mon, 1 Jan 2024 10:00:00 +0000',
  'Message-ID: <1@paypa1-secure.com>',
  'Received: from paypa1-secure.com (unknown [10.0.0.1]) by mx.example.org; Mon, 1 Jan 2024 10:00:05 +0000',
  'Authentication-Results: mx.example.org; spf=fail; dkim=fail; dmarc=fail',
  'Content-Type: text/html',
  '',
  '<html><body>Dear customer, please verify your account urgently: ' +
    '<a href="http://paypa1-secure.com/verify">https://paypal.com/account</a>. ' +
    'Also http://192.168.0.1/login.php and https://bit.ly/3abc. ' +
    'CLICK NOW OR YOUR ACCOUNT WILL BE SUSPENDED IMMEDIATELY TODAY ONLY LAST CHANCE.' +
    '</body></html>',
  '',
].join('\r\n');

test('a plain pasted note is low risk with no header-derived evidence', async () => {
  const result = await runPipeline("Hi, just checking in about tomorrow's meeting.");
  assert.equal(result.verdict, 'Low Risk');
  assert.equal(result.authAvailable, false);
  assert.equal(result.receivedChain, null);
  assert.equal(result.confidence.level, 'low');
});

test('a phishing-style message scores High Risk and gets every analyst artifact', async () => {
  const result = await runPipeline(PHISH);
  assert.equal(result.verdict, 'High Risk');
  assert.ok(result.score >= 60, `score ${result.score}`);
  assert.equal(result.authAvailable, true);
  assert.equal(result.authPassed, false);

  const ids = new Set(result.signals.map((s) => s.id));
  for (const id of ['dmarc_fail', 'deceptive_link_text', 'urgency_language', 'display_name_brand_spoof']) {
    assert.ok(ids.has(id), `expected ${id} among ${[...ids].join(', ')}`);
  }

  assert.ok(result.mitre.length > 0);
  assert.ok(result.iocs.some((i) => i.type === 'email' && i.value === 'security@paypa1-secure.com'));
  assert.ok(result.iocs.some((i) => i.type === 'url' && i.value === 'http://192.168.0.1/login.php'));
  assert.ok(result.iocs.some((i) => i.type === 'ip' && i.value === '10.0.0.1'));
  assert.match(result.sigmaRule, /paypa1-secure\.com/);
  assert.match(result.kqlQuery, /paypa1-secure\.com/);
  assert.ok(result.recommendations.length > 0);
  assert.ok(result.categories.length >= 3, 'evidence should span several categories');
});

test('an executable link surfaces as payload evidence and as a url IOC', async () => {
  const result = await runPipeline(
    ['From: attacker@evil-domain.tk', 'Subject: test', '', 'Click http://evil-domain.tk/malware.exe now.', ''].join('\r\n'),
  );
  assert.ok(result.categories.some((c) => c.category === 'payload'));
  assert.ok(result.iocs.some((i) => i.type === 'url' && i.value.endsWith('/malware.exe')));
});

test('the full pipeline makes no network calls', async () => {
  networkAttempts.length = 0;
  await runPipeline(PHISH);
  assert.deepEqual(networkAttempts, []);
  // And the guard itself works — otherwise an empty list proves nothing.
  assert.throws(() => dns.lookup('example.com', () => {}), /network access attempted/);
  networkAttempts.length = 0;
});
