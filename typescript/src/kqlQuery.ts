// Microsoft 365 Defender / Microsoft Sentinel Advanced Hunting KQL generation.
//
// Same payoff as lib/sigmaRule.ts — turn a set of indicators into a reusable
// hunting artifact — but for Advanced Hunting specifically rather than a
// generic SIEM. Unlike Sigma, which deliberately uses made-up field names
// because email telemetry isn't standardized across platforms, this targets
// Microsoft's own documented Advanced Hunting schema directly: the table and
// column names below (EmailEvents, EmailUrlInfo, EmailAttachmentInfo,
// UrlClickEvents, DeviceNetworkEvents, DeviceFileEvents) are real and stable,
// so the output is meant to be pasted and run as-is, not translated first.
//
// Takes the same Ioc[] shape lib/iocs.ts's extractIocs() already produces
// (from an analyzed email) or its parseIocText() produces (from freeform
// pasted text) — one generator serves both the phish-report pipeline
// integration and the standalone /tools/kql-builder tool.

import type { Ioc } from './types';

interface KqlOptions {
  /** How far back each subquery looks. Defaults to 30 days. */
  lookbackDays?: number;
}

/** Quotes a KQL string literal and never lets a value break out of it. */
function kqlString(value: string): string {
  const cleaned = value.replace(/[\r\n]+/g, ' ').trim();
  return `"${cleaned.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function kqlArray(name: string, values: string[]): string {
  return `let ${name} = dynamic([${values.map(kqlString).join(', ')}]);`;
}

function uniqueValues(iocs: Ioc[], type: Ioc['type']): string[] {
  return [...new Set(iocs.filter((i) => i.type === type).map((i) => i.value))];
}

function buildKqlQuery(iocs: Ioc[], options: KqlOptions = {}): string {
  const lookbackDays = options.lookbackDays ?? 30;

  const domains = uniqueValues(iocs, 'domain');
  const urls = uniqueValues(iocs, 'url');
  const ips = uniqueValues(iocs, 'ip');
  const emails = uniqueValues(iocs, 'email');
  const hashes = uniqueValues(iocs, 'hash');
  const filenames = uniqueValues(iocs, 'filename');

  if (domains.length + urls.length + ips.length + emails.length + hashes.length + filenames.length === 0) {
    return [
      '// No indicator here was concrete enough to hunt on — nothing emitted',
      '// rather than a query that would just union in every row from every table.',
      '',
    ].join('\n');
  }

  const letLines: string[] = [`let Lookback = ${lookbackDays}d;`];
  const blocks: string[] = [];

  if (domains.length || emails.length) {
    if (domains.length) letLines.push(kqlArray('SuspectDomains', domains));
    if (emails.length) letLines.push(kqlArray('SuspectSenders', emails));
    const conditions: string[] = [];
    if (domains.length) conditions.push('SenderFromAddress has_any (SuspectDomains)');
    if (emails.length) conditions.push('SenderFromAddress in~ (SuspectSenders)');
    blocks.push(
      [
        '(',
        '    EmailEvents',
        '    | where Timestamp > ago(Lookback)',
        `    | where ${conditions.join(' or ')}`,
        '    | extend MatchedOn = "sender", MatchedTable = "EmailEvents"',
        ')',
      ].join('\n')
    );
  }

  if (urls.length || domains.length) {
    if (urls.length) letLines.push(kqlArray('SuspectUrls', urls));
    const conditions: string[] = [];
    if (urls.length) conditions.push('Url in~ (SuspectUrls)');
    if (domains.length) conditions.push('UrlDomain has_any (SuspectDomains)');
    blocks.push(
      [
        '(',
        '    EmailUrlInfo',
        '    | where Timestamp > ago(Lookback)',
        `    | where ${conditions.join(' or ')}`,
        '    | extend MatchedOn = "url", MatchedTable = "EmailUrlInfo"',
        ')',
      ].join('\n'),
      [
        '(',
        // Safe Links click telemetry — separate from EmailUrlInfo (what the
        // message contained) because this is "did anyone actually click it,"
        // a materially different and higher-signal question.
        '    UrlClickEvents',
        '    | where Timestamp > ago(Lookback)',
        `    | where ${conditions.join(' or ')}`,
        '    | extend MatchedOn = "url_click", MatchedTable = "UrlClickEvents"',
        ')',
      ].join('\n')
    );
  }

  if (hashes.length || filenames.length) {
    if (hashes.length) letLines.push(kqlArray('SuspectHashes', hashes));
    if (filenames.length) letLines.push(kqlArray('SuspectFilenames', filenames));
    const conditions: string[] = [];
    if (hashes.length) conditions.push('SHA256 in (SuspectHashes)');
    if (filenames.length) conditions.push('FileName in~ (SuspectFilenames)');
    blocks.push(
      [
        '(',
        '    EmailAttachmentInfo',
        '    | where Timestamp > ago(Lookback)',
        `    | where ${conditions.join(' or ')}`,
        '    | extend MatchedOn = "attachment", MatchedTable = "EmailAttachmentInfo"',
        ')',
      ].join('\n'),
      // Endpoint tables — whether these indicators showed up beyond the
      // mailbox, i.e. an attachment that was actually opened/run somewhere.
      // Needs Defender for Endpoint data in the workspace; see the header
      // comment below.
      [
        '(',
        '    DeviceFileEvents',
        '    | where Timestamp > ago(Lookback)',
        `    | where ${conditions.join(' or ')}`,
        '    | extend MatchedOn = "file", MatchedTable = "DeviceFileEvents"',
        ')',
      ].join('\n')
    );
  }

  if (ips.length) {
    letLines.push(kqlArray('SuspectIPs', ips));
    blocks.push(
      [
        '(',
        '    EmailEvents',
        '    | where Timestamp > ago(Lookback)',
        '    | where SenderIPv4 in (SuspectIPs) or SenderIPv6 in (SuspectIPs)',
        '    | extend MatchedOn = "sender_ip", MatchedTable = "EmailEvents"',
        ')',
      ].join('\n'),
      [
        '(',
        '    DeviceNetworkEvents',
        '    | where Timestamp > ago(Lookback)',
        '    | where RemoteIP in (SuspectIPs)',
        '    | extend MatchedOn = "network_ip", MatchedTable = "DeviceNetworkEvents"',
        ')',
      ].join('\n')
    );
  }

  if (domains.length) {
    blocks.push(
      [
        '(',
        '    DeviceNetworkEvents',
        '    | where Timestamp > ago(Lookback)',
        '    | where RemoteUrl has_any (SuspectDomains)',
        '    | extend MatchedOn = "network_domain", MatchedTable = "DeviceNetworkEvents"',
        ')',
      ].join('\n')
    );
  }

  return [
    '// Generated by the farksecurity.com phish-report analyzer.',
    '//',
    '// Advanced Hunting query against the Microsoft 365 Defender / Microsoft',
    '// Sentinel schema. Table and column names are Microsoft\'s own, so this',
    '// should run as-is rather than needing field-name mapping first.',
    '//',
    '// STARTING POINT: adjust Lookback, and note DeviceFileEvents /',
    '// DeviceNetworkEvents need Defender for Endpoint data in the workspace —',
    '// drop those blocks if you only have Defender for Office 365. has_any',
    '// does substring-style matching on SenderFromAddress / RemoteUrl, so',
    '// review hits before acting on a domain match alone.',
    '',
    ...letLines,
    '',
    'union isfuzzy=true',
    blocks.join(',\n'),
    '| sort by Timestamp desc',
    '',
  ].join('\n');
}

export { buildKqlQuery };
