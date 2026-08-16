// Sigma rule generation.
//
// This is the piece that turns the tool from "tells you about one email" into
// something with a detection-engineering payoff: the analyzed message becomes a
// reusable artifact you can take back to a SIEM so the next copy of the same
// campaign is caught without anyone pasting it in here.
//
// The output is explicitly a starting point, and says so in its own comments.
// Email telemetry field names are not standardized across platforms the way
// Windows event fields are, so the selections below use plain descriptive names
// that have to be mapped to whatever the reader's pipeline actually calls them.
// Generating something honest and clearly labelled beats generating something
// that looks drop-in and silently matches nothing.

import { randomUUID } from 'crypto';
import type { AttachmentSummary, Signal, UrlAnalysis } from './types';
import { extname } from './attachmentCheck';

interface SigmaInput {
  subject: string | null;
  senderDomain: string | null;
  replyToDomain: string | null;
  urls: UrlAnalysis[];
  attachments: AttachmentSummary[];
  signals: Signal[];
  verdict: string;
  score: number;
}

/** Quotes a YAML scalar only when it needs it, and never lets one break out. */
function yamlString(value: string): string {
  const cleaned = value.replace(/[\r\n]+/g, ' ').trim();
  return `'${cleaned.replace(/'/g, "''")}'`;
}

function indentList(items: string[], indent: string): string[] {
  return items.map((item) => `${indent}- ${yamlString(item)}`);
}

/** Words from the subject distinctive enough to be worth matching on. */
function subjectKeywords(subject: string | null): string[] {
  if (!subject) return [];
  const stopwords = new Set([
    'the', 'and', 'for', 'you', 'your', 'our', 'has', 'have', 'been', 'from',
    'this', 'that', 'with', 'will', 'are', 'was', 'not', 're', 'fw', 'fwd',
  ]);

  return [...new Set(
    subject
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter((word) => word.length >= 4 && !stopwords.has(word))
  )].slice(0, 6);
}

function buildSigmaRule(input: SigmaInput): string {
  const riskyUrls = input.urls.filter((u) => u.risk === 'malicious' || u.risk === 'suspicious');
  const riskyHosts = [...new Set(riskyUrls.map((u) => u.hostname).filter((h): h is string => Boolean(h)))];
  const dangerousExtensions = [...new Set(
    input.attachments.map((a) => extname(a.filename)).filter(Boolean)
  )];
  // The one selection in this whole rule that's genuinely high-confidence
  // rather than a starting point: an exact hash match essentially never false
  // positives the way a domain or keyword selection can. Only available for
  // attachments parsed from a raw .eml/pasted message — see lib/emailParser.ts.
  const attachmentHashes = [...new Set(
    input.attachments.map((a) => a.sha256).filter((h): h is string => Boolean(h))
  )];
  const keywords = subjectKeywords(input.subject);

  const attackTags = [...new Set(
    input.signals.flatMap((s) => s.mitre || []).map((id) => `attack.${id.toLowerCase()}`)
  )].sort();

  const selections: string[] = [];
  const conditionParts: string[] = [];

  if (input.senderDomain) {
    selections.push('  sender_domain:');
    selections.push('    sender|endswith:');
    selections.push(...indentList([`@${input.senderDomain}`], '      '));
    conditionParts.push('sender_domain');
  }

  if (input.replyToDomain && input.replyToDomain !== input.senderDomain) {
    selections.push('  reply_to_domain:');
    selections.push('    reply_to|endswith:');
    selections.push(...indentList([`@${input.replyToDomain}`], '      '));
    conditionParts.push('reply_to_domain');
  }

  if (riskyHosts.length > 0) {
    selections.push('  link_hosts:');
    selections.push('    url|contains:');
    selections.push(...indentList(riskyHosts, '      '));
    conditionParts.push('link_hosts');
  }

  if (dangerousExtensions.length > 0) {
    selections.push('  attachment_type:');
    selections.push('    attachment_name|endswith:');
    selections.push(...indentList(dangerousExtensions, '      '));
    conditionParts.push('attachment_type');
  }

  if (attachmentHashes.length > 0) {
    selections.push('  attachment_hash:');
    selections.push('    attachment_hash|contains:');
    selections.push(...indentList(attachmentHashes, '      '));
    conditionParts.push('attachment_hash');
  }

  if (keywords.length > 0) {
    selections.push('  subject_keywords:');
    selections.push('    subject|contains|all:');
    selections.push(...indentList(keywords.slice(0, 3), '      '));
    conditionParts.push('subject_keywords');
  }

  if (conditionParts.length === 0) {
    return [
      '# No indicator in this message was distinctive enough to build a rule from.',
      '# A rule matching only generic body phrases would fire on legitimate mail',
      '# constantly, so nothing is emitted here rather than something unusable.',
      '',
    ].join('\n');
  }

  const level = input.score >= 60 ? 'high' : input.score >= 30 ? 'medium' : 'low';

  return [
    '# Generated by the farksecurity.com phish-report analyzer.',
    '#',
    '# STARTING POINT, NOT A FINISHED RULE. Email telemetry field names differ',
    '# per platform (Defender, Proofpoint, Mimecast, a mail gateway log...), so',
    '# map sender / reply_to / url / attachment_name / attachment_hash / subject',
    '# onto whatever your pipeline actually calls them before deploying. Review',
    '# each selection: the sender domain may be a compromised legitimate host you',
    '# do not want to block outright, and subject keywords are the most',
    '# false-positive-prone part. attachment_hash is the exception — an exact',
    '# hash match is high-confidence on its own and worth keeping as-is.',
    '',
    // Quoted, not bare. The subject is attacker-controlled and a bare YAML
    // scalar containing ": " parses as a nested key — enough to make the
    // emitted rule invalid, or to smuggle a key into it.
    `title: ${yamlString(`Phishing indicators observed in message${input.subject ? ` - ${input.subject.replace(/[\r\n]+/g, ' ').slice(0, 60)}` : ''}`)}`,
    `id: ${randomUUID()}`,
    'status: experimental',
    `description: ${yamlString(`Indicators extracted from a single message assessed as ${input.verdict} (${input.score}/100) by heuristic analysis.`)}`,
    'author: farksecurity.com phish-report',
    `date: ${new Date().toISOString().slice(0, 10)}`,
    'logsource:',
    '  category: mail',
    'detection:',
    ...selections,
    `  condition: ${conditionParts.join(' or ')}`,
    'falsepositives:',
    '  - Legitimate mail from a compromised but otherwise trusted sender',
    '  - Shared sending infrastructure where the domain is not attacker-controlled',
    '  - Subject keywords appearing in unrelated legitimate correspondence',
    `level: ${level}`,
    ...(attackTags.length > 0 ? ['tags:', ...attackTags.map((t) => `  - ${t}`)] : []),
    '',
  ].join('\n');
}

export { buildSigmaRule, subjectKeywords };
