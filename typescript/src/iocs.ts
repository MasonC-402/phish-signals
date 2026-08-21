// Indicator extraction and defanging.
//
// The tool previously ended at a verdict, which is where the analyst's job
// actually starts. Whoever is looking at this needs to paste indicators into a
// ticket, a block list, or a note to a colleague — and needs them defanged, so
// that pasting a live phishing URL into a chat client doesn't render a clickable
// link or trigger a preview fetch that tips off the sender.

import type { AttachmentSummary, Ioc, ReceivedChainAnalysis, UrlAnalysis } from './types';

/**
 * Defanging convention follows what SOC tooling generally emits: the scheme is
 * broken so nothing auto-links, and every dot is bracketed so no client
 * re-detects a hostname. Deliberately applied to the whole string rather than
 * just the authority — chat and ticket systems will happily linkify a bare
 * "evil.tk/login" out of a path too.
 */
function defang(value: string): string {
  return value
    .replace(/^http/i, 'hxxp')
    .replace(/\./g, '[.]')
    .replace(/@/g, '[@]');
}

// Inverse of defang() above, for pasting a defanged IOC report back into
// something that needs live values (a search bar, a blocklist import). Order
// matters: the bracketed dot has to be restored before the scheme, otherwise
// "hxxp[://]" would collapse its own brackets into the wrong thing first.
//
// Also accepts hxxp[://] — bracketed around the colon-slash-slash rather
// than just the scheme letters — even though defang() above never produces
// that form itself. It's a common convention from other tools (VirusTotal,
// MISP-style exports, plenty of SOC tickets), and refanging it costs nothing
// extra: the pattern simply never matches text that doesn't contain it.
function refang(value: string): string {
  return value
    .replace(/\[:\/\/\]/gi, '://')
    .replace(/\[\.\]/gi, '.')
    .replace(/\[@\]/gi, '@')
    .replace(/^hxxp/i, 'http');
}

function ioc(type: Ioc['type'], value: string): Ioc {
  return { type, value, defanged: defang(value) };
}

function addressOf(headerValue: string | null | undefined): string | null {
  if (!headerValue) return null;
  const match = String(headerValue).match(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/i);
  return match ? match[0].toLowerCase() : null;
}

interface IocSources {
  urls: UrlAnalysis[];
  attachments: AttachmentSummary[];
  chain: ReceivedChainAnalysis | null;
  from: string | null;
  replyTo: string | null;
  returnPath: string | null;
}

function extractIocs(sources: IocSources): Ioc[] {
  const iocs: Ioc[] = [];
  const seen = new Set<string>();

  const push = (candidate: Ioc | null) => {
    if (!candidate) return;
    const key = `${candidate.type}:${candidate.value}`;
    if (seen.has(key)) return;
    seen.add(key);
    iocs.push(candidate);
  };

  // Only links that actually raised something. A clean link is not an indicator
  // and including it would make the list useless to paste anywhere.
  for (const url of sources.urls) {
    if (url.risk !== 'malicious' && url.risk !== 'suspicious') continue;
    push(ioc('url', url.url));
    if (url.hostname) push(ioc('domain', url.hostname));
  }

  for (const address of [sources.from, sources.replyTo, sources.returnPath]) {
    const parsed = addressOf(address);
    if (parsed) push(ioc('email', parsed));
  }

  if (sources.chain && sources.chain.originIp) {
    push(ioc('ip', sources.chain.originIp));
  }
  if (sources.chain && sources.chain.originHost) {
    push(ioc('domain', sources.chain.originHost));
  }

  for (const file of sources.attachments) {
    push(ioc('filename', file.filename));
    // Hex digests have no dots, scheme, or "@" to break, so defang() is a
    // harmless no-op on them — no special-casing needed, the generic helper
    // already produces defanged === value for a hash. All three algorithms are
    // included together, matching how most real IOC reports list them, since
    // different blocklists and tools still index by different ones.
    if (file.sha256) push(ioc('hash', file.sha256));
    if (file.sha1) push(ioc('hash', file.sha1));
    if (file.md5) push(ioc('hash', file.md5));
  }

  return iocs;
}

// Freeform IOC parsing, for /tools/kql-builder — pasted indicators that
// don't come from an analyzed email at all, so there's no UrlAnalysis or
// AttachmentSummary to read structure from, just raw text. Every token is
// refang()ed first so a paste straight out of this site's own IOC Defang
// tool (or any SOC ticket) classifies the same as a live value would.

const HASH_PATTERN = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;
const EMAIL_PATTERN = /^[\w.+-]+@[\w-]+(\.[\w-]+)+$/i;
const IPV4_PATTERN = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV6_PATTERN = /^[a-f0-9:]{2,}$/i;
// Extensions worth recognizing as "this token is a filename," not a
// hostname — broader than attachmentCheck.ts's dangerous-extension sets,
// since this just needs to identify a filename, not judge its risk.
// Deliberately excludes '.com' — a real legacy DOS executable extension, but
// negligible next to how overwhelmingly it means the TLD in any pasted text.
// '.zip' and '.one' are both real, if rare, gTLDs too (a lookalike ".zip"
// domain is itself a known phishing trick), so a bare "example.zip" pasted
// with no path still reads as a filename here — an accepted residual
// ambiguity, not a gap worth a heavier disambiguation pass for two rare
// TLDs.
const FILENAME_EXTENSIONS = new Set([
  '.exe', '.dll', '.scr', '.bat', '.cmd', '.pif', '.vbs', '.vbe',
  '.js', '.jse', '.wsf', '.wsh', '.msi', '.msp', '.ps1', '.psm1', '.jar',
  '.hta', '.cpl', '.reg', '.lnk', '.iso', '.docm', '.xlsm', '.pptm',
  '.dotm', '.xltm', '.potm', '.xlam', '.xlsb', '.doc', '.docx', '.xls',
  '.xlsx', '.ppt', '.pptx', '.pdf', '.zip', '.rar', '.7z', '.rtf', '.one',
]);
// A domain needs a plausible alphabetic TLD — this alone is what keeps
// "invoice.exe" from being misread as a two-label hostname once the
// filename check above has already had first refusal at it.
const DOMAIN_PATTERN = /^(?!\d+$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$/i;

function isValidIpv4(host: string): boolean {
  return IPV4_PATTERN.test(host) && host.split('.').every((octet) => Number(octet) <= 255);
}

function classifyToken(rawToken: string): Ioc | null {
  // Surrounding punctuation a paste commonly carries along: brackets,
  // angle brackets, trailing sentence punctuation.
  const token = refang(rawToken).replace(/^[[<(]+|[\]>),.;:!?]+$/g, '').trim();
  if (!token) return null;

  if (HASH_PATTERN.test(token)) return ioc('hash', token.toLowerCase());
  if (EMAIL_PATTERN.test(token)) return ioc('email', token.toLowerCase());

  if (/^https?:\/\//i.test(token)) return ioc('url', token);

  const hostAndPath = token.match(/^([a-z0-9.-]+)(\/\S*)$/i);
  if (hostAndPath && DOMAIN_PATTERN.test(hostAndPath[1]) && !FILENAME_EXTENSIONS.has(extnameOf(hostAndPath[1]))) {
    return ioc('url', `http://${token}`);
  }

  if (isValidIpv4(token)) return ioc('ip', token);
  if (token.includes(':') && IPV6_PATTERN.test(token) && token.split(':').length > 2) return ioc('ip', token.toLowerCase());

  const extension = extnameOf(token);
  if (extension && FILENAME_EXTENSIONS.has(extension) && !token.includes('/')) return ioc('filename', token);

  if (DOMAIN_PATTERN.test(token)) return ioc('domain', token.toLowerCase());

  return null;
}

function extnameOf(value: string): string {
  const match = value.toLowerCase().match(/\.[a-z0-9]+$/);
  return match ? match[0] : '';
}

/** Parses freeform pasted text (any mix of live or defanged IOCs, any separator) into a de-duplicated Ioc[]. */
function parseIocText(text: string): Ioc[] {
  const iocs: Ioc[] = [];
  const seen = new Set<string>();

  for (const rawToken of text.split(/[\s,;|]+/)) {
    const candidate = classifyToken(rawToken);
    if (!candidate) continue;
    const key = `${candidate.type}:${candidate.value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    iocs.push(candidate);
  }

  return iocs;
}

export { extractIocs, defang, refang, parseIocText };
