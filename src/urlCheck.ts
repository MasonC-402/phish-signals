// Pure structural/heuristic URL analysis — no external API calls

import { KNOWN_BRAND_DOMAINS, brandLabel, normalizeConfusables, registrableDomain } from './domains';
import { describeHostname } from './punycode';
import type { Signal, SignalResult, UrlAnalysis, UrlRisk } from './types';

const SUSPICIOUS_TLDS = [
  '.zip', '.mov', '.xyz', '.top', '.club', '.gq', '.tk', '.ml', '.cf', '.ga',
  '.work', '.click', '.link', '.support', '.icu', '.rest', '.quest',
  '.cam', '.sbs', '.cfd', '.bond', '.lol', '.beauty', '.autos', '.monster',
];

const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
  'rebrand.ly', 'shorturl.at', 'cutt.ly', 'tiny.cc', 'rb.gy',
  'shorte.st', 'bl.ink', 'lnkd.in', 'trib.al', 'tny.im', 's.id',
];

// Extensions that, delivered straight from a link in an email, are a payload
// rather than a document.
const DANGEROUS_DOWNLOAD_EXTENSIONS = [
  '.exe', '.scr', '.msi', '.bat', '.cmd', '.vbs', '.js', '.jar', '.ps1',
  '.hta', '.iso', '.img', '.vhd', '.lnk', '.7z', '.rar', '.cab',
];

// Ports that aren't a normal way to reach a public web page.
const EXPECTED_PORTS = new Set(['', '80', '443', '8443']);

const CREDENTIAL_KEYWORDS = /\b(login|signin|sign-in|verify|verification|secure|account|update|confirm|password|credential|authenticate|unlock|recover)\b/gi;

function levenshtein(a: string, b: string): number {
  const matrix: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 0; j <= b.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      matrix[i][j] = a[i - 1] === b[j - 1]
        ? matrix[i - 1][j - 1]
        : Math.min(matrix[i - 1][j - 1], matrix[i][j - 1], matrix[i - 1][j]) + 1;
    }
  }
  return matrix[a.length][b.length];
}

// True when the host is the brand itself or a subdomain of it. Runs over the
// entire brand list before any fuzzy comparison — see the note in domains.ts
// about ups.com/usps.com.
function isKnownBrand(host: string): boolean {
  return KNOWN_BRAND_DOMAINS.some((brand) => host === brand || host.endsWith('.' + brand));
}

function checkTyposquat(hostname: string): string | null {
  const host = hostname.toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
  if (isKnownBrand(host)) return null;

  // Compare the registrable domain, so login.paypa1.com is caught by way of
  // paypa1.com rather than being diluted by its subdomain.
  const candidate = registrableDomain(host);
  if (isKnownBrand(candidate)) return null;

  const normalizedCandidate = normalizeConfusables(candidate);
  for (const brand of KNOWN_BRAND_DOMAINS) {
    if (normalizedCandidate === normalizeConfusables(brand)) return brand;
  }

  for (const brand of KNOWN_BRAND_DOMAINS) {
    // An edit distance of 1-2 is only meaningful between strings of similar
    // length; this also bounds the O(n*m) matrix below, which was otherwise
    // allocated against an attacker-controlled hostname up to the full input
    // length, 20 times per URL.
    if (Math.abs(candidate.length - brand.length) > 2) continue;
    const distance = levenshtein(candidate, brand);
    if (distance > 0 && distance <= 2) return brand;
  }

  return null;
}

// A brand name showing up as a subdomain label, or hyphenated into an unrelated
// registrable domain: paypal.com.secure-verify.net, secure-paypal.com,
// microsoft-account.login.xyz. This is by far the most common real-world shape
// and scored zero before — it isn't a typosquat (the spelling is exact) and
// four labels sits under the excessive-subdomain threshold.
function brandImpersonation(hostname: string): string | null {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (isKnownBrand(host)) return null;

  const registrable = registrableDomain(host);
  if (isKnownBrand(registrable)) return null;

  const subdomainPart = host.slice(0, Math.max(0, host.length - registrable.length));
  const subLabels = subdomainPart.split('.').filter(Boolean);
  const registrableTokens = registrable.split('.')[0].split('-');

  for (const brand of KNOWN_BRAND_DOMAINS) {
    const label = brandLabel(brand);

    // In a subdomain: paypal.com.evil.net, login.microsoft.evil.net
    if (subLabels.some((l) => l === label || l.split('-').includes(label))) {
      return brand;
    }

    // Hyphenated into the registrable domain: secure-paypal.com. A bare
    // single-token match is skipped deliberately — that would flag legitimate
    // regional domains like paypal.co.uk that just aren't on the brand list.
    if (registrableTokens.length > 1 && registrableTokens.includes(label)) {
      return brand;
    }
  }

  return null;
}

function isIpLiteral(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, '');
  // Dotted quad, with the octets actually validated.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    return host.split('.').every((octet) => Number(octet) <= 255);
  }
  // Bare decimal (http://3232235777/), hex (0x7f000001), and octal forms. The
  // WHATWG URL parser normalizes most of these to dotted quad before we see
  // them, but not every caller goes through it.
  if (/^\d+$/.test(host) || /^0x[0-9a-f]+$/i.test(host) || /^0[0-7]+$/.test(host)) return true;
  return host.includes(':') && /^[a-f0-9:]+$/i.test(host);
}

function hasPunycode(hostname: string): boolean {
  return hostname.toLowerCase().includes('xn--');
}

function hasSuspiciousTld(hostname: string): boolean {
  return SUSPICIOUS_TLDS.some((tld) => hostname.toLowerCase().endsWith(tld));
}

function isShortener(hostname: string): boolean {
  const host = hostname.toLowerCase();
  return URL_SHORTENERS.some((s) => host === s || host.endsWith('.' + s));
}

function excessiveSubdomains(hostname: string): boolean {
  return hostname.split('.').length >= 5;
}

function credentialKeywordCount(pathAndQuery: string): number {
  const matches = pathAndQuery.match(CREDENTIAL_KEYWORDS);
  if (!matches) return 0;
  return new Set(matches.map((m) => m.toLowerCase())).size;
}

function hasDangerousDownload(pathname: string): string | null {
  const lower = pathname.toLowerCase();
  return DANGEROUS_DOWNLOAD_EXTENSIONS.find((ext) => lower.endsWith(ext)) || null;
}

// http://real-looking-domain.com@evil.com/ — the browser goes to evil.com.
// Only the authority is examined: the previous version stripped the scheme and
// tested the whole remainder, so every unsubscribe link carrying the
// recipient's address in a query parameter was scored as this trick.
function hasAtSymbolTrick(url: string): boolean {
  const authority = url.replace(/^https?:\/\//i, '').split(/[/?#]/)[0];
  return authority.includes('@');
}

function parseUrl(url: string): URL | null {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

function analyzeUrl(url: string): UrlAnalysis {
  const parsed = parseUrl(url);
  if (!parsed) {
    return { url, risk: 'unknown', detail: 'Could not parse this URL.' };
  }

  const hostname = parsed.hostname;
  const reasons: string[] = [];
  let riskScore = 0;

  const typosquatMatch = checkTyposquat(hostname);
  if (typosquatMatch) {
    reasons.push(`Closely resembles "${typosquatMatch}" (likely typosquat)`);
    riskScore += 35;
  }

  // Mutually exclusive with the above — a lookalike domain and a brand-bearing
  // subdomain are the same intent, and scoring both would double-count it.
  const impersonatedBrand = !typosquatMatch ? brandImpersonation(hostname) : null;
  if (impersonatedBrand) {
    reasons.push(`Puts "${brandLabel(impersonatedBrand)}" in the hostname, but the real domain is "${registrableDomain(hostname)}"`);
    riskScore += 35;
  }

  if (hasAtSymbolTrick(url)) {
    reasons.push('Contains "@" trick. The real destination differs from what appears before the @');
    riskScore += 35;
  }

  if (isIpLiteral(hostname)) {
    reasons.push('Uses a raw IP address instead of a domain name');
    riskScore += 25;
  }

  // Decoded rather than merely detected: "uses punycode" is true but useless,
  // whereas showing that xn--pypal-4ve.com reads as "pаypal.com" with a
  // Cyrillic 'а' is the whole finding. Mixed-script and whole-script
  // confusables are separate cases — аррӏе.com is not mixed at all, it is
  // uniformly Cyrillic, so a mixed-script test alone never catches it.
  const unicode = describeHostname(hostname);
  if (unicode.mixed) {
    reasons.push(`Hostname reads as "${unicode.decoded}" and mixes ${unicode.scripts.join(' with ')} characters in a single label, a homograph trick for faking a familiar domain`);
    riskScore += 35;
  } else if (unicode.confusable) {
    reasons.push(`Hostname reads as "${unicode.decoded}" but is written entirely in ${unicode.scripts.filter((s) => s !== 'Latin').join('/')} characters chosen to look like Latin letters`);
    riskScore += 35;
  } else if (unicode.decoded) {
    reasons.push(`Internationalized domain, reads as "${unicode.decoded}" (${unicode.scripts.join(', ')}). Legitimate in itself, but verify it is the domain you expect`);
    riskScore += 10;
  } else if (hasPunycode(hostname)) {
    reasons.push('Uses punycode encoding that could not be decoded, often used to fake lookalike domains');
    riskScore += 25;
  }

  const dangerousExt = hasDangerousDownload(parsed.pathname);
  if (dangerousExt) {
    reasons.push(`Links directly to a ${dangerousExt} file, an executable or archive payload rather than a document`);
    riskScore += 30;
  }

  if (excessiveSubdomains(hostname)) {
    reasons.push('Unusually long subdomain chain, possibly hiding the real domain');
    riskScore += 15;
  }

  if (!EXPECTED_PORTS.has(parsed.port)) {
    reasons.push(`Served from a non-standard port (${parsed.port}), unusual for a legitimate public site`);
    riskScore += 15;
  }

  if (hasSuspiciousTld(hostname)) {
    reasons.push(`Uses a TLD (${hostname.split('.').pop()}) commonly associated with abuse`);
    riskScore += 10;
  }

  if (isShortener(hostname)) {
    reasons.push('Uses a URL shortener, destination is hidden');
    riskScore += 10;
  }

  const credentialWords = credentialKeywordCount(parsed.pathname + parsed.search);
  if (credentialWords >= 2) {
    reasons.push('URL path contains multiple login/verification keywords');
    riskScore += 10;
  }

  riskScore = Math.min(riskScore, 100);

  let risk: UrlRisk = 'clean';
  if (riskScore >= 30) risk = 'malicious';
  else if (riskScore >= 10) risk = 'suspicious';

  return {
    url,
    hostname,
    risk,
    detail: reasons.length > 0 ? reasons.join('; ') : 'No structural red flags detected.',
    riskScore,
    decodedHost: unicode.decoded,
    scripts: unicode.scripts,
  };
}

const MAX_URLS_ANALYZED = 25;

function checkUrls(urls: string[] | undefined): UrlAnalysis[] {
  if (!urls || urls.length === 0) return [];
  return urls.slice(0, MAX_URLS_ANALYZED).map(analyzeUrl);
}

/**
 * Turns the per-URL analysis into evidence for the scoring model.
 *
 * URL findings previously moved the score without ever appearing in the flag
 * list, so a report could read "no obvious red flags" beside a score of 60.
 * They are emitted as one signal per severity band rather than one per URL:
 * twenty links to the same malicious host is one finding, not twenty.
 */
function summarizeUrlSignals(analyses: UrlAnalysis[]): Signal[] {
  const malicious = analyses.filter((u) => u.risk === 'malicious');
  const suspicious = analyses.filter((u) => u.risk === 'suspicious');
  const signals: Signal[] = [];

  const hostList = (list: UrlAnalysis[]) =>
    [...new Set(list.map((u) => u.hostname).filter(Boolean))].slice(0, 3).join(', ');

  if (malicious.length > 0) {
    signals.push({
      id: 'malicious_links',
      category: 'payload',
      severity: 'high',
      label: 'High-Risk Links',
      detail: `${malicious.length} link${malicious.length === 1 ? '' : 's'} showed strong structural red flags (${hostList(malicious)}). See the Links table for the specific reason on each.`,
      mitre: ['T1566.002', 'T1204.001'],
    });
  }

  if (suspicious.length > 0) {
    signals.push({
      id: 'suspicious_links',
      category: 'payload',
      severity: 'medium',
      label: 'Suspicious Links',
      detail: `${suspicious.length} link${suspicious.length === 1 ? '' : 's'} showed weaker but notable red flags (${hostList(suspicious)}).`,
      mitre: ['T1566.002'],
    });
  }

  // Explicitly stated rather than left implicit: a message with nothing to
  // click and nothing to open cannot deliver a payload directly, which is
  // genuine evidence toward it being benign.
  if (analyses.length === 0) {
    signals.push({
      id: 'no_links_present',
      category: 'payload',
      severity: 'info',
      benign: true,
      label: 'No Links in the Message',
      detail: 'The message contains no links at all, so there is nothing to click. It could still be a reply-to-me fraud attempt, which the social-engineering checks cover.',
    });
  }

  return signals;
}

// The decoded URL itself is already scored like any other link by
// summarizeUrlSignals() above, since lib/emailParser.ts folds it into the
// same `urls` list. This is purely a transparency signal: without it, a QR
// code resolving to an otherwise-unremarkable link would leave no trace at
// all that the tool found and followed it, which matters because a QR code
// routing a reader around text-based filtering is itself worth naming even
// when its destination turns out to be clean.
function checkQrCodes(qrCodeUrls: string[] | undefined): SignalResult {
  const urls = qrCodeUrls || [];
  if (urls.length === 0) return { signals: [] };

  const examples = urls.slice(0, 3).join(', ');

  return {
    signals: [{
      id: 'qr_code_link',
      category: 'payload',
      severity: 'low',
      label: 'QR Code Contains a Link',
      detail: `An embedded image contains a QR code that decodes to ${urls.length === 1 ? 'a link' : `${urls.length} links`}: ${examples}. It was analyzed the same as any other link in the message — see the Links table for its risk assessment. Routing a reader through a QR code is an increasingly common way to get a link past text-based filtering and past someone glancing at where a link actually points.`,
      mitre: ['T1566.002'],
    }],
  };
}

export { checkUrls, checkTyposquat, brandImpersonation, levenshtein, isIpLiteral, summarizeUrlSignals, checkQrCodes, MAX_URLS_ANALYZED };
