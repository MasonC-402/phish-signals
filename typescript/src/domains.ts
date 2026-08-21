// Shared domain helpers. Used by urlCheck (typosquat/impersonation detection)
// and authCheck (From vs Return-Path/Reply-To comparison), which previously
// compared full hostnames and so flagged every third-party sending service.

// Brands impersonated often enough in real phishing to be worth special-casing.
// Order is irrelevant now — the whitelist pass in urlCheck runs over the whole
// list before any distance comparison starts. It did matter once: 'usps.com'
// sits before 'ups.com', and with the whitelist check nested inside the
// comparison loop, ups.com matched usps.com at edit distance 1 and got scored
// as a typosquat of a brand it actually is.
export const KNOWN_BRAND_DOMAINS = [
  'paypal.com', 'amazon.com', 'microsoft.com', 'apple.com', 'google.com',
  'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'irs.gov', 'netflix.com',
  'docusign.com', 'usps.com', 'fedex.com', 'ups.com', 'facebook.com',
  'instagram.com', 'linkedin.com', 'dropbox.com', 'office.com', 'outlook.com',
  'adobe.com', 'dhl.com', 'citibank.com', 'amex.com', 'coinbase.com',
  'binance.com', 'whatsapp.com', 'icloud.com', 'onedrive.com', 'sharepoint.com',
  'zoom.us', 'slack.com', 'github.com', 'stripe.com', 'intuit.com',
];

// Multi-part public suffixes common enough to matter here. This is deliberately
// a short hand-maintained list rather than a bundled copy of the full Public
// Suffix List — it only needs to be good enough to stop "mail.example.co.uk"
// from being read as registrable domain "co.uk", and a stale PSL snapshot is
// its own maintenance problem.
const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'sch.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz',
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'co.za', 'org.za', 'gov.za',
  'com.mx', 'com.sg', 'com.hk', 'com.tw', 'com.cn', 'com.tr', 'com.ar',
  'co.in', 'net.in', 'org.in', 'gov.in',
  'co.kr', 'or.kr',
]);

// Approximate eTLD+1. Returns the input unchanged when it has too few labels
// to reduce (a bare TLD, a hostname, an IP literal).
export function registrableDomain(hostname: string): string {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  const parts = host.split('.');
  if (parts.length <= 2) return host;

  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_PART_SUFFIXES.has(lastTwo)) {
    return parts.slice(-3).join('.');
  }
  return lastTwo;
}

// Characters routinely swapped to build a lookalike domain that reads correctly
// at a glance: paypa1.com, rnicrosoft.com, arnazon.com, netfl1x.com. Both the
// candidate and the brand go through this before comparison, so a pure
// substitution collapses to an exact match rather than relying on edit distance
// (which would also match plenty of innocent domains at the same threshold).
export function normalizeConfusables(value: string): string {
  return value
    .toLowerCase()
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/[1|!]/g, 'l')
    .replace(/0/g, 'o')
    .replace(/5/g, 's')
    .replace(/\$/g, 's')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/7/g, 't');
}

// The brand's distinctive label — 'paypal' from 'paypal.com'. Used to spot the
// brand appearing somewhere it shouldn't (a subdomain, or hyphenated into an
// unrelated registrable domain).
export function brandLabel(brandDomain: string): string {
  return brandDomain.split('.')[0];
}
