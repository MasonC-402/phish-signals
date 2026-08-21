// Received-header chain analysis.
//
// This was the single largest blind spot: the delivery path was parsed by
// mailparser and then thrown away. The chain is the one part of a message an
// attacker cannot fully forge — they can prepend whatever they like, but every
// hop *after* the injection point is written by servers they don't control, and
// those hops record what the sending machine actually was as well as what it
// claimed to be. Comparing those two is a real spoofing check that needs no
// network access, which matters here because this tool makes no external calls.

import { registrableDomain, KNOWN_BRAND_DOMAINS, brandLabel } from './domains';
import type { ReceivedChainAnalysis, ReceivedHop, Signal } from './types';

// RFC 1918 / loopback / link-local / unique-local. A message whose *entry* hop
// is one of these was injected inside a network rather than arriving from the
// internet, which is normal for internal mail and notable for anything claiming
// to be from an outside brand.
function isPrivateIp(ip: string): boolean {
  if (/^10\./.test(ip)) return true;
  if (/^127\./.test(ip)) return true;
  if (/^192\.168\./.test(ip)) return true;
  if (/^169\.254\./.test(ip)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true;
  const lower = ip.toLowerCase();
  return lower === '::1' || lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80');
}

function parseHop(line: string, index: number): ReceivedHop {
  // Strip the header name and unfold continuation lines into one string.
  const value = line.replace(/^received:\s*/i, '').replace(/\s+/g, ' ').trim();

  const heloMatch = value.match(/\bfrom\s+([^\s(;]+)/i);
  const byMatch = value.match(/\bby\s+([^\s(;]+)/i);

  // The parenthesised group right after `from` is where the receiving server
  // records what it independently observed: "from CLAIMED (RDNS [IP])".
  const parenMatch = value.match(/\bfrom\s+[^\s(;]+\s*\(([^)]*)\)/i);
  const paren = parenMatch ? parenMatch[1] : '';

  const ipMatch = (paren.match(/\[([0-9a-fA-F.:]+)\]/) || value.match(/\[([0-9a-fA-F.:]+)\]/));
  const ip = ipMatch ? ipMatch[1] : null;

  let reverseDns: string | null = null;
  if (paren) {
    const host = paren.replace(/\[[^\]]*\]/g, '').trim().split(/\s+/)[0];
    // Receivers write "unknown" when the reverse lookup failed.
    if (host && !/^unknown$/i.test(host) && /[a-z]/i.test(host)) {
      reverseDns = host.replace(/\.$/, '').toLowerCase();
    }
  }

  const dateMatch = value.match(/;\s*([^;]+)$/);
  const timestamp = dateMatch ? dateMatch[1].trim() : null;

  const helo = heloMatch ? heloMatch[1].replace(/\.$/, '').toLowerCase() : null;

  // Only meaningful when both sides are real hostnames.
  const heloMismatch = Boolean(
    helo && reverseDns
    && /\./.test(helo) && /\./.test(reverseDns)
    && registrableDomain(helo) !== registrableDomain(reverseDns)
  );

  return {
    index,
    helo,
    reverseDns,
    ip,
    by: byMatch ? byMatch[1].replace(/\.$/, '').toLowerCase() : null,
    timestamp,
    heloMismatch,
    private: ip ? isPrivateIp(ip) : false,
  };
}

function parseDate(value: string | null): number | null {
  if (!value) return null;
  const parsed = new Date(value).getTime();
  return Number.isNaN(parsed) ? null : parsed;
}

function analyzeReceivedChain(headerLines: { key: string; line: string }[]): ReceivedChainAnalysis {
  const received = headerLines.filter((h) => h.key.toLowerCase() === 'received');

  if (received.length === 0) {
    return { hops: [], originIp: null, originHost: null, signals: [] };
  }

  // Received headers are *prepended* at each hop, so the last one in the
  // message is the first hop chronologically. Reversed here so the chain reads
  // origin -> recipient, which is the order an analyst thinks in.
  const hops = received
    .map((h) => h.line)
    .reverse()
    .map(parseHop);

  const signals: Signal[] = [];
  const origin = hops[0];

  // A HELO announcing one organization while reverse DNS resolves to another is
  // the classic spoofed-sender shape. Weighted higher when the claimed name is
  // a brand, since that is a deliberate choice rather than a misconfiguration.
  const mismatchedHops = hops.filter((h) => h.heloMismatch);
  if (mismatchedHops.length > 0) {
    const hop = mismatchedHops[0];
    const claimsBrand = KNOWN_BRAND_DOMAINS.some((brand) => {
      const label = brandLabel(brand);
      return hop.helo ? hop.helo.split('.').includes(label) : false;
    });

    signals.push({
      id: claimsBrand ? 'helo_brand_impersonation' : 'helo_rdns_mismatch',
      category: 'infrastructure',
      severity: claimsBrand ? 'high' : 'medium',
      label: claimsBrand ? 'Sending Server Impersonates a Brand' : 'Sending Server Name Mismatch',
      detail: `A relay announced itself as "${hop.helo}" but the receiving server resolved the connection back to "${hop.reverseDns}"${hop.ip ? ` (${hop.ip})` : ''}. The sending machine is not what it claimed to be.`,
      mitre: ['T1656'],
    });
  }

  // Every hop rewrites the chain below it, but it cannot rewrite the clocks of
  // servers further along. Time running backwards means a hop was fabricated.
  const timestamps = hops.map((h) => parseDate(h.timestamp));
  for (let i = 1; i < timestamps.length; i++) {
    const previous = timestamps[i - 1];
    const current = timestamps[i];
    // 5 minutes of slack for ordinary clock skew between mail servers.
    if (previous !== null && current !== null && current < previous - 5 * 60 * 1000) {
      signals.push({
        id: 'received_timestamp_regression',
        category: 'infrastructure',
        severity: 'high',
        label: 'Forged Delivery Path',
        detail: 'Timestamps in the Received chain run backwards: a later hop is dated before an earlier one. Servers cannot rewrite the clocks of servers further down the path, so at least one of these headers was fabricated.',
        mitre: ['T1656'],
      });
      break;
    }
  }

  if (origin && origin.private && hops.length === 1) {
    signals.push({
      id: 'origin_private_ip',
      category: 'infrastructure',
      severity: 'low',
      label: 'Message Entered From a Private Address',
      detail: `The only recorded hop came from ${origin.ip}, a private/internal address. For mail claiming to be from an outside organization, that means it was injected inside a network rather than delivered across the internet.`,
      mitre: ['T1534'],
    });
  }

  if (hops.length === 1) {
    signals.push({
      id: 'single_hop_delivery',
      category: 'infrastructure',
      severity: 'low',
      label: 'Direct Delivery, No Relay Path',
      detail: 'The message records only one hop. Legitimate mail from an established provider almost always shows several. A single hop is typical of a script or host connecting straight to the recipient mail server.',
    });
  }

  return {
    hops,
    originIp: origin ? origin.ip : null,
    originHost: origin ? (origin.reverseDns || origin.helo) : null,
    signals,
  };
}

export { analyzeReceivedChain, isPrivateIp };
