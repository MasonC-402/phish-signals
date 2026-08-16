import { registrableDomain, brandLabel } from './domains';
import { checkTyposquat, brandImpersonation } from './urlCheck';
import type { AuthCheckResult, Signal } from './types';

// Header values from mailparser vary by header: some are plain strings, some
// are AddressObject-shaped ({ text, html, value }), some are Date/arrays.
// Only the shapes actually seen on the headers we read here are handled;
// anything else degrades to "no value" rather than a type error at runtime.
function asText(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) {
    // A repeated header (mailparser collapses same-named headers into an
    // array on the Map) joined into one string. Authentication-Results no
    // longer goes through this path — see selectAuthoritativeAuthResults()
    // below, which reads it from headerLines instead so a specific hop can be
    // picked rather than every occurrence blended together — but From/
    // Return-Path/Reply-To still can repeat and still need a single string.
    return value.map(asText).filter(Boolean).join('; ');
  }
  if (value && typeof value === 'object' && 'text' in value && typeof (value as { text: unknown }).text === 'string') {
    return (value as { text: string }).text;
  }
  return undefined;
}

function extractDomain(addressString: string | undefined): string | null {
  if (!addressString) return null;
  const match = String(addressString).match(/@([^\s>,;]+)/);
  return match ? match[1].toLowerCase().replace(/\.$/, '') : null;
}

// Multiple Authentication-Results headers happen whenever the message passed
// through more than one authenticating hop — a mailing list, a corporate
// gateway, an internal relay each re-stamping their own. Headers are
// prepended at each hop, so headerLines' wire order runs newest-hop-first;
// reversing it — the same convention analyzeReceivedChain() already uses to
// read the Received chain origin-to-recipient (see lib/receivedChain.ts) —
// gives oldest-first. The OLDEST Authentication-Results header is the one
// stamped by the first real server to receive the message from the internet,
// which makes it the only hop whose SPF/DKIM/DMARC check is actually
// evaluating the claimed original sender against the claimed origin. A later
// hop's re-stamp is checking that hop's own resend, which routinely fails SPF
// for entirely benign reasons (forwarding rewrites the envelope sender) —
// previously every header was folded into one string and regex-scanned for
// any occurrence of e.g. "dmarc=fail" anywhere in it, so a single ordinary
// mailing-list or corporate-gateway forward could turn a message that
// genuinely passed authentication at the point of actual delivery into a
// reported hard DMARC failure.
const AUTHSERV_ID_PATTERN = /^([^\s;]+)/;

interface AuthoritativeAuthResults {
  /** The selected header's value text, with the header name stripped. Empty when nothing survived selection. */
  text: string;
  /** The authserv-id token of the selected header, or null. Exposed on AuthCheckResult for checkHeaderAnomalies to cross-reference — see lib/types.ts. */
  authservId: string | null;
  /**
   * True when at least one Authentication-Results header was discarded as
   * not belonging to a real hop — i.e. it predates every real hop, and can
   * only be something the sender wrote into the original message before it
   * ever reached real mail infrastructure, not something a real relay
   * stamped.
   */
  discardedForgedHeader: boolean;
}

// "Blindly trust the oldest header present" is exactly what a single forged
// trailing Authentication-Results header defeats: a receiving MTA only ever
// *prepends*, so a header the sender wrote into the original raw message —
// before it ever reached a real mail server — is permanently the oldest one
// in wire order, indistinguishable by age alone from a genuine early hop.
//
// The structural tell used instead: each real hop that authenticates the
// message contributes at most one Authentication-Results header, alongside
// its own Received line, so the total number of real Authentication-Results
// headers can never exceed the total number of Received headers. Trusting
// only the N most recent Authentication-Results headers (N = the Received
// count) keeps everything a real hop could plausibly have added and discards
// anything past that — which, past that point, can only be something that
// predates every real hop and was part of what the sender composed.
//
// This is deliberately NOT "must sit above the last Received line" — an
// earlier version of this fix used exactly that position check and it was
// wrong: real MTAs commonly write their own Received line *before* (above)
// their own Authentication-Results stamp for the same hop (this is standard
// Gmail/most-MTA header order), which would misclassify a completely
// legitimate single-hop message's genuine, passing header as forged and
// discard it. Counting by total Received headers rather than requiring a
// specific position ordering is what makes this correct regardless of
// whether a given hop wrote its own Received-then-AR or AR-then-Received.
//
// Verified against the concrete exploit this closes: a message that
// hard-fails at the real receiving MTA (dmarc_fail/spf_fail/dkim_fail)
// previously got fully suppressed to a single benign auth_fully_passed
// signal by appending one forged trailing "Authentication-Results:
// fake-server; spf=pass; dkim=pass; dmarc=pass" header — see
// test/analysis.test.ts and test/smoke.test.ts.
//
// This doesn't extend to an attacker who forges extra fake Received headers
// too, specifically to inflate N and smuggle their forged
// Authentication-Results in under the higher count: that's a materially
// harder problem — this tool makes no DNS/network calls and has no
// cryptographic way to tell a genuine Received line from a fabricated one —
// and is a known, accepted residual limitation of a purely structural,
// offline heuristic. What this closes is the specific, verified, much
// cheaper attack: one appended header with no accompanying forged delivery
// chain.
//
// When there's no Received header at all to anchor against (N = 0), nothing
// here can be validated either way, so every present header is kept and the
// oldest of them wins — the same best-effort behaviour as before this fix,
// not a regression for a partial paste that simply never included Received
// lines.
function selectAuthoritativeAuthResults(headerLines: { key: string; line: string }[]): AuthoritativeAuthResults {
  const receivedCount = headerLines.filter((h) => h.key.toLowerCase() === 'received').length;

  // Wire order is newest-first, so this is already sorted newest-to-oldest.
  const allCandidates = headerLines
    .map((h, index) => ({ h, index }))
    .filter(({ h }) => h.key.toLowerCase() === 'authentication-results');

  // The N most recent — i.e. everything a real hop could plausibly have
  // added, discarding only whatever's left over (necessarily older than all
  // of those).
  const trustedCandidates = receivedCount === 0 ? allCandidates : allCandidates.slice(0, receivedCount);

  const discardedForgedHeader = receivedCount > 0 && trustedCandidates.length < allCandidates.length;

  if (trustedCandidates.length === 0) {
    return { text: '', authservId: null, discardedForgedHeader };
  }

  const oldest = trustedCandidates[trustedCandidates.length - 1];
  const text = oldest.h.line.replace(/^authentication-results:\s*/i, '');
  const authservIdMatch = AUTHSERV_ID_PATTERN.exec(text);
  const authservId = authservIdMatch ? authservIdMatch[1].replace(/\.$/, '') : null;

  return { text, authservId, discardedForgedHeader };
}

// checkTyposquat/brandImpersonation were written for URL hostnames, but both
// reduce to a registrable-domain comparison against the same brand list
// internally, which is exactly what a bare From/Reply-To domain string
// already is — no URL construction needed. This is the same trick as a
// lookalike link, applied to a sending/reply identity rather than to
// something merely referenced in the body: "support@paypa1-secure.com"
// carries no suspicious link at all, and previously scored nothing for it.
//
// `field`/`headerLabel` distinguish a From-domain finding from a Reply-To one
// in both the signal id (so scoreSignals' dedupe-by-id can't silently drop
// one in favour of the other when both fire for different domains) and the
// displayed label.
function checkDomainImpersonation(domain: string | null, field: 'sender' | 'reply_to', headerLabel: string): Signal[] {
  if (!domain) return [];

  const typosquatMatch = checkTyposquat(domain);
  if (typosquatMatch) {
    return [{
      id: `${field}_domain_typosquat`,
      category: 'identity',
      severity: 'high',
      label: `${headerLabel} Domain Resembles a Known Brand`,
      detail: `The message's ${headerLabel} is "${domain}", which closely resembles "${typosquatMatch}" — a likely typosquat rather than the real domain. This is an actual identity in the message, not just a link destination.`,
      mitre: ['T1656'],
    }];
  }

  // Mutually exclusive with the typosquat check, same reasoning urlCheck.ts
  // uses for the equivalent link-hostname check: a lookalike spelling and a
  // brand-bearing subdomain/hyphenation are the same intent, and scoring both
  // would double-count one finding.
  const impersonatedBrand = brandImpersonation(domain);
  if (impersonatedBrand) {
    return [{
      id: `${field}_domain_brand_impersonation`,
      category: 'identity',
      severity: 'high',
      label: `${headerLabel} Domain Puts a Brand Name Where It Doesn't Belong`,
      detail: `The message's ${headerLabel} is "${domain}", which puts "${brandLabel(impersonatedBrand)}" in the hostname while the real domain is unrelated. Same trick as a lookalike link, but in the message's own identity.`,
      mitre: ['T1656'],
    }];
  }

  return [];
}

// headers is a Map (from mailparser), or null if plain-text paste.
// headerLines carries the same header data in original wire order — needed
// here (rather than reading straight off the Map) only to pick out which
// Authentication-Results header is authoritative when more than one is
// present; see selectAuthoritativeAuthResults() above.
function checkAuthentication(headers: Map<string, unknown> | null, headerLines: { key: string; line: string }[]): AuthCheckResult {
  if (!headers) {
    return { available: false, passed: false, signals: [], selectedAuthservId: null };
  }

  const signals: Signal[] = [];
  const selection = selectAuthoritativeAuthResults(headerLines);
  const authResults = selection.text;

  // The header itself being present at all — more Authentication-Results
  // headers than the message has real hops to have stamped them — is
  // meaningful evidence independent of whatever the extra one claims: no
  // legitimate mail client or MTA ever writes this header into a message
  // before it reaches real mail infrastructure, so a surplus one can only be
  // something written into the original content. Kept high rather than
  // critical since this is inferred from structure, not a network
  // verification, but it's a deliberate, hard-to-accidentally-trigger shape.
  if (selection.discardedForgedHeader) {
    signals.push({
      id: 'forged_authentication_results_header',
      category: 'authentication',
      severity: 'high',
      label: 'Authentication-Results Header Predates Real Delivery',
      detail: 'The message carries more Authentication-Results headers than it has Received headers to have stamped them — meaning at least one could not have been added by a real mail server relaying the message, and was instead already present in the content as sent. A real server only ever adds this header at the moment it performs the check, never earlier. The extra header was ignored when determining SPF/DKIM/DMARC status below.',
      mitre: ['T1656'],
    });
  }

  // DMARC is the authoritative result and carries the highest severity of the
  // three: it is precisely the check that asks "is this message authorized by
  // the domain in the From header". SPF and DKIM sit below it because a DMARC
  // failure is *composed of* their failures — the scoring model then counts the
  // strongest signal in this category in full and the rest at a discount, so
  // one unauthenticated message no longer scores as three separate findings.
  if (/dmarc=fail/i.test(authResults)) {
    signals.push({
      id: 'dmarc_fail',
      category: 'authentication',
      severity: 'high',
      label: 'DMARC Failure',
      detail: 'The message failed DMARC. It is not authorized by the domain it claims to come from — the strongest single indicator of sender spoofing available from headers alone.',
      mitre: ['T1656'],
    });
  } else if (/dmarc=(quarantine|reject)/i.test(authResults)) {
    signals.push({
      id: 'dmarc_enforced',
      category: 'authentication',
      severity: 'high',
      label: 'DMARC Enforcement Applied',
      detail: "The receiving server applied the sending domain's DMARC enforcement policy, which means alignment failed and the domain owner asked for exactly this to be treated as suspect.",
      mitre: ['T1656'],
    });
  } else if (/dmarc=none/i.test(authResults)) {
    signals.push({
      id: 'dmarc_none',
      category: 'authentication',
      severity: 'low',
      label: 'No DMARC Policy',
      detail: 'The sending domain publishes no DMARC policy, so nothing prevents another server from spoofing it and nothing here can confirm the sender either way.',
    });
  }

  if (/spf=fail/i.test(authResults)) {
    signals.push({
      id: 'spf_fail',
      category: 'authentication',
      severity: 'medium',
      label: 'SPF Failure',
      detail: 'The sending server is not on the list of servers authorized to send for this domain.',
      mitre: ['T1656'],
    });
  } else if (/spf=(softfail|neutral)/i.test(authResults)) {
    signals.push({
      id: 'spf_softfail',
      category: 'authentication',
      severity: 'low',
      label: 'SPF Softfail',
      detail: 'SPF returned a soft failure or neutral result, so the sending server is only weakly authorized for this domain.',
    });
  } else if (/spf=none/i.test(authResults)) {
    signals.push({
      id: 'spf_none',
      category: 'authentication',
      severity: 'low',
      label: 'SPF Not Set Up',
      detail: "The sending domain doesn't publish an SPF policy at all, so this check couldn't confirm anything either way.",
    });
  }

  if (/dkim=fail/i.test(authResults)) {
    signals.push({
      id: 'dkim_fail',
      category: 'authentication',
      severity: 'medium',
      label: 'DKIM Failure',
      detail: 'The cryptographic signature did not validate. The message content or its headers were altered after signing, or the signature was forged outright.',
      mitre: ['T1656'],
    });
  } else if (/dkim=none/i.test(authResults)) {
    signals.push({
      id: 'dkim_none',
      category: 'authentication',
      severity: 'low',
      label: 'No DKIM Signature',
      detail: 'The message was not signed with DKIM, so there is no cryptographic evidence tying it to the sending domain.',
    });
  }

  if (authResults.trim() === '') {
    signals.push({
      id: 'no_auth_results',
      category: 'authentication',
      severity: 'low',
      label: 'No Authentication Results',
      detail: "This message carries no Authentication-Results header, so SPF/DKIM/DMARC couldn't be checked at all. Common for mail that bypassed normal filtering, and it means the checks below are working with less to go on.",
    });
  }

  const fromDomain = extractDomain(asText(headers.get('from')));
  const returnPathDomain = extractDomain(asText(headers.get('return-path')));

  // Compared at the registrable-domain level: bounce.example.com vs example.com
  // is one organization using a subdomain for bounce handling, which is how
  // essentially every mail platform works.
  if (fromDomain && returnPathDomain && registrableDomain(fromDomain) !== registrableDomain(returnPathDomain)) {
    signals.push({
      id: 'return_path_mismatch',
      category: 'identity',
      severity: 'low',
      label: 'Return-Path Mismatch',
      detail: `Bounces for this message go to "${returnPathDomain}" while it claims to be from "${fromDomain}". Normal for mail sent through a newsletter tool or CRM, so weigh it alongside the other findings rather than on its own.`,
    });
  }

  const replyToDomain = extractDomain(asText(headers.get('reply-to')));
  if (fromDomain && replyToDomain && registrableDomain(replyToDomain) !== registrableDomain(fromDomain)) {
    signals.push({
      id: 'reply_to_mismatch',
      category: 'identity',
      severity: 'medium',
      label: 'Replies Go to a Different Domain',
      detail: `Hitting reply sends your response to "${replyToDomain}", not "${fromDomain}". This is how a conversation gets quietly redirected to the attacker, and it is the standard setup for business email compromise.`,
      mitre: ['T1656'],
    });
  }

  signals.push(...checkDomainImpersonation(fromDomain, 'sender', 'From'));

  // Reply-To can carry the same trick as From, and it's the address a reply
  // actually goes to — checked independently of fromDomain above rather than
  // only when it already disagrees with fromDomain, since a typosquatted
  // Reply-To next to a clean From is exactly how a "reply to the real person,
  // but from a lookalike" BEC setup would look.
  if (replyToDomain && (!fromDomain || registrableDomain(replyToDomain) !== registrableDomain(fromDomain))) {
    signals.push(...checkDomainImpersonation(replyToDomain, 'reply_to', 'Reply-To'));
  }

  const passed = /spf=pass/i.test(authResults) && /dkim=pass/i.test(authResults) && /dmarc=pass/i.test(authResults);

  if (passed) {
    signals.push({
      id: 'auth_fully_passed',
      category: 'authentication',
      severity: 'info',
      benign: true,
      label: 'Sender Authentication Passed',
      detail: 'SPF, DKIM and DMARC all passed, so the message genuinely came from the domain it claims. That confirms the sender, not their intent — a compromised account passes every one of these.',
    });
  }

  return { available: true, passed, signals, selectedAuthservId: selection.authservId };
}

export { checkAuthentication };
