// Rule-based content analysis — no external API calls, no cost

import { registrableDomain } from './domains';
import { evaluateRuleset } from './rules/engine';
import { parseRuleFile } from './rules/loader';
import { RuleContext, Ruleset } from './rules/types';
import contentRuleData from './rules/data/content.json';
import type { LinkMismatch, Signal, SignalResult } from './types';

const GENERIC_GREETING_PATTERNS = [
  /^dear (customer|user|member|valued customer|sir\/madam)/im,
  /^dear [a-z]+@/im,
  /^(hello|hi) (customer|user|member)\b/im,
];

const KNOWN_BRAND_NAMES = [
  'paypal', 'amazon', 'microsoft', 'apple', 'bank of america', 'chase',
  'wells fargo', 'irs', 'netflix', 'docusign', 'google', 'facebook',
  'linkedin', 'dropbox', 'adobe', 'fedex', 'ups', 'usps', 'dhl',
  'coinbase', 'american express', 'citibank', 'office 365', 'onedrive',
];

// The four phrase-list rules (urgency, credential request, financial request,
// authority impersonation) are declarative data, shared with the Python port:
// the canonical copy is rules/core/content.json at the repo root, and
// ./rules/data/content.json is a byte-identical copy that conformance.test.ts
// checks against it. Edit the canonical file, then run `python3 rules/sync.py`.
// The remaining checks below stay as code because they need regexes or
// structured logic the rule grammar deliberately excludes.
const CONTENT_PHRASE_RULESET = new Ruleset(
  'content',
  parseRuleFile(contentRuleData as Record<string, unknown>, 'rules/data/content.json'),
);

function phraseRuleContext(text: string, fromAddress: string | null): RuleContext {
  return new RuleContext({
    isRawEmail: false,
    from: fromAddress,
    returnPath: null,
    replyTo: null,
    subject: null,
    date: null,
    headers: null,
    headerLines: [],
    textBody: text,
    htmlBody: null,
    scanText: text,
    urls: [],
    linkMismatches: [],
    dangerousSchemes: [],
    attachments: [],
    imageCount: 0,
    qrCodeUrls: [],
    qrImagesScanned: 0,
  });
}

function checkContent(bodyText: string | null | undefined, fromAddress: string | null | undefined): SignalResult {
  const signals: Signal[] = [];
  const text = bodyText || '';

  // Severity scales with how many distinct phrases hit (the rule file's
  // escalate_to / when_hits_at_least). One "urgent" is a word; four pressure
  // phrases in one message is a technique. strict: a phrase rule throwing is
  // a defect in shipped data, not something to swallow as a diagnostic.
  const phraseRun = evaluateRuleset(CONTENT_PHRASE_RULESET, phraseRuleContext(text, fromAddress || null), { strict: true });
  signals.push(...phraseRun.signals);

  if (GENERIC_GREETING_PATTERNS.some((re) => re.test(text))) {
    signals.push({
      id: 'generic_greeting',
      category: 'social',
      severity: 'low',
      label: 'Generic Greeting',
      detail: 'Addresses you generically rather than by name. An organization that holds an account for you generally knows your name.',
    });
  }

  if (fromAddress) {
    const displayNameMatch = fromAddress.match(/^"?([^"<]+)"?\s*<(.+)>$/);
    if (displayNameMatch) {
      const displayName = displayNameMatch[1].trim().toLowerCase();
      const actualEmail = displayNameMatch[2].trim().toLowerCase();

      const claimsBrand = KNOWN_BRAND_NAMES.find((b) => displayName.includes(b));
      if (claimsBrand && !actualEmail.includes(claimsBrand.replace(/\s/g, ''))) {
        signals.push({
          id: 'display_name_brand_spoof',
          category: 'identity',
          severity: 'high',
          label: 'Display Name Spoofing',
          detail: `The sender name says "${claimsBrand}" but the actual address is ${actualEmail}. Most mail clients show only the name, so this is what the recipient sees.`,
          mitre: ['T1656'],
        });
      }

      // "support@paypal.com" <attacker@evil.tk> — the display name is itself an
      // address, so a client that shows only the name shows something entirely
      // different from where the mail came from.
      const displayAsEmail = displayName.match(/[\w.+-]+@([\w.-]+\.[a-z]{2,})/i);
      if (displayAsEmail) {
        const claimedDomain = registrableDomain(displayAsEmail[1]);
        const actualDomain = registrableDomain(actualEmail.split('@')[1] || '');
        if (claimedDomain && actualDomain && claimedDomain !== actualDomain) {
          signals.push({
            id: 'display_name_address_spoof',
            category: 'identity',
            severity: 'high',
            label: 'Sender Address Spoofing',
            detail: `The display name shows an address at "${claimedDomain}", but the message was actually sent from "${actualDomain}".`,
            mitre: ['T1656'],
          });
        }
      }
    }
  }

  const capsWords = text.match(/\b[A-Z]{4,}\b/g) || [];
  if (capsWords.length >= 5) {
    signals.push({
      id: 'excessive_capitalization',
      category: 'social',
      severity: 'low',
      label: 'Excessive Capitalization',
      detail: 'Unusually heavy use of all-caps words, typically used to manufacture alarm.',
    });
  }

  return { signals };
}

// Anchors whose visible text names one domain while the href points somewhere
// else. Reported separately from the URL table because the deception is in the
// pairing, not in either URL alone — the destination can be an entirely
// ordinary-looking domain and the link still be a lie.
function checkLinkText(mismatches: LinkMismatch[] | undefined): SignalResult {
  const list = mismatches || [];
  if (list.length === 0) return { signals: [] };

  const examples = list
    .slice(0, 3)
    .map((m) => `"${m.claimedDomain}" actually goes to "${m.actualDomain}"`)
    .join('; ');

  return {
    signals: [{
      id: 'deceptive_link_text',
      category: 'payload',
      severity: 'high',
      label: 'Deceptive Link Text',
      detail: `${list.length} link${list.length === 1 ? '' : 's'} display one destination but point at another: ${examples}. There is no legitimate reason for a link to misstate where it goes.`,
      mitre: ['T1566.002', 'T1204.001'],
    }],
  };
}

const SCHEME_EXPLANATIONS: Record<string, string> = {
  data: 'a data: link can encode an entire fake page inline, with no hostname at all for a domain-based check to examine',
  javascript: 'a javascript: link runs code the moment it is clicked, with no page navigation involved',
  vbscript: 'a vbscript: link runs code the moment it is clicked, an old mechanism still occasionally abused',
};

// href="data:...", href="javascript:...". Structurally different from every
// other link finding in this file: those are about a link lying about where
// it goes, this is about a link having no "where" at all for a domain-based
// check to examine.
function checkDangerousSchemes(schemes: string[] | undefined): SignalResult {
  const list = schemes || [];
  if (list.length === 0) return { signals: [] };

  const explanations = list
    .map((s) => SCHEME_EXPLANATIONS[s] || `a ${s}: link is not a normal way for a link in an email to work`)
    .join('; ');

  return {
    signals: [{
      id: 'dangerous_link_scheme',
      category: 'payload',
      severity: 'high',
      label: 'Link Uses a Non-Web Scheme',
      detail: `The message contains a link using ${list.join('/')} instead of http(s). ${explanations}. There is no legitimate reason for this to appear in an email.`,
      mitre: ['T1566.002', 'T1204.001'],
    }],
  };
}

export { checkContent, checkLinkText, checkDangerousSchemes };
