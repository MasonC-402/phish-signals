// Rule-based content analysis — no external API calls, no cost

import { registrableDomain } from './domains';
import type { LinkMismatch, Signal, SignalResult } from './types';

const URGENCY_PHRASES = [
  'act now', 'immediate action', 'act immediately', 'urgent', 'act today',
  'account will be suspended', 'account suspended', 'account has been limited',
  'verify your account', 'confirm your identity', 'unusual activity',
  'suspended your account', 'your account will be closed', 'expires today',
  'expires in 24 hours', 'final notice', 'immediately or', 'failure to comply',
  'within 24 hours', 'last warning', 'avoid suspension', 'will be terminated',
];

const CREDENTIAL_REQUEST_PHRASES = [
  'enter your password', 'confirm your password', 'update your payment',
  'verify your payment', 'social security number', 'confirm your ssn',
  'login to verify', 'sign in to confirm', 'reset your password immediately',
  'provide your card number', 'confirm your card details', 'verify your login',
  're-enter your credentials', 'validate your account',
];

const FINANCIAL_REQUEST_PHRASES = [
  'wire transfer', 'gift card', 'gift cards', 'itunes card', 'google play card',
  'bitcoin', 'crypto payment', 'send payment to', 'update bank details',
  'change of payment', 'invoice attached', 'overdue invoice', 'outstanding balance',
  'routing number', 'account number', 'change in banking', 'remittance advice',
  'payment instructions', 'updated banking details',
];

const AUTHORITY_IMPERSONATION_PHRASES = [
  'this is your ceo', 'this is the ceo', 'on behalf of the ceo',
  'from the it department', 'it support team', 'helpdesk team',
  'this is urgent from', 'confidential request', 'do not discuss this',
  'keep this confidential', "don't tell anyone", 'between us',
  'are you at your desk', 'i need a favor', 'handle this discreetly',
];

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

function scanPhrases(text: string, phraseList: string[]): string[] {
  const lower = text.toLowerCase();
  return phraseList.filter((phrase) => lower.includes(phrase));
}

function quote(hits: string[]): string {
  return `"${hits.slice(0, 3).join('", "')}"`;
}

function checkContent(bodyText: string | null | undefined, fromAddress: string | null | undefined): SignalResult {
  const signals: Signal[] = [];
  const text = bodyText || '';

  // Severity scales with how many distinct phrases hit. One "urgent" is a word;
  // four pressure phrases in one message is a technique.
  const urgencyHits = scanPhrases(text, URGENCY_PHRASES);
  if (urgencyHits.length > 0) {
    signals.push({
      id: 'urgency_language',
      category: 'social',
      severity: urgencyHits.length >= 3 ? 'medium' : 'low',
      label: 'Urgency / Pressure Language',
      detail: `Contains phrases designed to rush you past thinking it through: ${quote(urgencyHits)}. Manufactured time pressure is the most consistent feature of phishing.`,
      mitre: ['T1566'],
    });
  }

  const credentialHits = scanPhrases(text, CREDENTIAL_REQUEST_PHRASES);
  if (credentialHits.length > 0) {
    signals.push({
      id: 'credential_request',
      category: 'social',
      severity: 'medium',
      label: 'Credential Request',
      detail: `Asks for login credentials or personal verification: ${quote(credentialHits)}. Legitimate organizations do not ask you to confirm a password by email.`,
      mitre: ['T1566.002', 'T1598.003'],
    });
  }

  const financialHits = scanPhrases(text, FINANCIAL_REQUEST_PHRASES);
  if (financialHits.length > 0) {
    signals.push({
      id: 'financial_request',
      category: 'social',
      severity: 'medium',
      label: 'Financial Request',
      detail: `References payment, transfer, or a change to financial details: ${quote(financialHits)}. Changed banking details arriving by email is the core of invoice fraud.`,
      mitre: ['T1566'],
    });
  }

  const impersonationHits = scanPhrases(text, AUTHORITY_IMPERSONATION_PHRASES);
  if (impersonationHits.length > 0) {
    signals.push({
      id: 'authority_impersonation',
      category: 'social',
      severity: 'medium',
      label: 'Authority Impersonation / Secrecy Request',
      detail: `Claims executive or IT authority, or asks you to keep it quiet: ${quote(impersonationHits)}. A request for secrecy exists to stop you verifying it through a second channel.`,
      mitre: ['T1656'],
    });
  }

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
