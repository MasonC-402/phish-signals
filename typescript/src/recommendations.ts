// Turns findings into what to actually do about them.
//
// A tool that returns "High Risk, 87/100" and stops has handed the reader a
// number, not an answer. This site's audience is small and mid-sized businesses
// without a security team, so the most useful output is the next action —
// especially the "if you already clicked it" case, where the window to limit
// the damage is measured in minutes and is exactly when someone goes looking
// for a tool like this.

import type { Recommendation, Signal } from './types';

interface RecommendationInput {
  verdict: 'Low Risk' | 'Medium Risk' | 'High Risk';
  signals: Signal[];
  authAvailable: boolean;
}

function buildRecommendations(input: RecommendationInput): Recommendation[] {
  const ids = new Set(input.signals.map((s) => s.id));
  const has = (...candidates: string[]) => candidates.some((id) => ids.has(id));

  const recommendations: Recommendation[] = [];

  const credentialRisk = has('credential_request', 'malicious_links', 'deceptive_link_text', 'suspicious_links');
  const attachmentRisk = has(
    'attachment_executable', 'attachment_double_extension', 'attachment_macro_document',
    'attachment_disk_image', 'attachment_shortcut'
  );

  if (input.verdict === 'High Risk' || input.verdict === 'Medium Risk') {
    recommendations.push({
      urgency: 'now',
      text: 'Do not click any link, open any attachment, or reply to this message.',
    });
  }

  // Deliberately first among the conditional actions: someone who already
  // entered a password is the person with the least time to spare.
  if (credentialRisk) {
    recommendations.push({
      urgency: 'now',
      text: 'If you already entered a password on a page this message linked to, change that password now on every account that shares it, then turn on multi-factor authentication. Do it from a different device if you can.',
    });
  }

  if (attachmentRisk) {
    recommendations.push({
      urgency: 'now',
      text: 'If you already opened the attachment (or clicked "Enable Content" in a document), disconnect the machine from the network and get it looked at before using it further.',
    });
  }

  if (has('financial_request', 'authority_impersonation')) {
    recommendations.push({
      urgency: 'now',
      text: 'Do not act on any payment request or change of bank details from this message. Confirm it by phone on a number you already had, never a number or link from the email itself.',
    });
  }

  if (has('reply_to_mismatch')) {
    recommendations.push({
      urgency: 'soon',
      text: 'Replies to this message go to a different domain than it appears to come from. If you have already replied, treat that thread as compromised and restart the conversation through a known-good address.',
    });
  }

  if (input.verdict !== 'Low Risk') {
    recommendations.push({
      urgency: 'soon',
      text: 'Report it: use the "Report phishing" button in your mail client, and forward it to your IT or security contact. That is what gets the sender blocked for everyone else in your organization.',
    });
  }

  if (!input.authAvailable) {
    recommendations.push({
      urgency: 'context',
      text: 'This analysis had no message headers to work with, so the sender could not be verified at all. For a much stronger answer, resubmit using "Show original" / "View source" in your mail client, or upload the saved .eml or .msg file.',
    });
  }

  if (input.verdict === 'Low Risk') {
    recommendations.push({
      urgency: 'context',
      text: 'Nothing conclusive was found, but these are structural heuristics with no view of reputation or content history. If the message asks you to move money, change credentials, or act urgently, verify it through a second channel regardless of this result.',
    });
  }

  return recommendations;
}

export { buildRecommendations };
