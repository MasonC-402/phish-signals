// Assembly point: takes the output of every check, scores it, and builds the
// analyst-facing artifacts (IOCs, ATT&CK mapping, Sigma rule, recommendations).
//
// The scoring itself lives in lib/signals.ts — this file's job is only to
// gather evidence and hand it over, so that how findings are weighed stays in
// one place and independent of where they came from.

import { scoreSignals, assessConfidence } from './signals';
import { extractIocs } from './iocs';
import { mapTechniques } from './mitre';
import { buildSigmaRule } from './sigmaRule';
import { buildRecommendations } from './recommendations';
import { registrableDomain } from './domains';
import type {
  AuthCheckResult,
  CombinedResult,
  HeaderAnomalyResult,
  ParsedEmail,
  ReceivedChainAnalysis,
  Signal,
  SignalResult,
  UrlAnalysis,
} from './types';

export interface AnalysisInput {
  parsed: ParsedEmail;
  auth: AuthCheckResult;
  urls: UrlAnalysis[];
  urlSignals: Signal[];
  content: SignalResult;
  linkText: SignalResult;
  dangerousSchemes: SignalResult;
  qrCodes: SignalResult;
  attachments: SignalResult;
  chain: ReceivedChainAnalysis | null;
  headerAnomalies: HeaderAnomalyResult;
}

function domainOf(address: string | null): string | null {
  if (!address) return null;
  const match = address.match(/@([\w.-]+\.[a-z]{2,})/i);
  return match ? registrableDomain(match[1].toLowerCase()) : null;
}

function combineResults(input: AnalysisInput): CombinedResult {
  const { parsed, auth, chain } = input;

  const allSignals: Signal[] = [
    ...auth.signals,
    ...input.content.signals,
    ...input.linkText.signals,
    ...input.dangerousSchemes.signals,
    ...input.qrCodes.signals,
    ...input.attachments.signals,
    ...input.urlSignals,
    ...input.headerAnomalies.signals,
    ...(chain ? chain.signals : []),
  ];

  const scored = scoreSignals(allSignals);

  const confidence = assessConfidence({
    headers: parsed.isRawEmail,
    authResults: auth.available && !auth.signals.some((s) => s.id === 'no_auth_results'),
    receivedChain: Boolean(chain && chain.hops.length > 0),
    htmlPart: Boolean(parsed.htmlBody),
    // Whether we had structural visibility into attachments at all, not
    // whether any were actually found. A raw email with zero attachments was
    // still fully inspected — mailparser reports exactly what MIME parts
    // exist, so "none" is a real, complete answer, benign evidence the same
    // way urlCheck.ts's no_links_present is, not a gap. Only a plain-text
    // paste has no MIME structure to look at in the first place, which is the
    // actual "we could not check this" case this dimension exists to name.
    // (Previously this read `attachments.length > 0 || imageCount > 0`, so
    // every ordinary attachment-free raw email reported "No attachment
    // metadata was present" under "What this analysis could not see" — true
    // in the narrowest sense, but indistinguishable from a genuine gap.)
    attachmentMetadata: parsed.isRawEmail,
  });

  const senderDomain = domainOf(parsed.from);
  const replyToDomain = domainOf(parsed.replyTo);

  return {
    score: scored.score,
    verdict: scored.verdict,
    confidence,
    signals: scored.signals,
    benignSignals: scored.benignSignals,
    categories: scored.categories,
    urls: input.urls,
    recommendations: buildRecommendations({
      verdict: scored.verdict,
      signals: scored.signals,
      authAvailable: auth.available,
    }),
    mitre: mapTechniques(scored.signals),
    iocs: extractIocs({
      urls: input.urls,
      attachments: parsed.attachments,
      chain,
      from: parsed.from,
      replyTo: parsed.replyTo,
      returnPath: parsed.returnPath,
    }),
    sigmaRule: buildSigmaRule({
      subject: parsed.subject,
      senderDomain,
      replyToDomain,
      urls: input.urls,
      attachments: parsed.attachments,
      signals: scored.signals,
      verdict: scored.verdict,
      score: scored.score,
    }),
    authAvailable: auth.available,
    authPassed: auth.passed,
    receivedChain: chain,
  };
}

export { combineResults };
