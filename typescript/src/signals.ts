// The scoring engine.
//
// The previous model summed a hand-picked weight per finding and capped the
// total at 100. That had three problems worth naming, because the shape of this
// file is a direct response to each:
//
//  1. Correlated findings were summed as independent evidence. SPF fail (25) +
//     DKIM fail (25) + DMARC fail (25) = 75, but DMARC failing *is* SPF and DKIM
//     failing to align — one fact counted three times. An unauthenticated
//     message hit "High Risk" before exhibiting any phishing behaviour at all.
//  2. Nothing could lower a score. There was no way to express that a finding
//     argues the message is legitimate.
//  3. A bare 0-100 number implied calibration that hand-picked weights don't
//     have, and said nothing about how much of the message was actually visible.
//
// So: signals carry a category and a severity instead of a raw number. Within a
// category the strongest signal counts in full and the rest contribute at a
// steep discount (they corroborate, they aren't new information). Categories are
// treated as the independent axes, so breadth across categories moves the score
// far more than depth inside one — which matches how phishing actually presents.

import type {
  CategoryScore,
  Confidence,
  EvidenceCategory,
  Severity,
  Signal,
} from './types';
import { CATEGORY_LABELS } from './types';

const SEVERITY_POINTS: Record<Severity, number> = {
  critical: 45,
  high: 28,
  medium: 14,
  low: 6,
  info: 0,
};

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

// Corroborating signals within a category contribute at this rate. Not zero
// (three independent spoofing indicators is worse than one) but nowhere near
// full value.
const CORROBORATION_RATE = 0.25;

// No single category can max out the score on its own. Reaching "High Risk"
// requires evidence on more than one axis.
const MAX_CATEGORY_SCORE = 55;

const CATEGORY_ORDER: EvidenceCategory[] = [
  'authentication',
  'identity',
  'infrastructure',
  'payload',
  'social',
];

function severityRankOf(signal: Signal): number {
  return SEVERITY_RANK[signal.severity];
}

/** Worst first, then alphabetically by label for a stable order. */
function bySeverityDesc(a: Signal, b: Signal): number {
  const diff = severityRankOf(b) - severityRankOf(a);
  return diff !== 0 ? diff : a.label.localeCompare(b.label);
}

function scoreCategory(category: EvidenceCategory, signals: Signal[]): CategoryScore {
  const sorted = [...signals].sort(bySeverityDesc);
  const points = sorted.map((s) => SEVERITY_POINTS[s.severity]);

  const strongest = points.length > 0 ? points[0] : 0;
  const corroboration = points.slice(1).reduce((sum, p) => sum + p, 0) * CORROBORATION_RATE;

  return {
    category,
    label: CATEGORY_LABELS[category],
    score: Math.round(Math.min(strongest + corroboration, MAX_CATEGORY_SCORE)),
    signals: sorted,
  };
}

/**
 * Benign evidence (aligned DMARC pass, no links or attachments at all) reduces
 * the score — but only when nothing high-severity fired. A message carrying an
 * executable shouldn't be able to talk its way down because its SPF was valid;
 * plenty of real phishing is sent from correctly-configured infrastructure the
 * attacker controls outright.
 */
function benignAdjustment(benignSignals: Signal[], worstSeverityRank: number): number {
  if (worstSeverityRank >= SEVERITY_RANK.high) return 0;
  return benignSignals.length * -6;
}

function assessConfidence(available: {
  headers: boolean;
  authResults: boolean;
  receivedChain: boolean;
  htmlPart: boolean;
  attachmentMetadata: boolean;
}): Confidence {
  const gaps: string[] = [];
  if (!available.headers) gaps.push('No message headers — this looks like pasted body text, so sender and routing checks could not run.');
  if (!available.authResults) gaps.push('No Authentication-Results header, so SPF, DKIM and DMARC results are unknown.');
  if (!available.receivedChain) gaps.push('No Received headers, so the delivery path and originating server could not be traced.');
  if (!available.htmlPart) gaps.push('No HTML part, so link text could not be compared against link destinations.');
  if (!available.attachmentMetadata) gaps.push('No attachment metadata was present in what was submitted.');

  const checks = Object.values(available);
  const completeness = checks.filter(Boolean).length / checks.length;

  let level: Confidence['level'] = 'low';
  if (completeness >= 0.8) level = 'high';
  else if (completeness >= 0.5) level = 'medium';

  return { level, completeness, gaps };
}

export interface ScoredEvidence {
  score: number;
  verdict: 'Low Risk' | 'Medium Risk' | 'High Risk';
  categories: CategoryScore[];
  signals: Signal[];
  benignSignals: Signal[];
}

function scoreSignals(allSignals: Signal[]): ScoredEvidence {
  // Same id twice (e.g. two attachments both executable) counts once — the
  // second adds no new information about whether this is a phish.
  const seen = new Set<string>();
  const deduped = allSignals.filter((s) => {
    if (seen.has(s.id)) return false;
    seen.add(s.id);
    return true;
  });

  const benignSignals = deduped.filter((s) => s.benign);
  const suspicious = deduped.filter((s) => !s.benign);

  const categories = CATEGORY_ORDER
    .map((category) => scoreCategory(category, suspicious.filter((s) => s.category === category)))
    .filter((c) => c.signals.length > 0);

  const worstSeverityRank = suspicious.reduce((worst, s) => Math.max(worst, severityRankOf(s)), 0);
  const raw = categories.reduce((sum, c) => sum + c.score, 0)
    + benignAdjustment(benignSignals, worstSeverityRank);

  const score = Math.max(0, Math.min(Math.round(raw), 100));

  let verdict: ScoredEvidence['verdict'] = 'Low Risk';
  if (score >= 60) verdict = 'High Risk';
  else if (score >= 30) verdict = 'Medium Risk';

  return {
    score,
    verdict,
    categories,
    signals: [...suspicious].sort(bySeverityDesc),
    benignSignals,
  };
}

export { scoreSignals, assessConfidence, SEVERITY_POINTS, SEVERITY_RANK, MAX_CATEGORY_SCORE, CORROBORATION_RATE };
