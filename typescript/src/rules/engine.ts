// Runs a ruleset against a context and collects the signals it produced.
// Mirrors python/src/phish_signals/rules/engine.py — see that file's module
// docstring for why this layer exists (fault isolation, emission checking,
// severity overrides) rather than just `rules.flatMap(r => r.evaluate(ctx))`.

import { EvidenceCategory, Severity, Signal } from '../types';
import { Rule, RuleContext, Ruleset, VALID_CATEGORIES, VALID_SEVERITIES } from './types';

// Why a rule contributed nothing, or contributed less than it tried to.
export type DiagnosticKind = 'error' | 'undeclared_signal' | 'malformed_signal';

// A rule that misbehaved, in JSON-able form. Meant to reach the caller —
// folded into a result, logged, or surfaced in a report's footer — so this
// is a plain shape, not a class: it crosses into conformance-compared output
// the same way a Signal does.
export interface RuleDiagnostic {
  ruleId: string;
  kind: DiagnosticKind;
  // Human-readable, safe to show. Never contains message content.
  message: string;
}

// What a ruleset produced: the evidence, and anything that went wrong.
export interface RuleRunResult {
  signals: Signal[];
  diagnostics: RuleDiagnostic[];
}

// Cheap structural check for the five required Signal keys. Worth doing
// because a rule is third-party code and a malformed value should not fail
// much later, inside scoring or JSON export, with an error that names
// neither the rule nor the message that triggered it. Also validates that
// category, severity, and id are within the allowed values — an invalid
// severity silently scores zero points, and an invalid category silently
// drops the signal from every category bucket, so both produce evidence
// that is not reflected in the verdict.
function looksLikeSignal(value: unknown): value is Signal {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;

  const hasRequiredStrings = ['id', 'category', 'severity', 'label', 'detail'].every(
    (key) => typeof v[key] === 'string',
  );
  if (!hasRequiredStrings) return false;

  return (
    !!v.id &&
    VALID_CATEGORIES.has(v.category as EvidenceCategory) &&
    VALID_SEVERITIES.has(v.severity as Severity)
  );
}

// Returns a copy of `signal` at a new severity. Spread-and-replace rather
// than field assignment: it copies exactly the keys present and no others,
// so a signal without `mitre` does not come back with `mitre` set to
// undefined. Under the deep equality conformance uses, those are different
// values.
function applyOverride(signal: Signal, severity: Severity): Signal {
  return { ...signal, severity };
}

// Runs one rule against context, with fault isolation, emission checking,
// and severity overrides — the three things evaluateRuleset adds over a bare
// rules.flatMap(r => r.evaluate(ctx)).
function runRule(
  rule: Rule,
  context: RuleContext,
  overrides: Readonly<Record<string, Severity>>,
  strict: boolean,
): { signals: Signal[]; diagnostics: RuleDiagnostic[] } {
  const signals: Signal[] = [];
  const diagnostics: RuleDiagnostic[] = [];

  let items: Signal[];
  try {
    const produced = rule.evaluate(context);
    if (produced == null) return { signals, diagnostics };
    items = produced;
  } catch (exc) {
    if (strict) throw exc;
    diagnostics.push({
      ruleId: rule.id,
      kind: 'error',
      // Constructor name only — a caught error's message can contain
      // attacker-controlled content lifted from the email being analyzed,
      // and diagnostics are documented as safe to display and log.
      message: exc instanceof Error ? exc.constructor.name : 'Error',
    });
    return { signals, diagnostics };
  }

  for (const item of items) {
    if (!looksLikeSignal(item)) {
      diagnostics.push({
        ruleId: rule.id,
        kind: 'malformed_signal',
        message:
          `rule returned a value that is not a Signal (${typeof item}); a Signal needs ` +
          "string 'id', 'category', 'severity', 'label' and 'detail'",
      });
      continue;
    }

    const signalId = item.id;
    if (!rule.emits.has(signalId)) {
      diagnostics.push({
        ruleId: rule.id,
        kind: 'undeclared_signal',
        message:
          `emitted signal id '${signalId}', which is not in the rule's declared emits ` +
          `${JSON.stringify([...rule.emits].sort())}; dropped because an undeclared id ` +
          "bypasses the ruleset's collision check and can suppress another rule's finding",
      });
      continue;
    }

    const override = overrides[signalId];
    signals.push(override ? applyOverride(item, override) : item);
  }

  return { signals, diagnostics };
}

// Runs every rule in `ruleset` against `context`.
//
// `strict`: re-raise instead of isolating a failing rule. Off by default,
// because in production one broken rule losing the whole analysis is worse
// than one broken rule losing its own finding. Turn it on in tests and CI,
// where a rule throwing is a defect you want to see as a failure rather than
// as a diagnostic nobody reads.
export function evaluateRuleset(
  ruleset: Ruleset,
  context: RuleContext,
  { strict = false }: { strict?: boolean } = {},
): RuleRunResult {
  const overrides = ruleset.severityOverrides;
  const signals: Signal[] = [];
  const diagnostics: RuleDiagnostic[] = [];

  for (const rule of ruleset) {
    const result = runRule(rule, context, overrides, strict);
    signals.push(...result.signals);
    diagnostics.push(...result.diagnostics);
  }

  return { signals, diagnostics };
}

// One line per diagnostic, for logging. Empty string when there are none.
export function formatDiagnostics(diagnostics: readonly RuleDiagnostic[]): string {
  return diagnostics.map((d) => `[${d.kind}] ${d.ruleId}: ${d.message}`).join('\n');
}

// Stack trace for a rule failure, for a debugger rather than a log. Kept out
// of RuleDiagnostic on purpose — it can contain message content lifted from
// the email being analyzed, and diagnostics are designed to be safe to
// display and ship. Call this yourself, with `strict: true`, when you are
// debugging a rule and know where the output is going.
export function ruleTraceback(exc: unknown): string {
  if (exc instanceof Error && exc.stack) return exc.stack;
  return String(exc);
}
