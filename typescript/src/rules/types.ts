// Shared shapes for the phish-signals rule layer (src/rules/*.ts).
// Mirrors python/src/phish_signals/rules/types.py — see that file's module
// docstring for the design rationale (why Rule.id and Rule.emits are
// deliberately distinct, why RuleContext is derived-data-only, etc).

import { AuthCheckResult, EvidenceCategory, HeaderAnomalyResult, ParsedEmail, Signal, Severity, ReceivedChainAnalysis, UrlAnalysis } from '../types';
import { registrableDomain } from '../domains';

// Every value a Signal.severity is allowed to hold. Used to validate both
// rule-produced signals (engine.ts) and severity overrides (Ruleset below).
export const VALID_SEVERITIES: ReadonlySet<Severity> = new Set([
  'info',
  'low',
  'medium',
  'high',
  'critical',
]);

// Every value a Signal.category is allowed to hold. Same role as
// VALID_SEVERITIES, for the category field.
export const VALID_CATEGORIES: ReadonlySet<EvidenceCategory> = new Set([
  'authentication',
  'identity',
  'infrastructure',
  'payload',
  'social',
]);

// A rule id must be '<namespace>.<name>', both lowercase identifiers. The
// namespace is what stops a custom rule from colliding with a built-in by
// accident.
export const RULE_ID_PATTERN = /^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/;

// Namespace reserved for rules shipped by this package.
export const CORE_NAMESPACE = 'core';

// Same pattern combineResults.ts's domainOf() matches on — kept here too
// since RuleContext must not depend on combineResults.ts.
const ADDRESS_DOMAIN = /@([\w.-]+\.[a-z]{2,})/i;

// Base class for every error this layer raises.
export class RuleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RuleError';
  }
}

// A ruleset could not be assembled — bad id, or two rules claiming one
// signal.
export class RulesetError extends RuleError {
  constructor(message: string) {
    super(message);
    this.name = 'RulesetError';
  }
}

// Registrable domain of an email address, or null. Mirrors domainOf() in
// combineResults.ts exactly, including its tolerance of a bare hostname with
// no local part.
function domainOf(address: string | null | undefined): string | null {
  const match = address?.match(ADDRESS_DOMAIN);
  return match ? registrableDomain(match[1].toLowerCase()) : null;
}

// Memoizes a per-instance computation on first access — the closest this
// language gets to Python's functools.cached_property, which RuleContext's
// derived fields rely on below.
function lazy<T>(compute: () => T): () => T {
  let cache: { value: T } | undefined;
  return () => (cache ??= { value: compute() }).value;
}

// Everything a rule is allowed to look at, plus cached derivations of it.
// Assembled once, before any rule runs, from work the pipeline has already
// done — nothing here performs I/O. Only `parsed` is required so a content
// rule can be constructed and unit-tested without standing up the whole
// pipeline.
export class RuleContext {
  #scanTextLower = lazy(() => (this.parsed.scanText ?? '').toLowerCase());
  #bodyTextLower = lazy(() => (this.parsed.textBody ?? '').toLowerCase());
  #htmlBodyLower = lazy(() => (this.parsed.htmlBody ?? '').toLowerCase());
  #subjectLower = lazy(() => (this.parsed.subject ?? '').toLowerCase());
  #senderDomain = lazy(() => domainOf(this.parsed.from));
  #replyToDomain = lazy(() => domainOf(this.parsed.replyTo));
  #returnPathDomain = lazy(() => domainOf(this.parsed.returnPath));
  #linkHostnames = lazy(
    () => new Set(this.urls.map((url) => url.hostname?.toLowerCase()).filter((h): h is string => !!h)),
  );
  #linkDomains = lazy(
    () =>
      new Set(
        [...this.linkHostnames]
          .map((hostname) => registrableDomain(hostname))
          .filter((d): d is string => !!d),
      ),
  );

  constructor(
    public readonly parsed: ParsedEmail,
    public readonly urls: UrlAnalysis[] = [],
    public readonly auth: AuthCheckResult | null = null,
    public readonly chain: ReceivedChainAnalysis | null = null,
    public readonly headerAnomalies: HeaderAnomalyResult | null = null,
  ) {}

  // scan_text_lower: subject + text part + de-tagged HTML, lowercased once
  // rather than in every rule. The field content heuristics should normally
  // match against.
  get scanTextLower(): string {
    return this.#scanTextLower();
  }

  // Text part of the message body, lowercased.
  get bodyTextLower(): string {
    return this.#bodyTextLower();
  }

  // HTML part of the message body, lowercased.
  get htmlBodyLower(): string {
    return this.#htmlBodyLower();
  }

  // Subject line, lowercased.
  get subjectLower(): string {
    return this.#subjectLower();
  }

  // Registrable domain of the From address, or null.
  get senderDomain(): string | null {
    return this.#senderDomain();
  }

  // Registrable domain of the Reply-To address, or null.
  get replyToDomain(): string | null {
    return this.#replyToDomain();
  }

  // Registrable domain of the Return-Path address, or null.
  get returnPathDomain(): string | null {
    return this.#returnPathDomain();
  }

  // Every hostname a URL check managed to resolve, lowercased.
  get linkHostnames(): ReadonlySet<string> {
    return this.#linkHostnames();
  }

  // Registrable domains of linkHostnames.
  get linkDomains(): ReadonlySet<string> {
    return this.#linkDomains();
  }
}

// What a rule's callable must look like. Returns an array rather than a
// single optional signal so a rule that finds three lookalike domains can
// report three findings.
export type RuleFn = (context: RuleContext) => Signal[];

// One named piece of detection logic. `emits` is checked against what
// `evaluate` actually returns at run time (see engine.ts) — declaring it
// here is what lets a ruleset detect a signal-id collision between two rules
// before either has run.
export class Rule {
  readonly id: string;
  readonly emits: ReadonlySet<string>;
  readonly evaluate: RuleFn;
  readonly tags: ReadonlySet<string>;
  readonly description: string;

  constructor(
    id: string,
    emits: Iterable<string>,
    evaluate: RuleFn,
    tags: Iterable<string> = [],
    description = '',
  ) {
    if (!RULE_ID_PATTERN.test(id)) {
      throw new RulesetError(
        `invalid rule id '${id}': expected '<namespace>.<name>', lowercase letters, digits and underscores only (e.g. 'acme.vendor_lookalike')`,
      );
    }
    this.emits = new Set(emits);
    if (this.emits.size === 0) {
      throw new RulesetError(
        `rule '${id}' declares no signal ids in 'emits'; a rule that can never produce a signal cannot affect a verdict`,
      );
    }

    this.id = id;
    this.evaluate = evaluate;
    this.tags = new Set(tags);
    this.description = description;
  }

  get namespace(): string {
    return this.id.split('.')[0];
  }
}

// Serializable description of a rule, for listing a ruleset.
export interface RuleInfo {
  id: string;
  emits: string[];
  tags: string[];
  description: string;
}

// An ordered, immutable collection of rules. Every derivation method returns
// a new Ruleset — nothing mutates in place, so narrowing the default set for
// one message can't affect the next.
export class Ruleset implements Iterable<Rule> {
  readonly name: string;
  readonly rules: readonly Rule[];
  readonly severityOverrides: Readonly<Record<string, Severity>>;

  constructor(
    name: string,
    rules: readonly Rule[] = [],
    severityOverrides: Readonly<Record<string, Severity>> = {},
  ) {
    this.name = name;
    this.rules = [...rules];
    this.severityOverrides = { ...severityOverrides };
    this.validate();
  }

  // Raises RulesetError on a duplicate rule id or duplicate signal id. The
  // signal-id case is the one that matters: a duplicate rule id is an
  // obvious mistake, but a duplicate *signal* id loads and runs cleanly and
  // quietly drops one rule's findings at scoring time.
  validate(): void {
    const seenRuleIds = new Set<string>();
    const emitters = new Map<string, Rule>();

    for (const rule of this.rules) {
      if (seenRuleIds.has(rule.id)) {
        throw new RulesetError(
          `ruleset '${this.name}' contains rule id '${rule.id}' twice; rule ids must be unique (use Ruleset.replaceRule to substitute one deliberately)`,
        );
      }
      seenRuleIds.add(rule.id);

      for (const signalId of [...rule.emits].sort()) {
        const owner = emitters.get(signalId);
        if (owner) {
          throw new RulesetError(
            `ruleset '${this.name}': rules '${owner.id}' and '${rule.id}' both emit signal id '${signalId}'. scoreSignals() deduplicates by signal id and keeps only the first, so one of these rules would be silently discarded. Rename the signal, or use Ruleset.replaceRule('${owner.id}', ...) if you meant to override it.`,
          );
        }
        emitters.set(signalId, rule);
      }
    }

    for (const [signalId, severity] of Object.entries(this.severityOverrides)) {
      if (!VALID_SEVERITIES.has(severity)) {
        throw new RulesetError(
          `ruleset '${this.name}': severity override for signal id '${signalId}' has invalid severity '${severity}'; must be one of ${JSON.stringify([...VALID_SEVERITIES].sort())}`,
        );
      }
      if (!emitters.has(signalId)) {
        throw new RulesetError(
          `ruleset '${this.name}': severity override for signal id '${signalId}', which no rule in this ruleset emits`,
        );
      }
    }
  }

  // Rules run in this order — see the module comment on validate() for why
  // that order matters.
  [Symbol.iterator](): Iterator<Rule> {
    return this.rules[Symbol.iterator]();
  }

  get length(): number {
    return this.rules.length;
  }

  // Rule by id, or null if this ruleset has none with that id.
  get(ruleId: string): Rule | null {
    return this.rules.find((r) => r.id === ruleId) ?? null;
  }

  // Lists what is in this ruleset, in run order, as plain JSON-able data.
  describe(): RuleInfo[] {
    return this.rules.map((rule) => ({
      id: rule.id,
      emits: [...rule.emits].sort(),
      tags: [...rule.tags].sort(),
      description: rule.description,
    }));
  }

  // Appends rules. Throws if any collides with what is already here.
  withRules(extra: Iterable<Rule>, name?: string): Ruleset {
    return new Ruleset(name ?? this.name, [...this.rules, ...extra], this.severityOverrides);
  }

  // Swaps one rule for another, in place, keeping run order — the supported
  // way to override a built-in with something that emits the same signal id.
  replaceRule(ruleId: string, newRule: Rule): Ruleset {
    if (!this.get(ruleId)) {
      throw new RulesetError(`ruleset '${this.name}' has no rule '${ruleId}' to replace`);
    }
    return new Ruleset(
      this.name,
      this.rules.map((r) => (r.id === ruleId ? newRule : r)),
      this.severityOverrides,
    );
  }

  // Drops rules by id. Unknown ids are ignored — this is a filter, not a
  // lookup.
  without(ruleIds: Iterable<string>): Ruleset {
    const drop = new Set(ruleIds);
    return this.#rebuild(this.rules.filter((r) => !drop.has(r.id)));
  }

  // Drops every rule carrying any of these tags.
  withoutTags(tags: Iterable<string>): Ruleset {
    const drop = new Set(tags);
    return this.#rebuild(this.rules.filter((r) => ![...r.tags].some((t) => drop.has(t))));
  }

  // Keeps only rules carrying at least one of these tags.
  withTags(tags: Iterable<string>): Ruleset {
    const keep = new Set(tags);
    return this.#rebuild(this.rules.filter((r) => [...r.tags].some((t) => keep.has(t))));
  }

  // Returns a ruleset with these signal-id severity overrides merged in.
  withSeverityOverrides(overrides: Readonly<Record<string, Severity>>): Ruleset {
    return new Ruleset(this.name, this.rules, { ...this.severityOverrides, ...overrides });
  }

  // Rebuilds after a filter, dropping overrides that no longer apply —
  // otherwise validate() would reject the result for a dangling override the
  // filter itself caused.
  #rebuild(kept: readonly Rule[]): Ruleset {
    const stillEmitted = new Set(kept.flatMap((r) => [...r.emits]));
    const prunedOverrides = Object.fromEntries(
      Object.entries(this.severityOverrides).filter(([signalId]) => stillEmitted.has(signalId)),
    );
    return new Ruleset(this.name, kept, prunedOverrides);
  }
}
