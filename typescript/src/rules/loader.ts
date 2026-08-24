/*
The declarative rule format: phishing rules as JSON data rather than code.

Most of what this engine looks for in message *content* is a phrase list and a
severity. ``checkContent`` in the TypeScript reference is four such lists and
four near-identical blocks of code around them. Written as code, each of those
has to be written twice — once per implementation — and every phrase added to
one side is drift until somebody adds it to the other. Written as data,
both implementations load the same file and there is nothing to keep in sync.

That is the whole argument for this module. It is not about making rules
prettier; it is about deleting a category of divergence that the
``conformance/`` suite otherwise exists to catch after the fact.

**What is deliberately not here: regular expressions.** This library feeds
attacker-controlled text into whatever matcher a rule declares. A regex
engine that backtracks has no timeout, and a user-supplied pattern plus a
crafted body is a denial of service in a library whose entire job is parsing
hostile input — and the person who wrote the rule is usually not the person
running it. So the declarative grammar is a closed set of matchers with
bounded cost, and free-form patterns are only available in code rules, where
whoever wrote the pattern is whoever ships it and owns the risk. Substring
scanning covers the overwhelming majority of real content rules; the handful
that genuinely need a pattern (generic-greeting detection, for instance) are
worth the few lines of code as a code rule instead.

Format — one JSON file per group of rules::

    {
      "version": 1,
      "namespace": "core",
      "rules": [
        {
          "id": "urgency_language",
          "category": "social",
          "label": "Urgency / Pressure Language",
          "severity": {
            "base": "low", "escalate_to": "medium", "when_hits_at_least": 3
          },
          "match": {
            "type": "phrases", "field": "scan_text", "any_of": ["act now"]
          },
          "detail": "Contains phrases designed to rush you: {hits}.",
          "mitre": ["T1566"],
          "tags": ["content"]
        }
      ]
    }

Validation is strict and unknown keys are an error, not a warning. A typo'd
``"severty"`` that loads quietly gives you a rule running at the wrong weight
with nothing to indicate it, which is worse than a file that refuses to load.
*/

import * as fs from 'node:fs';
import * as path from 'node:path';

import { EvidenceCategory, Severity, Signal } from '../types';
import { Rule, RuleContext, RuleError, RuleFn, Ruleset, VALID_CATEGORIES, VALID_SEVERITIES } from './types';

/** Format version understood by this loader. A file declaring anything else
 * is rejected rather than best-effort parsed, so that adding a matcher type
 * later cannot make an old loader silently ignore it. */
export const FORMAT_VERSION = 1;

/** Name of the `RuleContext` getter each `phrases` matcher field reads from,
 * already lowercased so a per-message lowercasing does not happen once per
 * rule. `scan_text` is the usual choice — subject plus text part plus
 * de-tagged HTML — so a lure that appears only in the subject or only inside
 * markup is still caught. */
export const TEXT_FIELDS: Readonly<Record<string, keyof RuleContext>> = {
  scan_text: 'scanTextLower',
  body_text: 'bodyTextLower',
  html_body: 'htmlBodyLower',
  subject: 'subjectLower',
};

const RULE_KEYS: ReadonlySet<string> = new Set([
  'id',
  'signal_id',
  'category',
  'label',
  'severity',
  'match',
  'detail',
  'mitre',
  'benign',
  'tags',
  'description',
]);
const REQUIRED_RULE_KEYS: ReadonlySet<string> = new Set([
  'id',
  'category',
  'label',
  'severity',
  'match',
  'detail',
]);
const FILE_KEYS: ReadonlySet<string> = new Set(['version', 'namespace', 'rules']);
const SEVERITY_KEYS: ReadonlySet<string> = new Set(['base', 'escalate_to', 'when_hits_at_least']);
const PHRASES_KEYS: ReadonlySet<string> = new Set(['type', 'field', 'any_of']);

/** A rule file was malformed. Names the file and the rule where possible. */
export class RuleLoadError extends RuleError {
  constructor(message: string) {
    super(message);
    this.name = 'RuleLoadError';
  }
}

function fail(where: string, message: string): RuleLoadError {
  return new RuleLoadError(`${where}: ${message}`);
}

/** Type name for an error message — not conformance-compared, so it only
 * needs to be readable, not identical to Python's `type(value).__name__`. */
function typeNameOf(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

function requireMapping(value: unknown, where: string, what: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw fail(where, `${what} must be an object, got ${typeNameOf(value)}`);
  }
  return value as Record<string, unknown>;
}

/** Rejects unknown keys rather than ignoring them, so a typo cannot silently
 * change what a rule does. */
function checkKeys(data: Record<string, unknown>, allowed: ReadonlySet<string>, where: string, what: string): void {
  const unknown = Object.keys(data)
    .filter((key) => !allowed.has(key))
    .sort();
  if (unknown.length > 0) {
    throw fail(
      where,
      `unknown ${what} key(s) ${JSON.stringify(unknown)}; allowed keys are ` +
        `${JSON.stringify([...allowed].sort())}. Unknown keys are rejected rather than ` +
        'ignored so a typo cannot silently change what a rule does',
    );
  }
}

function stringList(value: unknown, where: string, what: string): string[] {
  if (!Array.isArray(value) || !value.every((v) => typeof v === 'string')) {
    throw fail(where, `${what} must be a list of strings`);
  }
  return value as string[];
}

/** Renders matched phrases the way the reference implementation does: first
 * three hits, double-quoted, comma-separated — because this string lands in
 * `Signal.detail`, which conformance vectors compare verbatim. */
export function quoteHits(hits: readonly string[]): string {
  return `"${hits.slice(0, 3).join('", "')}"`;
}

/** Substitutes `{hits}` and `{hit_count}` into a detail template.
 *
 * Plain replacement rather than a template-literal-style engine: a template
 * loaded from a file must not be able to execute anything, and a literal
 * brace anywhere in a detail string — entirely plausible in security copy —
 * must not break substitution. `replaceAll` (not `replace`) matters here:
 * `replace` only touches the first match, and Python's `str.replace` — which
 * this mirrors for conformance — replaces every occurrence. */
export function renderDetail(template: string, hits: readonly string[]): string {
  return template.replaceAll('{hits}', quoteHits(hits)).replaceAll('{hit_count}', String(hits.length));
}

/** Returns `[base, escalated, threshold]`.
 *
 * Severity scaling with hit count is in the format because it is the pattern
 * the existing content checks already use, and for a good reason: one
 * "urgent" is a word, four pressure phrases in one message is a technique. A
 * plain string means no escalation, expressed as a threshold no hit count
 * can reach. */
function parseSeverity(value: unknown, where: string): [Severity, Severity, number] {
  if (typeof value === 'string') {
    if (!VALID_SEVERITIES.has(value as Severity)) {
      throw fail(where, `severity '${value}' is not one of ${JSON.stringify([...VALID_SEVERITIES].sort())}`);
    }
    const severity = value as Severity;
    return [severity, severity, 1 << 30];
  }

  const spec = requireMapping(value, where, 'severity');
  checkKeys(spec, SEVERITY_KEYS, where, 'severity');

  const baseRaw = spec.base;
  if (typeof baseRaw !== 'string' || !VALID_SEVERITIES.has(baseRaw as Severity)) {
    throw fail(where, `severity.base '${String(baseRaw)}' is not one of ${JSON.stringify([...VALID_SEVERITIES].sort())}`);
  }
  const base = baseRaw as Severity;

  if (!('escalate_to' in spec)) {
    if ('when_hits_at_least' in spec) {
      throw fail(
        where,
        'severity.when_hits_at_least is set but escalate_to is absent; a threshold without ' +
          'an escalation target has no effect and is likely a mistake',
      );
    }
    return [base, base, 1 << 30];
  }

  const escalateRaw = spec.escalate_to;
  if (typeof escalateRaw !== 'string' || !VALID_SEVERITIES.has(escalateRaw as Severity)) {
    throw fail(
      where,
      `severity.escalate_to '${String(escalateRaw)}' is not one of ${JSON.stringify([...VALID_SEVERITIES].sort())}`,
    );
  }
  const escalated = escalateRaw as Severity;

  const threshold = spec.when_hits_at_least;
  if (typeof threshold !== 'number' || !Number.isInteger(threshold) || threshold < 1) {
    throw fail(where, 'severity.when_hits_at_least must be an integer >= 1 when escalate_to is set');
  }
  return [base, escalated, threshold];
}

/** Validates a `phrases` matcher and returns `[contextAttr, phrases]`. */
function buildPhrasesMatcher(spec: Record<string, unknown>, where: string): [keyof RuleContext, string[]] {
  checkKeys(spec, PHRASES_KEYS, where, 'match');

  const fieldName = spec.field ?? 'scan_text';
  if (typeof fieldName !== 'string' || !(fieldName in TEXT_FIELDS)) {
    throw fail(where, `match.field '${String(fieldName)}' is not one of ${JSON.stringify(Object.keys(TEXT_FIELDS).sort())}`);
  }

  const phrases = stringList(spec.any_of, where, 'match.any_of');
  if (phrases.length === 0) {
    throw fail(where, 'match.any_of must contain at least one phrase');
  }

  for (const phrase of phrases) {
    if (phrase !== phrase.toLowerCase()) {
      throw fail(
        where,
        `match.any_of entry '${phrase}' contains uppercase; phrases are matched against ` +
          'pre-lowercased text, so an uppercase phrase can never match. Write it lowercase',
      );
    }
    if (phrase.trim() === '') {
      throw fail(where, 'match.any_of contains an empty phrase');
    }
  }

  // Order is preserved, not sorted: the reference filters the declared list
  // in declaration order, and the first three survivors are what `{hits}`
  // renders. Sorting here would change the detail string.
  return [TEXT_FIELDS[fieldName], phrases];
}

interface PhraseEvaluatorOptions {
  signalId: string;
  category: EvidenceCategory;
  label: string;
  detailTemplate: string;
  attr: keyof RuleContext;
  phrases: readonly string[];
  base: Severity;
  escalated: Severity;
  threshold: number;
  mitre: readonly string[];
  benign: boolean;
}

/** Closes over a validated spec and returns the rule's callable. Everything
 * is validated and bound once at load time so the per-message path is a
 * substring scan and nothing else — no property lookups into the spec, no
 * re-validation, no branching on format details. */
function makePhraseEvaluator(options: PhraseEvaluatorOptions): RuleFn {
  const { signalId, category, label, detailTemplate, attr, phrases, base, escalated, threshold, mitre, benign } =
    options;

  return (context: RuleContext): Signal[] => {
    const text = context[attr] as string;
    if (!text) return [];

    // Declaration order, matching the reference's `phraseList.filter(...)`.
    // `{hits}` renders the first three, so a different order here would
    // produce a different detail string for the same message.
    const hits = phrases.filter((phrase) => text.includes(phrase));
    if (hits.length === 0) return [];

    const signal: Signal = {
      id: signalId,
      category,
      severity: hits.length >= threshold ? escalated : base,
      label,
      detail: renderDetail(detailTemplate, hits),
    };
    // Optional keys are added only when they carry something. An absent
    // `mitre` and a `mitre` of undefined are different values under the deep
    // equality the conformance harness uses, so a key must never be set just
    // to keep the shape uniform.
    if (mitre.length > 0) signal.mitre = [...mitre];
    if (benign) signal.benign = true;
    return [signal];
  };
}

/** Builds one `Rule` from its declarative form.
 *
 * Exposed separately from file loading so a consumer can define data rules
 * inline — from a database row, a config service, or a test — without
 * writing a file first. */
export function parseRule(data: Record<string, unknown>, namespace: string, where = '<rule>'): Rule {
  checkKeys(data, RULE_KEYS, where, 'rule');

  const missing = [...REQUIRED_RULE_KEYS].filter((key) => !(key in data)).sort();
  if (missing.length > 0) {
    throw fail(where, `missing required rule key(s) ${JSON.stringify(missing)}`);
  }

  const localId = data.id;
  if (typeof localId !== 'string') {
    throw fail(where, 'rule id must be a string');
  }
  where = `${where} (rule '${localId}')`;

  const signalId = data.signal_id ?? localId;
  if (typeof signalId !== 'string' || !signalId) {
    throw fail(where, 'signal_id must be a non-empty string');
  }

  const category = data.category;
  if (typeof category !== 'string' || !VALID_CATEGORIES.has(category as EvidenceCategory)) {
    throw fail(where, `category '${String(category)}' is not one of ${JSON.stringify([...VALID_CATEGORIES].sort())}`);
  }

  const label = data.label;
  const detailTemplate = data.detail;
  if (typeof label !== 'string' || typeof detailTemplate !== 'string') {
    throw fail(where, 'label and detail must be strings');
  }

  const [base, escalated, threshold] = parseSeverity(data.severity, where);

  const matchSpec = requireMapping(data.match, where, 'match');
  const matchType = matchSpec.type;
  if (matchType !== 'phrases') {
    throw fail(
      where,
      `match.type '${String(matchType)}' is not supported; the declarative format currently ` +
        "supports 'phrases' only. Matchers with unbounded cost (regular expressions) are " +
        'intentionally excluded — write those as a code rule',
    );
  }
  const [attr, phrases] = buildPhrasesMatcher(matchSpec, where);

  const mitre = stringList(data.mitre ?? [], where, 'mitre');
  const tags = new Set(stringList(data.tags ?? [], where, 'tags'));

  const benign = data.benign ?? false;
  if (typeof benign !== 'boolean') {
    throw fail(where, 'benign must be a boolean');
  }

  const description = data.description ?? '';
  if (typeof description !== 'string') {
    throw fail(where, 'description must be a string');
  }

  const evaluate = makePhraseEvaluator({
    signalId,
    category: category as EvidenceCategory,
    label,
    detailTemplate,
    attr,
    phrases,
    base,
    escalated,
    threshold,
    mitre,
    benign,
  });

  return new Rule(`${namespace}.${localId}`, [signalId], evaluate, tags, description);
}

/** Builds the rules described by one already-parsed rule file. */
export function parseRuleFile(data: Record<string, unknown>, where = '<file>'): Rule[] {
  checkKeys(data, FILE_KEYS, where, 'file');

  const version = data.version;
  const isValidVersion = typeof version === 'number' && Number.isInteger(version) && version === FORMAT_VERSION;
  if (!isValidVersion) {
    throw fail(where, `unsupported format version '${String(version)}'; this loader understands version ${FORMAT_VERSION}`);
  }

  const namespace = data.namespace;
  if (typeof namespace !== 'string' || !namespace) {
    throw fail(where, "'namespace' must be a non-empty string");
  }

  const rulesRaw = data.rules;
  if (!Array.isArray(rulesRaw)) {
    throw fail(where, "'rules' must be a list");
  }

  return rulesRaw.map((entry, index) =>
    parseRule(requireMapping(entry, where, `rules[${index}]`), namespace, `${where} rules[${index}]`),
  );
}

/** Reads and parses one `.json` rule file. */
export function loadRuleFile(filePath: string): Rule[] {
  let text: string;
  try {
    text = fs.readFileSync(filePath, 'utf-8');
  } catch (exc) {
    throw fail(filePath, `could not be read: ${exc instanceof Error ? exc.message : String(exc)}`);
  }

  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (exc) {
    throw fail(filePath, `invalid JSON: ${exc instanceof Error ? exc.message : String(exc)}`);
  }

  return parseRuleFile(requireMapping(raw, filePath, 'rule file'), filePath);
}

/** Loads every `*.json` under `directory` into one ruleset.
 *
 * Files are read in sorted filename order and rules keep their in-file
 * order, so the resulting ruleset is identical run to run and machine to
 * machine. That matters because ruleset order decides which of two same-id
 * signals survives `scoreSignals`' dedupe — a ruleset whose order depended on
 * filesystem iteration order would be a verdict that changes between
 * machines for no visible reason.
 *
 * Not recursive. Subdirectories are for grouping files you load separately,
 * not a hierarchy this flattens behind your back. */
export function loadRuleset(directory: string, name: string, extra: Iterable<Rule> = []): Ruleset {
  let isDirectory: boolean;
  try {
    isDirectory = fs.statSync(directory).isDirectory();
  } catch {
    isDirectory = false;
  }
  if (!isDirectory) {
    throw fail(directory, 'is not a directory');
  }

  const filenames = fs
    .readdirSync(directory)
    .filter((entry) => entry.endsWith('.json'))
    .sort();

  const rules: Rule[] = [];
  for (const filename of filenames) {
    rules.push(...loadRuleFile(path.join(directory, filename)));
  }
  rules.push(...extra);

  // Ruleset's constructor validates — a signal id claimed by two files
  // surfaces here, as an error naming both rules.
  return new Ruleset(name, rules);
}
