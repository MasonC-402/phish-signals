# Shared rule definitions

Language-neutral phishing rules, as data. The Python implementation
(`python/`) loads the files in this directory via its declarative
rule loader. The TypeScript implementation (`typescript/`) still uses inline
phrase arrays; porting its content check to load from this directory is
planned but not yet done.

The goal: a phrase list written as data is added once and is live in both
languages immediately, with nothing to keep in sync. Until the TypeScript
loader lands, the Python side is the only consumer, and the TypeScript
phrase arrays must be kept in sync manually (or via `conformance/`).

## Relationship to `conformance/`

Complementary, not overlapping.

- **`rules/`** (here) is *shared input* — the same detection data feeding both
  implementations.
- **`conformance/`** is *shared expected output* — the same input/output pairs
  asserted against both implementations.

Rules that live here need much less conformance coverage than code rules do,
because there is only one copy of the thing that could be wrong. Vectors are
still worth having for the *evaluator* — that both languages render `{hits}`
identically, escalate severity at the same threshold, and scan the same text
field — but not for each individual phrase.

## Format

One JSON file per group of rules. `version` and `namespace` are required;
`namespace` becomes the prefix of every rule id in the file (`core.` for rules
shipped by this project).

```json
{
  "version": 1,
  "namespace": "core",
  "rules": [
    {
      "id": "urgency_language",
      "category": "social",
      "label": "Urgency / Pressure Language",
      "severity": { "base": "low", "escalate_to": "medium", "when_hits_at_least": 3 },
      "match": { "type": "phrases", "field": "scan_text", "any_of": ["act now", "urgent"] },
      "detail": "Contains phrases designed to rush you past thinking it through: {hits}.",
      "mitre": ["T1566"],
      "tags": ["content"],
      "description": "Manufactured time pressure."
    }
  ]
}
```

### Rule keys

| Key | Required | Notes |
| --- | --- | --- |
| `id` | yes | Local name. Full rule id is `<namespace>.<id>`. |
| `signal_id` | no | The `Signal.id` emitted. Defaults to `id`. Set it when the rule id and the output id should differ. |
| `category` | yes | `authentication` / `identity` / `infrastructure` / `payload` / `social`. |
| `label` | yes | Shown to the analyst. |
| `severity` | yes | A severity string, or `{base, escalate_to, when_hits_at_least}`. |
| `match` | yes | Currently `{"type": "phrases", "field": ..., "any_of": [...]}`. |
| `detail` | yes | Template. `{hits}` renders the first three matches, quoted; `{hit_count}` the total. |
| `mitre` | no | ATT&CK technique ids. Omitted from the signal entirely when absent. |
| `benign` | no | `true` when the finding argues the message is *legitimate*. |
| `tags` | no | Free-form, for selecting subsets. Not part of scoring. |
| `description` | no | One line, shown when listing a ruleset. |

`match.field` is one of `scan_text` (subject + text part + de-tagged HTML —
the usual choice), `body_text`, `html_body`, `subject`. Text is lowercased
before matching, so **phrases must be written lowercase**; an uppercase phrase
is rejected at load rather than silently never matching.

Unknown keys are an error, not a warning. A typo'd `"severty"` that loaded
quietly would give you a rule running at the wrong weight with nothing to
indicate it.

## No regular expressions

The matcher grammar is a closed set with bounded cost, and free-form patterns
are not in it. This library feeds attacker-controlled text into whatever
matcher a rule declares; a backtracking pattern plus a crafted body is a
denial of service, and the person who wrote the rule is usually not the person
running it. Rules that genuinely need a pattern are written as code rules, in
each implementation, where whoever ships the pattern owns the risk.

## Conventions

- Severity escalation is for phrase counts, and it is how the existing checks
  already behave: one "urgent" is a word, four pressure phrases in one message
  is a technique.
- Two rules must not emit the same `signal_id`. Scoring deduplicates by signal
  id and keeps only the first, so the second would be silently discarded —
  both implementations reject such a ruleset at load rather than run it.
- Phrase order inside `any_of` is meaningful: matches are collected in
  declaration order and `{hits}` renders the first three, so reordering the
  list changes the `detail` string a message produces.
