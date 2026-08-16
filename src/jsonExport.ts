// Machine-readable export of a finished analysis.
//
// Everything else this tool produces is written for a person to read: the
// findings list, the recommendations, the Sigma rule as a block of YAML. A
// SOAR playbook or a ticketing system's enrichment step wants the same
// information as structured data it can branch on, not prose it has to
// re-parse. This is that: the same CombinedResult the page renders from,
// serialized as-is.
//
// Kept intentionally dumb — no reshaping, no renaming fields, no subset. If a
// consumer only wants three fields out of it, that's a jq/JSONPath expression
// on their end, not a second schema for this file to keep in sync with the
// first one.

import type { CombinedResult } from './types';

function buildJsonExport(result: CombinedResult): string {
  // jsonReport hasn't been assigned onto `result` yet at the point this is
  // called (see routes/phish-report.ts), so there's nothing here for
  // JSON.stringify to need to exclude — but destructuring it out explicitly
  // makes that non-self-referential property obvious from reading this
  // function alone, rather than only true by call-order convention.
  const { jsonReport: _jsonReport, ...exportable } = result;
  return JSON.stringify(exportable, null, 2);
}

export { buildJsonExport };
