"""Pretty-printed JSON of a combined result, for a SOAR or ticketing system.

Port of ``typescript/src/jsonExport.ts``.

Everything else this tool produces is written for a person to read. A SOAR
playbook or a ticketing system's enrichment step wants the same information
as structured data it can branch on, not prose it has to re-parse.

Kept intentionally dumb — no reshaping, no renaming fields, no subset.
"""

from __future__ import annotations

import json

from .types import CombinedResult


def build_json_export(result: CombinedResult) -> str:
    # jsonReport hasn't been assigned onto ``result`` yet at the point this
    # is called, so there's nothing here for json.dumps to need to exclude —
    # but excluding it explicitly makes that non-self-referential property
    # obvious from reading this function alone, rather than only true by
    # call-order convention.
    exportable = {k: v for k, v in result.items() if k != "jsonReport"}
    return json.dumps(exportable, indent=2, ensure_ascii=False)


__all__ = ["build_json_export"]
