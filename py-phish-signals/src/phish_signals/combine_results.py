"""Aggregation — runs every check and assembles the CombinedResult.

Port of ``typescript/src/combineResults.ts``.

**Not implemented yet** — this module is a placeholder so the porting
surface is visible in the package layout rather than tracked somewhere
outside it.

Deliberately defines no callables. The conformance harness skips a vector
whose function is absent but *fails* one whose function exists and returns
the wrong value (see ``tests/test_conformance.py``), so a stub that raised
``NotImplementedError`` would turn "not ported yet" into the same red X as
"ported and wrong" the moment vectors land for this module.

Public surface to port, from ``typescript/src/index.ts``:

- ``combine_results``

The top of the pipeline: port this only once the checks it aggregates are
in place, or it has nothing to combine.
"""

from __future__ import annotations

__all__: list[str] = []
