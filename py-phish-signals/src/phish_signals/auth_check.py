"""SPF/DKIM/DMARC evaluation from Authentication-Results headers.

Port of ``typescript/src/authCheck.ts``.

**Not implemented yet** — this module is a placeholder so the porting
surface is visible in the package layout rather than tracked somewhere
outside it.

Deliberately defines no callables. The conformance harness skips a vector
whose function is absent but *fails* one whose function exists and returns
the wrong value (see ``tests/test_conformance.py``), so a stub that raised
``NotImplementedError`` would turn "not ported yet" into the same red X as
"ported and wrong" the moment vectors land for this module.

Public surface to port, from ``typescript/src/index.ts``:

- ``check_authentication``

Note the ``selectedAuthservId`` field on the result: the header-anomaly
check validates that exact same header rather than independently
re-deriving "the" authoritative one, so the two cannot disagree about
which header they mean. Preserve that coupling in the port.
"""

from __future__ import annotations

__all__: list[str] = []
