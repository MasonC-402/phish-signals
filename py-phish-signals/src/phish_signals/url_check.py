"""URL, typosquat, and brand-impersonation checks.

Port of ``typescript/src/urlCheck.ts``.

**Not implemented yet** — this module is a placeholder so the porting
surface is visible in the package layout rather than tracked somewhere
outside it.

Deliberately defines no callables. The conformance harness skips a vector
whose function is absent but *fails* one whose function exists and returns
the wrong value (see ``tests/test_conformance.py``), so a stub that raised
``NotImplementedError`` would turn "not ported yet" into the same red X as
"ported and wrong" the moment vectors land for this module.

Public surface to port, from ``typescript/src/index.ts``:

- ``check_urls``
- ``check_typosquat``
- ``brand_impersonation``
- ``levenshtein``
- ``is_ip_literal``
- ``summarize_url_signals``
- ``check_qr_codes``
- ``MAX_URLS_ANALYZED``
"""

from __future__ import annotations

__all__: list[str] = []
