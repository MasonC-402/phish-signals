"""Raw .eml and pasted-message parsing.

Port of ``typescript/src/emailParser.ts``.

**Not implemented yet** — this module is a placeholder so the porting
surface is visible in the package layout rather than tracked somewhere
outside it.

Deliberately defines no callables. The conformance harness skips a vector
whose function is absent but *fails* one whose function exists and returns
the wrong value (see ``tests/test_conformance.py``), so a stub that raised
``NotImplementedError`` would turn "not ported yet" into the same red X as
"ported and wrong" the moment vectors land for this module.

Public surface to port, from ``typescript/src/index.ts``:

- ``parse_email``
- ``extract_urls``
- ``extract_hrefs``
- ``find_link_mismatches``
- ``find_dangerous_schemes``
- ``looks_like_raw_email``

First module in the port that needs anything beyond the standard library's
reach. The reference uses ``mailparser``; the Python side should build on
the stdlib :mod:`email` package with ``email.policy.default``. Draft work
toward this lives in ``py-phish-signals/utils.py``, which is outside the
packaged ``src/phish_signals`` tree and ships nowhere — fold it in here
when porting, and match ``ParsedEmail`` in :mod:`phish_signals.types`
rather than inventing a narrower return shape.
"""

from __future__ import annotations

__all__: list[str] = []
