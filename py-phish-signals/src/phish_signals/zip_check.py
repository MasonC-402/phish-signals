"""ZIP central-directory listing, for archives attached to a message.

Port of ``typescript/src/zipCheck.ts``.

**Not implemented yet** — this module is a placeholder so the porting
surface is visible in the package layout rather than tracked somewhere
outside it.

Deliberately defines no callables. The conformance harness skips a vector
whose function is absent but *fails* one whose function exists and returns
the wrong value (see ``tests/test_conformance.py``), so a stub that raised
``NotImplementedError`` would turn "not ported yet" into the same red X as
"ported and wrong" the moment vectors land for this module.

Public surface to port, from ``typescript/src/index.ts``:

- ``list_zip_entries``
- ``looks_like_zip``
- ``MAX_ENTRIES_LISTED``

**Do not port this onto :mod:`zipfile` as-is.** The reference
implementation deliberately degrades gracefully on a truncated or forged
central directory rather than raising, and that matters for detection: an
attacker-crafted ZIP that makes the parser throw must not end up
indistinguishable from "nothing suspicious found." :mod:`zipfile` is
stricter than that, so either catch its exceptions to match the
documented behavior or port the hand-rolled central-directory parse
directly. See ``typescript/test/zipcheck.test.ts`` for the cases that
pin this.
"""

from __future__ import annotations

__all__: list[str] = []
