"""Outlook .msg to raw-email conversion.

Port of ``typescript/src/msgParser.ts``.

**Not implemented yet** — this module is a placeholder so the porting
surface is visible in the package layout rather than tracked somewhere
outside it.

Deliberately defines no callables. The conformance harness skips a vector
whose function is absent but *fails* one whose function exists and returns
the wrong value (see ``tests/test_conformance.py``), so a stub that raised
``NotImplementedError`` would turn "not ported yet" into the same red X as
"ported and wrong" the moment vectors land for this module.

Public surface to port, from ``typescript/src/index.ts``:

- ``msg_to_raw_email``

Needs a runtime dependency: the reference uses ``@kenjiuno/msgreader``,
the Python equivalent is ``extract-msg`` (``uv add extract-msg``). Note
that the reference deliberately never reads attachment content bytes
here — only filename, content type, and size.
"""

from __future__ import annotations

__all__: list[str] = []
