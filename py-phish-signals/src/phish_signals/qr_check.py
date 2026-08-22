"""QR-code decoding from embedded and attached images.

Port of ``typescript/src/qrCheck.ts``.

**Not implemented yet** — this module is a placeholder so the porting
surface is visible in the package layout rather than tracked somewhere
outside it.

Deliberately defines no callables. The conformance harness skips a vector
whose function is absent but *fails* one whose function exists and returns
the wrong value (see ``tests/test_conformance.py``), so a stub that raised
``NotImplementedError`` would turn "not ported yet" into the same red X as
"ported and wrong" the moment vectors land for this module.

Public surface to port, from ``typescript/src/index.ts``:

- ``scan_images_for_qr_codes``
- ``MAX_QR_IMAGES``
- ``MAX_QR_IMAGE_BYTES``
- ``MAX_QR_PIXELS``
- ``SCAN_TIME_BUDGET_MS``

Needs runtime dependencies: the reference uses ``jsqr``/``pngjs``/
``jpeg-js``; the Python equivalents are ``pyzbar`` plus Pillow, or
``opencv-python``. Port the bounds along with the logic — they exist to
stop a decompression-bomb image from turning analysis into a denial of
service, and are not optional detail.
"""

from __future__ import annotations

__all__: list[str] = []
