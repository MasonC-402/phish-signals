"""QR-code decoding from embedded and attached images.

Port of ``typescript/src/qrCheck.ts``.

Bounded on every axis an attacker controls, since this is the one place in
the pipeline that decodes pixel data from untrusted bytes:

- how many images are attempted (``MAX_QR_IMAGES``)
- how large the encoded file is (``MAX_QR_IMAGE_BYTES``)
- how many pixels the file's own declared dimensions claim to be
  (``MAX_QR_PIXELS``) — checked from the header Pillow parses on
  ``Image.open()`` (which does not itself decompress pixel data) before
  ``.load()`` is ever called, the same "check the declared size before
  decoding" defense the TypeScript reference applies to pngjs/jpeg-js
- a cumulative wall-clock budget across the whole per-email scan loop
  (``SCAN_TIME_BUDGET_MS``), as a backstop against the per-image bounds
  above being individually fine but still adding up

Uses Pillow to decode PNG/JPEG bytes into pixels and OpenCV's QR detector
to read a payload out of them — see ``pyproject.toml`` for why these,
rather than the TypeScript reference's jsqr/pngjs/jpeg-js or the other
Python option (pyzbar) named in this module's own pre-existing docstring.

Only PNG and JPEG are decoded, matching the reference: GIF/BMP/WEBP embedded
images are simply not attempted — ``imageCount`` still reports them as
present, but they don't count toward ``qrImagesScanned``.
"""

from __future__ import annotations

import time
from io import BytesIO
from typing import TypedDict

import cv2
import numpy as np
from PIL import Image

MAX_QR_IMAGES = 5
MAX_QR_IMAGE_BYTES = 3 * 1024 * 1024  # well under the 5 MB overall upload cap
# ~4MP (2000x2000): generous for anything meant to be human-scannable off a
# screen, and small next to the ~20MP this used to allow — a QR code doesn't
# get more decodable past a few hundred pixels a side, and every pixel here
# is CPU time spent synchronously (see the time budget below).
MAX_QR_PIXELS = 4_000_000

# Cumulative budget across the whole scan loop, not per image — the
# per-image bounds above can each look individually reasonable while still
# adding up to multiple seconds across a full request.
SCAN_TIME_BUDGET_MS = 750

_CONTENT_TYPES = frozenset({"image/png", "image/jpeg", "image/jpg"})


class DecodableImage(TypedDict):
    contentType: str
    content: bytes


class _ScanResult(TypedDict):
    payloads: list[str]
    scannedCount: int


_qr_detector = cv2.QRCodeDetector()


def _decode_to_pixels(buffer: bytes) -> np.ndarray | None:
    try:
        with Image.open(BytesIO(buffer)) as img:
            width, height = img.size
            if width == 0 or height == 0 or width * height > MAX_QR_PIXELS:
                return None
            # Pillow only parses the header on open(); the actual pixel
            # decompression this bounds against happens here, on .load()
            # (implicit inside convert()).
            return np.array(img.convert("RGB"))
    except Exception:
        # Malformed or adversarial image bytes — nothing to scan, not a crash.
        return None


def scan_images_for_qr_codes(images: list[DecodableImage] | None) -> _ScanResult:
    """Scans up to ``MAX_QR_IMAGES`` eligible embedded/attached images and
    returns whatever text payload each decoded QR code contains.
    Interpreting that payload — is it a URL worth risk-scoring, or something
    else — is left to the caller.

    ``scannedCount`` counts images actually *attempted*, not images a QR
    code was successfully found in — an image the deadline or the
    pixel/size bounds cause to be skipped entirely was never attempted and
    isn't counted, but an attempted image that fails to decode (unsupported
    format variant, corrupt bytes, no QR code present) still counts as
    checked.
    """
    payloads: list[str] = []
    scanned_count = 0
    deadline = time.monotonic() + SCAN_TIME_BUDGET_MS / 1000

    for image in images or []:
        if scanned_count >= MAX_QR_IMAGES:
            break
        if time.monotonic() >= deadline:
            break

        content_type = (image.get("contentType") or "").lower().split(";")[0].strip()
        if content_type not in _CONTENT_TYPES:
            continue
        content = image.get("content")
        if not content or len(content) > MAX_QR_IMAGE_BYTES:
            continue

        scanned_count += 1
        pixels = _decode_to_pixels(content)
        if pixels is None:
            continue

        try:
            data, _points, _straight_qrcode = _qr_detector.detectAndDecode(pixels)
            if data:
                payloads.append(data)
        except Exception:
            # A malformed or adversarial pixel buffer shouldn't be able to
            # take the whole analysis down with it.
            continue

    return {"payloads": payloads, "scannedCount": scanned_count}


__all__ = [
    "MAX_QR_IMAGES",
    "MAX_QR_IMAGE_BYTES",
    "MAX_QR_PIXELS",
    "SCAN_TIME_BUDGET_MS",
    "DecodableImage",
    "scan_images_for_qr_codes",
]
