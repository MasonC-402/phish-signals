"""Round-trip tests for qr_check.py against real, generated QR-code images."""

from __future__ import annotations

from io import BytesIO

import cv2
import numpy as np
import pytest
from PIL import Image

from phish_signals.qr_check import (
    MAX_QR_IMAGE_BYTES,
    MAX_QR_IMAGES,
    scan_images_for_qr_codes,
)


def _qr_png_bytes(payload: str) -> bytes:
    encoder = cv2.QRCodeEncoder.create()
    matrix = encoder.encode(payload)  # already 0/255 uint8, 1 module per pixel
    # Scale up (a 1px-per-module QR is too small for a real decoder to find
    # reliably once re-encoded through PNG) and add a quiet-zone border —
    # QR decoders rely on the white margin around the finder patterns to
    # even recognize the code is there.
    scaled = np.kron(matrix, np.ones((8, 8), dtype=np.uint8))
    quiet_zone = 8 * 4
    bordered = np.pad(scaled, quiet_zone, constant_values=255)
    img = Image.fromarray(bordered, mode="L")
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_decodes_a_real_qr_code_from_a_png() -> None:
    content = _qr_png_bytes("https://example.com/phish")
    result = scan_images_for_qr_codes(
        [
            {"contentType": "image/png", "content": content},
        ]
    )
    assert result["scannedCount"] == 1
    assert result["payloads"] == ["https://example.com/phish"]


def test_decodes_from_a_jpeg_too() -> None:
    content = _qr_png_bytes("https://example.com/jpeg-path")
    with Image.open(BytesIO(content)) as img:
        buf = BytesIO()
        img.convert("RGB").save(buf, format="JPEG", quality=95)
        jpeg_bytes = buf.getvalue()

    result = scan_images_for_qr_codes(
        [
            {"contentType": "image/jpeg", "content": jpeg_bytes},
        ]
    )
    assert result["scannedCount"] == 1
    assert result["payloads"] == ["https://example.com/jpeg-path"]


def test_image_with_no_qr_code_counts_as_scanned_but_finds_nothing() -> None:
    blank = Image.new("RGB", (100, 100), color="white")
    buf = BytesIO()
    blank.save(buf, format="PNG")

    result = scan_images_for_qr_codes(
        [
            {"contentType": "image/png", "content": buf.getvalue()},
        ]
    )
    assert result["scannedCount"] == 1
    assert result["payloads"] == []


def test_non_image_content_types_are_skipped_without_counting() -> None:
    result = scan_images_for_qr_codes(
        [
            {"contentType": "image/gif", "content": b"whatever"},
            {"contentType": "application/pdf", "content": b"whatever"},
        ]
    )
    assert result == {"payloads": [], "scannedCount": 0}


def test_oversized_encoded_bytes_are_skipped_without_counting() -> None:
    oversized = b"x" * (MAX_QR_IMAGE_BYTES + 1)
    result = scan_images_for_qr_codes(
        [
            {"contentType": "image/png", "content": oversized},
        ]
    )
    assert result == {"payloads": [], "scannedCount": 0}


def test_corrupt_image_bytes_still_count_as_attempted() -> None:
    result = scan_images_for_qr_codes(
        [
            {"contentType": "image/png", "content": b"not a real png" * 10},
        ]
    )
    assert result["scannedCount"] == 1
    assert result["payloads"] == []


def test_stops_after_max_qr_images() -> None:
    blank_png = BytesIO()
    Image.new("RGB", (10, 10), color="white").save(blank_png, format="PNG")
    images = [
        {"contentType": "image/png", "content": blank_png.getvalue()}
        for _ in range(MAX_QR_IMAGES + 3)
    ]
    result = scan_images_for_qr_codes(images)
    assert result["scannedCount"] == MAX_QR_IMAGES


def test_none_and_empty_input() -> None:
    assert scan_images_for_qr_codes(None) == {"payloads": [], "scannedCount": 0}
    assert scan_images_for_qr_codes([]) == {"payloads": [], "scannedCount": 0}


@pytest.mark.parametrize("declared_pixels_only", [True])
def test_declared_oversized_dimensions_are_rejected_before_decoding(
    declared_pixels_only,
) -> None:
    # A PNG whose IHDR claims more pixels than MAX_QR_PIXELS must be
    # rejected from its header alone, without Pillow ever being asked to
    # decompress that many pixels.
    import struct
    import zlib

    width = height = 3000  # 9,000,000 > MAX_QR_PIXELS (4,000,000)
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data))
        )

    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(b"\x00" + b"\x00" * width))
        + chunk(b"IEND", b"")
    )
    result = scan_images_for_qr_codes([{"contentType": "image/png", "content": png}])
    assert result["scannedCount"] == 1
    assert result["payloads"] == []
