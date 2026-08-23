"""ZIP central-directory listing — filenames and declared sizes only, never
decompression.

Port of ``typescript/src/zipCheck.ts``.

A ZIP's central directory sits at (or very near) the end of the file and
lists every entry's name and size, along with where its compressed data
starts, without ever needing to read or decompress a single byte of that
data. It's what lets a flat "this is an archive, contents unknown" finding
become "this archive contains invoice.pdf.exe" without opening anything.

Whether to attempt a listing at all is decided by sniffing the file's own
magic bytes (:func:`looks_like_zip`), not by trusting the filename/extension.
"""

from __future__ import annotations

import struct
from typing import Literal, TypedDict

from .types import ZipEntry

_ZIP_LOCAL_FILE_SIGNATURE = (
    0x504B0304  # 'PK\x03\x04' — a normal, non-empty archive's first entry
)
_ZIP_EMPTY_ARCHIVE_SIGNATURE = (
    0x504B0506  # 'PK\x05\x06' — an EOCD with nothing before it
)
_EOCD_SIGNATURE = 0x06054B50
_CENTRAL_DIR_SIGNATURE = 0x02014B50
_EOCD_MIN_SIZE = 22
_CENTRAL_DIR_HEADER_SIZE = 46
# EOCD_MIN_SIZE plus the largest possible trailing comment (a 16-bit length).
_MAX_COMMENT_SEARCH = _EOCD_MIN_SIZE + 65535
# A bound on how many directory entries are read out, not on how many the
# archive may actually contain — protects against an adversarial or corrupt
# central directory describing an implausible number of tiny entries.
MAX_ENTRIES_LISTED = 500
# The ZIP64 sentinel value stored in the ordinary (32-bit) EOCD fields when
# the real value doesn't fit.
_ZIP64_SENTINEL_32 = 0xFFFFFFFF
_ZIP64_SENTINEL_16 = 0xFFFF


class _NotZip(TypedDict):
    status: Literal["not-zip"]


class _Unreadable(TypedDict):
    status: Literal["unreadable"]


class _Ok(TypedDict):
    status: Literal["ok"]
    entries: list[ZipEntry]


ZipListResult = _NotZip | _Unreadable | _Ok


def looks_like_zip(buffer: bytes) -> bool:
    if len(buffer) < 4:
        return False
    magic = struct.unpack_from(">I", buffer, 0)[0]
    return magic in (_ZIP_LOCAL_FILE_SIGNATURE, _ZIP_EMPTY_ARCHIVE_SIGNATURE)


def _find_end_of_central_directory(buffer: bytes) -> int | None:
    """Scans backward from the end of the buffer for the EOCD signature,
    since a ZIP file can carry an arbitrary trailing comment after the
    central directory, of up to 65535 bytes.
    """
    search_start = max(0, len(buffer) - _MAX_COMMENT_SEARCH)
    i = len(buffer) - _EOCD_MIN_SIZE
    while i >= search_start:
        if struct.unpack_from("<I", buffer, i)[0] == _EOCD_SIGNATURE:
            return i
        i -= 1
    return None


def _read_central_directory_entries(
    buffer: bytes, central_dir_start: int, central_dir_end: int
) -> list[ZipEntry]:
    """Walks the byte range the EOCD itself claims the central directory
    occupies, parsing sequential entry records until the range runs out,
    rather than looping exactly ``totalEntries`` times — see the TypeScript
    source for why that distinction matters against a forged entry count.
    """
    entries: list[ZipEntry] = []
    offset = central_dir_start

    while offset < central_dir_end and len(entries) < MAX_ENTRIES_LISTED:
        if offset + _CENTRAL_DIR_HEADER_SIZE > len(buffer):
            break
        if struct.unpack_from("<I", buffer, offset)[0] != _CENTRAL_DIR_SIGNATURE:
            break

        uncompressed_size = struct.unpack_from("<I", buffer, offset + 24)[0]
        filename_length = struct.unpack_from("<H", buffer, offset + 28)[0]
        extra_length = struct.unpack_from("<H", buffer, offset + 30)[0]
        comment_length = struct.unpack_from("<H", buffer, offset + 32)[0]

        name_start = offset + _CENTRAL_DIR_HEADER_SIZE
        name_end = name_start + filename_length
        if name_end > len(buffer):
            break

        entries.append(
            {
                "filename": buffer[name_start:name_end].decode(
                    "utf-8", errors="replace"
                ),
                "uncompressedSize": uncompressed_size,
            }
        )
        offset = name_end + extra_length + comment_length

    return entries


def list_zip_entries(buffer: bytes) -> ZipListResult:
    """Sniffs whether ``buffer`` looks like a ZIP at all (content, not
    filename) and, if so, lists its central directory's entry names and
    declared sizes. Three-way result rather than ``list[ZipEntry] | None``,
    so a ZIP that couldn't actually be read (ZIP64, a malformed or
    out-of-range EOCD) is distinguishable from both "not a ZIP" and "a
    genuinely empty one".
    """
    if not looks_like_zip(buffer):
        return {"status": "not-zip"}
    if len(buffer) < _EOCD_MIN_SIZE:
        return {"status": "unreadable"}

    eocd_offset = _find_end_of_central_directory(buffer)
    if eocd_offset is None:
        return {"status": "unreadable"}

    try:
        total_entries = struct.unpack_from("<H", buffer, eocd_offset + 10)[0]
        central_dir_start = struct.unpack_from("<I", buffer, eocd_offset + 16)[0]
    except struct.error:
        return {"status": "unreadable"}

    # ZIP64: the real values live in a separate locator/EOCD64 record this
    # module doesn't parse. Reading the sentinel as a literal offset/count
    # would produce garbage, so this is treated as unreadable.
    if total_entries == _ZIP64_SENTINEL_16 or central_dir_start == _ZIP64_SENTINEL_32:
        return {"status": "unreadable"}

    if central_dir_start > eocd_offset or central_dir_start >= len(buffer):
        return {"status": "unreadable"}

    entries = _read_central_directory_entries(buffer, central_dir_start, eocd_offset)
    return {"status": "ok", "entries": entries}


__all__ = ["MAX_ENTRIES_LISTED", "ZipListResult", "list_zip_entries", "looks_like_zip"]
