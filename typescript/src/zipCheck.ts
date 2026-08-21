// ZIP central-directory listing — filenames and declared sizes only, never
// decompression.
//
// A ZIP's central directory sits at (or very near) the end of the file and
// lists every entry's name and size, along with where its compressed data
// starts, without ever needing to read or decompress a single byte of that
// data. Reading only this directory is a deliberately narrow exception to
// "attachment checks never touch content bytes" (see the file comment in
// lib/attachmentCheck.ts): it's a metadata read, the same category of
// operation as hashing the whole attachment, not a content-parsing one — no
// entry's compressed bytes are ever inflated or executed. It's what lets a
// flat "this is an archive, contents unknown" finding become "this archive
// contains invoice.pdf.exe" without opening anything.
//
// Wired to the same boundary attachment hashing already respects: this only
// ever runs against a Buffer mailparser has already buffered for the
// .eml/pasted path (RawAttachmentMeta.content). lib/msgParser.ts never reads
// attachment content bytes at all, so .msg archives are never handed here.
//
// Whether to attempt a listing at all is decided by sniffing the file's own
// magic bytes (looksLikeZip()), not by trusting the filename/extension —
// nothing stops an attachment named "invoice.zipx" or with no extension at
// all from being a plain ZIP underneath, and gating purely on ".zip" would
// let a rename alone evade the dangerous-inner-file check entirely. The
// caller (lib/emailParser.ts) is expected to attempt this on every
// content-buffered attachment, not just ones with a recognized archive
// extension.

import type { ZipEntry } from './types';

const ZIP_LOCAL_FILE_SIGNATURE = 0x504b0304; // 'PK\x03\x04' — a normal, non-empty archive's first entry
const ZIP_EMPTY_ARCHIVE_SIGNATURE = 0x504b0506; // 'PK\x05\x06' — an EOCD with nothing before it: a genuinely empty archive
const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_DIR_SIGNATURE = 0x02014b50;
const EOCD_MIN_SIZE = 22;
const CENTRAL_DIR_HEADER_SIZE = 46;
// EOCD_MIN_SIZE plus the largest possible trailing comment (a 16-bit length).
const MAX_COMMENT_SEARCH = EOCD_MIN_SIZE + 65535;
// A bound on how many directory entries are read out, not on how many the
// archive may actually contain — protects against an adversarial or corrupt
// central directory describing an implausible number of tiny entries.
const MAX_ENTRIES_LISTED = 500;
// The ZIP64 sentinel value stored in the ordinary (32-bit) EOCD fields when
// the real value doesn't fit — a signal to look for a ZIP64 locator record
// instead of trusting these fields directly, not a literal offset/count.
const ZIP64_SENTINEL_32 = 0xffffffff;
const ZIP64_SENTINEL_16 = 0xffff;

type ZipListResult =
  | { status: 'not-zip' }
  | { status: 'unreadable' }
  | { status: 'ok'; entries: ZipEntry[] };

function looksLikeZip(buffer: Buffer): boolean {
  if (buffer.length < 4) return false;
  const magic = buffer.readUInt32BE(0);
  return magic === ZIP_LOCAL_FILE_SIGNATURE || magic === ZIP_EMPTY_ARCHIVE_SIGNATURE;
}

// Scans backward from the end of the buffer for the EOCD signature, since a
// ZIP file can carry an arbitrary trailing comment after the central
// directory, of up to 65535 bytes.
function findEndOfCentralDirectory(buffer: Buffer): number | null {
  const searchStart = Math.max(0, buffer.length - MAX_COMMENT_SEARCH);
  for (let i = buffer.length - EOCD_MIN_SIZE; i >= searchStart; i--) {
    if (buffer.readUInt32LE(i) === EOCD_SIGNATURE) return i;
  }
  return null;
}

// Walks the byte range the EOCD itself claims the central directory occupies
// — [centralDirStart, centralDirEnd) — parsing sequential entry records
// until the range runs out, rather than looping exactly `totalEntries`
// times. This is what keeps a forged `totalEntries` of 0 from hiding a
// central directory that's still genuinely present and readable: the EOCD's
// declared count is never used as the loop bound, only the byte range is
// (and that range's boundaries — the central directory's start offset from
// the EOCD, and the EOCD's own position, independently located by scanning
// backward for its signature above — are two different, independently
// derived values, not the same trust anchor read twice).
//
// This does not attempt to recover a central directory whose *start offset*
// itself was forged to a bogus value — verifying that would mean either
// trusting a second independent structure this format doesn't provide, or
// brute-force scanning the whole file for central-directory-shaped byte
// sequences, which risks false matches inside compressed entry data (a
// worse problem than the one being solved). That remains an accepted
// residual limitation of a purely structural, offline listing — the same
// category of tradeoff as lib/authCheck.ts's Authentication-Results
// selection not defending against a fully forged Received chain.
function readCentralDirectoryEntries(buffer: Buffer, centralDirStart: number, centralDirEnd: number): ZipEntry[] {
  const entries: ZipEntry[] = [];
  let offset = centralDirStart;

  while (offset < centralDirEnd && entries.length < MAX_ENTRIES_LISTED) {
    if (offset + CENTRAL_DIR_HEADER_SIZE > buffer.length) break;
    if (buffer.readUInt32LE(offset) !== CENTRAL_DIR_SIGNATURE) break;

    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const filenameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);

    const nameStart = offset + CENTRAL_DIR_HEADER_SIZE;
    const nameEnd = nameStart + filenameLength;
    if (nameEnd > buffer.length) break;

    entries.push({ filename: buffer.toString('utf8', nameStart, nameEnd), uncompressedSize });
    offset = nameEnd + extraLength + commentLength;
  }

  // Caveat worth knowing rather than fixing: this reads the name from each
  // *central directory* record only. Each entry's *local* file header
  // (immediately preceding its compressed data, never read by this module at
  // all) carries its own, independent copy of the filename, and a
  // maliciously crafted archive can make the two disagree — some extraction
  // tools honor the central directory's name, others honor the local
  // header's, so what a human ends up seeing on extraction isn't guaranteed
  // to be what's listed here. Cross-checking would mean walking the local
  // headers too, which this module deliberately doesn't do (it would still
  // only be reading metadata, not entry bytes, but it's more surface for
  // comparatively little payoff against a narrow, specific trick).
  return entries;
}

/**
 * Sniffs whether `buffer` looks like a ZIP at all (content, not filename —
 * see the file comment) and, if so, lists its central directory's entry
 * names and declared sizes. Three-way result rather than `ZipEntry[] |
 * null`, so a ZIP that couldn't actually be read (ZIP64, a malformed or
 * out-of-range EOCD) is distinguishable from both "not a ZIP" and "a
 * genuinely empty one" — collapsing those together would silently read as
 * "nothing dangerous inside" when the truth is closer to "couldn't check."
 */
function listZipEntries(buffer: Buffer): ZipListResult {
  if (!looksLikeZip(buffer)) return { status: 'not-zip' };
  if (buffer.length < EOCD_MIN_SIZE) return { status: 'unreadable' };

  const eocdOffset = findEndOfCentralDirectory(buffer);
  if (eocdOffset === null) return { status: 'unreadable' };

  let totalEntries: number;
  let centralDirStart: number;
  try {
    totalEntries = buffer.readUInt16LE(eocdOffset + 10);
    centralDirStart = buffer.readUInt32LE(eocdOffset + 16);
  } catch {
    return { status: 'unreadable' };
  }

  // ZIP64: the real values live in a separate locator/EOCD64 record this
  // module doesn't parse. Reading the sentinel as a literal offset/count
  // would produce garbage (typically an offset far past the buffer, or a
  // wildly wrong entry count), so this is treated as unreadable rather than
  // silently returning an empty or nonsensical list.
  if (totalEntries === ZIP64_SENTINEL_16 || centralDirStart === ZIP64_SENTINEL_32) {
    return { status: 'unreadable' };
  }

  if (centralDirStart > eocdOffset || centralDirStart >= buffer.length) {
    return { status: 'unreadable' };
  }

  const entries = readCentralDirectoryEntries(buffer, centralDirStart, eocdOffset);
  return { status: 'ok', entries };
}

export { listZipEntries, looksLikeZip, MAX_ENTRIES_LISTED };
export type { ZipListResult };
