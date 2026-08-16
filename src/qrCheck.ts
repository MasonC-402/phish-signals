// Pure-JS QR code decoding for embedded/attached images — no external API
// calls, no shelling out to a native decoder, nothing sent anywhere. This
// closes a blind spot the tool used to only describe rather than address: an
// image can carry a QR code whose link no text-based scan will ever see, and
// until now the UI could only say so, not check it.
//
// Bounded on every axis an attacker controls, since this is the one place in
// the pipeline that decodes pixel data from untrusted bytes and it's all
// synchronous, CPU-bound work on the request thread with no `await` yield
// point anywhere inside it:
//   - how many images are attempted (MAX_QR_IMAGES)
//   - how large the encoded file is (MAX_QR_IMAGE_BYTES, already small next
//     to the request's overall 5 MB upload cap)
//   - how many pixels the file's own declared dimensions claim to be
//     (MAX_QR_PIXELS) — checked before pngjs/jpeg-js ever allocate a
//     decompressed buffer, since a small, highly compressible image can
//     declare an enormous width/height independent of its compressed byte
//     size (a classic decompression-bomb shape)
//   - for PNG specifically, whether it's Adam7-interlaced at all (rejected
//     outright — see decodePng()'s comment): pngjs's interlaced decode path
//     ignores the declared-dimensions bound entirely, so the pixel-count
//     check above does nothing to stop it on its own
//   - a cumulative wall-clock budget across the whole per-email scan loop
//     (SCAN_TIME_BUDGET_MS in scanImagesForQrCodes), as a backstop against
//     the per-image bounds above being individually fine but still adding up
//     to several seconds of blocked event loop across MAX_QR_IMAGES images —
//     moving this to a worker pool would be the fuller fix if this ever
//     becomes the bottleneck, but a pixel cap plus a time budget is
//     sufficient mitigation for a single-process deployment at this
//     request's rate limit.
//
// Wired to the same boundary attachment hashing already respects (see the
// file comment in lib/emailParser.ts): this only ever runs against a Buffer
// mailparser has already buffered for the .eml/pasted path
// (RawAttachmentMeta.content). lib/msgParser.ts never reads attachment
// content bytes at all, so a .msg's embedded images are never handed here —
// same reasoning as the hash fields being absent for that path.
//
// Only PNG and JPEG are decoded: the only two raster formats with mature,
// pure-JS decoders available (pngjs, jpeg-js) that don't require a native
// binding or a bundler. GIF/BMP/WEBP embedded images are simply not
// attempted — imageCount still reports them as present, but they don't count
// toward qrImagesScanned.

import { inflateSync } from 'zlib';
import jsQR from 'jsqr';
import { PNG } from 'pngjs';
import { decode as decodeJpeg } from 'jpeg-js';

const MAX_QR_IMAGES = 5;
const MAX_QR_IMAGE_BYTES = 3 * 1024 * 1024; // well under the 5 MB overall upload cap
// ~4MP (2000x2000): generous for anything meant to be human-scannable off a
// screen, and small next to the ~20MP this used to allow — a QR code doesn't
// get more decodable past a few hundred pixels a side, and every pixel here
// is CPU time spent synchronously on the request thread (see the file
// comment on the time budget below).
const MAX_QR_PIXELS = 4_000_000;

interface DecodableImage {
  contentType: string;
  content: Buffer;
}

interface DecodedPixels {
  data: Uint8ClampedArray;
  width: number;
  height: number;
}

// Read width/height/interlace straight off the wire bytes (signature + IHDR
// chunk, always the first 29 bytes of a valid PNG) rather than decoding
// first, so a crafted declared size — or, as below, the interlace flag —
// that would decompress into a multi-gigabyte RGBA buffer is rejected before
// pngjs ever allocates it.
function readPngHeader(buffer: Buffer): { width: number; height: number; interlaced: boolean } | null {
  if (buffer.length < 29) return null;
  const isPng = buffer.readUInt32BE(0) === 0x89504e47 && buffer.readUInt32BE(4) === 0x0d0a1a0a;
  if (!isPng) return null;
  // IHDR's data bytes start at file offset 16 (8-byte signature + 4-byte
  // chunk length + 4-byte "IHDR" type): width(4) height(4) bitdepth(1)
  // colortype(1) compression(1) filter(1) interlace(1) — interlace is the
  // 13th and last IHDR data byte, at offset 16+12 = 28.
  return {
    width: buffer.readUInt32BE(16),
    height: buffer.readUInt32BE(20),
    interlaced: buffer.readUInt8(28) !== 0,
  };
}

// Walks the PNG's chunk structure collecting IDAT payloads, stopping at
// IEND. Used only to feed our own bounded pre-check inflate below — the real,
// correct decode (filter reversal, bit-depth widening, interlace pass
// reconstruction) still happens in pngjs; this never reinterprets the pixel
// data itself.
function extractIdatData(buffer: Buffer): Buffer | null {
  const chunks: Buffer[] = [];
  let offset = 8; // past the signature
  while (offset + 8 <= buffer.length) {
    const length = buffer.readUInt32BE(offset);
    const type = buffer.toString('ascii', offset + 4, offset + 8);
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    if (dataEnd + 4 > buffer.length) return null; // truncated or malformed chunk length
    if (type === 'IDAT') chunks.push(buffer.subarray(dataStart, dataEnd));
    if (type === 'IEND') break;
    offset = dataEnd + 4; // skip the trailing 4-byte CRC
  }
  return chunks.length > 0 ? Buffer.concat(chunks) : null;
}

function decodePng(buffer: Buffer): DecodedPixels | null {
  const header = readPngHeader(buffer);
  if (!header || header.width === 0 || header.height === 0 || header.width * header.height > MAX_QR_PIXELS) return null;

  // pngjs's interlaced (Adam7) decode path runs zlib.inflateSync() on the
  // full IDAT stream with no size bound at all — unlike the non-interlaced
  // path, which does derive a maxLength from the declared dimensions. A tiny
  // file declaring 1x1 pixels but carrying a highly compressible multi-
  // hundred-megabyte payload sails straight through the pixel-count check
  // above and inflates in full regardless, entirely independent of what the
  // header claims. A QR code is never Adam7-interlaced, so rejecting this
  // outright costs nothing in real coverage. Verified against pngjs's
  // parser-sync.js: `zlib.inflateSync(inflateData)` with no maxLength
  // whenever `metaData.interlace` is true.
  if (header.interlaced) return null;

  // Defense-in-depth, independent of pngjs's own internal bounding: a ceiling
  // this module computes itself, applied via Node's own zlib.inflateSync
  // (not pngjs's), before pngjs ever runs its own inflate. This is what
  // protects against the same class of bug reappearing on a pngjs version
  // bump — e.g. if a future release's non-interlaced maxLength calculation
  // changes or regresses — rather than only against the specific interlace
  // bypass rejected above.
  const idat = extractIdatData(buffer);
  if (!idat) return null;
  try {
    // 4 bytes/pixel (RGBA) plus a filter-type byte per row is comfortably
    // above what any bit depth/color type combination for this pixel count
    // could legitimately need — this only needs to be a safe ceiling, not a
    // tight one.
    const ceiling = header.width * header.height * 4 + header.height * 8 + 1024;
    inflateSync(idat, { maxOutputLength: ceiling });
  } catch {
    return null;
  }

  // pngjs always expands its output to RGBA regardless of the source color
  // type, which is exactly the shape jsQR expects.
  const png = PNG.sync.read(buffer);
  return { data: new Uint8ClampedArray(png.data), width: png.width, height: png.height };
}

function decodeJpg(buffer: Buffer): DecodedPixels | null {
  const decoded = decodeJpeg(buffer, {
    maxResolutionInMP: MAX_QR_PIXELS / 1_000_000,
    maxMemoryUsageInMB: 256,
    // formatAsRGBA defaults to true, which is what jsQR needs.
  });
  if (decoded.width === 0 || decoded.height === 0) return null;
  return { data: new Uint8ClampedArray(decoded.data), width: decoded.width, height: decoded.height };
}

function decodeToPixels(buffer: Buffer, contentType: string): DecodedPixels | null {
  try {
    if (contentType === 'image/png') return decodePng(buffer);
    if (contentType === 'image/jpeg' || contentType === 'image/jpg') return decodeJpg(buffer);
  } catch {
    return null; // malformed or adversarial image bytes — nothing to scan, not a crash
  }
  return null;
}

// Cumulative budget across the whole scan loop below, not per image — the
// per-image bounds (MAX_QR_IMAGES, MAX_QR_IMAGE_BYTES, MAX_QR_PIXELS) can
// each look individually reasonable while still adding up to multiple
// seconds of blocked event loop across a full request, since none of this
// work has an await point for the loop to yield at. This can only check the
// deadline *between* images — a decode already in flight is synchronous, CPU-
// bound work that nothing here can preempt mid-call — so the realistic worst
// case is this budget plus one more image's decode+scan time, not a hard
// cutoff at exactly 750ms.
const SCAN_TIME_BUDGET_MS = 750;

/**
 * Scans up to MAX_QR_IMAGES eligible embedded/attached images and returns
 * whatever text payload each decoded QR code contains. Interpreting that
 * payload — is it a URL worth risk-scoring, or something else — is left to
 * the caller, the same division of labour extractUrls() already has with the
 * HTML it's handed: this module only turns pixels into a string.
 *
 * scannedCount counts images actually *attempted*, not images a QR code was
 * successfully found in — an image this deadline or the pixel/size bounds
 * cause to be skipped entirely was never attempted and isn't counted, but an
 * attempted image that fails to decode (unsupported format variant,
 * corrupt bytes, no QR code present) still counts as checked. The UI copy
 * that surfaces this number ("N of them were checked for a QR code") is
 * phrased to match: it claims an attempt was made, not that anything was
 * found.
 */
function scanImagesForQrCodes(images: DecodableImage[]): { payloads: string[]; scannedCount: number } {
  const payloads: string[] = [];
  let scannedCount = 0;
  const deadline = Date.now() + SCAN_TIME_BUDGET_MS;

  for (const image of images) {
    if (scannedCount >= MAX_QR_IMAGES) break;
    if (Date.now() >= deadline) break;

    const contentType = (image.contentType || '').toLowerCase().split(';')[0].trim();
    if (contentType !== 'image/png' && contentType !== 'image/jpeg' && contentType !== 'image/jpg') continue;
    if (!image.content || image.content.length === 0 || image.content.length > MAX_QR_IMAGE_BYTES) continue;

    scannedCount++;
    const pixels = decodeToPixels(image.content, contentType);
    if (!pixels) continue;

    try {
      const result = jsQR(pixels.data, pixels.width, pixels.height);
      if (result && result.data) payloads.push(result.data);
    } catch {
      // A malformed or adversarial pixel buffer shouldn't be able to take
      // the whole analysis down with it.
    }
  }

  return { payloads, scannedCount };
}

export { scanImagesForQrCodes, MAX_QR_IMAGES, MAX_QR_IMAGE_BYTES, MAX_QR_PIXELS, SCAN_TIME_BUDGET_MS };
