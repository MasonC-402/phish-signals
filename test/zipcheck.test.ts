import { test } from 'node:test';
import assert from 'node:assert/strict';
import { crc32 } from 'node:zlib';

import { listZipEntries } from '../src/zipCheck';
import { parseEmail } from '../src/emailParser';

// A real, valid ZIP (STORED/uncompressed method) built by hand — no
// dependency needed just to produce a fixture this narrow. Deflate isn't
// used since listZipEntries() never reads entry bytes at all, only the
// central directory, so the entries can be empty placeholders.
function buildStoredZip(entries: { name: string; content: Buffer }[]): Buffer {
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name, 'utf8');
    const crc = crc32(entry.content) >>> 0;
    const size = entry.content.length;

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(0, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(size, 18);
    local.writeUInt32LE(size, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28);
    localParts.push(local, nameBuf, entry.content);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt16LE(0, 12);
    central.writeUInt16LE(0, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(size, 20);
    central.writeUInt32LE(size, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(offset, 42);
    centralParts.push(central, nameBuf);

    offset += local.length + nameBuf.length + entry.content.length;
  }

  const centralDirStart = offset;
  const centralDir = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDir.length, 12);
  eocd.writeUInt32LE(centralDirStart, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localParts, centralDir, eocd]);
}

test('listZipEntries reads filenames and sizes from a real ZIP central directory', () => {
  const zip = buildStoredZip([
    { name: 'readme.txt', content: Buffer.from('hello') },
    { name: 'invoice.pdf.exe', content: Buffer.from('not really a pdf') },
  ]);

  const result = listZipEntries(zip);
  assert.equal(result.status, 'ok');
  if (result.status !== 'ok') return;
  assert.equal(result.entries.length, 2);
  assert.equal(result.entries[0].filename, 'readme.txt');
  assert.equal(result.entries[0].uncompressedSize, 5);
  assert.equal(result.entries[1].filename, 'invoice.pdf.exe');
});

test('a non-ZIP buffer is reported as not-zip, not an error', () => {
  assert.equal(listZipEntries(Buffer.from('not a zip at all')).status, 'not-zip');
  assert.equal(listZipEntries(Buffer.alloc(0)).status, 'not-zip');
});

test('a truncated central directory returns whatever was read successfully, not an exception', () => {
  const zip = buildStoredZip([{ name: 'a.txt', content: Buffer.from('x') }]);
  // Chop the buffer mid-way through the central directory, after the EOCD
  // signature search window would still find a (now-nonexistent) EOCD.
  const truncated = zip.subarray(0, zip.length - 30);
  assert.doesNotThrow(() => listZipEntries(truncated));
});

test('an empty archive (zero entries) is handled cleanly', () => {
  const zip = buildStoredZip([]);
  const result = listZipEntries(zip);
  assert.equal(result.status, 'ok');
  if (result.status === 'ok') assert.deepEqual(result.entries, []);
});

test('the ZIP signature is sniffed from content, not trusted from a filename', () => {
  // listZipEntries() itself takes no filename at all — this just confirms a
  // genuinely non-ZIP buffer is recognized as such regardless of what
  // anyone might call it, which is the property lib/emailParser.ts's
  // content-first gating depends on.
  const zip = buildStoredZip([{ name: 'x.txt', content: Buffer.from('y') }]);
  assert.equal(listZipEntries(zip).status, 'ok');
  assert.equal(listZipEntries(Buffer.from('PK is not enough on its own')).status, 'not-zip');
});

test('a forged totalEntries of 0 does not hide a real central directory', () => {
  // The loop bound is the byte range [centralDirStart, eocdOffset), not the
  // EOCD's declared count — this proves a lying count doesn't skip entries
  // that are still genuinely present and readable in that range.
  const zip = buildStoredZip([
    { name: 'readme.txt', content: Buffer.from('hello') },
    { name: 'invoice.pdf.exe', content: Buffer.from('not really a pdf') },
  ]);
  const eocdOffset = zip.length - 22; // buildStoredZip always appends a 22-byte EOCD with no comment
  assert.equal(zip.readUInt32LE(eocdOffset), 0x06054b50, 'precondition: EOCD signature at the expected offset');
  const forged = Buffer.from(zip);
  forged.writeUInt16LE(0, eocdOffset + 10); // total entries this disk
  forged.writeUInt16LE(0, eocdOffset + 8); // total entries overall

  const result = listZipEntries(forged);
  assert.equal(result.status, 'ok');
  if (result.status === 'ok') {
    assert.equal(result.entries.length, 2, 'both real entries should still be found despite the forged count of 0');
    assert.ok(result.entries.some((e) => e.filename === 'invoice.pdf.exe'));
  }
});

test('a ZIP64 sentinel in the EOCD is reported as unreadable, not as an empty or garbage listing', () => {
  const zip = buildStoredZip([{ name: 'a.txt', content: Buffer.from('x') }]);
  const eocdOffset = zip.length - 22;
  const forged = Buffer.from(zip);
  forged.writeUInt16LE(0xffff, eocdOffset + 10); // ZIP64 sentinel for total entries
  assert.equal(listZipEntries(forged).status, 'unreadable');

  const forgedOffset = Buffer.from(zip);
  forgedOffset.writeUInt32LE(0xffffffff, eocdOffset + 16); // ZIP64 sentinel for central-dir start offset
  assert.equal(listZipEntries(forgedOffset).status, 'unreadable');
});

test('a central-directory start offset past the EOCD is reported as unreadable rather than misread', () => {
  const zip = buildStoredZip([{ name: 'a.txt', content: Buffer.from('x') }]);
  const eocdOffset = zip.length - 22;
  const forged = Buffer.from(zip);
  forged.writeUInt32LE(eocdOffset + 1000, eocdOffset + 16); // nonsensical offset, past the EOCD itself
  assert.equal(listZipEntries(forged).status, 'unreadable');
});

// ── Wired through parseEmail/summarizeAttachments ────────────────────────

function buildZipAttachmentEml(filename: string, zip: Buffer): string {
  return [
    'From: sender@example.com',
    'Subject: Archive test',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="BOUND"',
    '',
    '--BOUND',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'See attached.',
    '',
    '--BOUND',
    `Content-Type: application/zip; name="${filename}"`,
    `Content-Disposition: attachment; filename="${filename}"`,
    'Content-Transfer-Encoding: base64',
    '',
    zip.toString('base64'),
    '',
    '--BOUND--',
    '',
  ].join('\r\n');
}

test('a ZIP attachment on the .eml path carries its directory listing', async () => {
  const zip = buildStoredZip([
    { name: 'Invoice_Statement.pdf.exe', content: Buffer.from('placeholder, not a real executable') },
  ]);
  const parsed = await parseEmail(buildZipAttachmentEml('documents.zip', zip));

  assert.equal(parsed.attachments.length, 1);
  const file = parsed.attachments[0];
  assert.ok(file.zipEntries, 'expected zipEntries to be populated for a .zip attachment');
  assert.equal(file.zipEntries?.length, 1);
  assert.equal(file.zipEntries?.[0].filename, 'Invoice_Statement.pdf.exe');
});

test('a non-ZIP attachment never gets a zipEntries field', async () => {
  const parsed = await parseEmail(buildZipAttachmentEml('notes.txt', Buffer.from('irrelevant, not zip content')));
  assert.equal(parsed.attachments[0].zipEntries, undefined);
});

test('a real ZIP renamed to a non-.zip extension is still listed — content sniffing is not evaded by renaming', async () => {
  const zip = buildStoredZip([
    { name: 'Invoice_Statement.pdf.exe', content: Buffer.from('placeholder, not a real executable') },
  ]);
  // Nothing about this filename says "archive" at all.
  const parsed = await parseEmail(buildZipAttachmentEml('invoice.pdf', zip));

  assert.equal(parsed.attachments.length, 1);
  const file = parsed.attachments[0];
  assert.ok(file.zipEntries, 'expected zipEntries to be populated despite the misleading filename');
  assert.equal(file.zipEntries?.[0].filename, 'Invoice_Statement.pdf.exe');
});

test('.msg-sourced ZIP attachments never carry a directory listing, same boundary as hashing', async () => {
  const synthesized = 'From: "Sender" <a@b.com>\r\nSubject: test\r\n\r\nBody text here.';
  const extraAttachments = [{ filename: 'archive.zip', contentType: 'application/zip', size: 4321 }];
  const parsed = await parseEmail(synthesized, extraAttachments);

  assert.equal(parsed.attachments.length, 1);
  assert.equal(parsed.attachments[0].zipEntries, undefined);
});
