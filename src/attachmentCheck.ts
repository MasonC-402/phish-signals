// Attachment metadata analysis — filename, extension, and declared type only.
// This file never touches content bytes itself; where a hash or a ZIP
// directory listing is present on AttachmentSummary, it was computed once,
// upstream, in lib/emailParser.ts (the listing via lib/zipCheck.ts, reading
// only the ZIP central directory — never decompressing an entry).

import { stripDangerousUnicode } from './sanitize';
import type { AttachmentSummary, Signal, SignalResult, ZipEntry } from './types';

const EXECUTABLE_EXTENSIONS = new Set([
  '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.vbe', '.js', '.jse',
  '.wsf', '.wsh', '.msi', '.msp', '.ps1', '.psm1', '.jar', '.hta', '.cpl', '.reg',
]);

const MACRO_EXTENSIONS = new Set(['.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm', '.xlam', '.xlsb']);

// Containers used to smuggle a payload past scanners that only look at the
// outermost file, and disk images that mount on double-click without the
// mark-of-the-web warning a downloaded executable would get.
const ARCHIVE_EXTENSIONS = new Set(['.zip', '.rar', '.7z', '.cab', '.gz', '.tar', '.ace', '.arj']);
const DISK_IMAGE_EXTENSIONS = new Set(['.iso', '.img', '.vhd', '.vhdx', '.dmg']);
const SCRIPT_SHORTCUT_EXTENSIONS = new Set(['.lnk', '.url', '.scf', '.inf', '.chm', '.one', '.xll', '.wll']);

// What's dangerous inside a ZIP is the same as what's dangerous as a
// top-level attachment — an executable, a macro document, or a script/
// shortcut container. Disk images are left out: mounting a nested disk image
// straight out of an archive listing is a stretch two containers deep, and
// including it would mean flagging plenty of entirely ordinary "backup.zip
// containing backup.dmg" archives.
const DANGEROUS_INNER_EXTENSIONS = new Set([
  ...EXECUTABLE_EXTENSIONS,
  ...MACRO_EXTENSIONS,
  ...SCRIPT_SHORTCUT_EXTENSIONS,
]);

// Extensions that read as an ordinary document or image. Declaring one of
// these as an executable MIME type below is a narrow, low-noise mismatch —
// unlike a generic "declared type doesn't match the extension" check, which
// would misfire constantly: plenty of legitimate mail clients declare
// ordinary attachments as application/octet-stream whenever they don't
// recognize the type, so that generic type is deliberately left out of the
// executable set rather than treated as suspicious on its own.
const BENIGN_EXTENSIONS = new Set([
  '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.txt', '.csv', '.rtf',
]);

const EXECUTABLE_MIME_TYPES = new Set([
  'application/x-msdownload',
  'application/x-dosexec',
  'application/x-executable',
  'application/vnd.microsoft.portable-executable',
  'application/x-ms-shortcut',
]);

// Normalized before anything else is extracted, since the extension match
// below is anchored to the very end of the string and none of these evade
// the plain-whitespace trim that used to run first:
//   - a NUL byte truncates what most systems and viewers ever actually
//     render for the name, so only what's before the first one is
//     considered — "invoice.exe\0.txt" reads as "invoice.exe", matching what
//     a human would actually perceive, not the ".txt" a naive suffix match
//     would find past the NUL.
//   - zero-width and bidi-control characters (RTLO in particular — the
//     classic "invoice.exe" + U+202E trick that visually reverses part of a
//     filename) aren't whitespace, so a naive trailing-character trim leaves
//     them in place and the extension regex, anchored to $, then finds
//     nothing at all past them.
//   - only the basename (after the last / or \) is considered, so an
//     embedded path segment can't hide the real extension from the trailing
//     match either.
// Trailing dots and whitespace are stripped after that normalization:
// "invoice.exe " and "invoice.exe." both resolve to .exe on Windows, and
// both would otherwise read as having no extension at all.
function extname(filename: string | undefined): string {
  const truncatedAtNul = (filename || '').split('\0')[0];
  const normalized = stripDangerousUnicode(truncatedAtNul);
  const basename = normalized.split(/[/\\]/).pop() || '';
  const cleaned = basename.replace(/[\s.]+$/, '');
  const match = /\.[a-z0-9]+$/i.exec(cleaned);
  return match ? match[0].toLowerCase() : '';
}

// e.g. "invoice.pdf.exe" — a real extension immediately followed by a
// dangerous one, the classic disguise trick.
function hasDoubleExtension(filename: string | undefined, ext: string): boolean {
  if (!ext) return false;
  const withoutFinalExt = (filename || '').replace(/[\s.]+$/, '').slice(0, -ext.length);
  return /\.[a-z0-9]{2,4}$/i.test(withoutFinalExt);
}

// "photo.jpg" declared as application/x-msdownload — the filename says
// picture, the message's own metadata says Windows executable. Disjoint from
// the extension-based checks above by construction: BENIGN_EXTENSIONS and
// EXECUTABLE_EXTENSIONS never overlap, so a file actually named "invoice.exe"
// is caught by the executable-extension check instead and never double-fires here.
function hasExecutableMimeMismatch(ext: string, contentType: string | undefined): boolean {
  if (!BENIGN_EXTENSIONS.has(ext)) return false;
  const type = (contentType || '').toLowerCase().split(';')[0].trim();
  return EXECUTABLE_MIME_TYPES.has(type);
}

// Reuses extname() so a nested "readme.pdf.exe" inside the archive is caught
// by the same double-extension-shaped trick as a top-level one, without a
// duplicate check. stripDangerousUnicode() runs on the name that's actually
// returned (and later shown in the finding's detail text), not just on what
// extname() sees internally: an entry name carrying an RTLO character would
// still have the extension correctly identified (extname() already
// normalizes its own input), but the *raw* name reaching the report would
// still visually reverse/mislead — e.g. reading as "invoice.png" on screen
// while the underlying bytes say ".exe". Top-level attachment filenames
// already get this same treatment at the routes/phish-report.ts display
// step; this is that same treatment applied here, at the point a ZIP
// entry's name is decided to be worth showing at all.
function findDangerousZipEntries(entries: ZipEntry[]): string[] {
  return entries
    .map((e) => stripDangerousUnicode(e.filename))
    .filter((name) => DANGEROUS_INNER_EXTENSIONS.has(extname(name)));
}

function checkAttachments(attachments: AttachmentSummary[] | undefined): SignalResult {
  const signals: Signal[] = [];

  for (const file of attachments || []) {
    const ext = extname(file.filename);
    // Driven by whether the file content-sniffed as a ZIP (lib/zipCheck.ts),
    // not by its extension — an attachment renamed to hide that it's really
    // a ZIP would previously have skipped this check entirely.
    const dangerousInner = file.zipEntries ? findDangerousZipEntries(file.zipEntries) : [];

    if (hasExecutableMimeMismatch(ext, file.contentType)) {
      signals.push({
        id: 'attachment_mime_extension_mismatch',
        category: 'payload',
        severity: 'high',
        label: 'Declared Type Contradicts the Filename',
        detail: `"${file.filename}" has an extension that reads as an ordinary document or image, but the message declares its type as "${file.contentType}", which is an executable format. The two disagree.`,
        mitre: ['T1036.008', 'T1566.001'],
      });
    }

    if (EXECUTABLE_EXTENSIONS.has(ext) && hasDoubleExtension(file.filename, ext)) {
      signals.push({
        id: 'attachment_double_extension',
        category: 'payload',
        severity: 'critical',
        label: 'Disguised Executable Attachment',
        detail: `"${file.filename}" uses a double extension to pass an executable off as a document. This is deliberate deception, not a misconfiguration.`,
        mitre: ['T1566.001', 'T1036.007', 'T1204.002'],
      });
    } else if (EXECUTABLE_EXTENSIONS.has(ext)) {
      signals.push({
        id: 'attachment_executable',
        category: 'payload',
        severity: 'critical',
        label: 'Executable Attachment',
        detail: `"${file.filename}" is a directly executable file type (${ext}). Opening it runs code on your machine.`,
        mitre: ['T1566.001', 'T1204.002'],
      });
    } else if (MACRO_EXTENSIONS.has(ext)) {
      signals.push({
        id: 'attachment_macro_document',
        category: 'payload',
        severity: 'high',
        label: 'Macro-Enabled Document',
        detail: `"${file.filename}" is a macro-enabled Office document (${ext}). The macro runs on "Enable Content", which is what the message body is usually written to talk you into.`,
        mitre: ['T1566.001', 'T1204.002'],
      });
    } else if (DISK_IMAGE_EXTENSIONS.has(ext)) {
      signals.push({
        id: 'attachment_disk_image',
        category: 'payload',
        severity: 'high',
        label: 'Disk Image Attachment',
        detail: `"${file.filename}" is a disk image (${ext}). These mount on double-click and their contents bypass the "downloaded from the internet" warning an executable would trigger.`,
        mitre: ['T1566.001', 'T1204.002'],
      });
    } else if (SCRIPT_SHORTCUT_EXTENSIONS.has(ext)) {
      signals.push({
        id: 'attachment_shortcut',
        category: 'payload',
        severity: 'high',
        label: 'Shortcut / Script Container Attachment',
        detail: `"${file.filename}" is a shortcut or script container (${ext}). It looks inert but can launch an arbitrary command when opened.`,
        mitre: ['T1566.001', 'T1204.002'],
      });
    } else if (dangerousInner.length > 0) {
      const shown = dangerousInner.slice(0, 3).map((n) => `"${n}"`).join(', ');
      const more = dangerousInner.length > 3 ? `, and ${dangerousInner.length - 3} more` : '';
      // Called out explicitly when the filename doesn't even say .zip: a
      // real archive under a misleading extension is itself a deception on
      // top of whatever's inside it, not just an incidental naming quirk.
      const renamedNote = ext === '.zip' ? '' : ` The filename doesn't even indicate an archive (extension: "${ext || 'none'}"), which is itself worth noting.`;
      signals.push({
        id: 'attachment_archive_contains_executable',
        category: 'payload',
        severity: 'critical',
        label: 'Archive Contains a Disguised Executable',
        detail: `"${file.filename}" is a ZIP archive (identified from its content, not just its name).${renamedNote} Its directory listing shows ${shown}${more} — a directly executable or macro-bearing file sitting inside what looks like an ordinary archive. Its compressed bytes were never extracted or run; only the directory listing was read.`,
        mitre: ['T1566.001', 'T1204.002', 'T1027.001'],
      });
    } else if (file.zipUnreadable) {
      // Distinct from both "nothing dangerous inside" and "not an archive at
      // all" — this file content-sniffs as a ZIP but its directory couldn't
      // actually be read (most likely ZIP64, which lib/zipCheck.ts doesn't
      // parse). Named explicitly rather than silently falling through to no
      // signal, so a reader can't mistake "couldn't check" for "checked,
      // clean."
      signals.push({
        id: 'attachment_archive_unreadable',
        category: 'payload',
        severity: 'low',
        label: 'Archive Directory Could Not Be Read',
        detail: `"${file.filename}" is a ZIP archive, but its central directory could not be read (most likely a ZIP64 archive, which isn't supported here). Its contents are unknown rather than confirmed clean — this is not the same as having been checked and found nothing dangerous.`,
        mitre: ['T1566.001'],
      });
    } else if (ARCHIVE_EXTENSIONS.has(ext)) {
      signals.push({
        id: 'attachment_archive',
        category: 'payload',
        severity: 'low',
        label: 'Archive Attachment',
        detail: `"${file.filename}" is an archive (${ext}). Not suspicious alone, but archives are routinely used to hide an executable from scanners that only inspect the outer file. Its contents were not opened.`,
        mitre: ['T1566.001'],
      });
    }
  }

  return { signals };
}

export { checkAttachments, extname, hasDoubleExtension, hasExecutableMimeMismatch };
