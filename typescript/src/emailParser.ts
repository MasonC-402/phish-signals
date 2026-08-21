import { createHash } from 'crypto';
import { simpleParser } from 'mailparser';
import { registrableDomain } from './domains';
import { stripDangerousUnicode } from './sanitize';
import { scanImagesForQrCodes } from './qrCheck';
import { listZipEntries } from './zipCheck';
import type { AttachmentSummary, LinkMismatch, ParsedEmail, RawAttachmentMeta } from './types';

// The trailing character class deliberately excludes the punctuation that
// commonly *follows* a URL rather than belonging to it — mailparser's HTML-to-
// text conversion renders links as "[http://example.com]", which used to leave
// a trailing "]" glued to every extracted URL, breaking both the parse and the
// rendered Links Found table.
const URL_PATTERN = /\bhttps?:\/\/[^\s<>"'`\])}]+/gi;
const TRAILING_PUNCTUATION = /[.,;:!?'")\]}>]+$/;

const ANCHOR_PATTERN = /<a\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
const HREF_PATTERN = /\bhref\s*=\s*["'](https?:\/\/[^"']+)["']/gi;

// href="data:...", href="javascript:...", href="vbscript:..." — schemes with
// no hostname at all. This is invisible to every check above: extractHrefs
// only matches http(s), and a data: URI can encode an entire fake login page
// inline (no domain for any reputation-style check to ever see), while
// javascript:/vbscript: run code directly on click. There is no legitimate
// reason for any of these to appear as a link in an email.
const DANGEROUS_SCHEME_PATTERN = /\bhref\s*=\s*["'](data|javascript|vbscript):/gi;

function cleanUrl(url: string): string {
  return url.replace(TRAILING_PUNCTUATION, '');
}

function extractUrls(text: string | null | undefined): string[] {
  if (!text) return [];
  return (text.match(URL_PATTERN) || []).map(cleanUrl).filter(Boolean);
}

// Links are pulled from the HTML part's href attributes as well as the plain
// text. Previously this was `textBody || htmlBody`, so for any multipart
// message with both parts — which is nearly all real mail — the HTML was never
// looked at. A benign plaintext part next to a malicious HTML part is the
// standard phishing layout, and it scored zero.
function extractHrefs(html: string | null | undefined): string[] {
  if (!html) return [];
  const found: string[] = [];
  for (const match of html.matchAll(HREF_PATTERN)) {
    found.push(cleanUrl(match[1]));
  }
  return found;
}

function findDangerousSchemes(html: string | null | undefined): string[] {
  if (!html) return [];
  const found = new Set<string>();
  for (const match of html.matchAll(DANGEROUS_SCHEME_PATTERN)) {
    found.add(match[1].toLowerCase());
  }
  return [...found];
}

function stripTags(html: string): string {
  return html.replace(/<[^>]*>/g, ' ').replace(/&nbsp;/gi, ' ').replace(/\s+/g, ' ').trim();
}

function decodeEntities(value: string): string {
  return value
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#0?39;|&apos;/gi, "'");
}

// <a href="http://evil.tk/login">https://paypal.com/account</a> — the anchor
// text names one destination and the href points at another. One of the
// clearest phishing signals available from the message alone, and it is only
// visible in the HTML part.
function findLinkMismatches(html: string | null | undefined): LinkMismatch[] {
  if (!html) return [];
  const mismatches: LinkMismatch[] = [];

  for (const match of html.matchAll(ANCHOR_PATTERN)) {
    const href = decodeEntities(match[1].trim());
    const text = decodeEntities(stripTags(match[2]));
    if (!/^https?:\/\//i.test(href)) continue;

    // Only compare when the anchor text is itself a URL or a bare domain —
    // "Click here" tells us nothing.
    const textUrlMatch = text.match(/^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/?#]|$)/i);
    if (!textUrlMatch) continue;

    let hrefHost: string;
    try {
      hrefHost = new URL(href).hostname;
    } catch {
      continue;
    }

    const claimed = registrableDomain(textUrlMatch[1].replace(/^www\./i, ''));
    const actual = registrableDomain(hrefHost.replace(/^www\./i, ''));
    if (claimed !== actual) {
      mismatches.push({ text: text.slice(0, 120), href: href.slice(0, 300), claimedDomain: claimed, actualDomain: actual });
    }
  }

  return mismatches;
}

// Header-block detection. The old version tested a single /^(From|Received|
// Return-Path):/im anywhere in the input, which both missed header blocks
// starting with Delivered-To/To/Subject and misfired on an ordinary pasted body
// that happened to quote a "From:" line. This instead walks the top of the
// input and requires an actual contiguous header block there.
const HEADER_LINE = /^[A-Za-z][A-Za-z0-9-]{1,40}:\s*\S/;
const TRANSPORT_HEADER = /^(from|received|return-path|delivered-to|message-id|dkim-signature|authentication-results):/i;

function looksLikeRawEmail(raw: string): boolean {
  const lines = raw.slice(0, 8000).split('\n');
  let headerCount = 0;
  let sawTransportHeader = false;

  for (const line of lines) {
    if (line.trim() === '') break; // blank line ends the header block
    if (HEADER_LINE.test(line)) {
      headerCount++;
      if (TRANSPORT_HEADER.test(line)) sawTransportHeader = true;
    } else if (/^[ \t]+\S/.test(line)) {
      continue; // folded continuation of the previous header
    } else {
      break; // prose — not a header block
    }
  }

  // Two headers is enough on its own; a single one counts only if it's a real
  // transport header rather than something like "Note: ..." opening a message.
  return headerCount >= 2 || (headerCount === 1 && sawTransportHeader);
}

// Digests only, never interpretation: the bytes are hashed as an opaque blob
// and the buffer is discarded the moment this returns. Nothing about the
// file's format, structure, or content is ever parsed or decoded — hashing
// doesn't require any of that, which is exactly why it doesn't compromise the
// "attachment bytes are never opened" design the rest of this pipeline holds
// to. MD5 and SHA-1 are included alongside SHA-256 despite both being broken
// for collision resistance, because they're still what a lot of existing
// hash-indexed threat intel and blocklists key on for exactly this kind of
// "is this a known-bad file" lookup — not used here for any integrity purpose.
function hashAttachment(content: Buffer): { md5: string; sha1: string; sha256: string } {
  return {
    md5: createHash('md5').update(content).digest('hex'),
    sha1: createHash('sha1').update(content).digest('hex'),
    sha256: createHash('sha256').update(content).digest('hex'),
  };
}

// mailparser puts both real attachments and inline/embedded images (e.g. a
// signature logo, or a QR code standing in for a text link) in the same
// `attachments` array, distinguished by contentDisposition/cid. Only
// filename/type/size are ever looked at *structurally* — nothing here parses
// or opens what a file actually contains. Hashing is the one exception, and
// only for attachments that arrived via a raw .eml/pasted message: mailparser
// has already buffered those bytes as an ordinary part of MIME parsing, so
// hashing them introduces no new read of untrusted input. .msg attachments
// (see lib/msgParser.ts) never carry a `content` buffer at all — that parser
// deliberately never calls the library's attachment-extraction function — so
// they pass through here with no hash, same as always.
// Attempted on every content-buffered attachment, regardless of filename or
// declared type — listZipEntries() itself sniffs the actual bytes and
// returns 'not-zip' immediately for anything that isn't, so this is cheap
// for the common non-archive case and, unlike a filename check, isn't
// evaded by an attachment renamed to ".zipx" or given no extension at all.
function zipFields(content: Buffer | undefined): Pick<AttachmentSummary, 'zipEntries' | 'zipUnreadable'> {
  if (!content) return {};
  const result = listZipEntries(content);
  if (result.status === 'ok') return result.entries.length > 0 ? { zipEntries: result.entries } : {};
  if (result.status === 'unreadable') return { zipUnreadable: true };
  return {};
}

function summarizeAttachments(attachments: RawAttachmentMeta[] | undefined): { files: AttachmentSummary[]; imageCount: number } {
  const list = attachments || [];
  const files = list
    .filter((a) => a.contentDisposition !== 'inline' && !a.related)
    .map((a) => ({
      filename: a.filename || '(unnamed)',
      contentType: a.contentType || 'unknown',
      size: a.size || 0,
      ...(a.content ? hashAttachment(a.content) : {}),
      ...zipFields(a.content),
    }));
  const imageCount = list.filter((a) => (a.contentType || '').startsWith('image/')).length;
  return { files, imageCount };
}

// QR scanning runs over every image mailparser found — including inline ones
// (contentDisposition === 'inline'), unlike summarizeAttachments()'s `files`
// list above, since an inline embedded logo/banner-shaped image is exactly
// where a phishing kit hides a QR code meant to be seen, not downloaded.
function scanForQrCodeUrls(attachments: RawAttachmentMeta[] | undefined): { urls: string[]; scannedCount: number } {
  const images = (attachments || [])
    .filter((a) => (a.contentType || '').toLowerCase().startsWith('image/') && a.content)
    .map((a) => ({ contentType: a.contentType || '', content: a.content as Buffer }));

  const { payloads, scannedCount } = scanImagesForQrCodes(images);
  const urls = dedupe(payloads.flatMap((payload) => extractUrls(payload)));
  return { urls, scannedCount };
}

function dedupe(urls: string[]): string[] {
  return [...new Set(urls)];
}

async function parseEmail(rawContent: string, extraAttachments?: RawAttachmentMeta[]): Promise<ParsedEmail> {
  if (looksLikeRawEmail(rawContent)) {
    const parsed = await simpleParser(rawContent);
    const textBody = parsed.text || '';
    const htmlBody = typeof parsed.html === 'string' ? parsed.html : '';
    // extraAttachments, not parsed.attachments, whenever the caller supplied
    // it. Only lib/msgParser.ts's caller ever does — and its reconstructed
    // text (real preserved headers, or a synthesized "From: ...\r\nSubject:
    // ...") virtually always satisfies looksLikeRawEmail() above, landing in
    // *this* branch. mailparser then finds zero real MIME attachment parts in
    // that reconstructed text (there aren't any — the synthesized text is
    // headers plus body only), so parsed.attachments was always empty here
    // and every .msg attachment silently vanished, regardless of what
    // msgParser had actually found in the real .msg structure. The `??`
    // makes an explicitly-supplied attachment list win regardless of which
    // branch fires, rather than only in the other one.
    const { files, imageCount } = summarizeAttachments(extraAttachments ?? parsed.attachments);
    // Same extraAttachments-over-parsed.attachments preference as above and
    // for the same reason: a .msg's images (if any survived the reconstructed
    // text as real MIME parts at all) live in extraAttachments, not in what
    // mailparser found in the synthesized text.
    const { urls: qrCodeUrls, scannedCount: qrImagesScanned } = scanForQrCodeUrls(extraAttachments ?? parsed.attachments);
    const subject = parsed.subject || null;

    return {
      isRawEmail: true,
      from: parsed.from?.text || null,
      returnPath: (parsed.headers.get('return-path') as string | undefined) || null,
      replyTo: parsed.replyTo?.text || null,
      subject,
      date: parsed.date ? parsed.date.toISOString() : null,
      headers: parsed.headers,
      // Raw lines in wire order. The headers Map collapses repeated headers in
      // ways that lose ordering, and the Received chain is only meaningful in
      // the order the servers wrote it.
      headerLines: (parsed.headerLines || []).map((h) => ({ key: h.key, line: h.line })),
      textBody,
      htmlBody,
      // Subject line carries the urgency bait as often as the body does, and
      // the HTML part may hold text the plaintext alternative deliberately omits.
      // stripDangerousUnicode() here matters for a different reason than it
      // does when applied to header text for display: zero-width characters
      // inserted mid-word ("ver​ify your acc​ount") defeat the plain
      // substring matching in checkContent()'s phrase lists without this —
      // this is the one place that scan actually happens, so the evasion has
      // to be stripped before matching, not just before rendering.
      scanText: stripDangerousUnicode([subject || '', textBody, stripTags(htmlBody)].join('\n')),
      urls: dedupe([...extractUrls(textBody), ...extractHrefs(htmlBody), ...extractUrls(stripTags(htmlBody)), ...qrCodeUrls]),
      linkMismatches: findLinkMismatches(htmlBody),
      dangerousSchemes: findDangerousSchemes(htmlBody),
      attachments: files,
      imageCount,
      qrCodeUrls,
      qrImagesScanned,
    };
  }

  // Plain paste, or a .msg whose original MIME structure couldn't be
  // preserved — attachment metadata comes from the caller instead (see
  // lib/msgParser.ts), since it isn't part of the raw text itself.
  const { files, imageCount } = summarizeAttachments(extraAttachments);

  return {
    isRawEmail: false,
    from: null,
    returnPath: null,
    replyTo: null,
    subject: null,
    date: null,
    headers: null,
    headerLines: [],
    textBody: rawContent,
    htmlBody: null,
    scanText: stripDangerousUnicode(rawContent),
    urls: dedupe(extractUrls(rawContent)),
    linkMismatches: [],
    dangerousSchemes: [],
    attachments: files,
    imageCount,
    // Never populated on this path: a plain-text paste has no image bytes at
    // all, and a .msg's extraAttachments never carries `.content` (see
    // lib/msgParser.ts) — the same boundary the hash fields above respect.
    qrCodeUrls: [],
    qrImagesScanned: 0,
  };
}

export { parseEmail, extractUrls, extractHrefs, findLinkMismatches, findDangerousSchemes, looksLikeRawEmail };
