import MsgReader from '@kenjiuno/msgreader';
import { ValidationError } from './sanitize';
import type { MsgParseResult } from './types';

// Outlook .msg files are pure-JS-parsed here (no native/binary parser involved,
// so a malformed file can only throw a JS exception, never corrupt memory).
// We don't do anything with .msg structure ourselves beyond reading a few
// plain-text fields back out — everything downstream (auth/URL/content checks)
// still runs on the same "raw email text" shape as the .eml/paste path, so
// none of that analysis code needs to know .msg exists at all.
const UNREADABLE = 'Could not read this .msg file. It may be corrupted or not a valid Outlook message.';

function msgToRawEmail(buffer: Buffer): MsgParseResult {
  // getFileData() is inside the try as well as the constructor: a malformed
  // compound-file structure can parse far enough to construct and then throw
  // during field extraction, which previously escaped as a generic 500-path
  // error instead of the user-facing ValidationError this clearly intends.
  let data: ReturnType<MsgReader['getFileData']>;
  try {
    // @kenjiuno/msgreader's constructor is typed as ArrayBuffer | DataView,
    // but it works fine with a Node Buffer (a Uint8Array) at runtime — the
    // typing just doesn't reflect that.
    const msgReader = new MsgReader(buffer as unknown as ArrayBuffer);
    data = msgReader.getFileData();
  } catch (err) {
    throw new ValidationError(UNREADABLE);
  }

  if (!data || data.error || data.dataType !== 'msg') {
    throw new ValidationError(UNREADABLE);
  }

  const body = data.body || '';

  // .msg attachments never survive the plain-text conversion below, so pull
  // their metadata out separately here — filename/extension/size only,
  // never the actual bytes (getAttachment() is never called).
  const attachments = (data.attachments || []).map((a) => ({
    filename: a.fileName || a.fileNameShort || '(unnamed)',
    contentType: guessContentType(a.extension),
    size: a.contentLength || 0,
  }));

  // If the .msg still carries its original transport headers (common when a
  // received email was saved to disk as .msg), reuse them as-is — they hold
  // the real Authentication-Results/Return-Path/Reply-To that authCheck.ts
  // looks for. Otherwise (e.g. a message drafted natively in Outlook and
  // never transmitted) synthesize a minimal header block from the
  // structured sender/subject fields instead.
  if (data.headers && data.headers.trim()) {
    return { rawEmail: data.headers.trim() + '\r\n\r\n' + body, attachments };
  }

  const fromEmail = data.senderSmtpAddress || data.senderEmail || '';
  const fromName = (data.senderName || '').replace(/["\r\n]/g, '');
  const from = fromName ? `"${fromName}" <${fromEmail}>` : fromEmail;
  const subject = (data.subject || '').replace(/[\r\n]+/g, ' ');

  return { rawEmail: `From: ${from}\r\nSubject: ${subject}\r\n\r\n${body}`, attachments };
}

// .msg stores attachments as raw extension strings, not MIME types — a
// rough guess is enough here since this only feeds the image-count note,
// not any actual content handling.
function guessContentType(extension: string | undefined): string {
  const ext = (extension || '').toLowerCase();
  if (['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'].includes(ext)) {
    return 'image/' + ext.slice(1);
  }
  return 'application/octet-stream';
}

export { msgToRawEmail };
