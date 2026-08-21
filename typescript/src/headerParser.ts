// Lightweight parser for a block of raw email headers pasted on their own —
// not a full .eml message. Produces the same {headerLines, headers} shapes
// lib/receivedChain.ts's analyzeReceivedChain() and lib/authCheck.ts's
// checkAuthentication() already consume from mailparser, without pulling in
// mailparser or doing any MIME/body parsing at all: both of those functions
// only ever need the header block, per lib/emailParser.ts's own parseEmail(),
// which is a header parser co-located inside a MIME parser rather than
// something truly fused to it.

export interface ParsedHeaders {
  /** Raw header lines, unfolded, in original (wire) order. */
  headerLines: { key: string; line: string }[];
  /** Lowercase header name -> first (i.e. most recent, since wire order is newest-first) value. */
  headers: Map<string, unknown>;
}

// Header field-name per RFC 5322: printable US-ASCII excluding colon.
const HEADER_LINE = /^([!-9;-~]+):[ \t]?(.*)$/;

function parseHeaderText(raw: string): ParsedHeaders {
  const normalized = raw.replace(/\r\n/g, '\n');
  const rawLines = normalized.split('\n');

  // Unfold continuation lines (leading whitespace) into the header above them.
  const lines: string[] = [];
  for (const line of rawLines) {
    if (/^[ \t]/.test(line) && lines.length > 0) {
      lines[lines.length - 1] += ' ' + line.trim();
    } else if (line.trim() !== '') {
      lines.push(line);
    }
  }

  const headerLines: { key: string; line: string }[] = [];
  const headers = new Map<string, unknown>();

  for (const line of lines) {
    const match = HEADER_LINE.exec(line);
    if (!match) continue;
    const key = match[1].toLowerCase();
    const value = match[2];
    headerLines.push({ key, line });
    // First occurrence wins: wire order is newest-first, so for a singular
    // header (From/Reply-To/Return-Path/Subject) the first instance is the
    // most recent one, matching what a real message would present.
    if (!headers.has(key)) headers.set(key, value);
  }

  return { headerLines, headers };
}

export { parseHeaderText };
