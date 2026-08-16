// Shared shapes for the phish-report analysis pipeline (lib/*.ts + routes/phish-report.ts).

// Evidence categories. Scoring treats these as the independent axes: several
// weak signals spread across different categories say more than a pile of
// correlated signals inside one. See lib/signals.ts.
export type EvidenceCategory = 'authentication' | 'identity' | 'infrastructure' | 'payload' | 'social';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const CATEGORY_LABELS: Record<EvidenceCategory, string> = {
  authentication: 'Authentication',
  identity: 'Sender Identity',
  infrastructure: 'Routing & Infrastructure',
  payload: 'Links & Attachments',
  social: 'Social Engineering',
};

// One piece of evidence. Replaces the old `Flag`, which carried a hand-picked
// numeric weight and nothing else — no category (so correlated findings were
// summed as if independent), no severity, and no way to express that a finding
// argues *for* the message being legitimate.
export interface Signal {
  /** Stable identifier, e.g. 'spf_fail'. Used for dedupe and rule generation. */
  id: string;
  category: EvidenceCategory;
  severity: Severity;
  label: string;
  detail: string;
  /** MITRE ATT&CK technique IDs this evidence maps to. */
  mitre?: string[];
  /** True when this argues the message is legitimate rather than suspicious. */
  benign?: boolean;
}

export interface SignalResult {
  signals: Signal[];
}

export interface AuthCheckResult extends SignalResult {
  /** False when there were no headers to check at all (a plain-text paste). */
  available: boolean;
  /** True when SPF, DKIM and DMARC were all present and passing. */
  passed: boolean;
  /**
   * The authserv-id token of whichever Authentication-Results header
   * lib/authCheck.ts's selectAuthoritativeAuthResults() picked as
   * authoritative (or null if none survived selection). Exposed so
   * lib/headerAnomalies.ts's authserv_id_mismatch check validates that exact
   * same header instead of independently re-deriving "the" header from
   * headerLines and risking disagreement with what checkAuthentication
   * actually scored — the two checks must agree on which header they mean.
   */
  selectedAuthservId: string | null;
}

export interface AttachmentSummary {
  filename: string;
  contentType: string;
  size: number;
  // Present only for attachments parsed from a raw .eml/pasted message, where
  // mailparser has already buffered the bytes in memory as part of ordinary
  // MIME parsing — hashing them adds no new read of untrusted input. Absent
  // for .msg attachments, where the parser deliberately never reads content
  // bytes at all (see lib/msgParser.ts). Not a cryptographic integrity
  // control — these exist so a known-bad file can be looked up or matched
  // against a blocklist, which is why MD5 and SHA-1 are included alongside
  // SHA-256 despite both being broken for collision resistance: most existing
  // hash-indexed threat intel still keys on one of the three.
  md5?: string;
  sha1?: string;
  sha256?: string;
  // Present only for an attachment that content-sniffs as a ZIP (regardless
  // of its filename/extension — see lib/zipCheck.ts) on the same
  // content-buffered path as the hashes above — read from the central
  // directory only (filenames and declared sizes), never decompressed.
  // Omitted (not an empty array) when the archive was successfully read and
  // genuinely has no entries.
  zipEntries?: ZipEntry[];
  // True when the file content-sniffs as a ZIP but the central directory
  // could not actually be read (ZIP64, a malformed or out-of-range EOCD).
  // Kept distinct from a simple absence of `zipEntries` so "couldn't check"
  // is never silently indistinguishable from "checked, nothing dangerous
  // inside" in the UI/signals.
  zipUnreadable?: boolean;
}

/** One entry from a ZIP's central directory — name and declared size only. */
export interface ZipEntry {
  filename: string;
  uncompressedSize: number;
}

// Loosely-shaped input accepted by summarizeAttachments() in emailParser.ts —
// covers both mailparser's real Attachment objects (which carry
// contentDisposition/related and, unless streaming is enabled, a buffered
// `content`) and msgParser's plain {filename,contentType,size} objects, which
// never carry content at all.
export interface RawAttachmentMeta {
  filename?: string;
  contentType?: string;
  size?: number;
  contentDisposition?: string;
  related?: boolean;
  content?: Buffer;
}

// An <a> whose visible text claims one domain while its href points at another.
export interface LinkMismatch {
  text: string;
  href: string;
  claimedDomain: string;
  actualDomain: string;
}

/** One parsed `Received:` header. */
export interface ReceivedHop {
  index: number;
  /** Hostname the sending server announced in HELO/EHLO. */
  helo: string | null;
  /** Hostname the receiving server resolved the connection back to. */
  reverseDns: string | null;
  ip: string | null;
  by: string | null;
  timestamp: string | null;
  /** HELO and reverse DNS disagree at the registrable-domain level. */
  heloMismatch: boolean;
  private: boolean;
}

export interface ReceivedChainAnalysis {
  hops: ReceivedHop[];
  /** The bottom-most hop — where the message actually entered the mail system. */
  originIp: string | null;
  originHost: string | null;
  signals: Signal[];
}

export interface HeaderAnomalyResult extends SignalResult {
  messageIdDomain: string | null;
  mailer: string | null;
}

export type UrlRisk = 'unknown' | 'clean' | 'suspicious' | 'malicious';

export interface UrlAnalysis {
  url: string;
  hostname?: string;
  risk: UrlRisk;
  detail: string;
  riskScore?: number;
  /** Unicode form of a punycode hostname, plus the scripts it mixes. */
  decodedHost?: string | null;
  scripts?: string[];
}

export interface MessageInfo {
  subject: string;
  from: string;
  returnPath: string | null;
  replyTo: string | null;
  date: string | null;
}

/** Indicator of compromise, in both plain and defanged form. */
export interface Ioc {
  type: 'url' | 'domain' | 'ip' | 'email' | 'filename' | 'hash';
  value: string;
  defanged: string;
}

export interface MitreTechnique {
  id: string;
  name: string;
  url: string;
}

export interface Recommendation {
  /** Ordering hint: 'now' actions are shown first and styled as urgent. */
  urgency: 'now' | 'soon' | 'context';
  text: string;
}

export interface CategoryScore {
  category: EvidenceCategory;
  label: string;
  score: number;
  signals: Signal[];
}

/** How much of the message we actually got to look at. */
export interface Confidence {
  level: 'high' | 'medium' | 'low';
  /** 0-1, share of the evidence sources that were available. */
  completeness: number;
  /** Human-readable list of what could not be checked. */
  gaps: string[];
}

export interface CombinedResult {
  score: number;
  verdict: 'Low Risk' | 'Medium Risk' | 'High Risk';
  confidence: Confidence;
  /** Every signal, worst first. */
  signals: Signal[];
  benignSignals: Signal[];
  categories: CategoryScore[];
  urls: UrlAnalysis[];
  recommendations: Recommendation[];
  mitre: MitreTechnique[];
  iocs: Ioc[];
  sigmaRule: string;
  authAvailable: boolean;
  authPassed: boolean;
  receivedChain?: ReceivedChainAnalysis | null;
  linkMismatches?: LinkMismatch[];
  messageInfo?: MessageInfo | null;
  attachments?: AttachmentSummary[];
  imageCount?: number;
  /** How many embedded/attached images were actually run through the QR decoder (bounded — see lib/qrCheck.ts). */
  qrImagesScanned?: number;
  /** Pretty-printed JSON of this same result, for feeding a SOAR or ticketing system. Set last, after every other field. */
  jsonReport?: string;
}

export interface ParsedEmail {
  isRawEmail: boolean;
  from: string | null;
  returnPath: string | null;
  replyTo: string | null;
  subject: string | null;
  date: string | null;
  headers: Map<string, unknown> | null;
  /** Raw header lines in original order — needed to read the Received chain. */
  headerLines: { key: string; line: string }[];
  textBody: string;
  htmlBody: string | null;
  /** Subject + text part + de-tagged HTML part, i.e. everything the content heuristics should see. */
  scanText: string;
  urls: string[];
  linkMismatches: LinkMismatch[];
  /** 'data' / 'javascript' / 'vbscript' — hrefs with no hostname at all, invisible to every URL-based check. */
  dangerousSchemes: string[];
  attachments: AttachmentSummary[];
  imageCount: number;
  /** URLs decoded from a QR code in an embedded/attached image. Already folded into `urls` — kept separate too so a dedicated signal can name them. */
  qrCodeUrls: string[];
  /** How many images were actually attempted (bounded — see lib/qrCheck.ts), regardless of whether any decoded to anything. */
  qrImagesScanned: number;
}

export interface MsgAttachment {
  filename: string;
  contentType: string;
  size: number;
}

export interface MsgParseResult {
  rawEmail: string;
  attachments: MsgAttachment[];
}
