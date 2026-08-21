// Public API surface. Everything a consumer needs — types, checks, scoring,
// and output formatting — is re-exported from here; the individual modules
// are internal layout, not a contract.

// Shared shapes (Signal, UrlAnalysis, AuthCheckResult, CombinedResult, the
// ParsedEmail/RawAttachmentMeta/MsgParseResult interfaces the parsing
// functions below produce, etc.) plus the CATEGORY_LABELS constant.
export * from './types';

// Registrable-domain / brand-list utilities.
export { KNOWN_BRAND_DOMAINS, registrableDomain, normalizeConfusables, brandLabel } from './domains';

// Punycode decoding and homograph/confusable-script detection.
export { decodeLabel, decodeHostname, scriptsOf, describeHostname, isWholeScriptConfusable } from './punycode';

// Input handling.
export { ValidationError, sanitizeInput, stripDangerousUnicode } from './sanitize';
export { parseHeaderText } from './headerParser';
export type { ParsedHeaders } from './headerParser';

// Checks — each takes plain data (a URL string, a header-lines array, an
// AttachmentSummary[], ...) and returns Signal[]-bearing results. None of
// these need a parser package; feed them your own structured data.
export { checkUrls, checkTyposquat, brandImpersonation, levenshtein, isIpLiteral, summarizeUrlSignals, checkQrCodes, MAX_URLS_ANALYZED } from './urlCheck';
export { analyzeReceivedChain, isPrivateIp } from './receivedChain';
export { checkAuthentication } from './authCheck';
export { checkHeaderAnomalies } from './headerAnomalies';
export { checkContent, checkLinkText, checkDangerousSchemes } from './contentCheck';
export { checkAttachments, extname, hasDoubleExtension, hasExecutableMimeMismatch } from './attachmentCheck';
export { mapTechniques, TECHNIQUES, techniqueUrl } from './mitre';
export { listZipEntries, looksLikeZip, MAX_ENTRIES_LISTED } from './zipCheck';
export type { ZipListResult } from './zipCheck';

// Scoring, aggregation, and output formatting.
export { scoreSignals, assessConfidence, SEVERITY_POINTS, SEVERITY_RANK, MAX_CATEGORY_SCORE, CORROBORATION_RATE } from './signals';
export type { ScoredEvidence } from './signals';
export { extractIocs, defang, refang, parseIocText } from './iocs';
export { buildRecommendations } from './recommendations';
export { buildSigmaRule, subjectKeywords } from './sigmaRule';
export { buildKqlQuery } from './kqlQuery';
export { buildJsonExport } from './jsonExport';
export { combineResults } from './combineResults';
export type { AnalysisInput } from './combineResults';

// Parsing — turns a raw .eml, a pasted email/headers, or an Outlook .msg file
// (via msgToRawEmail) into the structured shape the checks above consume.
// The only part of this package with real runtime dependencies (mailparser,
// @kenjiuno/msgreader, jsqr, pngjs, jpeg-js) — everything above this section
// is plain data in, plain data out.
export { parseEmail, extractUrls, extractHrefs, findLinkMismatches, findDangerousSchemes, looksLikeRawEmail } from './emailParser';
export { msgToRawEmail } from './msgParser';
export { scanImagesForQrCodes, MAX_QR_IMAGES, MAX_QR_IMAGE_BYTES, MAX_QR_PIXELS, SCAN_TIME_BUDGET_MS } from './qrCheck';
