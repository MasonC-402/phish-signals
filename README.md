# @farksecurity/phish-signals

Heuristic phishing-detection engine, extracted from [farksecurity.com's
phish-report tool](https://farksecurity.com/phish-report): URL/domain
typosquat and homograph checks, SPF/DKIM/DMARC-aware header analysis,
Received-chain spoofing checks, IOC defang/refang, MITRE ATT&CK mapping,
Sigma rule generation, and parsing for raw `.eml`/pasted messages, Outlook
`.msg` files, and embedded QR codes. No network calls, no external API keys —
everything runs locally on data you already have.

## Install

```bash
npm install @farksecurity/phish-signals
```

## Quick start

```ts
import { parseEmail, checkUrls, checkAuthentication, combineResults } from '@farksecurity/phish-signals';

// A single URL, no email context needed.
const [result] = checkUrls(['http://paypa1-secure.tk/login']);
console.log(result.risk, result.detail);
// 'malicious', 'Closely resembles "paypal.com" (likely typosquat)'

// A full raw .eml or pasted message.
const raw = [
  'From: CEO <ceo@example.com>',
  'Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail',
  '',
  'Click http://paypa1-secure.tk/login to verify.',
].join('\r\n');

const parsed = await parseEmail(raw);
console.log(checkAuthentication(parsed.headers, parsed.headerLines).signals.map((s) => s.id));
// [ 'dmarc_fail', 'spf_fail', 'dkim_fail' ]
```

Every check takes plain data and returns `Signal[]`-bearing results
(`{ id, category, severity, label, detail, mitre?, benign? }`) rather than a
raw numeric score — see the `Signal`/`EvidenceCategory`/`Severity` types. The
checks below don't need `parseEmail` at all if you already have structured
data (a URL string, a header-lines array) from elsewhere.

## What's included

- **URL/domain analysis** (`checkUrls`, `checkTyposquat`, `brandImpersonation`, `isIpLiteral`) — typosquatting, brand impersonation, IP-literal links, dangerous extensions, URL shorteners, and more, scored per URL.
- **Punycode / homograph detection** (`describeHostname`, `decodeHostname`, `isWholeScriptConfusable`) — a hand-written RFC 3492 decoder distinguishing mixed-script and whole-script-confusable homograph domains from ordinary internationalized domains.
- **Header analysis** (`checkAuthentication`, `checkHeaderAnomalies`, `analyzeReceivedChain`) — SPF/DKIM/DMARC parsing (including a structural check against forged trailing Authentication-Results headers), thread-hijack detection, and Received-chain HELO/reverse-DNS spoofing checks.
- **Attachment/content checks** (`checkAttachments`, `checkContent`, `checkLinkText`, `checkDangerousSchemes`) — dangerous extensions (including inside a ZIP's central directory), double extensions, MIME/extension mismatches, urgency language, link-text/href mismatches.
- **Scoring** (`scoreSignals`, `assessConfidence`, `MAX_CATEGORY_SCORE`) — combines signals across categories so correlated findings don't stack, and no single category dominates.
- **Analyst output** (`extractIocs`/`defang`/`refang`/`parseIocText`, `mapTechniques`, `buildSigmaRule`, `buildKqlQuery`, `buildRecommendations`, `buildJsonExport`) — defanged IOC lists (from a parsed email, or from freeform pasted text via `parseIocText`), MITRE ATT&CK technique mapping, generated Sigma detection rules, Microsoft 365 Defender / Sentinel Advanced Hunting KQL queries, and prioritized next-step recommendations.
- **Parsing** (`parseEmail`, `msgToRawEmail`, `scanImagesForQrCodes`) — turns a raw `.eml`, pasted message, or Outlook `.msg` file into the structured shape every check above consumes, plus bounded QR-code decoding for embedded/attached images. This is the one part of the package with real runtime dependencies (`mailparser`, `@kenjiuno/msgreader`, `jsqr`, `pngjs`, `jpeg-js`) — everything above it is plain data in, plain data out.
- **Input handling** (`sanitizeInput`, `stripDangerousUnicode`, `parseHeaderText`) — control-character stripping, RTLO/zero-width-character removal, and a lightweight parser for raw pasted header blocks (for when you have headers but not a full message).

## Status

Extracted and open-sourced from an in-production tool, and now developed here
in its own right rather than synced out of another repo. The same heuristics
also ship inside [farkwebsite](https://github.com/MasonC-402/farkwebsite)'s
phish-report tool, but the two copies evolve independently and are not kept in
lockstep, so pin a version rather than assuming score/verdict output is stable
across releases.

## License

MIT
