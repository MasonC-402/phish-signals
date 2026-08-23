"""Heuristic phishing-detection engine.

Independent Python implementation of the same detection engine published to
npm as ``@farksecurity/phish-signals`` (``../../typescript``). Not a binding
around it — see ``../../conformance/`` for what keeps the two in agreement on
what a given input means.

This module's role is the same as ``typescript/src/index.ts``: the public API
surface. Everything a consumer needs is re-exported from here; the submodules
underneath are internal layout, not a contract.

Every module through the checks/scoring/output layer is stdlib-only.
``msg_parser`` and ``qr_check`` are the two deliberate exceptions — see
``pyproject.toml`` for why ``extract-msg``, ``pillow`` and
``opencv-python-headless`` are this otherwise-dependency-free package's only
runtime dependencies.

The rule layer (:mod:`phish_signals.rules`) gives the detection logic a name,
so it can be listed, disabled, replaced, or extended by consumers. The
declarative half of it loads phrase-list rules from JSON so they are defined
once and shared across implementations.

Naming: the TypeScript source is camelCase because that is idiomatic there,
and the conformance vectors name functions the same way since it is the
reference implementation. This side uses ordinary Python naming
(``registrable_domain``, not ``registrableDomain``); the harness converts
between them. The exception is *data* keys inside the returned dicts —
``benignSignals``, ``originIp`` — which stay camelCase because they cross the
language boundary in JSON exports and conformance vectors, where the exact
spelling is part of the contract rather than an internal style choice.
"""

from __future__ import annotations

# Import order below is alphabetical by module (ruff's isort rule enforces
# this and will re-sort on every `ruff format`, so it's not maintained by
# hand). The thematic grouping that mirrors typescript/src/index.ts's
# sectioning — shared types, domain helpers, input handling, checks,
# scoring/output, parsing — lives in __all__ instead, where RUF022 is
# disabled specifically so that grouping can be preserved (see pyproject.toml).
from .attachment_check import (
    ARCHIVE_EXTENSIONS,
    DISK_IMAGE_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
    MACRO_EXTENSIONS,
    SCRIPT_SHORTCUT_EXTENSIONS,
    check_attachments,
    extname,
    has_double_extension,
    has_executable_mime_mismatch,
)
from .auth_check import check_authentication
from .combine_results import AnalysisInput, combine_results
from .content_check import (
    CONTENT_RULESET,
    KNOWN_BRAND_NAMES,
    check_content,
    check_dangerous_schemes,
    check_link_text,
)
from .domains import (
    KNOWN_BRAND_DOMAINS,
    brand_label,
    normalize_confusables,
    registrable_domain,
)
from .email_parser import (
    extract_hrefs,
    extract_urls,
    find_dangerous_schemes,
    find_link_mismatches,
    looks_like_raw_email,
    parse_email,
)
from .header_anomalies import check_header_anomalies
from .header_parser import ParsedHeaders, parse_header_text
from .iocs import defang, extract_iocs, parse_ioc_text, refang
from .json_export import build_json_export
from .kql_query import build_kql_query
from .mitre import TECHNIQUES, map_techniques, technique_url
from .msg_parser import msg_to_raw_email
from .punycode import (
    decode_hostname,
    decode_label,
    describe_hostname,
    is_whole_script_confusable,
    scripts_of,
)
from .qr_check import (
    MAX_QR_IMAGE_BYTES,
    MAX_QR_IMAGES,
    MAX_QR_PIXELS,
    SCAN_TIME_BUDGET_MS,
    DecodableImage,
    scan_images_for_qr_codes,
)
from .received_chain import analyze_received_chain, is_private_ip
from .recommendations import build_recommendations
from .rules import (
    Rule,
    RuleContext,
    RuleDiagnostic,
    RuleError,
    RuleInfo,
    RuleLoadError,
    RuleRunResult,
    Ruleset,
    RulesetError,
    evaluate_ruleset,
    load_rule_file,
    load_ruleset,
    parse_rule,
)
from .sanitize import (
    DEFAULT_MAX_LENGTH,
    ValidationError,
    sanitize_input,
    strip_dangerous_unicode,
)
from .sigma_rule import build_sigma_rule, subject_keywords
from .signals import (
    CORROBORATION_RATE,
    MAX_CATEGORY_SCORE,
    SEVERITY_POINTS,
    SEVERITY_RANK,
    assess_confidence,
    score_signals,
)
from .types import (
    CATEGORY_LABELS,
    AttachmentSummary,
    AuthCheckResult,
    Availability,
    CategoryScore,
    CombinedResult,
    Confidence,
    EvidenceCategory,
    HeaderAnomalyResult,
    HeaderLine,
    HostnameDescription,
    Ioc,
    IocType,
    LinkMismatch,
    MessageInfo,
    MitreTechnique,
    MsgAttachment,
    MsgParseResult,
    ParsedEmail,
    RawAttachmentMeta,
    ReceivedChainAnalysis,
    ReceivedHop,
    Recommendation,
    ScoredEvidence,
    Severity,
    Signal,
    SignalResult,
    UrlAnalysis,
    UrlRisk,
    Verdict,
    ZipEntry,
)
from .url_check import (
    DANGEROUS_DOWNLOAD_EXTENSIONS,
    EXPECTED_PORTS,
    MAX_URLS_ANALYZED,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    analyze_url,
    brand_impersonation,
    check_qr_codes,
    check_typosquat,
    check_urls,
    is_ip_literal,
    levenshtein,
    summarize_url_signals,
)
from .zip_check import (
    MAX_ENTRIES_LISTED,
    ZipListResult,
    list_zip_entries,
    looks_like_zip,
)

__version__ = "0.1.0"

#: Which submodules actually have an implementation behind them, as opposed to
#: a documented stub. Exposed so a caller can branch on the state of the port
#: instead of discovering it through an ``ImportError``.
IMPLEMENTED_MODULES: frozenset[str] = frozenset(
    {
        "types",
        "domains",
        "punycode",
        "sanitize",
        "header_parser",
        "signals",
        "iocs",
        "rules",
        "content_check",
        "url_check",
        "auth_check",
        "received_chain",
        "header_anomalies",
        "attachment_check",
        "mitre",
        "zip_check",
        "recommendations",
        "sigma_rule",
        "kql_query",
        "json_export",
        "combine_results",
        "email_parser",
        "msg_parser",
        "qr_check",
    }
)

__all__ = [
    # Version and port status
    "IMPLEMENTED_MODULES",
    "__version__",
    # Shared shapes
    "CATEGORY_LABELS",
    "AttachmentSummary",
    "AuthCheckResult",
    "Availability",
    "CategoryScore",
    "CombinedResult",
    "Confidence",
    "EvidenceCategory",
    "HeaderAnomalyResult",
    "HeaderLine",
    "HostnameDescription",
    "Ioc",
    "IocType",
    "LinkMismatch",
    "MessageInfo",
    "MitreTechnique",
    "MsgAttachment",
    "MsgParseResult",
    "ParsedEmail",
    "RawAttachmentMeta",
    "ReceivedChainAnalysis",
    "ReceivedHop",
    "Recommendation",
    "ScoredEvidence",
    "Severity",
    "Signal",
    "SignalResult",
    "UrlAnalysis",
    "UrlRisk",
    "Verdict",
    "ZipEntry",
    # Domains
    "KNOWN_BRAND_DOMAINS",
    "brand_label",
    "normalize_confusables",
    "registrable_domain",
    # Punycode / homographs
    "decode_hostname",
    "decode_label",
    "describe_hostname",
    "is_whole_script_confusable",
    "scripts_of",
    # Input handling
    "DEFAULT_MAX_LENGTH",
    "ParsedHeaders",
    "ValidationError",
    "parse_header_text",
    "sanitize_input",
    "strip_dangerous_unicode",
    # Checks
    "ARCHIVE_EXTENSIONS",
    "CONTENT_RULESET",
    "DANGEROUS_DOWNLOAD_EXTENSIONS",
    "DISK_IMAGE_EXTENSIONS",
    "EXECUTABLE_EXTENSIONS",
    "EXPECTED_PORTS",
    "KNOWN_BRAND_NAMES",
    "MACRO_EXTENSIONS",
    "MAX_ENTRIES_LISTED",
    "MAX_URLS_ANALYZED",
    "SCRIPT_SHORTCUT_EXTENSIONS",
    "SUSPICIOUS_TLDS",
    "TECHNIQUES",
    "URL_SHORTENERS",
    "ZipListResult",
    "analyze_received_chain",
    "analyze_url",
    "brand_impersonation",
    "check_attachments",
    "check_authentication",
    "check_content",
    "check_dangerous_schemes",
    "check_header_anomalies",
    "check_link_text",
    "check_qr_codes",
    "check_typosquat",
    "check_urls",
    "extname",
    "has_double_extension",
    "has_executable_mime_mismatch",
    "is_ip_literal",
    "is_private_ip",
    "levenshtein",
    "list_zip_entries",
    "looks_like_zip",
    "map_techniques",
    "summarize_url_signals",
    "technique_url",
    # Rules
    "Rule",
    "RuleContext",
    "RuleDiagnostic",
    "RuleError",
    "RuleInfo",
    "RuleLoadError",
    "RuleRunResult",
    "Ruleset",
    "RulesetError",
    "evaluate_ruleset",
    "load_rule_file",
    "load_ruleset",
    "parse_rule",
    # Scoring, aggregation, and output formatting
    "AnalysisInput",
    "CORROBORATION_RATE",
    "MAX_CATEGORY_SCORE",
    "SEVERITY_POINTS",
    "SEVERITY_RANK",
    "assess_confidence",
    "build_json_export",
    "build_kql_query",
    "build_recommendations",
    "build_sigma_rule",
    "combine_results",
    "defang",
    "extract_iocs",
    "parse_ioc_text",
    "refang",
    "score_signals",
    "subject_keywords",
    # Parsing
    "DecodableImage",
    "MAX_QR_IMAGES",
    "MAX_QR_IMAGE_BYTES",
    "MAX_QR_PIXELS",
    "SCAN_TIME_BUDGET_MS",
    "extract_hrefs",
    "extract_urls",
    "find_dangerous_schemes",
    "find_link_mismatches",
    "looks_like_raw_email",
    "msg_to_raw_email",
    "parse_email",
    "scan_images_for_qr_codes",
]
