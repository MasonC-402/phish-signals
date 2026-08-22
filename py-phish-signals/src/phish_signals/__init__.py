"""Heuristic phishing-detection engine.

Independent Python implementation of the same detection engine published to
npm as ``@farksecurity/phish-signals`` (``../../typescript``). Not a binding
around it — see ``../../conformance/`` for what keeps the two in agreement on
what a given input means.

This module's role is the same as ``typescript/src/index.ts``: the public API
surface. Everything a consumer needs is re-exported from here; the submodules
underneath are internal layout, not a contract.

Ported so far — the zero-runtime-dependency layer, which is also the layer the
conformance vectors currently cover: shared types, domain helpers, punycode
and homograph identification, input sanitizing, scoring, and IOC handling. The
checks, aggregation, and parsing layers exist as documented stubs and export
nothing yet; :data:`IMPLEMENTED_MODULES` is the machine-readable version of
that status.

Plus one layer with no counterpart in the reference implementation yet: the
rule layer (:mod:`phish_signals.rules`), which gives the detection logic
currently written inline inside each check a name, so it can be listed,
disabled, replaced, or written by a consumer of this library. The checks
layer is still stubs on this side, which is why the rule layer landed first
— those checks get to be *built* as rules rather than ported and then
retrofitted. It is designed to port to TypeScript, and the declarative half
of it is designed so that most content rules never need porting at all: both
implementations read the same JSON.

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

# Registrable-domain / brand-list utilities.
from .domains import (
    KNOWN_BRAND_DOMAINS,
    brand_label,
    normalize_confusables,
    registrable_domain,
)

# Indicator extraction and defanging.
from .iocs import defang, extract_iocs, parse_ioc_text, refang

# Punycode decoding and homograph/confusable-script detection.
from .punycode import (
    decode_hostname,
    decode_label,
    describe_hostname,
    is_whole_script_confusable,
    scripts_of,
)

# Rule layer: named detection units, custom rules, declarative rulesets.
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

# Input handling.
from .sanitize import (
    DEFAULT_MAX_LENGTH,
    ValidationError,
    sanitize_input,
    strip_dangerous_unicode,
)

# Scoring.
from .signals import (
    CORROBORATION_RATE,
    MAX_CATEGORY_SCORE,
    SEVERITY_POINTS,
    SEVERITY_RANK,
    assess_confidence,
    score_signals,
)

# Shared shapes, plus the CATEGORY_LABELS constant.
from .types import (
    CATEGORY_LABELS,
    AttachmentSummary,
    AuthCheckResult,
    Availability,
    CategoryScore,
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
    ParsedEmail,
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

__version__ = "0.1.0"

#: Which submodules actually have an implementation behind them, as opposed to
#: a documented stub. Exposed so a caller can branch on the state of the port
#: instead of discovering it through an ``ImportError``; it shrinks to
#: irrelevance as the remaining modules land.
IMPLEMENTED_MODULES: frozenset[str] = frozenset(
    {"types", "domains", "punycode", "sanitize", "signals", "iocs", "rules"}
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
    "ParsedEmail",
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
    "ValidationError",
    "sanitize_input",
    "strip_dangerous_unicode",
    # Scoring
    "CORROBORATION_RATE",
    "MAX_CATEGORY_SCORE",
    "SEVERITY_POINTS",
    "SEVERITY_RANK",
    "assess_confidence",
    "score_signals",
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
    # IOCs
    "defang",
    "extract_iocs",
    "parse_ioc_text",
    "refang",
]
