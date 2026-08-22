"""Shared shapes for the analysis pipeline. Mirrors ``typescript/src/types.ts``.

Every shape here is a :class:`~typing.TypedDict`, not a dataclass, and that is
a load-bearing choice rather than a stylistic one. The conformance harness
compares ``func(input) == expect`` where ``expect`` is JSON parsed straight
off disk, by exact deep equality (see ``../../conformance/README.md``). A
dataclass instance never compares equal to a ``dict``, so every vectored
function would fail no matter how correct its logic was. A TypedDict *is* a
plain ``dict`` at runtime, so the same value that satisfies a type checker
also compares equal to the JSON the vector expects.

The corollary — and it is the thing to remember when editing this file — is
that a TypedDict body may contain **annotations only**. Methods written inside
one are silently discarded at runtime: the class is not really a class, and
``TypedDict(...)`` returns a bare ``dict`` whose ``__init__`` never ran and on
which ``hasattr(value, 'your_method')`` is ``False``. Behavior belongs in
module-level functions that take and return these dicts, which is how the
TypeScript side is written too.

Optional keys use the ``class Required(TypedDict)`` + ``class Full(Required,
total=False)`` split rather than ``typing.NotRequired``, which is 3.11+ while
this package supports 3.10. The distinction matters for conformance: an
absent ``mitre`` key and a ``mitre`` key set to ``None`` are different values
under deep equality, so optional keys must genuinely be able to be absent.
"""

from __future__ import annotations

from typing import Literal, TypedDict

# Evidence categories. Scoring treats these as the independent axes: several
# weak signals spread across different categories say more than a pile of
# correlated signals inside one. See signals.py.
EvidenceCategory = Literal[
    "authentication", "identity", "infrastructure", "payload", "social"
]

Severity = Literal["critical", "high", "medium", "low", "info"]

Verdict = Literal["Low Risk", "Medium Risk", "High Risk"]

UrlRisk = Literal["unknown", "clean", "suspicious", "malicious"]

IocType = Literal["url", "domain", "ip", "email", "filename", "hash"]

CATEGORY_LABELS: dict[EvidenceCategory, str] = {
    "authentication": "Authentication",
    "identity": "Sender Identity",
    "infrastructure": "Routing & Infrastructure",
    "payload": "Links & Attachments",
    "social": "Social Engineering",
}


class _SignalRequired(TypedDict):
    id: str
    category: EvidenceCategory
    severity: Severity
    label: str
    detail: str


class Signal(_SignalRequired, total=False):
    """One piece of evidence.

    Carries a category and a severity rather than a hand-picked numeric
    weight, so that correlated findings inside one category can be discounted
    against each other instead of summed as if independent.
    """

    #: MITRE ATT&CK technique IDs this evidence maps to.
    mitre: list[str]
    #: True when this argues the message is legitimate rather than suspicious.
    benign: bool


class CategoryScore(TypedDict):
    category: EvidenceCategory
    label: str
    score: int
    signals: list[Signal]


class Confidence(TypedDict):
    """How much of the message we actually got to look at."""

    level: Literal["high", "medium", "low"]
    #: 0-1, share of the evidence sources that were available.
    completeness: float
    #: Human-readable list of what could not be checked.
    gaps: list[str]


class Availability(TypedDict):
    """What :func:`phish_signals.signals.assess_confidence` was able to see.

    Keys stay camelCase to match the TypeScript reference: this shape crosses
    the language boundary in JSON exports and conformance vectors, where the
    key spelling is part of the contract rather than an internal detail.
    """

    headers: bool
    authResults: bool
    receivedChain: bool
    htmlPart: bool
    attachmentMetadata: bool


class ScoredEvidence(TypedDict):
    """Return shape of :func:`phish_signals.signals.score_signals`."""

    score: int
    verdict: Verdict
    categories: list[CategoryScore]
    signals: list[Signal]
    benignSignals: list[Signal]


class Ioc(TypedDict):
    """Indicator of compromise, in both plain and defanged form."""

    type: IocType
    value: str
    defanged: str


class _UrlAnalysisRequired(TypedDict):
    url: str
    risk: UrlRisk
    detail: str


class UrlAnalysis(_UrlAnalysisRequired, total=False):
    hostname: str
    riskScore: int
    #: Unicode form of a punycode hostname, plus the scripts it mixes.
    decodedHost: str | None
    scripts: list[str]


class HostnameDescription(TypedDict):
    """Return shape of :func:`phish_signals.punycode.describe_hostname`."""

    decoded: str | None
    scripts: list[str]
    mixed: bool
    confusable: bool


class ZipEntry(TypedDict):
    """One entry from a ZIP's central directory — name and declared size only."""

    filename: str
    uncompressedSize: int


class _AttachmentSummaryRequired(TypedDict):
    filename: str
    contentType: str
    size: int


class AttachmentSummary(_AttachmentSummaryRequired, total=False):
    # Not cryptographic integrity controls — these exist so a known-bad file
    # can be looked up against a blocklist, which is why MD5 and SHA-1 sit
    # alongside SHA-256 despite both being broken for collision resistance:
    # most existing hash-indexed threat intel still keys on one of the three.
    md5: str
    sha1: str
    sha256: str
    zipEntries: list[ZipEntry]
    #: True when the file sniffs as a ZIP but its central directory could not
    #: be read. Kept distinct from an absent ``zipEntries`` so "couldn't
    #: check" is never indistinguishable from "checked, nothing inside".
    zipUnreadable: bool


class ReceivedHop(TypedDict):
    """One parsed ``Received:`` header."""

    index: int
    helo: str | None
    reverseDns: str | None
    ip: str | None
    by: str | None
    timestamp: str | None
    #: HELO and reverse DNS disagree at the registrable-domain level.
    heloMismatch: bool
    private: bool


class ReceivedChainAnalysis(TypedDict):
    hops: list[ReceivedHop]
    #: The bottom-most hop — where the message entered the mail system.
    originIp: str | None
    originHost: str | None
    signals: list[Signal]


class LinkMismatch(TypedDict):
    """An anchor whose visible text claims one domain while its href
    points at another."""

    text: str
    href: str
    claimedDomain: str
    actualDomain: str


# Functional syntax, not the class form: the key really is spelled "from" —
# it is a mail header name that crosses into JSON output — and "from" is a
# Python keyword, so it cannot be written as a class attribute. Renaming it to
# "from_" would change the exported JSON and break parity with the TypeScript
# side, which is the one thing this file exists to preserve.
MessageInfo = TypedDict(
    "MessageInfo",
    {
        "subject": str,
        "from": str,
        "returnPath": str | None,
        "replyTo": str | None,
        "date": str | None,
    },
)


class MitreTechnique(TypedDict):
    id: str
    name: str
    url: str


class Recommendation(TypedDict):
    #: Ordering hint: 'now' actions are shown first and styled as urgent.
    urgency: Literal["now", "soon", "context"]
    text: str


__all__ = [
    "CATEGORY_LABELS",
    "AttachmentSummary",
    "Availability",
    "CategoryScore",
    "Confidence",
    "EvidenceCategory",
    "HostnameDescription",
    "Ioc",
    "IocType",
    "LinkMismatch",
    "MessageInfo",
    "MitreTechnique",
    "ReceivedChainAnalysis",
    "ReceivedHop",
    "Recommendation",
    "ScoredEvidence",
    "Severity",
    "Signal",
    "UrlAnalysis",
    "UrlRisk",
    "Verdict",
    "ZipEntry",
]
