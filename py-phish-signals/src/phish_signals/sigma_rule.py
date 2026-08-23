"""Sigma detection-rule generation from the signals that fired.

Port of ``typescript/src/sigmaRule.ts``.

This is the piece that turns the tool from "tells you about one email" into
something with a detection-engineering payoff: the analyzed message becomes
a reusable artifact you can take back to a SIEM so the next copy of the same
campaign is caught without anyone pasting it in here.

The output is explicitly a starting point, and says so in its own comments.
Email telemetry field names are not standardized across platforms the way
Windows event fields are, so the selections below use plain descriptive
names that have to be mapped to whatever the reader's pipeline actually
calls them.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from .attachment_check import extname
from .types import AttachmentSummary, Signal, UrlAnalysis

_NEWLINES_RE = re.compile(r"[\r\n]+")
_WORD_SPLIT_RE = re.compile(r"[^a-z0-9]+")

_STOPWORDS: frozenset[str] = frozenset(
    {
        "the",
        "and",
        "for",
        "you",
        "your",
        "our",
        "has",
        "have",
        "been",
        "from",
        "this",
        "that",
        "with",
        "will",
        "are",
        "was",
        "not",
        "re",
        "fw",
        "fwd",
    }
)


def _yaml_string(value: str) -> str:
    """Quotes a YAML scalar only when it needs it, and never lets one break out."""
    cleaned = _NEWLINES_RE.sub(" ", value).strip()
    return "'" + cleaned.replace("'", "''") + "'"


def _indent_list(items: list[str], indent: str) -> list[str]:
    return [f"{indent}- {_yaml_string(item)}" for item in items]


def subject_keywords(subject: str | None) -> list[str]:
    """Words from the subject distinctive enough to be worth matching on."""
    if not subject:
        return []

    words = _WORD_SPLIT_RE.split(subject.lower())
    seen: list[str] = []
    for word in words:
        if len(word) >= 4 and word not in _STOPWORDS and word not in seen:
            seen.append(word)
    return seen[:6]


def build_sigma_rule(
    *,
    subject: str | None,
    sender_domain: str | None,
    reply_to_domain: str | None,
    urls: list[UrlAnalysis],
    attachments: list[AttachmentSummary],
    signals: list[Signal],
    verdict: str,
    score: int,
) -> str:
    risky_urls = [u for u in urls if u["risk"] in ("malicious", "suspicious")]
    risky_hosts: list[str] = []
    for u in risky_urls:
        host = u.get("hostname")
        if host and host not in risky_hosts:
            risky_hosts.append(host)

    dangerous_extensions: list[str] = []
    for a in attachments:
        ext = extname(a["filename"])
        if ext and ext not in dangerous_extensions:
            dangerous_extensions.append(ext)

    # The one selection in this whole rule that's genuinely high-confidence
    # rather than a starting point: an exact hash match essentially never
    # false positives the way a domain or keyword selection can. Only
    # available for attachments parsed from a raw .eml/pasted message.
    attachment_hashes: list[str] = []
    for a in attachments:
        digest = a.get("sha256")
        if digest and digest not in attachment_hashes:
            attachment_hashes.append(digest)

    keywords = subject_keywords(subject)

    attack_tags: list[str] = sorted(
        {f"attack.{id.lower()}" for s in signals for id in (s.get("mitre") or [])}
    )

    selections: list[str] = []
    condition_parts: list[str] = []

    if sender_domain:
        selections.append("  sender_domain:")
        selections.append("    sender|endswith:")
        selections.extend(_indent_list([f"@{sender_domain}"], "      "))
        condition_parts.append("sender_domain")

    if reply_to_domain and reply_to_domain != sender_domain:
        selections.append("  reply_to_domain:")
        selections.append("    reply_to|endswith:")
        selections.extend(_indent_list([f"@{reply_to_domain}"], "      "))
        condition_parts.append("reply_to_domain")

    if risky_hosts:
        selections.append("  link_hosts:")
        selections.append("    url|contains:")
        selections.extend(_indent_list(risky_hosts, "      "))
        condition_parts.append("link_hosts")

    if dangerous_extensions:
        selections.append("  attachment_type:")
        selections.append("    attachment_name|endswith:")
        selections.extend(_indent_list(dangerous_extensions, "      "))
        condition_parts.append("attachment_type")

    if attachment_hashes:
        selections.append("  attachment_hash:")
        selections.append("    attachment_hash|contains:")
        selections.extend(_indent_list(attachment_hashes, "      "))
        condition_parts.append("attachment_hash")

    if keywords:
        selections.append("  subject_keywords:")
        selections.append("    subject|contains|all:")
        selections.extend(_indent_list(keywords[:3], "      "))
        condition_parts.append("subject_keywords")

    if not condition_parts:
        return "\n".join(
            [
                "# No indicator in this message was distinctive enough to build a rule "
                "from.",
                "# A rule matching only generic body phrases would fire on legitimate "
                "mail",
                "# constantly, so nothing is emitted here rather than something "
                "unusable.",
                "",
            ]
        )

    level = "high" if score >= 60 else "medium" if score >= 30 else "low"

    title_subject = (
        f" - {_NEWLINES_RE.sub(' ', subject).strip()[:60]}" if subject else ""
    )
    title_value = _yaml_string(
        f"Phishing indicators observed in message{title_subject}"
    )
    description_value = _yaml_string(
        f"Indicators extracted from a single message assessed as {verdict} "
        f"({score}/100) by heuristic analysis."
    )

    lines = [
        "# Generated by the farksecurity.com phish-report analyzer.",
        "#",
        "# STARTING POINT, NOT A FINISHED RULE. Email telemetry field names differ",
        "# per platform (Defender, Proofpoint, Mimecast, a mail gateway log...), so",
        "# map sender / reply_to / url / attachment_name / attachment_hash / subject",
        "# onto whatever your pipeline actually calls them before deploying. Review",
        "# each selection: the sender domain may be a compromised legitimate host you",
        "# do not want to block outright, and subject keywords are the most",
        "# false-positive-prone part. attachment_hash is the exception — an exact",
        "# hash match is high-confidence on its own and worth keeping as-is.",
        "",
        # Quoted, not bare. The subject is attacker-controlled and a bare
        # YAML scalar containing ": " parses as a nested key.
        f"title: {title_value}",
        f"id: {uuid.uuid4()}",
        "status: experimental",
        f"description: {description_value}",
        "author: farksecurity.com phish-report",
        f"date: {datetime.now(timezone.utc).date().isoformat()}",
        "logsource:",
        "  category: mail",
        "detection:",
        *selections,
        f"  condition: {' or '.join(condition_parts)}",
        "falsepositives:",
        "  - Legitimate mail from a compromised but otherwise trusted sender",
        "  - Shared sending infrastructure where the domain is not attacker-controlled",
        "  - Subject keywords appearing in unrelated legitimate correspondence",
        f"level: {level}",
        *(["tags:", *[f"  - {t}" for t in attack_tags]] if attack_tags else []),
        "",
    ]
    return "\n".join(lines)


__all__ = ["build_sigma_rule", "subject_keywords"]
