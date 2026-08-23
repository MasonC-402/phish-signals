"""Kusto query generation for Defender/Sentinel hunting.

Port of ``typescript/src/kqlQuery.ts``.

Same payoff as ``sigma_rule.py`` — turn a set of indicators into a reusable
hunting artifact — but for Microsoft 365 Defender / Microsoft Sentinel
Advanced Hunting specifically. Unlike Sigma, which deliberately uses
made-up field names because email telemetry isn't standardized across
platforms, this targets Microsoft's own documented Advanced Hunting schema
directly: the table and column names below (EmailEvents, EmailUrlInfo,
EmailAttachmentInfo, UrlClickEvents, DeviceNetworkEvents, DeviceFileEvents)
are real and stable, so the output is meant to be pasted and run as-is.
"""

from __future__ import annotations

import re

from .types import Ioc, IocType

_NEWLINES_RE = re.compile(r"[\r\n]+")


def _kql_string(value: str) -> str:
    """Quotes a KQL string literal and never lets a value break out of it."""
    cleaned = _NEWLINES_RE.sub(" ", value).strip()
    escaped = cleaned.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _kql_array(name: str, values: list[str]) -> str:
    return f"let {name} = dynamic([{', '.join(_kql_string(v) for v in values)}]);"


def _unique_values(iocs: list[Ioc], ioc_type: IocType) -> list[str]:
    seen: list[str] = []
    for i in iocs:
        if i["type"] == ioc_type and i["value"] not in seen:
            seen.append(i["value"])
    return seen


def build_kql_query(iocs: list[Ioc], *, lookback_days: int = 30) -> str:
    domains = _unique_values(iocs, "domain")
    urls = _unique_values(iocs, "url")
    ips = _unique_values(iocs, "ip")
    emails = _unique_values(iocs, "email")
    hashes = _unique_values(iocs, "hash")
    filenames = _unique_values(iocs, "filename")

    if not (domains or urls or ips or emails or hashes or filenames):
        return "\n".join(
            [
                "// No indicator here was concrete enough to hunt on — nothing emitted",
                "// rather than a query that would just union in every row from every "
                "table.",
                "",
            ]
        )

    let_lines: list[str] = [f"let Lookback = {lookback_days}d;"]
    blocks: list[str] = []

    if domains or emails:
        if domains:
            let_lines.append(_kql_array("SuspectDomains", domains))
        if emails:
            let_lines.append(_kql_array("SuspectSenders", emails))
        conditions: list[str] = []
        if domains:
            conditions.append("SenderFromAddress has_any (SuspectDomains)")
        if emails:
            conditions.append("SenderFromAddress in~ (SuspectSenders)")
        blocks.append(
            "\n".join(
                [
                    "(",
                    "    EmailEvents",
                    "    | where Timestamp > ago(Lookback)",
                    f"    | where {' or '.join(conditions)}",
                    '    | extend MatchedOn = "sender", MatchedTable = "EmailEvents"',
                    ")",
                ]
            )
        )

    if urls or domains:
        if urls:
            let_lines.append(_kql_array("SuspectUrls", urls))
        conditions = []
        if urls:
            conditions.append("Url in~ (SuspectUrls)")
        if domains:
            conditions.append("UrlDomain has_any (SuspectDomains)")
        blocks.append(
            "\n".join(
                [
                    "(",
                    "    EmailUrlInfo",
                    "    | where Timestamp > ago(Lookback)",
                    f"    | where {' or '.join(conditions)}",
                    '    | extend MatchedOn = "url", MatchedTable = "EmailUrlInfo"',
                    ")",
                ]
            )
        )
        blocks.append(
            "\n".join(
                [
                    "(",
                    # Safe Links click telemetry — separate from EmailUrlInfo (what
                    # the message contained) because this is "did anyone actually
                    # click it," a materially different and higher-signal question.
                    "    UrlClickEvents",
                    "    | where Timestamp > ago(Lookback)",
                    f"    | where {' or '.join(conditions)}",
                    '    | extend MatchedOn = "url_click", '
                    'MatchedTable = "UrlClickEvents"',
                    ")",
                ]
            )
        )

    if hashes or filenames:
        if hashes:
            let_lines.append(_kql_array("SuspectHashes", hashes))
        if filenames:
            let_lines.append(_kql_array("SuspectFilenames", filenames))
        conditions = []
        if hashes:
            conditions.append("SHA256 in (SuspectHashes)")
        if filenames:
            conditions.append("FileName in~ (SuspectFilenames)")
        blocks.append(
            "\n".join(
                [
                    "(",
                    "    EmailAttachmentInfo",
                    "    | where Timestamp > ago(Lookback)",
                    f"    | where {' or '.join(conditions)}",
                    '    | extend MatchedOn = "attachment", '
                    'MatchedTable = "EmailAttachmentInfo"',
                    ")",
                ]
            )
        )
        # Endpoint tables — whether these indicators showed up beyond the
        # mailbox. Needs Defender for Endpoint data in the workspace.
        blocks.append(
            "\n".join(
                [
                    "(",
                    "    DeviceFileEvents",
                    "    | where Timestamp > ago(Lookback)",
                    f"    | where {' or '.join(conditions)}",
                    '    | extend MatchedOn = "file", '
                    'MatchedTable = "DeviceFileEvents"',
                    ")",
                ]
            )
        )

    if ips:
        let_lines.append(_kql_array("SuspectIPs", ips))
        blocks.append(
            "\n".join(
                [
                    "(",
                    "    EmailEvents",
                    "    | where Timestamp > ago(Lookback)",
                    "    | where SenderIPv4 in (SuspectIPs) or SenderIPv6 in "
                    "(SuspectIPs)",
                    '    | extend MatchedOn = "sender_ip", '
                    'MatchedTable = "EmailEvents"',
                    ")",
                ]
            )
        )
        blocks.append(
            "\n".join(
                [
                    "(",
                    "    DeviceNetworkEvents",
                    "    | where Timestamp > ago(Lookback)",
                    "    | where RemoteIP in (SuspectIPs)",
                    '    | extend MatchedOn = "network_ip", '
                    'MatchedTable = "DeviceNetworkEvents"',
                    ")",
                ]
            )
        )

    if domains:
        blocks.append(
            "\n".join(
                [
                    "(",
                    "    DeviceNetworkEvents",
                    "    | where Timestamp > ago(Lookback)",
                    "    | where RemoteUrl has_any (SuspectDomains)",
                    '    | extend MatchedOn = "network_domain", '
                    'MatchedTable = "DeviceNetworkEvents"',
                    ")",
                ]
            )
        )

    lines = [
        "// Generated by the farksecurity.com phish-report analyzer.",
        "//",
        "// Advanced Hunting query against the Microsoft 365 Defender / Microsoft",
        "// Sentinel schema. Table and column names are Microsoft's own, so this",
        "// should run as-is rather than needing field-name mapping first.",
        "//",
        "// STARTING POINT: adjust Lookback, and note DeviceFileEvents /",
        "// DeviceNetworkEvents need Defender for Endpoint data in the workspace —",
        "// drop those blocks if you only have Defender for Office 365. has_any",
        "// does substring-style matching on SenderFromAddress / RemoteUrl, so",
        "// review hits before acting on a domain match alone.",
        "",
        *let_lines,
        "",
        "union isfuzzy=true",
        ",\n".join(blocks),
        "| sort by Timestamp desc",
        "",
    ]
    return "\n".join(lines)


__all__ = ["build_kql_query"]
