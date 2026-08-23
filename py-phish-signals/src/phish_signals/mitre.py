"""MITRE ATT&CK technique mapping.

Port of ``typescript/src/mitre.ts``.

Signals carry technique IDs; this resolves them to names and links. The point
is to put the finding in language a SOC already uses — "this is T1566.002"
travels between tools and teams in a way "suspicious link" does not, and it
gives whoever reads the report a route into ATT&CK's own mitigation and
detection guidance rather than stopping at our description.
"""

from __future__ import annotations

from .types import MitreTechnique, Signal

TECHNIQUES: dict[str, str] = {
    "T1566": "Phishing",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1598.003": "Phishing for Information: Spearphishing Link",
    "T1204": "User Execution",
    "T1204.001": "User Execution: Malicious Link",
    "T1204.002": "User Execution: Malicious File",
    "T1036.007": "Masquerading: Double File Extension",
    "T1036.008": "Masquerading: Masquerade File Type",
    "T1534": "Internal Spearphishing",
    "T1656": "Impersonation",
}


def technique_url(id: str) -> str:
    """URL of a technique's ATT&CK page. Mirrors ``techniqueUrl``."""
    # Sub-techniques live at /techniques/TXXXX/YYY/ rather than /TXXXX.YYY/.
    parent, _, sub = id.partition(".")
    if sub:
        return f"https://attack.mitre.org/techniques/{parent}/{sub}/"
    return f"https://attack.mitre.org/techniques/{parent}/"


def map_techniques(signals: list[Signal]) -> list[MitreTechnique]:
    """Distinct techniques across every signal that fired, sorted by id.

    Mirrors ``mapTechniques``.
    """
    ids: set[str] = set()
    for signal in signals:
        for id in signal.get("mitre") or []:
            if id in TECHNIQUES:
                ids.add(id)

    return [
        {"id": id, "name": TECHNIQUES[id], "url": technique_url(id)}
        for id in sorted(ids)
    ]


__all__ = ["TECHNIQUES", "map_techniques", "technique_url"]
