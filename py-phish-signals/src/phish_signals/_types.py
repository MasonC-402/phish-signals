# Type definitions for the phish_signals package.

# Author: Mason Clemons

from typing import TypedDict, Callable
from .indicator import Indicator

class IndicatorDict(TypedDict):
    indicator_types: list[str]
    indicator_type: str
    value: str
    # specific types of indicators can be added here as needed, e.g., "ipv4", "domain", "url", etc.
    def __init__(self, indicator_type: str, value: str):
        self["indicator_type"] = indicator_type
        self["value"] = value
        self["indicator_types"] = ["ipv4", "domain", "url", "email", "hash", "filename", "file_extension", "SPF_Pass", "DKIM_Pass", "DMARC_Pass", "header", "suspicious_text"]
    def __repr__(self):
        return f"IndicatorDict(indicator_type={self['indicator_type']}, value={self['value']})"
    def to_indicator(self) -> Indicator:
        return Indicator(indicator_type=self["indicator_type"], value=self["value"])
    def from_indicator(indicator: Indicator) -> "IndicatorDict":
        return IndicatorDict(indicator_type=indicator.indicator_type, value=indicator.value)
    def is_valid(self) -> bool:
        return isinstance(self["indicator_type"], str) and bool(self["indicator_type"]) and isinstance(self["value"], str) and bool(self["value"])
    def __eq__(self, other):
        if not isinstance(other, IndicatorDict):
            return NotImplemented
        return self["indicator_type"] == other["indicator_type"] and self["value"] == other["value"]
    def __hash__(self):
        return hash((self["indicator_type"], self["value"]))
    def get_indicator_types(self) -> list[str]:
        return self["indicator_types"]
    def set_indicator_types(self, indicator_types: list[str]):
        self["indicator_types"] = indicator_types   
    def get_indicator_type(self) -> str:
        return self["indicator_type"]
    def set_indicator_type(self, indicator_type: str):
        self["indicator_type"] = indicator_type
    def get_value(self) -> str:
        return self["value"]
    def set_value(self, value: str):
        self["value"] = value
    def to_dict(self) -> dict:
        return {
            "indicator_type": self["indicator_type"],
            "value": self["value"],
            "indicator_types": self["indicator_types"]
        }
    def from_dict(cls, data: dict) -> "IndicatorDict":
        return IndicatorDict(
            indicator_type=data.get("indicator_type", ""),
            value=data.get("value", "")
        )
    def __contains__(self, key: str) -> bool:
        return key in self.keys()
    def keys(self) -> list[str]:
        return list(self.keys())
    def values(self) -> list:
        return list(self.values())
    def items(self) -> list[tuple[str, any]]:
        return list(self.items())

class Verdict(TypedDict):
    verdict: str
    confidence: float
    confidence_min: float
    confidence_max: float
    verdict_types: list[str]
    verdict_check: Callable[[str], bool]
    def __init__(self, verdict: str, confidence: float):
        self["verdict"] = verdict
        self["confidence"] = confidence
        self["verdict_types"] = ["malicious", "suspicious", "benign", "unknown"]
        self["confidence_min"] = 0.0
        self["confidence_max"] = 1.0
        self.verdict_check(verdict)


    def __repr__(self):
        return f"Verdict(verdict={self['verdict']}, confidence={self['confidence']})"
    def to_dict(self) -> dict:
        return {
            "verdict": self["verdict"],
            "confidence": self["confidence"]
        }
    def from_dict(cls, data: dict) -> "Verdict":
        return Verdict(
            verdict=data.get("verdict", ""),
            confidence=data.get("confidence", 0.0)
        )
    def is_valid(self) -> bool:
        return isinstance(self["verdict"], str) and bool(self["verdict"]) and isinstance(self["confidence"], float) and 0.0 <= self["confidence"] <= 1.0
    def get_verdict(self) -> str:
        return self["verdict"]
    def set_verdict(self, verdict: str):
        self["verdict"] = verdict
    def get_confidence(self) -> float:
        return self["confidence"]
    def set_confidence(self, confidence: float):
        self["confidence"] = confidence
    def get_verdict_types(self) -> list[str]:
        return self["verdict_types"]
    def set_verdict_types(self, verdict_types: list[str]):
        self["verdict_types"] = verdict_types
    def __contains__(self, key: str) -> bool:
        return key in self.keys()
    def keys(self) -> list[str]:
        return list(super().keys())
    def values(self) -> list:
        return list(super().values())
    def is_valid_verdict_type(self, verdict_type: str) -> bool:
        return verdict_type in self["verdict_types"]
    def is_valid_confidence(self, confidence: float) -> bool:
        return isinstance(confidence, float) and self["confidence_min"] <= confidence <= self["confidence_max"]
    def items(self) -> list[tuple[str, any]]:
        return list(super().items())
    def __eq__(self, other):
        if not isinstance(other, Verdict):
            return NotImplemented
        return self["verdict"] == other["verdict"] and self["confidence"] == other["confidence"]
    def __hash__(self):
        return hash((self["verdict"], self["confidence"]))

    def verdict_check(self, verdict: str) -> bool:
        """
        Check if the provided verdict is valid.

        Args:
            verdict (str): The verdict to check.

        Returns:
            bool: True if the verdict is valid, False otherwise.
        """
        return verdict in self["verdict_types"] and isinstance(verdict, str) and bool(verdict) and self.is_valid_verdict_type(verdict) and self.is_valid_confidence(self["confidence"])


    