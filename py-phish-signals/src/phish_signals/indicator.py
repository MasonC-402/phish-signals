from ._types import IndicatorDict

class Indicator:
    def __init__(self, indicator_type: str, value: str):
        self.indicator_type = indicator_type
        self.value = value
        self.TYPE_MAPPING: dict[str, str] = {
            "ipv4": "IPv4 Address",
            "domain": "Domain Name",
            "url": "URL",
            "email": "Email Address",
            "hash": "File Hash",
            "filename": "File Name",
            "file_extension": "File Extension",
            "SPF": "SPF Authentication Record",
            "DKIM": "DKIM Authentication Record",
            "DMARC": "DMARC Authentication Record",
            "header": "Email Header", 
        }

    def __repr__(self):
        return f"Indicator(type={self.indicator_type}, value={self.value})"

    def to_dict(self) -> IndicatorDict:
        return IndicatorDict(
            indicator_type=self.indicator_type,
            value=self.value
        )

    @classmethod
    def from_dict(cls, data: IndicatorDict):
        return cls(
            indicator_type=data.get("indicator_type"),
            value=data.get("value")
        )

    def __eq__(self, other):
        if not isinstance(other, Indicator):
            return NotImplemented
        return self.indicator_type == other.indicator_type and self.value == other.value

    def __hash__(self):
        return hash((self.indicator_type, self.value))

    def is_valid(self):
        # Basic validation: check if both indicator_type and value are non-empty strings
        return isinstance(self.indicator_type, str) and bool(self.indicator_type) and isinstance(self.value, str) and bool(self.value)