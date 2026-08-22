"""Tests for content_check — phrase-list rules, code rules, and standalone checks.

Each test group verifies one behavior that the content check is responsible for,
matching the TypeScript reference in ``contentCheck.ts``. Where the TypeScript
version has inline logic, the Python version delegates to the rules engine, so
these tests also exercise that integration path.
"""

from __future__ import annotations

import pytest

from phish_signals.content_check import (
    CONTENT_RULESET,
    check_content,
    check_dangerous_schemes,
    check_link_text,
)
from phish_signals.types import LinkMismatch, Signal


def signals_by_id(result: dict) -> dict[str, Signal]:
    return {s["id"]: s for s in result["signals"]}


# --------------------------------------------------------------------------
# Phrase-list rules (declarative, from content.json)
# --------------------------------------------------------------------------


class TestUrgencyLanguage:
    def test_fires_on_single_phrase(self) -> None:
        result = check_content("Please act now before it is too late.")
        sigs = signals_by_id(result)
        assert "urgency_language" in sigs
        assert sigs["urgency_language"]["severity"] == "low"
        assert sigs["urgency_language"]["category"] == "social"
        assert '"act now"' in sigs["urgency_language"]["detail"]

    def test_escalates_at_three_hits(self) -> None:
        result = check_content("act now, this is urgent, and your final notice")
        sigs = signals_by_id(result)
        assert sigs["urgency_language"]["severity"] == "medium"

    def test_does_not_fire_on_clean_text(self) -> None:
        result = check_content("Hello, your order has shipped. Thank you!")
        assert not any(s["id"] == "urgency_language" for s in result["signals"])

    def test_mitre_mapping(self) -> None:
        result = check_content("act now")
        sigs = signals_by_id(result)
        assert sigs["urgency_language"]["mitre"] == ["T1566"]


class TestCredentialRequest:
    def test_fires_on_password_request(self) -> None:
        result = check_content("Please enter your password to continue.")
        sigs = signals_by_id(result)
        assert "credential_request" in sigs
        assert sigs["credential_request"]["severity"] == "medium"

    def test_mitre_mapping(self) -> None:
        result = check_content("confirm your password")
        sigs = signals_by_id(result)
        assert sigs["credential_request"]["mitre"] == ["T1566.002", "T1598.003"]


class TestFinancialRequest:
    def test_fires_on_wire_transfer(self) -> None:
        result = check_content("Please send the wire transfer today.")
        sigs = signals_by_id(result)
        assert "financial_request" in sigs
        assert sigs["financial_request"]["severity"] == "medium"

    def test_fires_on_gift_card(self) -> None:
        result = check_content("Buy some gift cards and send me the codes.")
        sigs = signals_by_id(result)
        assert "financial_request" in sigs


class TestAuthorityImpersonation:
    def test_fires_on_ceo_claim(self) -> None:
        result = check_content("This is your CEO. I need you to handle something.")
        sigs = signals_by_id(result)
        assert "authority_impersonation" in sigs
        assert sigs["authority_impersonation"]["severity"] == "medium"

    def test_fires_on_secrecy_request(self) -> None:
        text = "Keep this confidential, do not discuss this with anyone."
        result = check_content(text)
        sigs = signals_by_id(result)
        assert "authority_impersonation" in sigs


# --------------------------------------------------------------------------
# Code rules (need regex or structured logic)
# --------------------------------------------------------------------------


class TestGenericGreeting:
    @pytest.mark.parametrize(
        "text",
        [
            "Dear Customer,\nPlease review your account.",
            "Dear valued customer, your order is ready.",
            "Dear sir/madam, we are writing to inform you.",
            "Dear user@example.com, your account needs attention.",
            "Hello customer, welcome to our service.",
            "Hi member, your subscription is expiring.",
        ],
    )
    def test_fires_on_generic_greetings(self, text: str) -> None:
        result = check_content(text)
        sigs = signals_by_id(result)
        assert "generic_greeting" in sigs
        assert sigs["generic_greeting"]["severity"] == "low"

    def test_does_not_fire_on_personal_greeting(self) -> None:
        result = check_content("Dear John,\nYour order has shipped.")
        assert not any(s["id"] == "generic_greeting" for s in result["signals"])

    def test_no_mitre_key_when_absent(self) -> None:
        result = check_content("Dear Customer, hello.")
        sigs = signals_by_id(result)
        assert "mitre" not in sigs["generic_greeting"]


class TestDisplayNameSpoof:
    def test_brand_spoof_detected(self) -> None:
        result = check_content(
            "Click here", from_address='"PayPal Support" <scammer@evil.test>'
        )
        sigs = signals_by_id(result)
        assert "display_name_brand_spoof" in sigs
        assert sigs["display_name_brand_spoof"]["severity"] == "high"
        assert sigs["display_name_brand_spoof"]["category"] == "identity"
        assert '"paypal"' in sigs["display_name_brand_spoof"]["detail"]

    def test_no_spoof_when_domain_matches(self) -> None:
        result = check_content(
            "Click here", from_address='"PayPal" <noreply@paypal.com>'
        )
        assert not any(
            s["id"] == "display_name_brand_spoof" for s in result["signals"]
        )

    def test_address_spoof_detected(self) -> None:
        result = check_content(
            "Click here",
            from_address='"support@paypal.com" <attacker@evil.test>',
        )
        sigs = signals_by_id(result)
        assert "display_name_address_spoof" in sigs
        assert sigs["display_name_address_spoof"]["severity"] == "high"

    def test_no_spoof_when_no_from(self) -> None:
        result = check_content("Click here", from_address=None)
        assert not any(
            s["id"] in ("display_name_brand_spoof", "display_name_address_spoof")
            for s in result["signals"]
        )


class TestExcessiveCaps:
    def test_fires_on_heavy_caps(self) -> None:
        result = check_content(
            "THIS is VERY IMPORTANT PLEASE READ NOW and RESPOND IMMEDIATELY"
        )
        sigs = signals_by_id(result)
        assert "excessive_capitalization" in sigs
        assert sigs["excessive_capitalization"]["severity"] == "low"

    def test_does_not_fire_on_normal_text(self) -> None:
        result = check_content("This is a normal email with ONE acronym.")
        assert not any(
            s["id"] == "excessive_capitalization" for s in result["signals"]
        )


# --------------------------------------------------------------------------
# Standalone checks (structured data, not text scanning)
# --------------------------------------------------------------------------


class TestCheckLinkText:
    def test_fires_on_mismatched_links(self) -> None:
        mismatches: list[LinkMismatch] = [
            {
                "text": "Click here",
                "href": "https://evil.test/phish",
                "claimedDomain": "paypal.com",
                "actualDomain": "evil.test",
            }
        ]
        result = check_link_text(mismatches)
        sigs = signals_by_id(result)
        assert "deceptive_link_text" in sigs
        assert sigs["deceptive_link_text"]["severity"] == "high"
        assert "1 link display" in sigs["deceptive_link_text"]["detail"]
        detail = sigs["deceptive_link_text"]["detail"]
        assert '"paypal.com" actually goes to "evil.test"' in detail

    def test_plural_in_detail(self) -> None:
        mismatches: list[LinkMismatch] = [
            {
                "text": "a", "href": "b",
                "claimedDomain": "a.com", "actualDomain": "b.com",
            },
            {
                "text": "c", "href": "d",
                "claimedDomain": "c.com", "actualDomain": "d.com",
            },
        ]
        result = check_link_text(mismatches)
        assert "2 links display" in result["signals"][0]["detail"]

    def test_empty_returns_no_signals(self) -> None:
        assert check_link_text([]) == {"signals": []}
        assert check_link_text(None) == {"signals": []}

    def test_mitre_mapping(self) -> None:
        mismatch: LinkMismatch = {
            "text": "x", "href": "y",
            "claimedDomain": "a.com", "actualDomain": "b.com",
        }
        result = check_link_text([mismatch])
        assert result["signals"][0]["mitre"] == ["T1566.002", "T1204.001"]


class TestCheckDangerousSchemes:
    def test_fires_on_data_scheme(self) -> None:
        result = check_dangerous_schemes(["data"])
        sigs = signals_by_id(result)
        assert "dangerous_link_scheme" in sigs
        assert "data" in sigs["dangerous_link_scheme"]["detail"]
        assert "fake page inline" in sigs["dangerous_link_scheme"]["detail"]

    def test_fires_on_javascript_scheme(self) -> None:
        result = check_dangerous_schemes(["javascript"])
        assert "runs code" in result["signals"][0]["detail"]

    def test_multiple_schemes(self) -> None:
        result = check_dangerous_schemes(["data", "javascript"])
        detail = result["signals"][0]["detail"]
        assert "data/javascript" in detail

    def test_unknown_scheme_gets_generic_explanation(self) -> None:
        result = check_dangerous_schemes(["blob"])
        assert "blob: link is not a normal way" in result["signals"][0]["detail"]

    def test_empty_returns_no_signals(self) -> None:
        assert check_dangerous_schemes([]) == {"signals": []}
        assert check_dangerous_schemes(None) == {"signals": []}

    def test_mitre_mapping(self) -> None:
        result = check_dangerous_schemes(["data"])
        assert result["signals"][0]["mitre"] == ["T1566.002", "T1204.001"]


# --------------------------------------------------------------------------
# Ruleset integration
# --------------------------------------------------------------------------


class TestContentRuleset:
    def test_ruleset_is_valid_and_has_expected_rule_count(self) -> None:
        # 4 declarative phrase rules + 3 code rules = 7
        assert len(CONTENT_RULESET) == 7

    def test_all_rules_have_content_or_identity_tags(self) -> None:
        for rule in CONTENT_RULESET:
            assert rule.tags & {"content", "identity"}, (
                f"rule {rule.id} has no 'content' or 'identity' tag"
            )

    def test_multiple_signals_from_single_message(self) -> None:
        """A realistic phishing message triggers multiple rules."""
        result = check_content(
            "Dear Customer,\n\n"
            "ACT NOW! Your account will be suspended within 24 hours.\n"
            "Please enter your password to verify your account.\n"
            "Send the wire transfer immediately.\n"
            "This is your CEO. Keep this confidential.",
            from_address='"Amazon Support" <phisher@evil.test>',
        )
        ids = {s["id"] for s in result["signals"]}
        assert "urgency_language" in ids
        assert "credential_request" in ids
        assert "financial_request" in ids
        assert "authority_impersonation" in ids
        assert "generic_greeting" in ids
        assert "display_name_brand_spoof" in ids

    def test_empty_input_produces_no_signals(self) -> None:
        result = check_content("")
        assert result["signals"] == []
        result = check_content(None)
        assert result["signals"] == []
