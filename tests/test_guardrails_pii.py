"""Comprehensive tests for PIIGuardrail."""

import pytest

from aegis.guardrails.pii import PIIGuardrail

# -- Email detection --------------------------------------------------------


class TestPIIEmail:
    def test_detects_email(self):
        g = PIIGuardrail(categories=["email"])
        result = g.check("contact me at user@example.com")
        assert result.detected is True
        assert "email" in result.categories_found

    def test_detects_email_with_plus(self):
        g = PIIGuardrail(categories=["email"])
        result = g.check("mail: user+tag@example.co.uk")
        assert result.detected is True

    def test_masks_email_preserves_domain(self):
        g = PIIGuardrail(categories=["email"])
        tr = g.check_and_transform("email: alice@example.com")
        assert tr.detected is True
        assert "@example.com" in tr.content
        assert "alice@" not in tr.content


# -- Credit card detection --------------------------------------------------


class TestPIICreditCard:
    def test_detects_visa(self):
        # 4111111111111111 is a well-known Visa test number (passes Luhn)
        g = PIIGuardrail(categories=["credit_card"])
        result = g.check("card: 4111111111111111")
        assert result.detected is True
        assert "credit_card" in result.categories_found

    def test_detects_visa_with_dashes(self):
        g = PIIGuardrail(categories=["credit_card"])
        result = g.check("card: 4111-1111-1111-1111")
        assert result.detected is True

    def test_detects_mastercard(self):
        # 5500000000000004 (Luhn valid MC test number)
        g = PIIGuardrail(categories=["credit_card"])
        result = g.check("mc: 5500000000000004")
        assert result.detected is True

    def test_detects_amex(self):
        # 378282246310005 (Luhn valid Amex test number)
        g = PIIGuardrail(categories=["credit_card"])
        result = g.check("amex: 378282246310005")
        assert result.detected is True

    def test_masks_credit_card_shows_first_last_four(self):
        g = PIIGuardrail(categories=["credit_card"])
        tr = g.check_and_transform("card: 4111111111111111")
        assert tr.detected is True
        # Should show first 4 and last 4 digits
        assert "4111" in tr.content
        assert "1111" in tr.content
        # Middle digits should be masked
        assert "*" in tr.content

    def test_luhn_rejects_invalid(self):
        g = PIIGuardrail(categories=["credit_card"])
        # 4111111111111112 fails Luhn
        result = g.check("card: 4111111111111112")
        assert result.detected is False


# -- SSN detection ----------------------------------------------------------


class TestPIISSN:
    def test_detects_us_ssn(self):
        g = PIIGuardrail(categories=["ssn"])
        result = g.check("ssn: 123-45-6789")
        assert result.detected is True
        assert "ssn" in result.categories_found

    def test_ssn_masks_format(self):
        g = PIIGuardrail(categories=["ssn"])
        tr = g.check_and_transform("ssn: 123-45-6789")
        assert tr.detected is True
        assert "123-45-6789" not in tr.content
        # Masked SSN uses mask chars in standard format
        assert "*" in tr.content

    def test_ssn_invalid_area_000(self):
        """Area code 000 is invalid."""
        g = PIIGuardrail(categories=["ssn"])
        result = g.check("ssn: 000-12-3456")
        assert result.detected is False

    def test_ssn_invalid_area_666(self):
        """Area code 666 is invalid."""
        g = PIIGuardrail(categories=["ssn"])
        result = g.check("ssn: 666-12-3456")
        assert result.detected is False


# -- Korean RRN detection ---------------------------------------------------


class TestPIIKoreanRRN:
    def test_detects_korean_rrn(self):
        g = PIIGuardrail(categories=["korean_rrn"])
        # Valid format: YYMMDD-G + 6 digits
        result = g.check("주민번호: 900101-1234567")
        assert result.detected is True
        assert "korean_rrn" in result.categories_found

    def test_masks_korean_rrn(self):
        g = PIIGuardrail(categories=["korean_rrn"])
        tr = g.check_and_transform("주민번호: 900101-1234567")
        assert tr.detected is True
        assert "900101-1234567" not in tr.content
        assert "*" in tr.content


# -- Korean phone detection -------------------------------------------------


class TestPIIKoreanPhone:
    def test_detects_korean_mobile(self):
        g = PIIGuardrail(categories=["korean_phone"])
        result = g.check("전화: 010-1234-5678")
        assert result.detected is True
        assert "korean_phone" in result.categories_found

    def test_detects_korean_mobile_no_dashes(self):
        g = PIIGuardrail(categories=["korean_phone"])
        result = g.check("전화: 01012345678")
        assert result.detected is True

    def test_detects_korean_mobile_international(self):
        g = PIIGuardrail(categories=["korean_phone"])
        result = g.check("phone: +82-10-1234-5678")
        assert result.detected is True

    def test_masks_korean_phone(self):
        g = PIIGuardrail(categories=["korean_phone"])
        tr = g.check_and_transform("전화: 010-1234-5678")
        assert tr.detected is True
        # Prefix digits should be preserved, rest masked
        assert "010" in tr.content
        assert "*" in tr.content


# -- US phone detection -----------------------------------------------------


class TestPIIUSPhone:
    def test_detects_us_phone_with_parens(self):
        g = PIIGuardrail(categories=["us_phone"])
        result = g.check("call (212) 555-1234")
        assert result.detected is True
        assert "us_phone" in result.categories_found

    def test_detects_us_phone_with_dashes(self):
        g = PIIGuardrail(categories=["us_phone"])
        result = g.check("call 212-555-1234")
        assert result.detected is True


# -- IP address detection ---------------------------------------------------


class TestPIIIPAddress:
    def test_detects_ip_address(self):
        g = PIIGuardrail(categories=["ip_address"], severity="medium")
        result = g.check("server: 192.168.1.100")
        assert result.detected is True
        assert "ip_address" in result.categories_found

    def test_masks_ip_last_two_octets(self):
        g = PIIGuardrail(categories=["ip_address"], severity="medium")
        tr = g.check_and_transform("server: 192.168.1.100")
        assert tr.detected is True
        # First two octets preserved, last two masked
        assert "192.168." in tr.content
        assert "*" in tr.content

    def test_rejects_invalid_octet(self):
        g = PIIGuardrail(categories=["ip_address"], severity="medium")
        result = g.check("not ip: 999.999.999.999")
        assert result.detected is False


# -- API key detection ------------------------------------------------------


class TestPIIAPIKeys:
    def test_detects_openai_key(self):
        g = PIIGuardrail(categories=["api_key"])
        key = "sk-" + "a" * 48
        result = g.check(f"key: {key}")
        assert result.detected is True
        assert "api_key" in result.categories_found

    def test_detects_openai_proj_key(self):
        g = PIIGuardrail(categories=["api_key"])
        key = "sk-proj-" + "A1b2C3d4" * 6
        result = g.check(f"key: {key}")
        assert result.detected is True

    def test_detects_aws_access_key(self):
        g = PIIGuardrail(categories=["api_key"])
        result = g.check("key: AKIAIOSFODNN7EXAMPLE")
        assert result.detected is True

    def test_detects_github_token(self):
        g = PIIGuardrail(categories=["api_key"])
        token = "ghp_" + "A" * 36
        result = g.check(f"token: {token}")
        assert result.detected is True

    def test_masks_api_key_shows_prefix(self):
        g = PIIGuardrail(categories=["api_key"])
        key = "sk-" + "a" * 48
        tr = g.check_and_transform(f"key: {key}")
        assert tr.detected is True
        # First 4 chars visible, rest masked
        assert "sk-a" in tr.content
        assert "*" in tr.content


# -- URL with credentials --------------------------------------------------


class TestPIIURLCredentials:
    def test_detects_url_with_credentials(self):
        g = PIIGuardrail(categories=["url_credentials"])
        result = g.check("connect to https://admin:password123@db.example.com")
        assert result.detected is True
        assert "url_credentials" in result.categories_found

    def test_masks_url_credentials(self):
        g = PIIGuardrail(categories=["url_credentials"])
        tr = g.check_and_transform("url: https://user:pass@host.com")
        assert tr.detected is True
        assert "user:pass" not in tr.content
        assert "*" in tr.content


# -- Category filtering -----------------------------------------------------


class TestPIICategoryFiltering:
    def test_filters_by_category(self):
        g = PIIGuardrail(categories=["email"])
        # SSN should NOT be detected when only email category active
        result = g.check("ssn: 123-45-6789")
        assert result.detected is False

    def test_multiple_categories(self):
        g = PIIGuardrail(categories=["email", "ssn"])
        result = g.check("email: a@b.com and ssn: 123-45-6789")
        assert result.detected is True
        assert "email" in result.categories_found
        assert "ssn" in result.categories_found

    def test_default_all_categories(self):
        g = PIIGuardrail()
        assert len(g.available_categories) > 0
        assert len(g.active_categories) > 0

    def test_severity_filter(self):
        """Default severity='high' excludes medium-severity patterns like IP."""
        g_high = PIIGuardrail(severity="high")
        result = g_high.check("ip: 192.168.1.1")
        # IP is medium severity, should be filtered out at high threshold
        assert result.detected is False

        g_medium = PIIGuardrail(severity="medium")
        result = g_medium.check("ip: 192.168.1.1")
        assert result.detected is True


# -- False positives --------------------------------------------------------


class TestPIIFalsePositives:
    def test_no_false_positive_on_normal_text(self):
        g = PIIGuardrail()
        texts = [
            "Hello, how are you today?",
            "The weather is nice.",
            "Please submit the report by Friday.",
            "The project has 42 tasks remaining.",
            "We need to schedule a meeting.",
        ]
        for text in texts:
            result = g.check(text)
            assert result.detected is False, f"False positive on: {text!r}"


# -- Multiple PII in one string --------------------------------------------


class TestPIIMultiple:
    def test_multiple_pii_types_in_one_string(self):
        g = PIIGuardrail()
        text = "email: user@example.com, ssn: 123-45-6789"
        result = g.check(text)
        assert result.detected is True
        assert len(result.matches) >= 2
        cats = result.categories_found
        assert "email" in cats
        assert "ssn" in cats

    def test_multiple_pii_masked(self):
        g = PIIGuardrail()
        text = "email: user@example.com, ssn: 123-45-6789"
        tr = g.check_and_transform(text)
        assert tr.detected is True
        assert "user@example.com" not in tr.content
        assert "123-45-6789" not in tr.content


# -- check() and check_and_transform() results -----------------------------


class TestPIIResultStructure:
    def test_check_returns_proper_result(self):
        g = PIIGuardrail(categories=["email"])
        result = g.check("email: user@example.com")
        assert result.detected is True
        assert len(result.matches) >= 1
        match = result.matches[0]
        assert match.category == "email"
        assert match.matched_text == "user@example.com"
        assert match.start >= 0
        assert match.end > match.start
        assert match.masked_text
        assert result.severity in ("low", "medium", "high", "critical")

    def test_check_and_transform_returns_masked_text(self):
        g = PIIGuardrail(categories=["email"])
        tr = g.check_and_transform("email: user@example.com")
        assert tr.detected is True
        assert tr.action_taken == "mask"
        assert tr.original_content == "email: user@example.com"
        assert tr.content != tr.original_content
        assert len(tr.matches) >= 1

    def test_no_detection_result(self):
        g = PIIGuardrail()
        result = g.check("nothing here")
        assert result.detected is False
        assert result.matches == []
        assert result.categories_found == set()
        assert result.severity == "none"

    def test_no_detection_transform_result(self):
        g = PIIGuardrail()
        tr = g.check_and_transform("nothing here")
        assert tr.detected is False
        assert tr.content == "nothing here"
        assert tr.action_taken == "none"


# -- Action modes -----------------------------------------------------------


class TestPIIActions:
    def test_block_action(self):
        g = PIIGuardrail(categories=["email"], action="block")
        tr = g.check_and_transform("email: user@example.com")
        assert tr.detected is True
        assert tr.action_taken == "block"
        assert "BLOCKED" in tr.content

    def test_warn_action(self):
        g = PIIGuardrail(categories=["email"], action="warn")
        tr = g.check_and_transform("email: user@example.com")
        assert tr.detected is True
        assert tr.action_taken == "warn"
        # Warn returns content unchanged
        assert tr.content == "email: user@example.com"

    def test_log_action(self):
        g = PIIGuardrail(categories=["email"], action="log")
        tr = g.check_and_transform("email: user@example.com")
        assert tr.detected is True
        assert tr.action_taken == "log"
        assert tr.content == "email: user@example.com"

    def test_invalid_action_raises(self):
        with pytest.raises(ValueError, match="Invalid action"):
            PIIGuardrail(action="invalid")


# -- Repr and properties ----------------------------------------------------


class TestPIIIBAN:
    """IBAN detection tests — issue #30."""

    def test_german_iban_compact(self):
        g = PIIGuardrail(categories=["iban"])
        result = g.check("Transfer to DE89370400440532013000")
        assert result.detected
        assert "iban" in result.categories_found

    def test_uk_iban_spaced(self):
        g = PIIGuardrail(categories=["iban"])
        result = g.check("Account: GB29 NWBK 6016 1331 9268 19")
        assert result.detected
        assert "iban" in result.categories_found

    def test_french_iban_spaced(self):
        g = PIIGuardrail(categories=["iban"])
        result = g.check("IBAN: FR76 3000 6000 0112 3456 7890 189")
        assert result.detected

    def test_dutch_iban(self):
        g = PIIGuardrail(categories=["iban"])
        result = g.check("NL91ABNA0417164300")
        assert result.detected

    def test_spanish_iban(self):
        g = PIIGuardrail(categories=["iban"])
        result = g.check("ES91 2100 0418 4502 0005 1332")
        assert result.detected

    def test_invalid_iban_mod97(self):
        g = PIIGuardrail(categories=["iban"])
        result = g.check("DE00000000000000000000")
        assert not result.detected

    def test_iban_masked(self):
        g = PIIGuardrail(categories=["iban"], action="mask")
        result = g.check_and_transform("Pay to DE89370400440532013000 please")
        assert "DE89370400440532013000" not in result.content
        assert "***" in result.content

    def test_iban_dashed_format(self):
        g = PIIGuardrail(categories=["iban"])
        result = g.check("GB29-NWBK-6016-1331-9268-19")
        assert result.detected


class TestPIIPassport:
    """Passport detection tests — issue #28."""

    @pytest.mark.parametrize(
        "text",
        [
            "Passport A12345678 issued in 2024.",
            "My passport number is M12345678.",
            "Passport no. 987654321",
            "Passport: 123456789 (United Kingdom)",
            "여권번호 M12345678 입니다.",
            "护照号码 E12345678",
            "パスポート TK1234567",
            "Travel document AB1234567 attached.",
        ],
        ids=[
            "us_with_keyword",
            "kr_with_keyword",
            "uk_passport_no",
            "uk_bare_digits_with_keyword",
            "korean_keyword",
            "chinese_keyword",
            "japanese_keyword",
            "travel_document",
        ],
    )
    def test_detects_passport_with_keyword(self, text):
        g = PIIGuardrail(categories=["passport"])
        result = g.check(text)
        assert result.detected
        assert "passport" in result.categories_found

    @pytest.mark.parametrize(
        "text",
        [
            "Please verify A12345678 before boarding.",
            "Traveller M12345678 checked in.",
            "Documents for AB1234567 are ready.",
        ],
        ids=["us_standalone", "kr_standalone", "two_letter_standalone"],
    )
    def test_detects_standalone_passport(self, text):
        g = PIIGuardrail(categories=["passport"])
        result = g.check(text)
        assert result.detected

    @pytest.mark.parametrize(
        "text",
        [
            "Order 123456789 shipped yesterday.",
            "Transaction id 987654321 completed.",
            "The build artifact is A20260829 from the nightly job.",
            "Invoice INV2026001 and PO P12345678 are attached.",
            "Error code E12345678 was returned by the gateway.",
            "Tracking number 1Z999AA10123456784.",
            "Product SKU AB1234567 is out of stock.",
            "Employee ID E1234567 requested leave.",
            "The population reached 123456789 last year.",
            "Ticket T1234567 was closed by support.",
            "Serial number XY9876543 on the label.",
            "Call us at 415 555 0132 or 4155550132.",
        ],
        ids=[
            "order_number",
            "transaction_id",
            "build_artifact",
            "purchase_order",
            "error_code",
            "tracking_number",
            "sku",
            "employee_id",
            "population_figure",
            "ticket_id",
            "serial_number",
            "phone_number",
        ],
    )
    def test_no_false_positive_on_other_identifiers(self, text):
        """The standalone shape is also every other business identifier.

        ``[A-Z]{1,2}[0-9]{7,8}`` matches purchase orders, SKUs, error codes and
        build artifacts. A label naming one of those in the preceding window
        disqualifies the match.
        """
        g = PIIGuardrail(categories=["passport"])
        result = g.check(text)
        assert not result.detected, f"False positive on: {text!r}"

    def test_passport_keyword_outranks_disqualifier(self):
        """A passport keyword in the window wins over a disqualifying label."""
        g = PIIGuardrail(categories=["passport"])
        result = g.check("Please send the invoice and your passport A12345678")
        assert result.detected

    def test_no_bare_nine_digit_rule(self):
        """UK numbers are keyword-only by design.

        A UK passport number is nine bare digits, indistinguishable from an
        order number or a phone number. Detecting it standalone would fire on
        ordinary business text, so it is caught by keyword context instead.
        """
        g = PIIGuardrail(categories=["passport"])
        assert not g.check("Reference 123456789 for your records.").detected
        assert g.check("Passport 123456789").detected

    def test_passport_masks_digits_and_keeps_prefix(self):
        g = PIIGuardrail(categories=["passport"], action="mask")
        result = g.check_and_transform("Passport A12345678 issued in 2024.")
        assert "A12345678" not in result.content
        assert "A********" in result.content


class TestPIIMisc:
    def test_repr(self):
        g = PIIGuardrail()
        r = repr(g)
        assert "PIIGuardrail" in r

    def test_available_categories(self):
        g = PIIGuardrail()
        cats = g.available_categories
        assert "email" in cats
        assert "credit_card" in cats
        assert "ssn" in cats

    def test_active_categories_with_filter(self):
        g = PIIGuardrail(categories=["email", "ssn"])
        active = g.active_categories
        assert "email" in active
        assert "ssn" in active
        # Other categories should not be active
        assert "korean_phone" not in active
