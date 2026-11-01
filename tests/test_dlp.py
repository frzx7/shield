from shield.core.events import Severity
from shield.modules.dlp.detectors import (
    mask,
    luhn_valid,
    find_api_keys,
    find_card_numbers,
    find_iban,
    scan,
)


def test_mask_hides_most_of_the_value():
    assert mask("AKIAIOSFODNN7EXAMPLE") == "AKIA" + "*" * 16


def test_mask_short_value():
    assert mask("abc") == "****"


def test_luhn_valid_number():
    assert luhn_valid("4111111111111111") is True


def test_luhn_invalid_number():
    assert luhn_valid("4111111111111112") is False


def test_finds_aws_key():
    findings = find_api_keys("my key is AKIAIOSFODNN7EXAMPLE ok")
    assert len(findings) == 1
    assert findings[0].kind == "aws_access_key"
    assert findings[0].severity == Severity.HIGH
    assert "IOSFODNN7EXAMPLE" not in findings[0].evidence


def test_finds_github_token():
    token = "ghp_" + "a" * 36
    findings = find_api_keys(f"token: {token}")
    assert len(findings) == 1
    assert findings[0].kind == "github_token"


def test_finds_private_key_header():
    findings = find_api_keys("-----BEGIN RSA PRIVATE KEY-----")
    assert len(findings) == 1
    assert findings[0].kind == "private_key"


def test_no_api_key_in_normal_text():
    assert find_api_keys("hello world, nothing secret here") == []


def test_finds_valid_card_with_spaces():
    findings = find_card_numbers("pay with 4111 1111 1111 1111 please")
    assert len(findings) == 1
    assert findings[0].kind == "card_number"


def test_ignores_number_failing_luhn():
    assert find_card_numbers("order id 4111111111111112") == []


def test_finds_azerbaijan_iban():
    findings = find_iban("IBAN: AZ21NABZ00000000137010001944")
    assert len(findings) == 1
    assert findings[0].kind == "iban_az"


def test_scan_combines_all_detectors():
    text = "AKIAIOSFODNN7EXAMPLE and 4111 1111 1111 1111"
    kinds = {f.kind for f in scan(text)}
    assert kinds == {"aws_access_key", "card_number"}