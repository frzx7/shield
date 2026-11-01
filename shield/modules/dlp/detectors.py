import re

from shield.core.events import Finding, Severity

# Each pattern describes what a secret "looks like".
API_KEY_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github_token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}
CARD_PATTERN = re.compile(r"\b(?:\d[ -]?){13,19}\b")
IBAN_AZ_PATTERN = re.compile(r"\bAZ\d{2}[A-Z]{4}[0-9A-Z]{20}\b")


def mask(value: str) -> str:
    """First 4 characters are kept, the rest are hidden with '*'."""
    if len(value) <= 4:
        return "****"
    return value[:4] + "*" * (len(value) - 4)

#Luhn algorithm
def luhn_valid(number: str) -> bool:
    """Returns a bool if string passes Luhn algorithm."""
    total = 0
    for index, char in enumerate(reversed(number)):
        digit = int(char)
        if index % 2 == 1:      # every second digit from the right       
            digit *= 2          # double it;
            if digit > 9:
                digit -= 9          #if result > 9, subtract 9
        total += digit
    return total % 10 == 0


def find_api_keys(text: str) -> list[Finding]:
    findings = []
    for kind, pattern in API_KEY_PATTERNS.items():
        for match in pattern.finditer(text):
            findings.append(
                Finding(
                    kind=kind,
                    severity=Severity.HIGH,
                    evidence=mask(match.group()),
                    rule_explanation=f"This looks like a secret ({kind}). Do not share it; rotate it if it was exposed.",
                )
            )
    return findings


def find_card_numbers(text: str) -> list[Finding]:
    findings = []
    for match in CARD_PATTERN.finditer(text):
        digits = re.sub(r"\D", "", match.group())  # \D - everything except numbers
        if luhn_valid(digits):
            findings.append(
                Finding(
                    kind="card_number",
                    severity=Severity.HIGH,
                    evidence=mask(digits),
                    rule_explanation=(
                        "This looks like a valid payment card number. "
                        "Avoid pasting it into chats, forms or documents."
                    ),
                )
            )
    return findings


def find_iban(text: str) -> list[Finding]:
    findings = []
    for match in IBAN_AZ_PATTERN.finditer(text):
        findings.append(
            Finding(
                kind="iban_az",
                severity=Severity.MEDIUM,
                evidence=mask(match.group()),
                rule_explanation=(
                    "This looks like an Azerbaijani bank account number (IBAN). "
                    "Share it only with people you trust."
                ),
            )
        )
    return findings


def scan(text: str) -> list[Finding]:
    """Here, each detector is activated and returns all detected data together."""
    return find_api_keys(text) + find_card_numbers(text) + find_iban(text)