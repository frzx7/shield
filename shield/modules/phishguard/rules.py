"""PhishGuard rule engine.
 
This module holds eight independent rules. Each rule is a small function that
takes a ParsedEmail and returns a list of Finding objects (an empty list when
the rule finds nothing). The function check_all() at the bottom runs every rule.
 
All analysis is static: no link is opened and no attachment is executed.
"""
 
import ipaddress
import re
from email.utils import parseaddr
from urllib.parse import urlparse
 
from shield.core.events import Finding, Severity
from shield.modules.phishguard.parser import ParsedEmail
 
# ---------------------------------------------------------------------------
# Configuration tables (edit these to tune the rules)
# ---------------------------------------------------------------------------
 
# This table maps a brand keyword to the domains that officially belong to it.
# A host that equals one of these domains, or is a subdomain of one, is trusted.
BRANDS = {
    "paypal": ("paypal.com",),
    "microsoft": (
        "microsoft.com",
        "live.com",
        "office.com",
        "outlook.com",
        "microsoftonline.com",
    ),
    "google": ("google.com", "gmail.com", "googlemail.com"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazon.co.uk", "amazon.de"),
    "facebook": ("facebook.com", "fb.com"),
    "instagram": ("instagram.com",),
    "netflix": ("netflix.com",),
    "linkedin": ("linkedin.com",),
    "dhl": ("dhl.com", "dhl.de"),
    "kapitalbank": ("kapitalbank.az",),
    "pashabank": ("pashabank.az",),
    "birbank": ("birbank.az",),
}
 
# This tuple lists words that attackers often attach to a brand name.
SUSPICIOUS_KEYWORDS = (
    "login",
    "signin",
    "secure",
    "verify",
    "support",
    "account",
    "update",
    "billing",
    "wallet",
)
 
# This table lists digits that attackers use in place of letters.
# The digit "1" is handled separately because it can mean "l" or "i".
DIGIT_LOOKALIKES = {"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"}
 
# This set lists well-known URL shortening services.
URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
    "tiny.cc",
    "rb.gy",
}
 
# These sets classify attachment extensions by danger level.
EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd", ".com",
    ".pif", ".ps1", ".msi", ".jar", ".lnk", ".iso", ".img", ".hta", ".wsf",
    ".dll", ".reg",
}  # fmt: skip
RISKY_EXTENSIONS = {".html", ".htm", ".docm", ".xlsm", ".pptm"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z"}
# This set lists harmless-looking extensions used as a decoy in "invoice.pdf.exe".
DECOY_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".jpeg", ".png",
}  # fmt: skip
 
# This table lists pressure phrases in Azerbaijani, Russian and English.
# Matching ignores case, Azerbaijani diacritics and the Russian letter "yo".
URGENCY_PHRASES = {
    "az": [
        "təcili",
        "dərhal",
        "hesabınız bloklanacaq",
        "hesabınız bloklanıb",
        "kartınız bloklanıb",
        "şifrənizi yeniləyin",
        "məlumatlarınızı təsdiqləyin",
        "son xəbərdarlıq",
        "24 saat ərzində",
    ],
    "ru": [
        "срочно",
        "немедленно",
        "ваш аккаунт будет заблокирован",
        "ваша учетная запись заблокирована",
        "ваш счет заблокирован",
        "подтвердите свои данные",
        "в течение 24 часов",
        "последнее предупреждение",
    ],
    "en": [
        "urgent",
        "verify now",
        "verify your account",
        "account suspended",
        "account will be suspended",
        "your account has been locked",
        "confirm your identity",
        "immediate action required",
        "act immediately",
        "within 24 hours",
        "final warning",
    ],
}
 
# This pattern reads "spf=fail", "dkim=pass" and similar pairs from the
# Authentication-Results header.
AUTH_PATTERN = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
 
# This pattern decides whether the visible text of a link looks like a domain
# or a URL (no spaces, has a dot and a letters-only ending).
DOMAIN_TEXT_PATTERN = re.compile(
    r"^(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:[/?#]\S*)?$",
    re.IGNORECASE,
)
 
# ---------------------------------------------------------------------------
# Helpers (shared by several rules)
# ---------------------------------------------------------------------------
 
 
def _unique(items):
    """This function removes duplicates and keeps the original order."""
    return list(dict.fromkeys(items))
 
 
def _host_from_url(url):
    """This function returns the lowercase hostname of a URL, or None.
 
    It also accepts scheme-less text such as "paypal.com/login" and skips
    links that do not point to a website (mailto:, tel:, javascript:, #anchor).
    """
    url = url.strip()
    if url.lower().startswith(("mailto:", "tel:", "javascript:", "data:", "#")):
        return None
    if "://" not in url and not url.startswith("//"):
        url = "//" + url
    try:
        host = urlparse(url).hostname
    except ValueError:
        return None
    return host.rstrip(".") if host else None
 
 
def _address_domain(address):
    """This function returns the domain of "Name <user@domain>", or None."""
    clean = parseaddr(address or "")[1]
    if "@" not in clean:
        return None
    return clean.rpartition("@")[2].strip().lower().rstrip(".") or None
 
 
def _link_hosts(email):
    """This function returns the unique hostnames of all links in the email."""
    hosts = [_host_from_url(href) for _, href in email.links]
    return _unique(host for host in hosts if host)
 
 
def _all_hosts(email):
    """This function returns link hosts plus the From and Reply-To domains."""
    hosts = _link_hosts(email)
    for address in (email.from_addr, email.reply_to):
        domain = _address_domain(address)
        if domain:
            hosts.append(domain)
    return _unique(hosts)
 
 
def _same_site(host_a, host_b):
    """This function says whether two hosts belong to the same site.
 
    "paypal.com" and "www.paypal.com" are the same site. "paypal.com" and
    "paypal.com.evil.example" are not.
    """
    return (
        host_a == host_b
        or host_a.endswith("." + host_b)
        or host_b.endswith("." + host_a)
    )
 
 
def _fold(text):
    """This function normalizes text for phrase matching.
 
    It lowercases, turns the Turkic dotted capital I into "i", removes
    combining dots, and replaces Azerbaijani diacritics with plain letters so
    that "TƏCİLİ" and "tecili" both become "tecili".
    """
    table = str.maketrans(
        {
            "ə": "e", "ı": "i", "ö": "o", "ü": "u",
            "ş": "s", "ç": "c", "ğ": "g", "ё": "е",
        }
    )  # fmt: skip
    folded = text.replace("İ", "i").casefold().replace("\u0307", "")
    return folded.translate(table)
 
 
def _decode_idna(host):
    """This function turns a punycode host into readable Unicode, if possible."""
    try:
        return host.encode("ascii").decode("idna")
    except UnicodeError:
        return host
 
 
# ---------------------------------------------------------------------------
# Rule 1: link text versus real destination
# ---------------------------------------------------------------------------
 
 
def check_link_mismatch(email: ParsedEmail) -> list[Finding]:
    """This rule flags links whose visible text names one site but lead to another."""
    findings = []
    seen = set()
    for visible_text, href in email.links:
        text = visible_text.strip()
 
        # This block skips link texts that do not look like a domain or URL,
        # such as "Click here".
        if not DOMAIN_TEXT_PATTERN.match(text):
            continue
 
        shown_host = _host_from_url(text)
        real_host = _host_from_url(href)
        if not shown_host or not real_host or _same_site(shown_host, real_host):
            continue
 
        # This block reports each (shown, real) pair only once.
        pair = (shown_host, real_host)
        if pair in seen:
            continue
        seen.add(pair)
 
        findings.append(
            Finding(
                kind="link_mismatch",
                severity=Severity.HIGH,
                evidence=real_host,
                rule_explanation=(
                    f"A link displays '{shown_host}' but actually leads to "
                    f"'{real_host}'. Attackers hide the real destination "
                    "behind a familiar-looking text."
                ),
            )
        )
    return findings
 
 
# ---------------------------------------------------------------------------
# Rule 2: lookalike domains
# ---------------------------------------------------------------------------
 
 
def _is_official(host):
    """This function says whether a host belongs to one of the known brands."""
    for domains in BRANDS.values():
        for domain in domains:
            if host == domain or host.endswith("." + domain):
                return True
    return False
 
 
def _label_variants(label):
    """This function returns the spellings a lookalike label could hide.
 
    It swaps lookalike digits for letters ("paypa1" -> "paypal") and the
    letter pairs "rn" and "vv" for "m" and "w" ("rnicrosoft" -> "microsoft").
    """
    variants = set()
    for one_means in ("l", "i"):
        table = str.maketrans({**DIGIT_LOOKALIKES, "1": one_means})
        base = label.translate(table)
        variants.add(base)
        variants.add(base.replace("rn", "m").replace("vv", "w"))
    return variants
 
 
def _embeds_brand(label, brand):
    """This function says whether a label wraps a brand name with extra words."""
    parts = label.split("-")
    if len(parts) > 1 and brand in parts:
        return True
    return brand in label and any(word in label for word in SUSPICIOUS_KEYWORDS)
 
 
def _lookalike_reason(host):
    """This function returns (severity, explanation) for a lookalike host, or None."""
    if _is_official(host):
        return None
 
    # This block checks every label except the last one (the TLD), so that
    # "paypal.com.evil.example" is caught through its first label.
    for label in host.split(".")[:-1]:
        variants = _label_variants(label)
        for brand in BRANDS:
            if label == brand:
                return (
                    Severity.HIGH,
                    f"The domain '{host}' uses the brand name '{brand}' but "
                    f"is not an official {brand} domain.",
                )
            if brand in variants:
                return (
                    Severity.HIGH,
                    f"The domain '{host}' imitates '{brand}' by replacing "
                    "letters with similar-looking characters.",
                )
            if _embeds_brand(label, brand):
                return (
                    Severity.MEDIUM,
                    f"The domain '{host}' wraps the brand name '{brand}' in "
                    "extra words, a common trick to look official.",
                )
    return None
 
 
def check_lookalike_domains(email: ParsedEmail) -> list[Finding]:
    """This rule flags domains that imitate a well-known brand."""
    findings = []
    for host in _all_hosts(email):
        reason = _lookalike_reason(host)
        if reason is None:
            continue
        severity, explanation = reason
        findings.append(
            Finding(
                kind="lookalike_domain",
                severity=severity,
                evidence=host,
                rule_explanation=explanation,
            )
        )
    return findings
 
 
# ---------------------------------------------------------------------------
# Rule 3: punycode and non-ASCII hostnames
# ---------------------------------------------------------------------------
 
 
def check_punycode(email: ParsedEmail) -> list[Finding]:
    """This rule flags internationalized domains, which can hide lookalike letters."""
    findings = []
    for host in _all_hosts(email):
        is_punycode = any(label.startswith("xn--") for label in host.split("."))
        if not is_punycode and host.isascii():
            continue
        findings.append(
            Finding(
                kind="punycode_domain",
                severity=Severity.MEDIUM,
                evidence=host,
                rule_explanation=(
                    f"The domain '{host}' uses international characters "
                    f"(it reads as '{_decode_idna(host)}'). Attackers use "
                    "letters from other alphabets that look identical to "
                    "Latin letters."
                ),
            )
        )
    return findings
 
 
# ---------------------------------------------------------------------------
# Rule 4: IP-address URLs and URL shorteners
# ---------------------------------------------------------------------------
 
 
def check_suspicious_urls(email: ParsedEmail) -> list[Finding]:
    """This rule flags links that use a raw IP address or a URL shortener."""
    findings = []
    for host in _link_hosts(email):
        # This block detects hosts that are literally an IP address.
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False
 
        if is_ip:
            findings.append(
                Finding(
                    kind="ip_address_url",
                    severity=Severity.HIGH,
                    evidence=host,
                    rule_explanation=(
                        f"A link points straight to the IP address {host}. "
                        "Legitimate services almost always use a domain name."
                    ),
                )
            )
        elif host in URL_SHORTENERS:
            findings.append(
                Finding(
                    kind="url_shortener",
                    severity=Severity.LOW,
                    evidence=host,
                    rule_explanation=(
                        f"A link uses the shortening service '{host}', which "
                        "hides the real destination."
                    ),
                )
            )
    return findings
 
 
# ---------------------------------------------------------------------------
# Rule 5: From versus Reply-To
# ---------------------------------------------------------------------------
 
 
def check_reply_to_mismatch(email: ParsedEmail) -> list[Finding]:
    """This rule flags emails whose replies would go to a different site."""
    from_domain = _address_domain(email.from_addr)
    reply_domain = _address_domain(email.reply_to)
 
    # This block stops when either address is missing, because there is
    # nothing to compare.
    if not from_domain or not reply_domain:
        return []
    if _same_site(from_domain, reply_domain):
        return []
 
    return [
        Finding(
            kind="reply_to_mismatch",
            severity=Severity.MEDIUM,
            evidence=reply_domain,
            rule_explanation=(
                f"The email is sent from '{from_domain}' but replies would go "
                f"to '{reply_domain}'. Attackers use this to collect answers "
                "while the sender looks trustworthy."
            ),
        )
    ]
 
 
# ---------------------------------------------------------------------------
# Rule 6: SPF, DKIM and DMARC results
# ---------------------------------------------------------------------------
 
 
def check_authentication(email: ParsedEmail) -> list[Finding]:
    """This rule flags failed sender-authentication checks.
 
    An empty header produces no finding, because a missing header means
    "unknown", not "failed".
    """
    findings = []
    seen = set()
    for mechanism, result in AUTH_PATTERN.findall(email.auth_results or ""):
        mechanism, result = mechanism.lower(), result.lower()
        if (mechanism, result) in seen:
            continue
        seen.add((mechanism, result))
 
        # This block maps each result to a severity.
        if result == "fail":
            severity = Severity.HIGH if mechanism == "dmarc" else Severity.MEDIUM
        elif result in ("softfail", "permerror"):
            severity = Severity.LOW
        else:
            continue
 
        findings.append(
            Finding(
                kind=f"{mechanism}_{result}",
                severity=severity,
                evidence=f"{mechanism}={result}",
                rule_explanation=(
                    f"The {mechanism.upper()} check returned '{result}', so "
                    "the sender may not be who the email claims."
                ),
            )
        )
    return findings
 
 
# ---------------------------------------------------------------------------
# Rule 7: dangerous attachments
# ---------------------------------------------------------------------------
 
 
def check_dangerous_attachments(email: ParsedEmail) -> list[Finding]:
    """This rule flags attachment names that suggest malware or credential theft."""
    findings = []
    for filename in email.attachments:
        lowered = filename.lower().strip()
        parts = lowered.split(".")
        final_ext = "." + parts[-1].strip() if len(parts) > 1 else ""
        previous_ext = "." + parts[-2].strip() if len(parts) > 2 else ""
 
        # This block picks one classification per attachment, most serious first.
        if "\u202e" in lowered:
            kind, severity = "rtl_override_filename", Severity.HIGH
            reason = (
                "The file name contains a hidden right-to-left control "
                "character that disguises the real extension."
            )
        elif final_ext in EXECUTABLE_EXTENSIONS and previous_ext in DECOY_EXTENSIONS:
            kind, severity = "double_extension", Severity.HIGH
            reason = (
                f"The file '{filename}' pretends to be a {previous_ext} file "
                f"but is really a {final_ext} program."
            )
        elif final_ext in EXECUTABLE_EXTENSIONS:
            kind, severity = "dangerous_attachment", Severity.HIGH
            reason = (
                f"The attachment '{filename}' is an executable or script "
                f"type ({final_ext}) that can run code on the computer."
            )
        elif final_ext in RISKY_EXTENSIONS:
            kind, severity = "risky_attachment", Severity.MEDIUM
            reason = (
                f"The attachment '{filename}' ({final_ext}) can contain "
                "fake login pages or macros."
            )
        elif final_ext in ARCHIVE_EXTENSIONS:
            kind, severity = "archive_attachment", Severity.LOW
            reason = (
                f"The archive '{filename}' can hide files that mail "
                "scanners cannot inspect."
            )
        else:
            continue
 
        findings.append(
            Finding(
                kind=kind,
                severity=severity,
                evidence=filename,
                rule_explanation=reason,
            )
        )
    return findings
 
 
# ---------------------------------------------------------------------------
# Rule 8: urgency language (Azerbaijani, Russian, English)
# ---------------------------------------------------------------------------
 
# This list pairs every phrase with its normalized form, computed once at import.
_URGENCY_FOLDED = [
    (phrase, _fold(phrase))
    for phrases in URGENCY_PHRASES.values()
    for phrase in phrases
]
 
 
def check_urgency_language(email: ParsedEmail) -> list[Finding]:
    """This rule flags pressure phrases in the subject and the body text."""
    text = _fold(f"{email.subject} {email.body_text}")
    hits = [original for original, folded in _URGENCY_FOLDED if folded in text]
    if not hits:
        return []
 
    # This block raises the severity when several pressure phrases appear
    # together, which is typical for phishing.
    severity = Severity.MEDIUM if len(hits) >= 2 else Severity.LOW
    return [
        Finding(
            kind="urgency_language",
            severity=severity,
            evidence=", ".join(hits[:3]),
            rule_explanation=(
                "The message uses pressure language to rush the reader "
                f"({len(hits)} phrase(s) found). Phishing emails create "
                "urgency so that people act before thinking."
            ),
        )
    ]
 
 
# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
 
# This tuple lists every rule that check_all() runs, in order.
ALL_RULES = (
    check_link_mismatch,
    check_lookalike_domains,
    check_punycode,
    check_suspicious_urls,
    check_reply_to_mismatch,
    check_authentication,
    check_dangerous_attachments,
    check_urgency_language,
)
 
 
def check_all(email: ParsedEmail) -> list[Finding]:
    """This function runs every rule and returns all findings together.
 
    It is the only function other modules (scoring, honeypot) should call.
    """
    findings = []
    for rule in ALL_RULES:
        findings.extend(rule(email))
    return findings
 