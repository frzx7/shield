from shield.core.events import Severity
from shield.modules.phishguard.parser import ParsedEmail
from shield.modules.phishguard.rules import (
    check_all,
    check_authentication,
    check_dangerous_attachments,
    check_link_mismatch,
    check_lookalike_domains,
    check_punycode,
    check_reply_to_mismatch,
    check_suspicious_urls,
    check_urgency_language,
)
 
 
# ---------- Rule 1: link text vs real href ----------
 
def test_link_mismatch_detected():
    email = ParsedEmail(links=[("paypal.com", "http://evil-site.example/login")])
    findings = check_link_mismatch(email)
    assert len(findings) == 1
    assert findings[0].kind == "link_mismatch"
    assert findings[0].severity == Severity.HIGH
    assert "evil-site.example" in findings[0].evidence
 
 
def test_link_mismatch_full_url_as_visible_text():
    email = ParsedEmail(
        links=[("https://paypal.com/login", "http://evil-site.example/x")]
    )
    assert len(check_link_mismatch(email)) == 1
 
 
def test_link_matching_domain_is_ok():
    email = ParsedEmail(links=[("paypal.com", "https://paypal.com/login")])
    assert check_link_mismatch(email) == []
 
 
def test_link_subdomain_of_same_site_is_ok():
    email = ParsedEmail(links=[("paypal.com", "https://www.paypal.com/login")])
    assert check_link_mismatch(email) == []
 
 
def test_link_text_that_is_not_a_domain_is_ignored():
    email = ParsedEmail(links=[("Click here", "http://evil-site.example/login")])
    assert check_link_mismatch(email) == []
 
 
def test_link_mismatch_with_no_links():
    assert check_link_mismatch(ParsedEmail()) == []
 
 
# ---------- Rule 2: lookalike domains ----------
 
def test_lookalike_digit_instead_of_letter():
    email = ParsedEmail(links=[("Log in", "http://paypa1.com/login")])
    findings = check_lookalike_domains(email)
    assert len(findings) == 1
    assert findings[0].kind == "lookalike_domain"
    assert findings[0].severity == Severity.HIGH
    assert "paypa1.com" in findings[0].evidence
 
 
def test_lookalike_rn_instead_of_m():
    email = ParsedEmail(links=[("Sign in", "https://rnicrosoft.com/")])
    findings = check_lookalike_domains(email)
    assert len(findings) == 1
    assert findings[0].kind == "lookalike_domain"
 
 
def test_brand_inside_longer_domain():
    email = ParsedEmail(links=[("Verify", "https://paypal-secure-login.example/")])
    findings = check_lookalike_domains(email)
    assert len(findings) == 1
    assert findings[0].kind == "lookalike_domain"
 
 
def test_brand_used_as_subdomain_of_other_site():
    email = ParsedEmail(links=[("Verify", "https://paypal.com.evil-site.example/")])
    assert len(check_lookalike_domains(email)) == 1
 
 
def test_lookalike_sender_domain():
    email = ParsedEmail(from_addr="support@paypa1.com")
    assert len(check_lookalike_domains(email)) == 1
 
 
def test_real_brand_domains_are_ok():
    email = ParsedEmail(
        from_addr="service@paypal.com",
        links=[
            ("a", "https://paypal.com/login"),
            ("b", "https://www.paypal.com/"),
            ("c", "https://mail.google.com/"),
        ],
    )
    assert check_lookalike_domains(email) == []
 
 
def test_unrelated_domain_is_ok():
    email = ParsedEmail(links=[("Docs", "https://example.org/page")])
    assert check_lookalike_domains(email) == []
 
 
# ---------- Rule 3: punycode / IDN ----------
 
def test_punycode_host_detected():
    email = ParsedEmail(links=[("Log in", "http://xn--pypal-4ve.com/login")])
    findings = check_punycode(email)
    assert len(findings) == 1
    assert findings[0].kind == "punycode_domain"
 
 
def test_non_ascii_host_detected():
    email = ParsedEmail(links=[("Log in", "http://p\u0430ypal.com/login")])
    assert len(check_punycode(email)) == 1
 
 
def test_plain_ascii_host_is_not_punycode():
    email = ParsedEmail(links=[("Docs", "https://example.org/")])
    assert check_punycode(email) == []
 
 
# ---------- Rule 4: IP URLs and shorteners ----------
 
def test_ip_address_url_detected():
    email = ParsedEmail(links=[("Open", "http://203.0.113.7:8080/login")])
    findings = check_suspicious_urls(email)
    assert len(findings) == 1
    assert findings[0].kind == "ip_address_url"
    assert findings[0].severity == Severity.HIGH
 
 
def test_url_shortener_detected():
    email = ParsedEmail(links=[("Open", "https://bit.ly/3abcdef")])
    findings = check_suspicious_urls(email)
    assert len(findings) == 1
    assert findings[0].kind == "url_shortener"
    assert findings[0].severity == Severity.LOW
 
 
def test_normal_url_is_ok():
    email = ParsedEmail(links=[("Docs", "https://example.org/page")])
    assert check_suspicious_urls(email) == []
 
 
# ---------- Rule 5: From vs Reply-To ----------
 
def test_reply_to_mismatch_detected():
    email = ParsedEmail(
        from_addr="PayPal <service@paypal.com>",
        reply_to="scam@evil-site.example",
    )
    findings = check_reply_to_mismatch(email)
    assert len(findings) == 1
    assert findings[0].kind == "reply_to_mismatch"
    assert findings[0].severity == Severity.MEDIUM
 
 
def test_reply_to_same_domain_is_ok():
    email = ParsedEmail(from_addr="a@example.org", reply_to="b@example.org")
    assert check_reply_to_mismatch(email) == []
 
 
def test_reply_to_subdomain_is_ok():
    email = ParsedEmail(from_addr="a@example.org", reply_to="b@mail.example.org")
    assert check_reply_to_mismatch(email) == []
 
 
def test_missing_reply_to_is_ok():
    email = ParsedEmail(from_addr="a@example.org")
    assert check_reply_to_mismatch(email) == []
 
 
# ---------- Rule 6: SPF / DKIM / DMARC ----------
 
def test_failed_authentication_detected():
    email = ParsedEmail(
        auth_results=(
            "mx.example.org; spf=fail smtp.mailfrom=x@example.org; "
            "dkim=pass header.d=example.org; dmarc=fail (p=none)"
        )
    )
    findings = check_authentication(email)
    assert {f.kind for f in findings} == {"spf_fail", "dmarc_fail"}
    dmarc = next(f for f in findings if f.kind == "dmarc_fail")
    assert dmarc.severity == Severity.HIGH
 
 
def test_softfail_is_low():
    email = ParsedEmail(auth_results="mx.example.org; spf=softfail")
    findings = check_authentication(email)
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
 
 
def test_passing_authentication_is_ok():
    email = ParsedEmail(auth_results="mx.example.org; spf=pass; dkim=pass; dmarc=pass")
    assert check_authentication(email) == []
 
 
def test_missing_authentication_header_is_ok():
    assert check_authentication(ParsedEmail()) == []
 
 
# ---------- Rule 7: dangerous attachments ----------
 
def test_double_extension_detected():
    email = ParsedEmail(attachments=["invoice.pdf.exe"])
    findings = check_dangerous_attachments(email)
    assert len(findings) == 1
    assert findings[0].kind == "double_extension"
    assert findings[0].severity == Severity.HIGH
 
 
def test_double_extension_is_case_insensitive():
    email = ParsedEmail(attachments=["INVOICE.PDF.EXE"])
    assert check_dangerous_attachments(email)[0].kind == "double_extension"
 
 
def test_executable_attachment_detected():
    email = ParsedEmail(attachments=["setup.exe"])
    findings = check_dangerous_attachments(email)
    assert findings[0].kind == "dangerous_attachment"
    assert findings[0].severity == Severity.HIGH
 
 
def test_html_attachment_is_medium():
    email = ParsedEmail(attachments=["login.html"])
    findings = check_dangerous_attachments(email)
    assert findings[0].kind == "risky_attachment"
    assert findings[0].severity == Severity.MEDIUM
 
 
def test_archive_attachment_is_low():
    email = ParsedEmail(attachments=["photos.zip"])
    findings = check_dangerous_attachments(email)
    assert findings[0].kind == "archive_attachment"
    assert findings[0].severity == Severity.LOW
 
 
def test_right_to_left_override_detected():
    email = ParsedEmail(attachments=["doc\u202efdp.exe"])
    assert check_dangerous_attachments(email)[0].kind == "rtl_override_filename"
 
 
def test_harmless_attachment_is_ok():
    email = ParsedEmail(attachments=["report.pdf", "photo.jpg"])
    assert check_dangerous_attachments(email) == []
 
 
# ---------- Rule 8: urgency language ----------
 
def test_urgency_single_phrase_is_low():
    email = ParsedEmail(body_text="Please verify now.")
    findings = check_urgency_language(email)
    assert len(findings) == 1
    assert findings[0].kind == "urgency_language"
    assert findings[0].severity == Severity.LOW
 
 
def test_urgency_several_phrases_is_medium():
    email = ParsedEmail(body_text="URGENT: verify now or your account suspended")
    assert check_urgency_language(email)[0].severity == Severity.MEDIUM
 
 
def test_urgency_azerbaijani_uppercase():
    email = ParsedEmail(subject="TƏCİLİ: məlumatlarınızı yeniləyin")
    findings = check_urgency_language(email)
    assert len(findings) == 1
    assert "təcili" in findings[0].evidence
 
 
def test_urgency_azerbaijani_typed_without_diacritics():
    email = ParsedEmail(body_text="Tecili! Hesabiniz bloklanacaq")
    assert check_urgency_language(email)[0].severity == Severity.MEDIUM
 
 
def test_urgency_russian():
    email = ParsedEmail(body_text="Срочно! Ваш аккаунт будет заблокирован")
    assert check_urgency_language(email)[0].severity == Severity.MEDIUM
 
 
def test_calm_text_has_no_urgency():
    email = ParsedEmail(body_text="Hello, your invoice for October is attached.")
    assert check_urgency_language(email) == []
 
 
# ---------- check_all ----------
 
def test_check_all_combines_rules():
    email = ParsedEmail(
        from_addr="PayPal <support@paypa1.com>",
        reply_to="help@evil-site.example",
        subject="URGENT: verify now",
        links=[("paypal.com", "http://203.0.113.7/login")],
        attachments=["invoice.pdf.exe"],
        auth_results="mx.example.org; spf=fail",
    )
    kinds = {f.kind for f in check_all(email)}
    assert kinds == {
        "link_mismatch",
        "lookalike_domain",
        "ip_address_url",
        "reply_to_mismatch",
        "spf_fail",
        "double_extension",
        "urgency_language",
    }
 
 
def test_check_all_clean_email_has_no_findings():
    email = ParsedEmail(
        from_addr="friend@example.org",
        subject="Lunch tomorrow?",
        body_text="Hello, are you free for lunch tomorrow?",
        links=[("Menu", "https://example.org/menu")],
    )
    assert check_all(email) == []
 