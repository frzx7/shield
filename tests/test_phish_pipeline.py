from pathlib import Path
 
from shield.core.events import Finding, Severity
from shield.modules.phishguard.parser import ParsedEmail, parse_eml
from shield.modules.phishguard.scoring import analyze, label_for, score_findings
 
SAMPLES = Path(__file__).parent / "samples"
PHISH = SAMPLES / "phish_paypal.eml"
BENIGN = SAMPLES / "benign_friend.eml"
AZERBAIJANI = SAMPLES / "azerbaijani_html_only.eml"
 
 
def make_finding(kind, severity):
    return Finding(kind=kind, severity=severity, evidence="x", rule_explanation="x")
 
 
# ---------- parser ----------
 
def test_parse_headers():
    email = parse_eml(PHISH)
    assert "support@paypa1.com" in email.from_addr
    assert email.reply_to == "help@evil-site.example"
    assert email.subject.startswith("URGENT")
    assert "spf=fail" in email.auth_results
 
 
def test_parse_links_from_html():
    email = parse_eml(PHISH)
    assert ("paypal.com/secure", "http://203.0.113.7/paypal/login") in email.links
    assert ("Click here", "https://bit.ly/3fakeLink") in email.links
 
 
def test_parse_attachment_names():
    assert parse_eml(PHISH).attachments == ["invoice.pdf.exe"]
 
 
def test_parse_accepts_str_path():
    assert parse_eml(str(PHISH)).subject.startswith("URGENT")
 
 
def test_parse_accepts_raw_text():
    raw = PHISH.read_text(encoding="utf-8")
    assert parse_eml(raw).subject.startswith("URGENT")
 
 
def test_parse_accepts_bytes():
    assert parse_eml(PHISH.read_bytes()).reply_to == "help@evil-site.example"
 
 
def test_html_only_email_gets_body_text():
    email = parse_eml(AZERBAIJANI)
    assert email.body_html != ""
    assert "Hesabınız bloklanacaq" in email.body_text
 
 
def test_script_content_is_not_visible_text():
    email = parse_eml(PHISH)
    assert "must not appear" not in email.body_text
 
 
def test_encoded_subject_is_decoded():
    assert parse_eml(AZERBAIJANI).subject.startswith("TƏCİLİ")
 
 
def test_plain_text_urls_become_links():
    email = parse_eml(BENIGN)
    assert ("https://example.org/menu", "https://example.org/menu") in email.links
 
 
def test_garbage_input_does_not_crash():
    email = parse_eml("this is not an email at all")
    assert isinstance(email, ParsedEmail)
    assert email.links == []
    assert email.attachments == []
 
 
# ---------- scoring ----------
 
def test_empty_findings_are_safe():
    assert score_findings([]) == 0
    assert label_for(0) == "safe"
 
 
def test_single_high_is_suspicious():
    score = score_findings([make_finding("a", Severity.HIGH)])
    assert score == 30
    assert label_for(score) == "suspicious"
 
 
def test_two_high_is_likely_phishing():
    score = score_findings(
        [make_finding("a", Severity.HIGH), make_finding("b", Severity.HIGH)]
    )
    assert score == 60
    assert label_for(score) == "likely phishing"
 
 
def test_score_is_capped_at_100():
    findings = [make_finding(f"kind{i}", Severity.HIGH) for i in range(6)]
    assert score_findings(findings) == 100
 
 
def test_same_kind_is_counted_once():
    findings = [make_finding("link_mismatch", Severity.HIGH) for _ in range(5)]
    assert score_findings(findings) == 30
 
 
def test_same_kind_uses_highest_severity():
    findings = [
        make_finding("auth", Severity.LOW),
        make_finding("auth", Severity.HIGH),
    ]
    assert score_findings(findings) == 30
 
 
# ---------- end to end ----------
 
def test_analyze_phishing_sample():
    report = analyze(PHISH)
    kinds = {f.kind for f in report.findings}
    assert report.label == "likely phishing"
    assert report.score == 100
    assert {
        "link_mismatch",
        "lookalike_domain",
        "ip_address_url",
        "url_shortener",
        "reply_to_mismatch",
        "spf_fail",
        "dmarc_fail",
        "double_extension",
        "urgency_language",
    } <= kinds
 
 
def test_analyze_benign_sample():
    report = analyze(BENIGN)
    assert report.findings == []
    assert report.score == 0
    assert report.label == "safe"
 
 
def test_analyze_azerbaijani_sample():
    report = analyze(AZERBAIJANI)
    kinds = {f.kind for f in report.findings}
    assert {"link_mismatch", "lookalike_domain", "urgency_language"} <= kinds
    assert report.label in ("suspicious", "likely phishing")
 
 
def test_analyze_accepts_parsed_email():
    email = ParsedEmail(body_text="Please verify now.")
    assert analyze(email).findings[0].kind == "urgency_language"
 
