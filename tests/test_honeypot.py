"""Tests for IOC extraction, the folder watcher and the honeypot command line."""

import json
import shutil
from pathlib import Path

from shield.core.events import Finding, Severity
from shield.core.storage import IOCRecord, IOCStore
from shield.modules.phishguard.honeypot import (
    MAX_DOMAINS,
    FolderWatcher,
    extract_iocs,
    main,
)
from shield.modules.phishguard.parser import ParsedEmail
from shield.modules.phishguard.scoring import PhishReport

SAMPLES = Path(__file__).parent / "samples"
BRANDS = {"paypal": ["paypal.com"]}


def make_report(*kinds, score=100, label="likely phishing"):
    """This helper builds a PhishReport from tactic names, without running any rule."""
    findings = [Finding(kind, Severity.HIGH, "evidence", "explanation") for kind in kinds]
    return PhishReport(score=score, label=label, findings=findings)


# ---------- extract_iocs ----------

def test_extract_sender_and_link_domains():
    email = ParsedEmail(
        from_addr="PayPal <Security@Evil.Example>",
        links=[("Log in", "https://login.other.example/a")],
    )
    record = extract_iocs(email, make_report("link_mismatch"))
    assert record.sender_address == "security@evil.example"
    assert record.sender_domain == "evil.example"
    assert record.domains == ["evil.example", "login.other.example"]


def test_extract_reply_to_domain_included():
    email = ParsedEmail(from_addr="a@one.example", reply_to="b@two.example")
    record = extract_iocs(email, make_report("reply_to_mismatch"))
    assert "two.example" in record.domains


def test_extract_domains_deduplicated_and_sorted():
    email = ParsedEmail(
        from_addr="a@a.example",
        links=[("x", "https://a.example/1"), ("y", "https://a.example/2")],
    )
    assert extract_iocs(email, make_report()).domains == ["a.example"]


def test_extract_ignores_mailto_and_tel_links():
    email = ParsedEmail(links=[("mail", "mailto:x@y.example"), ("call", "tel:123")])
    assert extract_iocs(email, make_report()).domains == []


def test_extract_limits_domain_count():
    links = [("x", f"https://h{i}.example/") for i in range(MAX_DOMAINS + 20)]
    record = extract_iocs(ParsedEmail(links=links), make_report())
    assert len(record.domains) == MAX_DOMAINS


def test_extract_keeps_tactic_kinds_never_evidence():
    finding = Finding("link_mismatch", Severity.HIGH, "SECRET-EVIDENCE", "explanation")
    report = PhishReport(score=30, label="suspicious", findings=[finding, finding])
    record = extract_iocs(ParsedEmail(), report)
    assert record.tactics == ["link_mismatch"]
    assert "SECRET-EVIDENCE" not in repr(record)


def test_extract_brand_from_lookalike():
    email = ParsedEmail(from_addr="x@paypal-secure.example")
    record = extract_iocs(email, make_report("lookalike_domain"), brands=BRANDS)
    assert record.brand == "paypal"


def test_extract_brand_digit_swap():
    email = ParsedEmail(from_addr="x@paypa1.example")
    record = extract_iocs(email, make_report("lookalike_domain"), brands=BRANDS)
    assert record.brand == "paypal"


def test_extract_no_brand_without_lookalike_finding():
    email = ParsedEmail(from_addr="x@paypal-secure.example")
    record = extract_iocs(email, make_report("spf_fail"), brands=BRANDS)
    assert record.brand is None


# ---------- FolderWatcher ----------

def make_watcher(tmp_path, **kwargs):
    inbox = tmp_path / "inbox"
    inbox.mkdir(exist_ok=True)
    kwargs.setdefault("min_age_seconds", 0)
    store = IOCStore(":memory:")
    return FolderWatcher(inbox, store, **kwargs), inbox, store


def drop(inbox, sample, name):
    shutil.copy(SAMPLES / sample, inbox / name)


def test_new_eml_is_analyzed_and_stored(tmp_path):
    watcher, inbox, store = make_watcher(tmp_path)
    drop(inbox, "benign_friend.eml", "a.eml")
    results = watcher.check_once()
    assert len(results) == 1
    assert store.count() == 1


def test_same_file_is_not_processed_twice(tmp_path):
    watcher, inbox, store = make_watcher(tmp_path)
    drop(inbox, "benign_friend.eml", "a.eml")
    watcher.check_once()
    assert watcher.check_once() == []
    assert store.count() == 1


def test_same_content_under_other_name_is_stored_once(tmp_path):
    watcher, inbox, store = make_watcher(tmp_path)
    drop(inbox, "phish_paypal.eml", "a.eml")
    drop(inbox, "phish_paypal.eml", "b.eml")
    assert len(watcher.check_once()) == 1
    assert store.count() == 1


def test_non_eml_files_are_ignored(tmp_path):
    watcher, inbox, store = make_watcher(tmp_path)
    (inbox / "note.txt").write_text("hello", encoding="utf-8")
    (inbox / "mail.eml.txt").write_text("hello", encoding="utf-8")
    assert watcher.check_once() == []
    assert store.count() == 0


def test_broken_file_does_not_crash_the_watcher(tmp_path):
    def boom(_data):
        raise ValueError("broken")

    watcher, inbox, store = make_watcher(tmp_path, parse_fn=boom)
    drop(inbox, "benign_friend.eml", "a.eml")
    assert watcher.check_once() == []
    assert watcher.check_once() == []
    assert store.count() == 0


def test_oversized_file_is_skipped(tmp_path):
    watcher, inbox, store = make_watcher(tmp_path, max_bytes=10)
    drop(inbox, "phish_paypal.eml", "a.eml")
    assert watcher.check_once() == []
    assert store.count() == 0


def test_fresh_file_waits_for_min_age(tmp_path):
    watcher, inbox, store = make_watcher(tmp_path, min_age_seconds=3600)
    drop(inbox, "phish_paypal.eml", "a.eml")
    assert watcher.check_once() == []
    assert store.count() == 0


def test_file_added_later_is_picked_up(tmp_path):
    watcher, inbox, store = make_watcher(tmp_path)
    assert watcher.check_once() == []
    drop(inbox, "benign_friend.eml", "late.eml")
    assert len(watcher.check_once()) == 1


def test_on_result_callback_receives_name_and_record(tmp_path):
    calls = []
    watcher, inbox, _store = make_watcher(
        tmp_path, on_result=lambda name, record: calls.append((name, record.label))
    )
    drop(inbox, "benign_friend.eml", "a.eml")
    watcher.check_once()
    assert calls == [("a.eml", "safe")]


def test_phishing_sample_end_to_end(tmp_path):
    watcher, inbox, _store = make_watcher(tmp_path)
    drop(inbox, "phish_paypal.eml", "a.eml")
    record = watcher.check_once()[0]
    assert record.score == 100
    assert record.label == "likely phishing"
    assert record.tactics != []


def test_benign_sample_end_to_end(tmp_path):
    watcher, inbox, _store = make_watcher(tmp_path)
    drop(inbox, "benign_friend.eml", "a.eml")
    record = watcher.check_once()[0]
    assert record.score == 0
    assert record.label == "safe"
    assert record.tactics == []


# ---------- command line ----------

def test_cli_stats_runs_on_empty_db(tmp_path, capsys):
    main(["--db", str(tmp_path / "t.db"), "stats"])
    assert "Total emails: 0" in capsys.readouterr().out


def test_cli_export_writes_json(tmp_path):
    db = tmp_path / "t.db"
    store = IOCStore(db)
    store.add(
        IOCRecord(sender_address="a@evil.example", sender_domain="evil.example",
                  domains=["evil.example"], tactics=["spf_fail"], score=15, label="safe"),
        "h1",
    )
    store.close()
    out = tmp_path / "out.json"
    main(["--db", str(db), "export", str(out)])
    assert len(json.loads(out.read_text(encoding="utf-8"))) == 1