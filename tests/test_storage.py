"""Tests for the SQLite IOC store."""

import csv
import json

from typing import Any
from shield.core.storage import IOCRecord, IOCStore


def make_record(**overrides):
    """This helper builds a valid IOCRecord; tests override only what they need."""
    values: dict[str, Any] = dict(
        sender_address="a@evil.example",
        sender_domain="evil.example",
        domains=["evil.example"],
        tactics=["link_mismatch"],
        brand=None,
        score=60,
        label="likely phishing",
    )
    values.update(overrides)
    return IOCRecord(**values)


def test_add_record_and_count():
    store = IOCStore(":memory:")
    assert store.add(make_record(), "hash1") is True
    assert store.count() == 1


def test_duplicate_hash_is_not_added_twice():
    store = IOCStore(":memory:")
    store.add(make_record(), "hash1")
    assert store.add(make_record(), "hash1") is False
    assert store.count() == 1


def test_has_hash():
    store = IOCStore(":memory:")
    store.add(make_record(), "hash1")
    assert store.has_hash("hash1") is True
    assert store.has_hash("other") is False


def test_data_survives_reopen(tmp_path):
    db = tmp_path / "ioc.db"
    first = IOCStore(db)
    first.add(make_record(), "hash1")
    first.close()
    second = IOCStore(db)
    assert second.count() == 1
    assert second.has_hash("hash1") is True
    second.close()


def test_stats_empty_store():
    stats = IOCStore(":memory:").stats()
    assert stats["total"] == 0
    assert stats["top_tactics"] == []
    assert stats["top_brands"] == []


def test_stats_top_tactics_most_common_first():
    store = IOCStore(":memory:")
    store.add(make_record(tactics=["link_mismatch", "spf_fail"]), "h1")
    store.add(make_record(tactics=["link_mismatch"]), "h2")
    store.add(make_record(tactics=["urgency_language"]), "h3")
    top = store.stats()["top_tactics"]
    assert top[0] == ("link_mismatch", 2)
    assert ("spf_fail", 1) in top


def test_stats_top_brands_ignores_missing_brand():
    store = IOCStore(":memory:")
    store.add(make_record(brand="paypal"), "h1")
    store.add(make_record(brand="paypal"), "h2")
    store.add(make_record(brand=None), "h3")
    assert store.stats()["top_brands"] == [("paypal", 2)]


def test_stats_label_counts():
    store = IOCStore(":memory:")
    store.add(make_record(), "h1")
    store.add(make_record(label="safe", score=0, tactics=[]), "h2")
    assert store.stats()["labels"] == {"likely phishing": 1, "safe": 1}


def test_export_json(tmp_path):
    store = IOCStore(":memory:")
    store.add(make_record(domains=["b.example", "a.example"]), "h1")
    out = tmp_path / "out.json"
    store.export_json(out)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data) == 1
    assert data[0]["sender_domain"] == "evil.example"
    assert data[0]["domains"] == ["a.example", "b.example"]
    assert data[0]["tactics"] == ["link_mismatch"]
    assert "file_hash" not in data[0]


def test_export_csv(tmp_path):
    store = IOCStore(":memory:")
    store.add(
        make_record(domains=["b.example", "a.example"], tactics=["spf_fail", "link_mismatch"]),
        "h1",
    )
    out = tmp_path / "out.csv"
    store.export_csv(out)
    with open(out, encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["domains"] == "a.example;b.example"
    assert rows[0]["tactics"] == "link_mismatch;spf_fail"
    assert rows[0]["score"] == "60"


def test_export_csv_neutralizes_formula_cells(tmp_path):
    store = IOCStore(":memory:")
    store.add(make_record(sender_address="=cmd|' /c calc'!A1"), "h1")
    out = tmp_path / "out.csv"
    store.export_csv(out)
    with open(out, encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["sender_address"] == "'=cmd|' /c calc'!A1"


def test_schema_stores_only_ioc_columns():
    store = IOCStore(":memory:")
    columns = set()
    for table in ("emails", "email_domains", "email_tactics"):
        for row in store._conn.execute(f"PRAGMA table_info({table})"):
            columns.add(row[1])
    assert columns == {
        "id", "file_hash", "seen_at", "sender_address", "sender_domain",
        "brand", "score", "label", "email_id", "domain", "kind",
    }