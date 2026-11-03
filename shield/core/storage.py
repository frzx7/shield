"""SQLite storage for honeypot indicators of compromise (IOCs).

This module keeps metadata only: sender, domains, tactic tags, score and
timestamp. It never stores email bodies, subjects, attachments or evidence.
"""

import csv
import json
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS emails (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    file_hash      TEXT NOT NULL UNIQUE,
    seen_at        TEXT NOT NULL,
    sender_address TEXT NOT NULL,
    sender_domain  TEXT NOT NULL,
    brand          TEXT,
    score          INTEGER NOT NULL,
    label          TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS email_domains (
    email_id INTEGER NOT NULL REFERENCES emails(id),
    domain   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS email_tactics (
    email_id INTEGER NOT NULL REFERENCES emails(id),
    kind     TEXT NOT NULL
);
"""

CSV_COLUMNS = [
    "seen_at", "sender_address", "sender_domain",
    "brand", "score", "label", "domains", "tactics",
]

TOP_TACTICS_SQL = (
    "SELECT kind, COUNT(DISTINCT email_id) AS n FROM email_tactics "
    "GROUP BY kind ORDER BY n DESC, kind LIMIT ?"
)
TOP_BRANDS_SQL = (
    "SELECT brand, COUNT(*) AS n FROM emails WHERE brand IS NOT NULL "
    "GROUP BY brand ORDER BY n DESC, brand LIMIT ?"
)
TOP_DOMAINS_SQL = (
    "SELECT domain, COUNT(DISTINCT email_id) AS n FROM email_domains "
    "GROUP BY domain ORDER BY n DESC, domain LIMIT ?"
)


@dataclass
class IOCRecord:
    """The indicators extracted from one email. No email content lives here."""

    sender_address: str = ""
    sender_domain: str = ""
    domains: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    brand: str | None = None
    score: int = 0
    label: str = "safe"


def _safe_cell(value):
    """This function stops spreadsheet formula injection in exported CSV files.

    A text cell that starts with = + - @ could be run as a formula by Excel,
    so a leading apostrophe is added to turn it into plain text.
    """
    if isinstance(value, str) and value and value[0] in "=+-@\t\r":
        return "'" + value
    return value


class IOCStore:
    """A small SQLite database of IOC records."""

    def __init__(self, db_path):
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(SCHEMA)

    def close(self):
        self._conn.close()

    def add(self, record, file_hash, seen_at=None):
        """Stores one record. Returns False when this file hash is already stored."""
        if seen_at is None:
            seen_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._conn:  # one transaction: all rows are saved, or none
            cursor = self._conn.execute(
                "INSERT OR IGNORE INTO emails "
                "(file_hash, seen_at, sender_address, sender_domain, brand, score, label) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (file_hash, seen_at, record.sender_address, record.sender_domain,
                 record.brand, record.score, record.label),
            )
            if cursor.rowcount == 0:  # the UNIQUE hash already existed
                return False
            email_id = cursor.lastrowid
            self._conn.executemany(
                "INSERT INTO email_domains (email_id, domain) VALUES (?, ?)",
                [(email_id, domain) for domain in record.domains],
            )
            self._conn.executemany(
                "INSERT INTO email_tactics (email_id, kind) VALUES (?, ?)",
                [(email_id, kind) for kind in record.tactics],
            )
        return True

    def has_hash(self, file_hash):
        row = self._conn.execute(
            "SELECT 1 FROM emails WHERE file_hash = ? LIMIT 1", (file_hash,)
        ).fetchone()
        return row is not None

    def count(self):
        return self._conn.execute("SELECT COUNT(*) FROM emails").fetchone()[0]

    def stats(self, limit=5):
        """Returns totals and the most common tactics, brands and domains."""
        labels = dict(
            self._conn.execute("SELECT label, COUNT(*) FROM emails GROUP BY label").fetchall()
        )
        return {
            "total": self.count(),
            "labels": labels,
            "top_tactics": self._conn.execute(TOP_TACTICS_SQL, (limit,)).fetchall(),
            "top_brands": self._conn.execute(TOP_BRANDS_SQL, (limit,)).fetchall(),
            "top_domains": self._conn.execute(TOP_DOMAINS_SQL, (limit,)).fetchall(),
        }

    def _export_rows(self):
        """This block loads every email with its domains and tactics as plain dicts."""
        domains = defaultdict(list)
        for email_id, domain in self._conn.execute(
            "SELECT email_id, domain FROM email_domains ORDER BY domain"
        ):
            domains[email_id].append(domain)
        tactics = defaultdict(list)
        for email_id, kind in self._conn.execute(
            "SELECT email_id, kind FROM email_tactics ORDER BY kind"
        ):
            tactics[email_id].append(kind)

        rows = []
        for (email_id, seen_at, address, domain, brand, score, label) in self._conn.execute(
            "SELECT id, seen_at, sender_address, sender_domain, brand, score, label "
            "FROM emails ORDER BY id"
        ):
            rows.append({
                "seen_at": seen_at,
                "sender_address": address,
                "sender_domain": domain,
                "brand": brand,
                "score": score,
                "label": label,
                "domains": domains[email_id],
                "tactics": tactics[email_id],
            })
        return rows

    def export_json(self, path):
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(self._export_rows(), handle, ensure_ascii=False, indent=2)

    def export_csv(self, path):
        # utf-8-sig adds a BOM so Excel on Windows reads the file as UTF-8.
        with open(path, "w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
            writer.writeheader()
            for row in self._export_rows():
                flat = dict(row)
                flat["domains"] = ";".join(row["domains"])
                flat["tactics"] = ";".join(row["tactics"])
                flat["brand"] = row["brand"] or ""
                writer.writerow({key: _safe_cell(value) for key, value in flat.items()})