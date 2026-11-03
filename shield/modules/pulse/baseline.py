"""The Pulse baseline: what is normal on this computer.

Stores only program names, start-up fingerprints and the learning start time.
"""

import sqlite3
from datetime import datetime, timedelta, timezone

LEARNING_HOURS = 48

SCHEMA = """
CREATE TABLE IF NOT EXISTS known_processes (name TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS startup_entries (entry TEXT PRIMARY KEY, digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def _utc_now():
    return datetime.now(timezone.utc)


class Baseline:
    def __init__(self, db_path, now=None, learning_hours=LEARNING_HOURS):
        self.learning_hours = learning_hours
        self._conn = sqlite3.connect(str(db_path))
        self._conn.executescript(SCHEMA)
        clock = now or _utc_now
        with self._conn:
            # OR IGNORE keeps the very first start time on every later run.
            self._conn.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES ('learning_started', ?)",
                (clock().isoformat(timespec="seconds"),),
            )

    def close(self):
        self._conn.close()

    def is_learning(self, now):
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = 'learning_started'"
        ).fetchone()
        started = datetime.fromisoformat(row[0])
        return now - started < timedelta(hours=self.learning_hours)

    def add_process(self, name):
        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO known_processes (name) VALUES (?)", (name.lower(),)
            )

    def knows_process(self, name):
        row = self._conn.execute(
            "SELECT 1 FROM known_processes WHERE name = ?", (name.lower(),)
        ).fetchone()
        return row is not None

    def load_startup(self):
        """Returns the saved start-up snapshot, or None if none was ever saved."""
        saved = self._conn.execute(
            "SELECT 1 FROM meta WHERE key = 'startup_saved'"
        ).fetchone()
        if saved is None:
            return None
        return dict(self._conn.execute("SELECT entry, digest FROM startup_entries").fetchall())

    def save_startup(self, entries):
        with self._conn:
            self._conn.execute("DELETE FROM startup_entries")
            self._conn.executemany(
                "INSERT INTO startup_entries (entry, digest) VALUES (?, ?)",
                list(entries.items()),
            )
            self._conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('startup_saved', '1')"
            )