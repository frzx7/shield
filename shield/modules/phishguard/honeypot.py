"""Honeypot: watch a folder for .eml files, analyze them statically, store IOCs.

Files are only read as bytes. Links are never opened and attachments are never
saved or run (principle 4).
"""

import argparse
import hashlib
import io
import sys
import time
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlparse

from shield.core.storage import IOCRecord, IOCStore
from shield.modules.phishguard.parser import parse_eml
from shield.modules.phishguard.rules import BRANDS
from shield.modules.phishguard.scoring import analyze

MAX_DOMAINS = 50                    # one email cannot flood the database
MAX_EML_BYTES = 5 * 1024 * 1024     # larger files are skipped
MIN_FILE_AGE_SECONDS = 1.0          # a file still being copied is not read yet
POLL_INTERVAL_SECONDS = 2.0
DEFAULT_DB = "shield_honeypot.db"

# Digits that attackers use in place of letters: paypa1 -> paypal.
_DIGIT_FIX = str.maketrans("0135", "oles")


# ---------- IOC extraction (pure functions) ----------

def _address_parts(header):
    """Returns (address, domain) from a header such as 'Name <a@b.com>'."""
    _, address = parseaddr(str(header or ""))
    address = address.strip().lower()
    if "@" not in address:
        return "", ""
    return address, address.rsplit("@", 1)[1]


def _host_of_url(url):
    """Returns the lowercase host of a URL, or '' (mailto:, tel:, #anchor have none)."""
    try:
        host = urlparse(url).hostname
    except ValueError:
        return ""
    return host.lower() if host else ""


def detect_brand(domains, tactics, brands=BRANDS):
    """Returns the brand being imitated, or None.

    A brand is reported only when the lookalike rule fired. Its keyword is then
    searched in the domains, also after fixing digit and 'rn' tricks.
    """
    if "lookalike_domain" not in tactics:
        return None
    for domain in domains:
        fixed = domain.translate(_DIGIT_FIX).replace("rn", "m")
        for brand in brands:
            keyword = brand.lower()
            if keyword in domain or keyword in fixed:
                return brand
    return None


def extract_iocs(email, report, brands=BRANDS):
    """Turns a ParsedEmail and its PhishReport into an IOCRecord (metadata only)."""
    sender_address, sender_domain = _address_parts(email.from_addr)
    _, reply_domain = _address_parts(email.reply_to)

    found = {sender_domain, reply_domain}
    for _text, href in email.links:
        found.add(_host_of_url(href))

    domains = sorted(domain for domain in found if domain)[:MAX_DOMAINS]
    tactics = sorted({finding.kind for finding in report.findings})  # kinds only, no evidence

    return IOCRecord(
        sender_address=sender_address,
        sender_domain=sender_domain,
        domains=domains,
        tactics=tactics,
        brand=detect_brand(domains, tactics, brands),
        score=report.score,
        label=report.label,
    )


# ---------- folder watcher ----------

class FolderWatcher:
    """Checks a folder for new .eml files. The caller decides when to check (polling)."""

    def __init__(self, folder, store, parse_fn=parse_eml, analyze_fn=analyze,
                 on_result=None, min_age_seconds=MIN_FILE_AGE_SECONDS,
                 max_bytes=MAX_EML_BYTES):
        self.folder = Path(folder)
        self.store = store
        self.parse_fn = parse_fn          # injected so tests can pass fakes
        self.analyze_fn = analyze_fn
        self.on_result = on_result
        self.min_age_seconds = min_age_seconds
        self.max_bytes = max_bytes
        self._seen = set()                # (name, mtime, size) of files already handled

    def check_once(self):
        """Processes every new .eml file and returns the IOCRecords that were stored."""
        try:
            paths = sorted(self.folder.iterdir())
        except OSError:
            return []
        results = []
        for path in paths:
            if path.suffix.lower() != ".eml" or not path.is_file():
                continue
            record = self._process(path)
            if record is not None:
                results.append(record)
        return results

    def _process(self, path):
        try:
            stat = path.stat()
            signature = (path.name, stat.st_mtime_ns, stat.st_size)
            if signature in self._seen:
                return None
            if stat.st_size > self.max_bytes:
                self._seen.add(signature)
                return None
            if self.min_age_seconds > 0 and time.time() - stat.st_mtime < self.min_age_seconds:
                return None               # maybe still being written; try on the next pass
            self._seen.add(signature)

            data = path.read_bytes()
            file_hash = hashlib.sha256(data).hexdigest()
            if self.store.has_hash(file_hash):
                return None

            parsed = self.parse_fn(data)
            report = self.analyze_fn(parsed)
            record = extract_iocs(parsed, report)
            if not self.store.add(record, file_hash):
                return None
        except Exception as error:        # one bad file must never stop the honeypot
            print(f"[honeypot] skipped {path.name}: {type(error).__name__}", file=sys.stderr)
            return None

        if self.on_result is not None:
            self.on_result(path.name, record)
        return record


# ---------- command line ----------

def format_stats(stats):
    def pairs(items):
        return ", ".join(f"{name} ({count})" for name, count in items) or "none"

    labels = ", ".join(f"{k} ({v})" for k, v in sorted(stats["labels"].items())) or "none"
    return "\n".join([
        f"Total emails: {stats['total']}",
        f"By label: {labels}",
        f"Top tactics: {pairs(stats['top_tactics'])}",
        f"Top impersonated brands: {pairs(stats['top_brands'])}",
        f"Top domains: {pairs(stats['top_domains'])}",
    ])


def _print_result(name, record):
    tactics = ", ".join(record.tactics) or "-"
    print(f"[{record.label}] score={record.score} {name} from {record.sender_domain or '?'}: {tactics}")


def run(folder, db_path, poll_seconds=POLL_INTERVAL_SECONDS):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    store = IOCStore(db_path)
    watcher = FolderWatcher(folder, store, on_result=_print_result)
    print(f"Watching {folder} (Ctrl+C to stop)")
    try:
        while True:
            watcher.check_once()
            time.sleep(poll_seconds)
    except KeyboardInterrupt:
        print("Stopped.")
    finally:
        store.close()


def _build_parser():
    parser = argparse.ArgumentParser(prog="python -m shield.modules.phishguard.honeypot")
    parser.add_argument("--db", default=DEFAULT_DB, help="path of the SQLite database")
    commands = parser.add_subparsers(dest="command", required=True)
    watch = commands.add_parser("watch", help="watch a folder for new .eml files")
    watch.add_argument("folder")
    commands.add_parser("stats", help="print statistics")
    export = commands.add_parser("export", help="export to .csv or .json")
    export.add_argument("output")
    return parser


def main(argv=None):
    args = _build_parser().parse_args(argv)
    if args.command == "watch":
        run(args.folder, args.db)
        return
    store = IOCStore(args.db)
    try:
        if args.command == "stats":
            print(format_stats(store.stats()))
        else:
            output = Path(args.output)
            if output.suffix.lower() == ".json":
                store.export_json(output)
            else:
                store.export_csv(output)
            print(f"Exported to {output}")
    finally:
        store.close()


if __name__ == "__main__":
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(encoding="utf-8")
    main()