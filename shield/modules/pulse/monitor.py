"""PulseMonitor: ties connections, the baseline and start-up entries together."""

import argparse
import sys
import time
from datetime import datetime, timezone

from shield.ai.null_provider import NullProvider
from shield.core.events import Finding, Severity
from shield.modules.pulse.baseline import LEARNING_HOURS, Baseline
from shield.modules.pulse.connections import (
    check_ports,
    is_external,
    read_connections,
)
from shield.modules.pulse.startup import diff_startup, read_startup_entries

POLL_INTERVAL_SECONDS = 5.0
DEFAULT_DB = "shield_pulse.db"


def _utc_now():
    return datetime.now(timezone.utc)


class PulseMonitor:
    """Checks the machine once per call. The caller decides when to check (polling)."""

    def __init__(self, baseline, read_connections=read_connections,
                 read_startup=read_startup_entries, on_findings=None, now=None):
        self.baseline = baseline
        self.read_connections = read_connections   # injected so tests can pass fakes
        self.read_startup = read_startup
        self.on_findings = on_findings
        self.now = now or _utc_now
        self._reported = set()                     # (process, ip, port) already handled
        self._warned = set()                       # readers whose failure was already printed

    def check_once(self):
        findings = self._check_connections() + self._check_startup()
        if findings and self.on_findings is not None:
            self.on_findings(findings)
        return findings

    def _safe_read(self, reader, fallback):
        """Runs a reader; on failure prints the error type once and returns the fallback."""
        try:
            return reader()
        except Exception as error:
            if reader not in self._warned:
                self._warned.add(reader)
                print(f"[pulse] reader failed: {type(error).__name__}", file=sys.stderr)
            return fallback

    def _check_connections(self):
        findings = []
        learning = self.baseline.is_learning(self.now())
        for conn in self._safe_read(self.read_connections, []):
            if not is_external(conn.remote_ip):
                continue
            key = (conn.process, conn.remote_ip, conn.remote_port)
            if key in self._reported:
                continue
            self._reported.add(key)

            findings.extend(check_ports(conn))        # port rules always apply
            if conn.process == "?":
                continue                              # an unreadable name cannot be judged
            if learning:
                self.baseline.add_process(conn.process)
            elif not self.baseline.knows_process(conn.process):
                findings.append(Finding(
                    "new_process_external", Severity.MEDIUM,
                    f"{conn.process} -> {conn.remote_ip}:{conn.remote_port}",
                    f"{conn.process} was not seen using the internet during the learning "
                    f"period and has now connected to {conn.remote_ip}:{conn.remote_port}. "
                    "If you recognize the program, run the 'approve' command for it.",
                ))
        return findings

    def _check_startup(self):
        current = self._safe_read(self.read_startup, None)
        if current is None:
            return []                                 # unreadable is not the same as empty
        saved = self.baseline.load_startup()
        findings = [] if saved is None else diff_startup(saved, current)
        self.baseline.save_startup(current)           # a change is reported once, then accepted
        return findings


def _print_findings(findings):
    explainer = NullProvider()
    for finding in findings:
        print(f"[{finding.severity.name}] {finding.kind}: {finding.evidence}")
        print(f"    {explainer.explain(finding)}")


def run(db_path, learning_hours, poll_seconds=POLL_INTERVAL_SECONDS):
    baseline = Baseline(db_path, learning_hours=learning_hours)
    monitor = PulseMonitor(baseline, on_findings=_print_findings)
    print(f"Pulse is watching (learning period: {learning_hours} h). Ctrl+C to stop.")
    try:
        while True:
            monitor.check_once()
            time.sleep(poll_seconds)
    except KeyboardInterrupt:
        print("Stopped.")
    finally:
        baseline.close()


def _scan():
    """One-time list of external connections with port flags; no baseline needed."""
    count = 0
    for conn in sorted(read_connections(), key=lambda c: c.process):
        if not is_external(conn.remote_ip):
            continue
        count += 1
        flags = ", ".join(f.kind for f in check_ports(conn)) or "-"
        print(f"{conn.process} -> {conn.remote_ip}:{conn.remote_port}  [{flags}]")
    if count == 0:
        print("No external connections.")


def _build_parser():
    parser = argparse.ArgumentParser(prog="python -m shield.modules.pulse")
    parser.add_argument("--db", default=DEFAULT_DB, help="path of the SQLite baseline")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("scan", help="list current external connections once")
    watch = commands.add_parser("watch", help="monitor continuously")
    watch.add_argument("--learning-hours", type=float, default=LEARNING_HOURS)
    approve = commands.add_parser("approve", help="mark a program as normal")
    approve.add_argument("name")
    return parser


def main(argv=None):
    args = _build_parser().parse_args(argv)
    if args.command == "scan":
        _scan()
    elif args.command == "approve":
        baseline = Baseline(args.db)
        try:
            baseline.add_process(args.name)
            print(f"Approved: {args.name.lower()}")
        finally:
            baseline.close()
    else:
        run(args.db, args.learning_hours)