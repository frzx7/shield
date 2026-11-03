"""Tests for the Pulse baseline, monitor and command line."""

from datetime import datetime, timedelta, timezone

from shield.modules.pulse.baseline import Baseline
from shield.modules.pulse.connections import Connection
from shield.modules.pulse.monitor import PulseMonitor, main

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
LEARNING_NOW = T0 + timedelta(hours=1)
AFTER_NOW = T0 + timedelta(hours=72)


def conn(ip="8.8.8.8", port=443, process="evil.exe"):
    return Connection(process=process, pid=1, remote_ip=ip, remote_port=port)


def make_monitor(conns=(), startup=None, now=AFTER_NOW, **kwargs):
    """This helper wires a monitor to fake readers; tests change `state` between passes."""
    baseline = Baseline(":memory:", now=lambda: T0)
    state = {"conns": list(conns), "startup": dict(startup or {})}
    monitor = PulseMonitor(
        baseline,
        read_connections=lambda: state["conns"],
        read_startup=lambda: state["startup"],
        now=lambda: now,
        **kwargs,
    )
    return monitor, baseline, state


def kinds(findings):
    return [f.kind for f in findings]


# ---------- Baseline ----------

def test_baseline_remembers_process_names_case_insensitively():
    baseline = Baseline(":memory:", now=lambda: T0)
    baseline.add_process("Chrome.EXE")
    assert baseline.knows_process("chrome.exe") is True
    assert baseline.knows_process("other.exe") is False


def test_baseline_learning_window():
    baseline = Baseline(":memory:", now=lambda: T0, learning_hours=48)
    assert baseline.is_learning(T0 + timedelta(hours=47)) is True
    assert baseline.is_learning(T0 + timedelta(hours=49)) is False


def test_baseline_keeps_first_learning_start_after_reopen(tmp_path):
    db = tmp_path / "pulse.db"
    first = Baseline(db, now=lambda: T0)
    first.close()
    second = Baseline(db, now=lambda: T0 + timedelta(hours=100))
    assert second.is_learning(T0 + timedelta(hours=49)) is False
    second.close()


def test_baseline_startup_snapshot_roundtrip():
    baseline = Baseline(":memory:", now=lambda: T0)
    assert baseline.load_startup() is None
    baseline.save_startup({"a": "1", "b": "2"})
    assert baseline.load_startup() == {"a": "1", "b": "2"}
    baseline.save_startup({"c": "3"})
    assert baseline.load_startup() == {"c": "3"}


# ---------- PulseMonitor: connections ----------

def test_learning_phase_learns_process_without_alarm():
    monitor, baseline, _ = make_monitor([conn()], now=LEARNING_NOW)
    assert monitor.check_once() == []
    assert baseline.knows_process("evil.exe") is True


def test_unknown_process_after_learning_is_reported():
    monitor, _, _ = make_monitor([conn()])
    assert kinds(monitor.check_once()) == ["new_process_external"]


def test_known_process_after_learning_is_quiet():
    monitor, baseline, _ = make_monitor([conn(process="chrome.exe")])
    baseline.add_process("chrome.exe")
    assert monitor.check_once() == []


def test_internal_connections_are_ignored():
    monitor, baseline, _ = make_monitor([conn(ip="192.168.1.9")])
    assert monitor.check_once() == []
    assert baseline.knows_process("evil.exe") is False


def test_unnamed_process_is_not_reported_as_new():
    monitor, _, _ = make_monitor([conn(process="?")])
    assert monitor.check_once() == []


def test_same_connection_is_reported_once():
    monitor, _, _ = make_monitor([conn()])
    assert len(monitor.check_once()) == 1
    assert monitor.check_once() == []


def test_suspicious_port_is_reported_even_while_learning():
    monitor, _, _ = make_monitor([conn(port=4444, process="chrome.exe")], now=LEARNING_NOW)
    assert kinds(monitor.check_once()) == ["suspicious_port"]


# ---------- PulseMonitor: start-up entries ----------

def test_first_startup_read_only_saves_snapshot():
    monitor, baseline, _ = make_monitor(startup={"HKCU\\Run\\a": "d1"})
    assert monitor.check_once() == []
    assert baseline.load_startup() == {"HKCU\\Run\\a": "d1"}


def test_added_startup_entry_is_reported_once():
    monitor, _, state = make_monitor(startup={"HKCU\\Run\\a": "d1"})
    monitor.check_once()
    state["startup"] = {"HKCU\\Run\\a": "d1", "HKCU\\Run\\b": "d2"}
    assert kinds(monitor.check_once()) == ["startup_added"]
    assert monitor.check_once() == []


def test_on_findings_callback_called_only_when_something_found():
    calls = []
    monitor, _, state = make_monitor([conn()], on_findings=calls.append)
    monitor.check_once()
    monitor.check_once()
    assert len(calls) == 1


# ---------- command line ----------

def test_cli_approve_adds_process_to_baseline(tmp_path):
    db = tmp_path / "pulse.db"
    main(["--db", str(db), "approve", "Chrome.exe"])
    baseline = Baseline(db)
    assert baseline.knows_process("chrome.exe") is True
    baseline.close()