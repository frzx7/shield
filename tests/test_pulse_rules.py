"""Tests for Pulse connection rules and start-up entry helpers."""

from shield.core.events import Severity
from shield.modules.pulse.connections import Connection, check_ports, is_external
from shield.modules.pulse.startup import diff_startup, read_startup_folder


def conn(ip="8.8.8.8", port=443, process="chrome.exe"):
    return Connection(process=process, pid=1, remote_ip=ip, remote_port=port)


# ---------- is_external ----------
# Note: documentation ranges (203.0.113.x) are NOT "global", so real public
# addresses are used here. They are only parsed, never contacted.

def test_public_ipv4_is_external():
    assert is_external("8.8.8.8") is True


def test_private_ranges_are_not_external():
    for ip in ("192.168.1.5", "10.0.0.1", "172.16.0.9"):
        assert is_external(ip) is False


def test_loopback_and_link_local_are_not_external():
    for ip in ("127.0.0.1", "::1", "169.254.1.1"):
        assert is_external(ip) is False


def test_ipv4_mapped_ipv6_is_unwrapped():
    assert is_external("::ffff:8.8.8.8") is True
    assert is_external("::ffff:192.168.1.1") is False


def test_invalid_address_is_not_external():
    assert is_external("not-an-ip") is False


# ---------- check_ports ----------

def test_common_port_gives_no_finding():
    assert check_ports(conn(port=443)) == []


def test_unusual_port_is_low():
    findings = check_ports(conn(port=50123))
    assert [f.kind for f in findings] == ["unusual_port"]
    assert findings[0].severity == Severity.LOW


def test_suspicious_port_is_medium():
    findings = check_ports(conn(port=4444))
    assert [f.kind for f in findings] == ["suspicious_port"]
    assert findings[0].severity == Severity.MEDIUM


def test_internal_address_is_never_flagged():
    assert check_ports(conn(ip="192.168.1.9", port=4444)) == []


# ---------- diff_startup ----------

def test_diff_added_entry_is_medium():
    findings = diff_startup({}, {"HKCU\\Run\\app": "d1"})
    assert [f.kind for f in findings] == ["startup_added"]
    assert findings[0].severity == Severity.MEDIUM


def test_diff_changed_entry_is_high():
    findings = diff_startup({"HKCU\\Run\\app": "d1"}, {"HKCU\\Run\\app": "d2"})
    assert [f.kind for f in findings] == ["startup_changed"]
    assert findings[0].severity == Severity.HIGH


def test_diff_removed_entry_gives_no_finding():
    assert diff_startup({"HKCU\\Run\\app": "d1"}, {}) == []


def test_diff_identical_gives_no_finding():
    entries = {"HKCU\\Run\\app": "d1"}
    assert diff_startup(entries, dict(entries)) == []


# ---------- read_startup_folder ----------

def test_startup_folder_entries_are_hashed_and_prefixed(tmp_path):
    (tmp_path / "a.lnk").write_bytes(b"shortcut")
    (tmp_path / "desktop.ini").write_text("[.ShellClassInfo]", encoding="utf-8")
    entries = read_startup_folder(tmp_path, "Startup")
    assert list(entries) == ["Startup\\a.lnk"]
    assert len(entries["Startup\\a.lnk"]) == 64


def test_startup_folder_digest_changes_with_content(tmp_path):
    target = tmp_path / "a.lnk"
    target.write_bytes(b"one")
    before = read_startup_folder(tmp_path, "Startup")
    target.write_bytes(b"two")
    after = read_startup_folder(tmp_path, "Startup")
    assert before != after


def test_missing_startup_folder_gives_empty_dict(tmp_path):
    assert read_startup_folder(tmp_path / "nope", "Startup") == {}