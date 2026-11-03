"""Reading Windows start-up entries and detecting changes between two snapshots.

Only a sha256 fingerprint of each entry is kept, never the command text.
Nothing listed here is ever executed.
"""

import hashlib
import os
import sys
from pathlib import Path

from shield.core.events import Finding, Severity

if sys.platform == "win32":
    import winreg

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
MAX_HASH_BYTES = 5 * 1024 * 1024
IGNORED_FILES = {"desktop.ini"}


def _digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_startup_folder(folder, label):
    """Returns {'label\\\\file name': sha256 of the file content} for one folder."""
    entries = {}
    folder = Path(folder)
    try:
        paths = sorted(folder.iterdir())
    except OSError:
        return entries
    for path in paths:
        if not path.is_file() or path.name.lower() in IGNORED_FILES:
            continue
        try:
            if path.stat().st_size > MAX_HASH_BYTES:
                value = _digest(f"size:{path.stat().st_size}")
            else:
                value = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            continue
        entries[f"{label}\\{path.name}"] = value
    return entries


def _read_run_key(label, hive):
    """Returns {'label\\\\value name': sha256 of the command} for one Run key."""
    entries = {}
    if sys.platform != "win32":
        return entries
    try:
        with winreg.OpenKey(hive, RUN_KEY) as key:
            index = 0
            while True:
                try:
                    name, value, _type = winreg.EnumValue(key, index)
                except OSError:  # no more values
                    break
                entries[f"{label}\\{name}"] = _digest(str(value))
                index += 1
    except OSError:  # key missing or not readable
        pass
    return entries


def read_startup_entries():
    """Collects Run keys (user and machine) and both Startup folders."""
    entries = {}
    if sys.platform == "win32":
        entries.update(_read_run_key("HKCU", winreg.HKEY_CURRENT_USER))
        entries.update(_read_run_key("HKLM", winreg.HKEY_LOCAL_MACHINE))
    suffix = Path("Microsoft/Windows/Start Menu/Programs/Startup")
    for variable, label in (("APPDATA", "Startup"), ("PROGRAMDATA", "CommonStartup")):
        base = os.environ.get(variable)
        if base:
            entries.update(read_startup_folder(Path(base) / suffix, label))
    return entries


def diff_startup(old, new):
    """Compares two snapshots. New entries are MEDIUM, changed entries are HIGH."""
    findings = []
    for entry in sorted(new):
        if entry not in old:
            findings.append(Finding(
                "startup_added", Severity.MEDIUM, entry,
                f"A new program was set to start automatically: {entry}. "
                "Malware often uses start-up entries to survive a restart.",
            ))
        elif old[entry] != new[entry]:
            findings.append(Finding(
                "startup_changed", Severity.HIGH, entry,
                f"The start-up entry {entry} now has different content than before.",
            ))
    return findings