import hashlib
import tkinter as tk

from collections.abc import Callable
from shield.ai.factory import get_default_provider
from shield.core.events import Finding
from shield.modules.dlp.detectors import scan
from shield.ai.factory import get_default_provider

POLL_INTERVAL_MS = 1000

class ClipboardWatcher:
    """Checks clipboard text for sensitive data. Never stores the text itself."""

    def __init__(
        self,
        read_clipboard: Callable[[], str | None],
        on_findings: Callable[[list[Finding]], None],
    ):
        self._read = read_clipboard
        self._on_findings = on_findings
        self._last_digest = None  # When the same text is copied, program doesn't check the same thing again.

    def check_once(self) -> None:
        text = self._read()
        if not text:
            return
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest == self._last_digest:
            return  # same content as last time, already checked
        self._last_digest = digest
        findings = scan(text)
        if findings:
            self._on_findings(findings)


def run() -> None:
    root = tk.Tk()
    root.withdraw()  # hide the empty window
    #provider = NullProvider()

    def read_clipboard() -> str | None:
        try:
            return root.clipboard_get()
        except tk.TclError:  # clipboard empty or holds a non-text item
            return None

    def report(findings: list[Finding]) -> None:
        provider = get_default_provider()
        for finding in findings:
            print(f"[{finding.severity.name}] {finding.kind}: {finding.evidence}")
            print(f" {provider.explain(finding)}")

    watcher = ClipboardWatcher(read_clipboard, report)

    def poll() -> None:
        watcher.check_once()
        root.after(POLL_INTERVAL_MS, poll)

    poll()
    print("Shield is watching the clipboard. Press Ctrl+C to stop.")
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("Stopped.")


if __name__ == "__main__":
    run()