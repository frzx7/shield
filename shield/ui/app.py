"""Shield main window (tkinter/ttk). Step 2: the Alerts tab with DLP and Pulse."""

import tkinter as tk
from datetime import datetime
from tkinter import ttk

from shield.ai.factory import ai_enabled_from_env, choose_provider_auto
from shield.core.config import detect_mode
from shield.core.events import Finding, Severity
from shield.modules.dlp.watcher import ClipboardWatcher
from shield.modules.pulse.baseline import Baseline
from shield.modules.pulse.monitor import POLL_INTERVAL_SECONDS, PulseMonitor
from shield.ui.controller import Explained, NewAlert, ShieldController
from shield.ui.tabs import SEVERITY_COLORS, HoneypotTab, PhishingTab

DRAIN_MS = 200
CLIPBOARD_MS = 1000
PULSE_MS = int(POLL_INTERVAL_SECONDS * 1000)
PULSE_DB = "shield_pulse.db"
UI_AI_TIMEOUT = 45.0
MAX_ROWS = 500

COLUMNS = (
    ("time", 70),
    ("source", 70),
    ("severity", 80),
    ("kind", 170),
    ("evidence", 260),
    ("ai", 40),
)


class AlertsTab(ttk.Frame):
    """This tab shows the alert table and the explanation of the selected row."""

    def __init__(self, parent):
        super().__init__(parent)
        self._alerts = {}  # alert_id -> {"finding": Finding, "ai": str or None}

        self.tree = ttk.Treeview(
            self,
            columns=[name for name, _ in COLUMNS],
            show="headings",
            height=12,
            selectmode="browse",
        )
        for name, width in COLUMNS:
            self.tree.heading(name, text=name.capitalize())
            self.tree.column(name, width=width, anchor="w")
        for severity, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(severity, background=color)

        scroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.detail = tk.Text(self, height=7, wrap="word", state="disabled")

        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        self.detail.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", lambda event: self._show_selected())

    def add(self, alert):
        """This method adds a new row at the top of the table."""
        finding = alert.finding
        self._alerts[alert.alert_id] = {"finding": finding, "ai": None}
        self.tree.insert(
            "",
            0,
            iid=str(alert.alert_id),
            values=(
                datetime.now().strftime("%H:%M:%S"),
                alert.source,
                finding.severity.name,
                finding.kind,
                finding.evidence[:80],
                "",
            ),
            tags=(finding.severity.name,),
        )
        rows = self.tree.get_children()
        if len(rows) > MAX_ROWS:
            oldest = rows[-1]
            self.tree.delete(oldest)
            self._alerts.pop(int(oldest), None)

    def set_ai(self, explained):
        """This method attaches the AI text to its row (if the row still exists)."""
        entry = self._alerts.get(explained.alert_id)
        if entry is None:
            return
        # When Ollama is unavailable the provider returns the rule text again.
        # That is not an AI answer, so the row is left unmarked.
        if explained.text == entry["finding"].rule_explanation:
            return
        entry["ai"] = explained.text
        self.tree.set(str(explained.alert_id), "ai", "✓")
        if self.tree.selection() == (str(explained.alert_id),):
            self._show_selected()

    def clear(self):
        """This method removes all rows."""
        self.tree.delete(*self.tree.get_children())
        self._alerts.clear()
        self._set_detail("")

    def _show_selected(self):
        selection = self.tree.selection()
        if not selection:
            return
        entry = self._alerts.get(int(selection[0]))
        if entry is None:
            return
        text = entry["finding"].rule_explanation
        if entry["ai"]:
            text += "\n\nAI explanation:\n" + entry["ai"]
        self._set_detail(text)

    def _set_detail(self, text):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.configure(state="disabled")


class ShieldApp:
    """This class builds the window and connects watchers, controller and tabs."""

    def __init__(self, root):
        self.root = root
        root.title("Shield")
        root.geometry("860x520")

        self.mode = detect_mode()
        self.controller = ShieldController(
            self.mode,
            ai_enabled=ai_enabled_from_env(),
            provider_factory=lambda mode, enabled: choose_provider_auto(
                mode, enabled, timeout=UI_AI_TIMEOUT
            ),
        )

        self._build_header()
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.alerts_tab = AlertsTab(self.notebook)
        self.notebook.add(self.alerts_tab, text="Alerts")
        self.phishing_tab = PhishingTab(self.notebook)
        self.notebook.add(self.phishing_tab, text="Phishing")
        self.honeypot_tab = HoneypotTab(self.notebook)
        self.notebook.add(self.honeypot_tab, text="Honeypot")

        self.clipboard = ClipboardWatcher(
            self._read_clipboard,
            lambda findings: self.controller.handle_findings("dlp", findings),
        )
        self.baseline = Baseline(PULSE_DB)
        self.pulse = PulseMonitor(
            self.baseline,
            on_findings=lambda findings: self.controller.handle_findings(
                "pulse", findings
            ),
        )

        root.protocol("WM_DELETE_WINDOW", self._on_close)
        root.after(DRAIN_MS, self._drain)
        root.after(CLIPBOARD_MS, self._poll_clipboard)
        root.after(PULSE_MS, self._poll_pulse)

    def _build_header(self):
        header = ttk.Frame(self.root)
        header.pack(fill="x", padx=8, pady=8)
        ttk.Label(header, text=f"Mode: {self.mode}").pack(side="left")

        self.ai_var = tk.BooleanVar(value=self.controller.ai_enabled)
        ai_box = ttk.Checkbutton(
            header,
            text="AI explanations (needs Ollama)",
            variable=self.ai_var,
            command=self._toggle_ai,
        )
        if not self.controller.ai_available:
            ai_box.configure(state="disabled", text="AI unavailable in lite mode")
        ai_box.pack(side="left", padx=16)

        ttk.Button(header, text="Clear", command=self._clear).pack(side="right")
        ttk.Button(header, text="Test alert", command=self._test_alert).pack(
            side="right", padx=6
        )

    def _toggle_ai(self):
        self.ai_var.set(self.controller.set_ai_enabled(self.ai_var.get()))

    def _clear(self):
        self.alerts_tab.clear()

    def _test_alert(self):
        finding = Finding(
            "test_alert",
            Severity.LOW,
            "demo evidence",
            "This is a demo alert that checks the window and the AI explanation.",
        )
        self.controller.handle_findings("test", [finding])

    def _read_clipboard(self):
        try:
            return self.root.clipboard_get()
        except tk.TclError:
            return None

    def _poll_clipboard(self):
        self.clipboard.check_once()
        self.root.after(CLIPBOARD_MS, self._poll_clipboard)

    def _poll_pulse(self):
        self.pulse.check_once()
        self.root.after(PULSE_MS, self._poll_pulse)

    def _drain(self):
        for event in self.controller.drain():
            if isinstance(event, NewAlert):
                self.alerts_tab.add(event)
            elif isinstance(event, Explained):
                self.alerts_tab.set_ai(event)
        self.root.after(DRAIN_MS, self._drain)
    
    def _on_close(self):
        self.honeypot_tab.close()
        self.baseline.close()
        self.root.destroy()


def main():
    """This function starts the Shield window."""
    root = tk.Tk()
    ShieldApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()