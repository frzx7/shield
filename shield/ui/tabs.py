"""Phishing and Honeypot tabs of the Shield window."""

import tkinter as tk
from collections import Counter
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from shield.core.storage import IOCStore
from shield.modules.phishguard.honeypot import POLL_INTERVAL_SECONDS, FolderWatcher
from shield.modules.phishguard.scoring import analyze

HONEYPOT_DB = "shield_honeypot.db"
HONEYPOT_MS = int(POLL_INTERVAL_SECONDS * 1000)
MAX_EML_BYTES = 5 * 1024 * 1024
MAX_ROWS = 500

SEVERITY_COLORS = {"HIGH": "#ffd6d6", "MEDIUM": "#fff0c2", "LOW": "#e6f0ff"}
LABEL_COLORS = {
    "safe": "#d9f2d9",
    "suspicious": "#fff0c2",
    "likely phishing": "#ffd6d6",
}


def _tag(label):
    """This helper turns a label into a safe tag name."""
    return label.replace(" ", "_")


class PhishingTab(ttk.Frame):
    """This tab analyzes one .eml file that the user picks."""

    def __init__(self, parent):
        super().__init__(parent)
        self._findings = {}  # row id -> Finding

        top = ttk.Frame(self)
        ttk.Button(top, text="Choose .eml file...", command=self.choose_file).pack(
            side="left"
        )
        self.file_label = ttk.Label(top, text="No file selected")
        self.file_label.pack(side="left", padx=10)

        self.verdict = tk.Label(
            self, text="", anchor="w", padx=8, pady=6, font=("Segoe UI", 13, "bold")
        )

        self.tree = ttk.Treeview(
            self,
            columns=("severity", "kind", "evidence"),
            show="headings",
            height=9,
            selectmode="browse",
        )
        for name, width in (("severity", 90), ("kind", 200), ("evidence", 420)):
            self.tree.heading(name, text=name.capitalize())
            self.tree.column(name, width=width, anchor="w")
        for severity, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(severity, background=color)
        self.tree.bind("<<TreeviewSelect>>", lambda event: self._show_selected())

        self.detail = tk.Text(self, height=6, wrap="word", state="disabled")

        top.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        self.verdict.grid(row=1, column=0, sticky="ew")
        self.tree.grid(row=2, column=0, sticky="nsew", pady=6)
        self.detail.grid(row=3, column=0, sticky="ew")
        self.rowconfigure(2, weight=1)
        self.columnconfigure(0, weight=1)

    def choose_file(self):
        """This method asks for a file and shows the analysis result."""
        chosen = filedialog.askopenfilename(
            filetypes=[("Email files", "*.eml"), ("All files", "*.*")]
        )
        if not chosen:
            return
        path = Path(chosen)
        try:
            if path.stat().st_size > MAX_EML_BYTES:
                messagebox.showwarning("Shield", "The file is larger than 5 MB.")
                return
            report = analyze(path)
        except OSError as error:
            messagebox.showerror(
                "Shield", f"Could not read the file ({type(error).__name__})."
            )
            return
        self.file_label.configure(text=path.name)
        self.show_report(report)

    def show_report(self, report):
        """This method fills the verdict, the table and the detail box."""
        self.tree.delete(*self.tree.get_children())
        self._findings.clear()
        self.verdict.configure(
            text=f"Score {report.score}/100: {report.label}",
            bg=LABEL_COLORS.get(report.label, "#eeeeee"),
        )
        for index, finding in enumerate(report.findings):
            self._findings[index] = finding
            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=(finding.severity.name, finding.kind, finding.evidence[:120]),
                tags=(finding.severity.name,),
            )
        if report.findings:
            self._set_detail("Select a row to read the explanation.")
        else:
            self._set_detail("No suspicious signs were found.")

    def _show_selected(self):
        selection = self.tree.selection()
        if selection:
            self._set_detail(self._findings[int(selection[0])].rule_explanation)

    def _set_detail(self, text):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.configure(state="disabled")


class HoneypotTab(ttk.Frame):
    """This tab watches a decoy folder and analyzes every new .eml that appears."""

    def __init__(self, parent, db_path=HONEYPOT_DB):
        super().__init__(parent)
        self._db_path = db_path
        self._folder = None
        self._store = None
        self._watcher = None
        self._job = None
        self._counts = Counter()

        top = ttk.Frame(self)
        ttk.Button(top, text="Choose folder...", command=self.choose_folder).pack(
            side="left"
        )
        self.folder_label = ttk.Label(top, text="No folder selected")
        self.folder_label.pack(side="left", padx=10)
        self.stop_button = ttk.Button(top, text="Stop", command=self.stop, state="disabled")
        self.stop_button.pack(side="right")
        self.start_button = ttk.Button(top, text="Start", command=self.start, state="disabled")
        self.start_button.pack(side="right", padx=6)

        columns = ("time", "file", "label", "score", "sender", "tactics")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=12)
        widths = (70, 160, 110, 50, 150, 280)
        for name, width in zip(columns, widths):
            self.tree.heading(name, text=name.capitalize())
            self.tree.column(name, width=width, anchor="w")
        for label, color in LABEL_COLORS.items():
            self.tree.tag_configure(_tag(label), background=color)

        self.status = ttk.Label(self, text="Choose a folder, then press Start.")

        top.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        self.tree.grid(row=1, column=0, sticky="nsew")
        self.status.grid(row=2, column=0, sticky="w", pady=(6, 0))
        self.rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)

    @property
    def running(self):
        return self._watcher is not None

    def choose_folder(self):
        """This method lets the user pick the decoy folder."""
        chosen = filedialog.askdirectory()
        if not chosen:
            return
        self._folder = Path(chosen)
        self.folder_label.configure(text=str(self._folder))
        if not self.running:
            self.start_button.configure(state="normal")

    def start(self):
        """This method opens the database and starts polling the folder."""
        if self.running or self._folder is None:
            return
        self._store = IOCStore(self._db_path)
        self._watcher = FolderWatcher(
            self._folder, self._store, on_result=self._on_result
        )
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self._update_status()
        self._tick()

    def stop(self):
        """This method stops polling and closes the database."""
        if self._job is not None:
            self.after_cancel(self._job)
            self._job = None
        if self._store is not None:
            self._store.close()
        self._store = None
        self._watcher = None
        self.stop_button.configure(state="disabled")
        if self._folder is not None:
            self.start_button.configure(state="normal")
        self.status.configure(text="Stopped.")

    def close(self):
        """This method is called when the window closes."""
        if self.running:
            self.stop()

    def _tick(self):
        if self._watcher is None:
            return
        self._watcher.check_once()
        self._job = self.after(HONEYPOT_MS, self._tick)

    def _on_result(self, name, record):
        self._counts[record.label] += 1
        self.tree.insert(
            "",
            0,
            values=(
                datetime.now().strftime("%H:%M:%S"),
                name,
                record.label,
                record.score,
                record.sender_domain or "?",
                ", ".join(record.tactics) or "-",
            ),
            tags=(_tag(record.label),),
        )
        rows = self.tree.get_children()
        if len(rows) > MAX_ROWS:
            self.tree.delete(rows[-1])
        self._update_status()

    def _update_status(self):
        if self._store is None:
            return
        session = ", ".join(
            f"{label} {self._counts[label]}" for label in LABEL_COLORS
        )
        self.status.configure(
            text=(
                f"Watching. Database: {self._store.count()} emails. "
                f"This session: {session}. "
                "Files whose content is already in the database are skipped."
            )
        )