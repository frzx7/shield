"""UI controller: queues alerts and fetches AI explanations in the background.

This module has no tkinter code, so it can be tested without a window.
The window only calls handle_findings(), drain() and set_ai_enabled().
"""

import itertools
import queue
import threading
from dataclasses import dataclass

from shield.ai.factory import MODEL_BY_MODE, choose_provider
from shield.core.events import Finding


@dataclass(frozen=True)
class NewAlert:
    """This event announces a finding; the rule text is already in the finding."""

    alert_id: int
    source: str
    finding: Finding


@dataclass(frozen=True)
class Explained:
    """This event carries the AI text for an alert that was announced earlier."""

    alert_id: int
    text: str


def run_in_thread(job):
    """This runner executes the job in a background thread."""
    threading.Thread(target=job, daemon=True).start()


class ShieldController:
    """This class connects the watchers, the AI provider and the window."""

    def __init__(
        self,
        mode,
        ai_enabled=True,
        provider_factory=choose_provider,
        run_async=run_in_thread,
    ):
        self.mode = mode
        self.ai_available = mode in MODEL_BY_MODE
        self.ai_enabled = bool(ai_enabled) and self.ai_available
        self._provider_factory = provider_factory
        self._run_async = run_async
        self._queue = queue.Queue()
        self._ids = itertools.count(1)

    def set_ai_enabled(self, flag):
        """This method switches AI on or off; lite mode can never switch it on."""
        self.ai_enabled = bool(flag) and self.ai_available
        return self.ai_enabled

    def handle_findings(self, source, findings):
        """This method queues each finding at once and asks the AI in the background."""
        for finding in findings:
            alert_id = next(self._ids)
            self._queue.put(NewAlert(alert_id, source, finding))
            if self.ai_enabled:
                self._run_async(lambda f=finding, i=alert_id: self._explain(i, f))

    def drain(self):
        """This method returns all queued events and empties the queue."""
        events = []
        while True:
            try:
                events.append(self._queue.get_nowait())
            except queue.Empty:
                return events

    def _explain(self, alert_id, finding):
        """This method runs in the background; errors and blank answers are ignored."""
        try:
            provider = self._provider_factory(self.mode, True)
            text = provider.explain(finding)
        except Exception:
            return
        if isinstance(text, str) and text.strip():
            self._queue.put(Explained(alert_id, text.strip()))