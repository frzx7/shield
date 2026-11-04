"""Tests for the UI controller (logic only, no tkinter)."""

from shield.ai.null_provider import NullProvider
from shield.core.events import Finding, Severity
from shield.ui.controller import Explained, NewAlert, ShieldController


def make_finding(kind="aws_access_key"):
    """This helper builds a small Finding for the tests."""
    return Finding(kind, Severity.HIGH, "AKIA****", "Rule text.")


class FakeProvider:
    """This fake provider returns a fixed answer or raises a fixed error."""

    def __init__(self, answer="AI text", error=None):
        self.answer = answer
        self.error = error

    def explain(self, finding):
        if self.error is not None:
            raise self.error
        return self.answer


def fake_factory(answer="AI text", error=None):
    """This helper builds a provider factory that never touches the network."""

    def factory(mode, ai_enabled):
        if ai_enabled:
            return FakeProvider(answer, error)
        return NullProvider()

    return factory


def run_now(job):
    """This runner executes the background job immediately, so tests stay simple."""
    job()


def make_controller(mode="standard", **kwargs):
    kwargs.setdefault("provider_factory", fake_factory())
    return ShieldController(mode, run_async=run_now, **kwargs)


def test_new_alert_is_queued_with_source_and_finding():
    controller = make_controller()
    controller.handle_findings("dlp", [make_finding()])
    first = controller.drain()[0]
    assert isinstance(first, NewAlert)
    assert first.source == "dlp"
    assert first.finding.kind == "aws_access_key"


def test_ai_text_arrives_after_the_new_alert():
    controller = make_controller()
    controller.handle_findings("dlp", [make_finding()])
    events = controller.drain()
    assert isinstance(events[0], NewAlert)
    assert isinstance(events[1], Explained)
    assert events[1].text == "AI text"
    assert events[1].alert_id == events[0].alert_id


def test_no_explained_event_when_ai_is_off():
    controller = make_controller(ai_enabled=False)
    controller.handle_findings("dlp", [make_finding()])
    assert len(controller.drain()) == 1


def test_each_alert_gets_a_unique_id():
    controller = make_controller(ai_enabled=False)
    controller.handle_findings("pulse", [make_finding("a"), make_finding("b")])
    events = controller.drain()
    assert len(events) == 2
    assert events[0].alert_id != events[1].alert_id


def test_toggle_ai_off_stops_ai_text():
    controller = make_controller()
    assert controller.set_ai_enabled(False) is False
    controller.handle_findings("dlp", [make_finding()])
    assert len(controller.drain()) == 1


def test_toggle_ai_on_again():
    controller = make_controller(ai_enabled=False)
    assert controller.set_ai_enabled(True) is True
    controller.handle_findings("dlp", [make_finding()])
    assert len(controller.drain()) == 2


def test_lite_mode_cannot_enable_ai():
    controller = ShieldController("lite", run_async=run_now)
    assert controller.ai_available is False
    assert controller.set_ai_enabled(True) is False
    assert controller.ai_enabled is False


def test_provider_error_does_not_crash():
    controller = make_controller(provider_factory=fake_factory(error=RuntimeError("boom")))
    controller.handle_findings("dlp", [make_finding()])
    events = controller.drain()
    assert len(events) == 1
    assert isinstance(events[0], NewAlert)


def test_blank_ai_answer_is_ignored():
    controller = make_controller(provider_factory=fake_factory(answer="   "))
    controller.handle_findings("dlp", [make_finding()])
    assert len(controller.drain()) == 1


def test_drain_empties_the_queue():
    controller = make_controller(ai_enabled=False)
    controller.handle_findings("dlp", [make_finding()])
    assert len(controller.drain()) == 1
    assert controller.drain() == []