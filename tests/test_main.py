"""Tests for the Shield entry point (python -m shield)."""

import pytest

from shield.__main__ import main


def test_default_opens_the_window():
    calls = []
    assert main([], launch=lambda: calls.append("open")) == 0
    assert calls == ["open"]


def test_info_prints_the_mode_and_does_not_open_the_window(monkeypatch):
    monkeypatch.setattr("shield.__main__.detect_mode", lambda: "lite")
    lines, calls = [], []
    code = main(["--info"], launch=lambda: calls.append("open"), out=lines.append)
    assert code == 0
    assert lines == ["Detected mode: lite"]
    assert calls == []


def test_window_error_is_reported_not_raised():
    def broken():
        raise RuntimeError("no display")

    lines = []
    assert main([], launch=broken, out=lines.append) == 1
    assert "Could not open the window" in lines[0]
    assert "RuntimeError" in lines[0]


def test_unknown_argument_is_rejected():
    with pytest.raises(SystemExit):
        main(["--banana"])