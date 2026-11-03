"""Tests for the default provider helper and the SHIELD_AI switch."""

from shield.ai import factory
from shield.ai.null_provider import NullProvider
from shield.ai.ollama_provider import OllamaProvider


def test_default_provider_is_null_in_lite_mode(monkeypatch):
    monkeypatch.setattr(factory, "detect_mode", lambda: "lite")
    monkeypatch.delenv("SHIELD_AI", raising=False)
    assert isinstance(factory.get_default_provider(), NullProvider)


def test_default_provider_is_ollama_in_standard_mode(monkeypatch):
    monkeypatch.setattr(factory, "detect_mode", lambda: "standard")
    monkeypatch.delenv("SHIELD_AI", raising=False)
    assert isinstance(factory.get_default_provider(), OllamaProvider)


def test_env_switch_off_disables_ai(monkeypatch):
    monkeypatch.setattr(factory, "detect_mode", lambda: "full")
    monkeypatch.setenv("SHIELD_AI", "off")
    assert isinstance(factory.get_default_provider(), NullProvider)


def test_env_switch_on_keeps_ai(monkeypatch):
    monkeypatch.setattr(factory, "detect_mode", lambda: "full")
    monkeypatch.setenv("SHIELD_AI", "on")
    assert isinstance(factory.get_default_provider(), OllamaProvider)