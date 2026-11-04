"""Tests for the default provider helper and the SHIELD_AI switch."""

from shield.ai import factory
from shield.ai.null_provider import NullProvider
from shield.ai.ollama_provider import OllamaProvider

BOTH = ("llama3.1:8b", "llama3.2:3b")


def setup(monkeypatch, mode, installed=BOTH):
    """This helper fakes the machine mode and the installed models."""
    monkeypatch.setattr(factory, "detect_mode", lambda: mode)
    monkeypatch.setattr(factory, "list_installed_models", lambda: list(installed))


def test_default_provider_is_null_in_lite_mode(monkeypatch):
    setup(monkeypatch, "lite")
    monkeypatch.delenv("SHIELD_AI", raising=False)
    assert isinstance(factory.get_default_provider(), NullProvider)


def test_default_provider_is_ollama_in_standard_mode(monkeypatch):
    setup(monkeypatch, "standard")
    monkeypatch.delenv("SHIELD_AI", raising=False)
    assert isinstance(factory.get_default_provider(), OllamaProvider)


def test_env_switch_off_disables_ai(monkeypatch):
    setup(monkeypatch, "full")
    monkeypatch.setenv("SHIELD_AI", "off")
    assert isinstance(factory.get_default_provider(), NullProvider)


def test_env_switch_on_keeps_ai(monkeypatch):
    setup(monkeypatch, "full")
    monkeypatch.setenv("SHIELD_AI", "on")
    assert isinstance(factory.get_default_provider(), OllamaProvider)


def test_default_provider_is_null_when_no_model_is_installed(monkeypatch):
    setup(monkeypatch, "full", installed=())
    monkeypatch.delenv("SHIELD_AI", raising=False)
    assert isinstance(factory.get_default_provider(), NullProvider)