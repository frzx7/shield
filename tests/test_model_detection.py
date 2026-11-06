"""Tests for installed-model detection and the automatic provider choice."""

import pytest

from shield.ai import factory
from shield.ai.factory import choose_provider_auto, pick_model
from shield.ai.null_provider import NullProvider
from shield.ai.ollama_provider import OllamaProvider, list_installed_models

BOTH = ["llama3.1:8b", "llama3.2:3b"]


class FakeGet:
    """This fake replaces the real GET request and records how it was used."""

    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = []

    def __call__(self, url, timeout):
        self.calls.append((url, timeout))
        if self.error is not None:
            raise self.error
        return self.result


def patch_installed(monkeypatch, names):
    """This helper makes the factory believe that exactly these models are installed."""
    monkeypatch.setattr(factory, "list_installed_models", lambda: list(names))


# ---------- list_installed_models ----------

def test_lists_model_names():
    get = FakeGet(result={"models": [{"name": "llama3.2:3b"}, {"name": "llama3.1:8b"}]})
    assert list_installed_models(get_fn=get) == ["llama3.2:3b", "llama3.1:8b"]
    assert get.calls[0][0].endswith("/api/tags")


def test_listing_returns_empty_list_on_error():
    assert list_installed_models(get_fn=FakeGet(error=ConnectionError("down"))) == []


@pytest.mark.parametrize("bad", [{}, {"models": "x"}, None])
def test_listing_returns_empty_list_on_broken_response(bad):
    assert list_installed_models(get_fn=FakeGet(result=bad)) == []


def test_listing_ignores_entries_without_a_name():
    get = FakeGet(result={"models": [{"name": "a"}, 5, {"size": 1}]})
    assert list_installed_models(get_fn=get) == ["a"]


# ---------- pick_model ----------

def test_full_prefers_the_big_model():
    assert pick_model("full", BOTH) == "llama3.1:8b"


def test_full_falls_back_to_the_small_model():
    assert pick_model("full", ["llama3.2:3b"]) == "llama3.2:3b"


def test_standard_uses_the_small_model():
    assert pick_model("standard", BOTH) == "llama3.2:3b"


def test_standard_does_not_use_the_big_model_alone():
    assert pick_model("standard", ["llama3.1:8b"]) is None


def test_nothing_installed_gives_none():
    assert pick_model("full", []) is None


def test_lite_and_unknown_modes_give_none():
    assert pick_model("lite", BOTH) is None
    assert pick_model("banana", BOTH) is None


# ---------- choose_provider_auto ----------

def test_auto_full_uses_8b_when_installed(monkeypatch):
    patch_installed(monkeypatch, BOTH)
    provider = choose_provider_auto("full")
    assert isinstance(provider, OllamaProvider)
    assert provider.model == "llama3.1:8b"


def test_auto_full_falls_back_to_3b(monkeypatch):
    patch_installed(monkeypatch, ["llama3.2:3b"])
    provider = choose_provider_auto("full")
    assert isinstance(provider, OllamaProvider)
    assert provider.model == "llama3.2:3b"


def test_auto_without_models_gives_null_provider(monkeypatch):
    patch_installed(monkeypatch, [])
    assert isinstance(choose_provider_auto("full"), NullProvider)


def test_auto_with_ai_off_never_asks_ollama(monkeypatch):
    def boom():
        raise AssertionError("must not be called")

    monkeypatch.setattr(factory, "list_installed_models", boom)
    assert isinstance(choose_provider_auto("full", ai_enabled=False), NullProvider)


def test_auto_lite_gives_null_provider(monkeypatch):
    patch_installed(monkeypatch, BOTH)
    assert isinstance(choose_provider_auto("lite"), NullProvider)


def test_auto_passes_the_timeout(monkeypatch):
    patch_installed(monkeypatch, BOTH)
    provider = choose_provider_auto("full", timeout=45.0)
    assert isinstance(provider, OllamaProvider)
    assert provider.timeout == 45.0