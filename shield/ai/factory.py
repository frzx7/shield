"""Chooses which explanation provider to use."""

import os

from shield.ai.null_provider import NullProvider
from shield.ai.ollama_provider import (
    DEFAULT_TIMEOUT,
    OllamaProvider,
    list_installed_models,
)
from shield.ai.provider import AIProvider
from shield.core.config import detect_mode

# The first model of each list is the preferred one. Modes that are missing
# here (such as "lite") never use AI.
MODEL_PREFERENCES = {
    "standard": ("llama3.2:3b",),
    "full": ("llama3.1:8b", "llama3.2:3b"),
}
MODEL_BY_MODE = {mode: models[0] for mode, models in MODEL_PREFERENCES.items()}


def choose_provider(mode: str, ai_enabled: bool = True) -> AIProvider:
    """This function returns NullProvider unless AI is on and the mode has a model."""
    if not ai_enabled:
        return NullProvider()
    model = MODEL_BY_MODE.get(mode)
    if model is None:
        return NullProvider()
    return OllamaProvider(model)


def pick_model(mode, installed):
    """This function returns the first preferred model that is installed, or None."""
    for model in MODEL_PREFERENCES.get(mode, ()):
        if model in installed:
            return model
    return None


def choose_provider_auto(
    mode: str, ai_enabled: bool = True, timeout: float = DEFAULT_TIMEOUT
) -> AIProvider:
    """This function asks Ollama which models exist and uses the best installed one."""
    if not ai_enabled or mode not in MODEL_PREFERENCES:
        return NullProvider()
    model = pick_model(mode, list_installed_models())
    if model is None:
        return NullProvider()
    return OllamaProvider(model, timeout=timeout)


def ai_enabled_from_env() -> bool:
    """This function reads the SHIELD_AI variable; only off/0/false/no disable AI."""
    value = os.environ.get("SHIELD_AI", "on").strip().lower()
    return value not in ("off", "0", "false", "no")


def get_default_provider() -> AIProvider:
    """This function builds the provider for the current machine and settings."""
    return choose_provider_auto(detect_mode(), ai_enabled_from_env())