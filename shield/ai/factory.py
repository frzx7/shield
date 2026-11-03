"""Chooses which explanation provider to use."""
import os

from shield.core.config import detect_mode
from shield.ai.null_provider import NullProvider
from shield.ai.ollama_provider import OllamaProvider
from shield.ai.provider import AIProvider

# Modes that are missing here (such as "lite") never use AI.
MODEL_BY_MODE = {
    "standard": "llama3.2:3b",
    "full": "llama3.1:8b",
}


def choose_provider(mode: str, ai_enabled: bool = True) -> AIProvider:
    """This function returns NullProvider unless AI is on and the mode allows it."""
    if not ai_enabled:
        return NullProvider()
    model = MODEL_BY_MODE.get(mode)
    if model is None:
        return NullProvider()
    return OllamaProvider(model)

def ai_enabled_from_env() -> bool:
    """This function reads the SHIELD_AI variable; only off/0/false/no disable AI."""
    value = os.environ.get("SHIELD_AI", "on").strip().lower()
    return value not in ("off", "0", "false", "no")


def get_default_provider() -> AIProvider:
    """This function builds the provider for the current machine and settings."""
    return choose_provider(detect_mode(), ai_enabled_from_env())