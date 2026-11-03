# Shield

A local-first personal security assistant for Windows. It checks suspicious emails,
watches system activity, and warns you before sensitive data leaks.
Works with or without a local AI model (Ollama).

## Status

Work in progress (v0.1 planned).

- [x] Core: `Finding` model, hardware mode detection
- [x] AI layer: provider interface, rule-only provider
- [x] Shield: clipboard leak detection
- [x] PhishGuard: email analysis and honeypot
- [x] Pulse: system monitor
- [ ] Optional local AI explanations (Ollama)

## Design principles

- **Rules decide, AI explains.** The verdict always comes from deterministic rules,
  so a malicious email cannot talk the AI into marking it safe.
- **AI is optional.** The app is fully functional without it.
- **Privacy first.** Sensitive content is never written to disk.

## Run

```powershell
python -m venv .shenv
.shenv\Scripts\activate
pip install -r requirements.txt
python -m shield
```

## Tests

```powershell
python -m pytest
```

requirements.txt hələ yoxdur. Bunu yaratmaq üçün terminalda pip freeze > requirements.txt işlət.

ARCHITECTURE.md şablonu
# Architecture

## Structure

```
shield/
  __main__.py        entry point
  core/
    events.py        Finding, Severity
    config.py        detect_mode()
  ai/
    provider.py      AIProvider interface
    null_provider.py rule-only explanations
tests/
```

## Key decisions

- Every module returns `Finding` objects.
- The explanation layer only sees `Finding`, never module internals.
- `NullProvider` is the default and the fallback.

## Progress log

- Day 1: core + ai layer, 2 tests passing.