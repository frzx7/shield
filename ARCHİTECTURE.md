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