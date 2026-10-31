from shield.core.events import Finding, Severity
from shield.ai.null_provider import NullProvider


def test_finding_creation():
    f = Finding("test", Severity.LOW, "abc", "izah")
    assert f.kind == "test"


def test_null_provider_returns_rule_explanation():
    f = Finding("test", Severity.LOW, "abc", "izah")
    assert NullProvider().explain(f) == "izah"