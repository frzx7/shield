"""PhishGuard scoring.
 
This module turns a list of findings into one risk score (0 to 100) and a
label. All weights live in the tables below so that they are easy to tune.
"""
 
from dataclasses import dataclass, field
 
from shield.core.events import Finding
from shield.modules.phishguard.parser import ParsedEmail, parse_eml
from shield.modules.phishguard.rules import check_all
 
# This table maps a severity name to the points it adds.
SEVERITY_POINTS = {"INFO": 0, "LOW": 5, "MEDIUM": 15, "HIGH": 30}
 
# These thresholds decide the label (the score must reach the value).
SUSPICIOUS_AT = 20
PHISHING_AT = 50
 
MAX_SCORE = 100
 
 
@dataclass
class PhishReport:
    """This class is the final answer of the PhishGuard analysis."""
 
    score: int
    label: str
    findings: list[Finding] = field(default_factory=list)
 
 
def label_for(score: int) -> str:
    """This function converts a score into "safe", "suspicious" or "likely phishing"."""
    if score >= PHISHING_AT:
        return "likely phishing"
    if score >= SUSPICIOUS_AT:
        return "suspicious"
    return "safe"
 
 
def score_findings(findings: list[Finding]) -> int:
    """This function adds up the points of all findings (capped at 100).
 
    Each finding kind counts once, with its highest severity. Ten links that
    all trigger "link_mismatch" therefore do not add ten times the points.
    """
    best_per_kind: dict[str, int] = {}
    for finding in findings:
        points = SEVERITY_POINTS.get(finding.severity.name, 0)
        best_per_kind[finding.kind] = max(best_per_kind.get(finding.kind, 0), points)
    return min(sum(best_per_kind.values()), MAX_SCORE)
 
 
def analyze(source) -> PhishReport:
    """This function runs the whole pipeline: parse, apply rules, score.
 
    The source can be an .eml path, raw email text, bytes, or a ParsedEmail.
    """
    email = source if isinstance(source, ParsedEmail) else parse_eml(source)
    findings = check_all(email)
    score = score_findings(findings)
    return PhishReport(score=score, label=label_for(score), findings=findings)
 