from dataclasses import dataclass
from enum import Enum


class Severity(Enum):     #Threat level
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass
class Finding:
    kind: str               # What was found, example: "api_key", "phishing_link"
    severity: Severity      # How dangerous is it 
    evidence: str           # Sensored evidence, example: "AKIA****"
    rule_explanation: str   # rule based explanation