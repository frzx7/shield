from shield.ai.provider import AIProvider


class NullProvider(AIProvider):
    def explain(self, finding) -> str:
        return finding.rule_explanation