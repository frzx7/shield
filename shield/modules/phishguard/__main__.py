"""Command line runner: python -m shield.modules.phishguard <file.eml>"""
 
import sys
import io
 
from shield.modules.phishguard.scoring import analyze
 
 
def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m shield.modules.phishguard <file.eml>")
        return 2
 
    # This block lets the Windows console print Azerbaijani and Russian text.
    # It runs only when stdout is a real text stream that supports reconfigure().
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
 
    report = analyze(argv[1])
    print(f"Score: {report.score}/100 ({report.label})")
    for finding in report.findings:
        print(f"- [{finding.severity.name}] {finding.kind}: {finding.evidence}")
        print(f"    {finding.rule_explanation}")
    return 0
 
 
if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
 