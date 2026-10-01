"""CLI: review Kubernetes manifests for deployment risk.

Usage:
    python -m src.cli review <path>            # human-readable report
    python -m src.cli review <path> --json     # machine-readable JSON
"""

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.analyzer import analyze  # noqa: E402


def _print_text(report):
    counts = report.counts
    print(f"release-guardian report  |  files: {report.files_scanned}  "
          f"resources: {report.resources_scanned}")
    print(f"risk score: {report.score}/100  |  verdict: {report.verdict}")
    print(f"findings: {counts['critical']} critical, {counts['high']} high, "
          f"{counts['medium']} medium, {counts['low']} low")
    print("-" * 70)
    if not report.findings:
        print("No issues found. Ship it.")
        return
    for f in report.sorted_findings():
        print(f"[{f.severity.upper():8}] {f.check_id}  {f.title}")
        print(f"           resource: {f.resource}")
        print(f"           detail:   {f.detail}")
        print(f"           fix:      {f.remediation}")
        print()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="release-guardian",
                                     description="Review Kubernetes manifests for deployment risk.")
    sub = parser.add_subparsers(dest="command", required=True)
    review = sub.add_parser("review", help="Review manifests at a file or directory path.")
    review.add_argument("path", help="YAML file or directory of Kubernetes manifests.")
    review.add_argument("--json", action="store_true", help="Emit the report as JSON.")
    args = parser.parse_args(argv)

    path = Path(args.path)
    if not path.exists():
        print(f"error: path not found: {path}", file=sys.stderr)
        return 2

    report = analyze(path)
    if args.json:
        payload = {
            "files_scanned": report.files_scanned,
            "resources_scanned": report.resources_scanned,
            "score": report.score,
            "verdict": report.verdict,
            "counts": report.counts,
            "findings": [asdict(f) for f in report.sorted_findings()],
        }
        print(json.dumps(payload, indent=2))
    else:
        _print_text(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
