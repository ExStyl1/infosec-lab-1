"""Turn the scanner JSON outputs into a concise GitHub Actions summary."""

import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scanner", choices=("bandit", "pip-audit", "dependency-check"))
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))

    if args.scanner == "bandit":
        print("### Bandit (SAST)")
        print(f"- Findings: **{len(report['results'])}**")
        print(f"- Lines analyzed: **{report['metrics']['_totals']['loc']}**")
    elif args.scanner == "pip-audit":
        dependencies = report["dependencies"]
        skipped = sum("skip_reason" in item for item in dependencies)
        findings = sum(len(item.get("vulns", [])) for item in dependencies)
        print("### pip-audit (PyPI SCA)")
        print(f"- Packages audited: **{len(dependencies) - skipped}**")
        print(f"- Skipped: **{skipped}**")
        print(f"- Known vulnerabilities: **{findings}**")
        if skipped or not dependencies:
            raise SystemExit("Incomplete dependency audit")
    else:
        dependencies = report["dependencies"]
        wheels = sum(item["fileName"].endswith(".whl") for item in dependencies)
        findings = sum(len(item.get("vulnerabilities", [])) for item in dependencies)
        print("### OWASP Dependency-Check (SCA)")
        print(f"- Wheel files analyzed: **{wheels}**")
        print(f"- Vulnerability findings: **{findings}**")
        if not wheels:
            raise SystemExit("No wheel files analyzed")


if __name__ == "__main__":
    main()
