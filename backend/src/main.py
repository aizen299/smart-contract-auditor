import argparse
import sys
import uuid
from datetime import datetime
from pathlib import Path

from src.scanner import run_slither, parse_slither_report
from src.exploit_simulator import run_foundry_tests
from src.rules import compute_risk_score
from src.report_gen import save_json, save_html

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--scan-id", required=False)
    return parser.parse_args()


def main():
    args = parse_args()
    target = Path(args.target)

    if not target.exists():
        print("Invalid target", file=sys.stderr)
        sys.exit(1)

    scan_id = args.scan_id or str(uuid.uuid4())

    slither_ok = run_slither(str(target))

    if not slither_ok:
        print("Slither failed to analyse contract — possible syntax error or unsupported pragma", file=sys.stderr)
        sys.exit(2)

    findings = parse_slither_report()
    risk_score = compute_risk_score(findings)
    sim = run_foundry_tests(verbose=True)

    report = {
        "scan_id": scan_id,
        "target": str(target),
        "generated": datetime.utcnow().isoformat(),
        "total_findings": len(findings),
        "risk_score": risk_score,
        "findings": findings,
        "exploit_simulation": sim,
    }

    save_json(report, scan_id)
    save_html(report, scan_id)

    print(scan_id)


if __name__ == "__main__":
    main()