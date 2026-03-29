import argparse
import sys
import uuid
from datetime import datetime
from pathlib import Path

from src.chainaudit.scanner import run_slither, parse_slither_report
from src.chainaudit.exploit_simulator import run_foundry_tests
from src.chainaudit.rules import compute_risk_score
from src.chainaudit.report_gen import save_json, save_html

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
        print("Slither failed to analyse contract", file=sys.stderr)
        sys.exit(2)

    findings = parse_slither_report(target=str(target))
    risk_score = compute_risk_score(findings)
    sim = run_foundry_tests(verbose=True)

    # Add ML exploitability predictions
    try:
        from src.chainaudit.ml.predictor import predictor
        contract_size = len(target.read_text(errors="ignore"))
        for finding in findings:
            ml_result = predictor.predict(finding, contract_size)
            finding["ml_exploitability"] = ml_result["exploitability"]
            finding["ml_confidence"] = ml_result["confidence"]
    except Exception:
        pass  # ML is optional — scan still works without it

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