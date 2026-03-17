import json
import subprocess
from pathlib import Path

from src.rules import map_finding

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
SLITHER_JSON = REPORTS_DIR / "slither.json"


def run_slither(target: str):
    REPORTS_DIR.mkdir(exist_ok=True)

    if SLITHER_JSON.exists():
        SLITHER_JSON.unlink()

    cmd = ["slither", target, "--json", str(SLITHER_JSON)]
    subprocess.run(cmd, capture_output=True, text=True)


def parse_slither_report():
    if not SLITHER_JSON.exists():
        return []

    data = json.loads(SLITHER_JSON.read_text())
    detectors = data.get("results", {}).get("detectors", [])

    findings = []
    seen = set()

    for d in detectors:
        check = (d.get("check") or "").lower()

        if not check:
            continue

        if check in seen:
            continue
        seen.add(check)

        rule = map_finding(check)

        findings.append({
            "title": rule.title,
            "severity": rule.severity,
            "description": rule.description,
            "fix": rule.fix,
            "check": check,
            "impact": d.get("impact"),
            "confidence": d.get("confidence"),
        })

    return findings