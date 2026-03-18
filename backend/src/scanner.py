import json
import subprocess
from pathlib import Path
from src.rules import map_finding

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
SLITHER_JSON = REPORTS_DIR / "slither.json"

IMPACT_ORDER = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}


def run_slither(target: str) -> bool:
    REPORTS_DIR.mkdir(exist_ok=True)

    if SLITHER_JSON.exists():
        SLITHER_JSON.unlink()

    cmd = ["slither", target, "--json", str(SLITHER_JSON)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)

    # Slither returns exit code 1 when it finds issues (normal)
    # It returns exit code 2+ on compilation failure
    if result.returncode > 1:
        return False

    return SLITHER_JSON.exists()


def parse_slither_report() -> list:
    if not SLITHER_JSON.exists():
        return []

    try:
        data = json.loads(SLITHER_JSON.read_text())
    except json.JSONDecodeError:
        return []

    # Check if Slither reported a compilation error
    if not data.get("success", True):
        return []

    detectors = data.get("results", {}).get("detectors", [])

    best: dict[str, dict] = {}

    for d in detectors:
        check = (d.get("check") or "").lower().strip()
        if not check:
            continue

        rule = map_finding(check)

        if rule.id == "unknown":
            continue

        impact = d.get("impact", "Low")
        impact_score = IMPACT_ORDER.get(impact, 0)

        if rule.id not in best:
            best[rule.id] = {
                "rule": rule,
                "check": check,
                "impact": impact,
                "impact_score": impact_score,
                "confidence": d.get("confidence", "Medium"),
                "occurrences": 1,
            }
        else:
            existing = best[rule.id]
            existing["occurrences"] += 1
            if impact_score > existing["impact_score"]:
                existing.update({
                    "check": check,
                    "impact": impact,
                    "impact_score": impact_score,
                    "confidence": d.get("confidence", "Medium"),
                })

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    findings = []
    for entry in best.values():
        rule = entry["rule"]
        findings.append({
            "title": rule.title,
            "severity": rule.severity,
            "description": rule.description,
            "fix": rule.fix,
            "check": entry["check"],
            "impact": entry["impact"],
            "confidence": entry["confidence"],
            "occurrences": entry["occurrences"],
        })

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    return findings