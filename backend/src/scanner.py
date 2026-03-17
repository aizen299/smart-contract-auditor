import json
import subprocess
from pathlib import Path

from src.rules import map_finding

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
SLITHER_JSON = REPORTS_DIR / "slither.json"

# Impact priority — higher index = higher priority
IMPACT_ORDER = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}


def run_slither(target: str):
    REPORTS_DIR.mkdir(exist_ok=True)

    if SLITHER_JSON.exists():
        SLITHER_JSON.unlink()

    cmd = ["slither", target, "--json", str(SLITHER_JSON)]
    subprocess.run(cmd, capture_output=True, text=True)


def parse_slither_report():
    if not SLITHER_JSON.exists():
        return []

    try:
        data = json.loads(SLITHER_JSON.read_text())
    except json.JSONDecodeError:
        return []

    detectors = data.get("results", {}).get("detectors", [])

    # -------------------------------------------------------------------
    # Step 1: Map every raw detector to a rule, collect all occurrences
    # grouped by rule ID so we can deduplicate intelligently.
    # -------------------------------------------------------------------
    # rule_id → best raw detector entry seen so far
    best: dict[str, dict] = {}

    for d in detectors:
        check = (d.get("check") or "").lower().strip()
        if not check:
            continue

        rule = map_finding(check)

        # Skip truly unknown/unclassified checks (solc-version noise etc.)
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

            # Keep the entry with the highest impact
            if impact_score > existing["impact_score"]:
                existing.update({
                    "check": check,
                    "impact": impact,
                    "impact_score": impact_score,
                    "confidence": d.get("confidence", "Medium"),
                })

    # -------------------------------------------------------------------
    # Step 2: Build the final findings list, sorted by severity
    # -------------------------------------------------------------------
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