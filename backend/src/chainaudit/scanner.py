import json
import subprocess
import tempfile
from pathlib import Path
from chainaudit.rules import map_finding, detect_l2_chain, get_l2_rules

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = Path(tempfile.gettempdir()) / "chainaudit_reports"
SLITHER_JSON = REPORTS_DIR / "slither.json"

IMPACT_ORDER = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}

def run_slither(target: str) -> bool:
    REPORTS_DIR.mkdir(exist_ok=True, parents=True)

    if SLITHER_JSON.exists():
        SLITHER_JSON.unlink()

    # Use absolute path — works on Windows and Mac regardless of cwd
    target_abs = str(Path(target).resolve())

    cmd = ["slither", target_abs, "--json", str(SLITHER_JSON)]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=90,
        cwd=str(Path(target_abs).parent),  # run from contract's directory
    )

    if not SLITHER_JSON.exists():
        return False

    try:
        data = json.loads(SLITHER_JSON.read_text())
        if not data.get("success", True) and not data.get("results", {}).get("detectors"):
            return False
    except json.JSONDecodeError:
        return False

    return True

def _read_source(target: str) -> str:
    """Read contract source — handles single file or directory."""
    path = Path(target)
    if path.is_file():
        return path.read_text(errors="ignore")
    if path.is_dir():
        # Concatenate all .sol files for pattern matching
        return "\n".join(
            f.read_text(errors="ignore")
            for f in path.rglob("*.sol")
        )
    return ""


def parse_slither_report(target: str = "") -> list:
    if not SLITHER_JSON.exists():
        return []

    try:
        data = json.loads(SLITHER_JSON.read_text())
    except json.JSONDecodeError:
        return []

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

    # -------------------------------------------------------------------
    # L2 auto-detection — scan source for L2 identifiers and inject
    # chain-specific rules that Slither doesn't natively detect
    # -------------------------------------------------------------------
    if target:
        source = _read_source(target)
        detected_chain = detect_l2_chain(source)

        if detected_chain:
            l2_rules = get_l2_rules(detected_chain)
            for rule in l2_rules:
                # Only inject if Slither didn't already catch it
                if rule.id not in best:
                    best[rule.id] = {
                        "rule": rule,
                        "check": rule.id,
                        "impact": "Medium",
                        "impact_score": IMPACT_ORDER.get("Medium", 2),
                        "confidence": "Medium",
                        "occurrences": 1,
                        "l2_detected": True,
                        "chain": detected_chain,
                    }

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    findings = []
    for entry in best.values():
        rule = entry["rule"]
        finding = {
            "title": rule.title,
            "severity": rule.severity,
            "description": rule.description,
            "fix": rule.fix,
            "check": entry["check"],
            "impact": entry["impact"],
            "confidence": entry["confidence"],
            "occurrences": entry["occurrences"],
        }
        # Tag L2 findings so the frontend can show a chain badge
        if entry.get("l2_detected"):
            finding["chain"] = entry.get("chain", "l2")
            finding["l2_detected"] = True

        findings.append(finding)

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    return findings