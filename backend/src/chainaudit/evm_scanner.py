import json
import logging
import subprocess
import tempfile
from pathlib import Path
from .evm_rules import map_finding, detect_l2_chain, get_l2_rules

log = logging.getLogger("chainaudit.evm")

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = Path(tempfile.gettempdir()) / "chainaudit_reports"
SLITHER_JSON = REPORTS_DIR / "slither.json"

IMPACT_ORDER = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}

def run_slither(target: str, json_path: Path | None = None) -> bool:
    """
    Run Slither against `target`, writing JSON to `json_path`.

    `json_path` defaults to the shared module-level SLITHER_JSON. Callers that
    may run concurrently must pass a unique path — the API now executes scans in
    a threadpool, so two requests sharing one output file would overwrite each
    other's results between the subprocess call and the parse.
    """
    out_path = json_path or SLITHER_JSON
    out_path.parent.mkdir(exist_ok=True, parents=True)

    if out_path.exists():
        out_path.unlink()

    # Use absolute path — works on Windows and Mac regardless of cwd
    target_path = Path(target).resolve()
    target_abs = str(target_path)

    # Ensure the parent directory exists before setting it as cwd
    cwd = str(target_path.parent) if target_path.parent.exists() else None

    cmd = ["slither", target_abs, "--json", str(out_path)]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=90,
        cwd=cwd,  # run from contract's directory if it exists
    )

    # Slither's own diagnostics were previously captured and discarded, so a
    # failed scan surfaced only as a generic "Slither failed" with no way to
    # tell a bad pragma from a missing solc. Log them at the point of failure.
    if not out_path.exists():
        log.warning(
            "Slither produced no report for %s (exit %s): %s",
            target_abs, result.returncode,
            (result.stderr or result.stdout or "").strip()[:500] or "no output",
        )
        return False

    try:
        data = json.loads(out_path.read_text())
        if not data.get("success", True) and not data.get("results", {}).get("detectors"):
            log.warning(
                "Slither reported failure for %s: %s",
                target_abs, str(data.get("error", ""))[:500] or "no detail",
            )
            return False
    except json.JSONDecodeError:
        log.warning("Slither wrote unparseable JSON for %s", target_abs)
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


def parse_slither_report(target: str = "", json_path: Path | None = None) -> list:
    """Parse Slither JSON into findings. See run_slither for `json_path`."""
    in_path = json_path or SLITHER_JSON
    if not in_path.exists():
        return []

    try:
        data = json.loads(in_path.read_text())
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