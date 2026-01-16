import json
import subprocess
from pathlib import Path

REPORTS_DIR = Path("reports")
SLITHER_JSON = REPORTS_DIR / "slither.json"


def run_slither(target="contracts"):
    REPORTS_DIR.mkdir(exist_ok=True)

    # delete old report so slither can write fresh
    if SLITHER_JSON.exists():
        SLITHER_JSON.unlink()

    cmd = ["slither", target, "--json", str(SLITHER_JSON)]
    result = subprocess.run(cmd, capture_output=True, text=True)

    # DEBUG (optional, but helpful)
    print("SLITHER RETURN CODE =", result.returncode)

    # Slither exit codes:
    # 0 = no findings
    # 1 = findings found (SUCCESS)
    # sometimes slither returns >1 but still generates json
    # So we only treat it as crash if JSON wasn't generated.
    if result.returncode > 1 and not SLITHER_JSON.exists():
        raise RuntimeError(
            f"Slither crashed!\nSTDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
        )

    return result.returncode


def parse_slither_report():
    if not SLITHER_JSON.exists():
        return []

    data = json.loads(SLITHER_JSON.read_text(encoding="utf-8"))
    detectors = data.get("results", {}).get("detectors", [])

    findings = []
    for d in detectors:
        findings.append(
            {
                "check": d.get("check"),
                "impact": d.get("impact"),
                "confidence": d.get("confidence"),
                "description": d.get("description"),
            }
        )

    return findings
