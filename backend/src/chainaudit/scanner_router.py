"""
ChainAudit — Scanner Router
Central dispatcher that detects chain type and routes to the correct scanner.
All scan entry points in api.py should call route_scan() instead of
importing scanner modules directly.
"""

import os
from pathlib import Path


_BACKEND_DIR = Path(__file__).resolve().parent.parent.parent


def route_scan(target: Path, ml_only: bool = False, scan_id: str | None = None) -> dict:
    """
    Main entry point for all scans.
    Detects chain, runs appropriate scanner, returns unified result dict.
    """
    from .chain_registry import detect_chain_from_file, is_solana_chain

    chain = detect_chain_from_file(target)

    if is_solana_chain(chain):
        return _scan_solana(target)
    else:
        return _scan_evm(target, chain=chain, ml_only=ml_only)


def route_scan_source(source: str, filename: str, ml_only: bool = False) -> dict:
    """
    Scan from raw source string — used when file content is already in memory.
    Writes to a temp file then calls route_scan.
    """
    import tempfile, shutil
    suffix = Path(filename).suffix or ".sol"
    tmp = Path(tempfile.mktemp(suffix=suffix))
    try:
        tmp.write_text(source, encoding="utf-8")
        return route_scan(tmp, ml_only=ml_only)
    finally:
        if tmp.exists():
            tmp.unlink()


# ─────────────────────────────────────────────────────────────────────────────
# EVM scanner
# ─────────────────────────────────────────────────────────────────────────────

def _scan_evm(target: Path, chain: str = "ethereum", ml_only: bool = False) -> dict:
    """Run EVM scan via Slither + L2 rules + ML predictions."""
    from .evm_scanner import run_slither, parse_slither_report
    from .evm_rules import compute_risk_score

    os.chdir(_BACKEND_DIR)
    ok = run_slither(str(target))
    if not ok:
        return {
            "status": "error",
            "chain": chain,
            "error": "Slither failed — possible syntax error or unsupported pragma",
            "risk_score": 0,
            "total_findings": 0,
            "findings": [],
        }

    findings = parse_slither_report(target=str(target))
    risk_score = compute_risk_score(findings)

    # ML predictions
    findings = _add_ml_predictions_evm(findings, target)

    # Exploit simulation (skipped if ml_only)
    simulation = {"success": False, "stdout": "", "stderr": "skipped"}
    if not ml_only:
        try:
            from .exploit_simulator import run_foundry_tests
            simulation = run_foundry_tests(verbose=False)
        except Exception as e:
            simulation = {"success": False, "stdout": "", "stderr": str(e)}

    return {
        "status": "success",
        "chain": chain,
        "risk_score": risk_score,
        "total_findings": len(findings),
        "findings": findings,
        "exploit_simulation": simulation,
    }


def _add_ml_predictions_evm(findings: list[dict], target: Path) -> list[dict]:
    """Attach ML predictions to EVM findings."""
    try:
        from .ml.predictor import predictor
        contract_size = target.stat().st_size if target.exists() else 500
        for f in findings:
            check      = f.get("check", "").lower()
            impact     = f.get("impact", "Medium").strip().capitalize()
            confidence = f.get("confidence", "Medium").strip().capitalize()
            result = predictor.predict(
                {"check": check, "impact": impact, "confidence": confidence},
                contract_size,
            )
            f["ml_exploitability"] = result.get("exploitability", "unknown")
            f["ml_confidence"]     = result.get("confidence", 0.0)
    except Exception:
        pass
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Solana scanner
# ─────────────────────────────────────────────────────────────────────────────

def _scan_solana(target: Path) -> dict:
    """Run Solana scan via cargo-audit + pattern scanner + ML predictions."""
    from .solana_scanner import scan_solana
    report = scan_solana(target)
    report["findings"] = _add_ml_predictions_solana(
        report.get("findings", []), target
    )
    report["total_findings"] = len(report.get("findings", []))
    return report


_SOLANA_TO_EVM_CHECK = {
    "missing-signer-check":     "suicidal",
    "missing-owner-check":      "suicidal",
    "arbitrary-cpi":            "reentrancy-eth",
    "integer-overflow":         "integer-overflow",
    "unchecked-arithmetic":     "integer-overflow",
    "unsafe-code":              "assembly",
    "account-confusion":        "incorrect-equality",
    "reentrancy-cpi":           "reentrancy-eth",
    "insecure-randomness":      "weak-prng",
    "missing-rent-exemption":   "missing-zero-check",
    "unvalidated-account-data": "missing-zero-check",
    "missing-close-account":    "locked-ether",
    "pdas-not-validated":       "incorrect-equality",
    "missing-freeze-authority": "suicidal",
    "deprecated-anchor":        "naming-convention",
}

_SEVERITY_CONFIDENCE = {
    "CRITICAL": 0.87, "HIGH": 0.74, "MEDIUM": 0.58, "LOW": 0.42,
}


def _add_ml_predictions_solana(findings: list[dict], target: Path) -> list[dict]:
    """Attach ML predictions to Solana findings via EVM check mapping."""
    try:
        from .ml.predictor import predictor
        contract_size = target.stat().st_size if target.exists() else 500

        for f in findings:
            rule_id   = f.get("rule_id", f.get("check", "")).lower().replace("_", "-")
            evm_check = _SOLANA_TO_EVM_CHECK.get(rule_id, "")

            if evm_check:
                conf_raw = f.get("confidence", "Medium")
                level    = conf_raw.strip().capitalize() if conf_raw else "Medium"
                result   = predictor.predict(
                    {"check": evm_check, "impact": level, "confidence": level},
                    contract_size,
                )
                f["ml_exploitability"] = result.get("exploitability", "unknown")
                f["ml_confidence"]     = result.get("confidence", 0.0)
            else:
                sev = f.get("severity", "LOW")
                f["ml_exploitability"] = sev
                f["ml_confidence"]     = _SEVERITY_CONFIDENCE.get(sev, 0.5)
    except Exception:
        pass
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Zip router — routes each file in a zip to correct scanner
# ─────────────────────────────────────────────────────────────────────────────

def route_zip_scan(
    sol_files: list[Path],
    rs_files: list[Path],
    ml_only: bool = False,
) -> list[dict]:
    """
    Scan all files extracted from a zip.
    Returns a list of per-file result dicts.
    """
    results = []

    for sol_file in sol_files:
        result = _scan_evm(sol_file, ml_only=ml_only)
        result["file"] = sol_file.name
        results.append(result)

    for rs_file in rs_files:
        result = _scan_solana(rs_file)
        result["file"] = rs_file.name
        results.append(result)

    return results
