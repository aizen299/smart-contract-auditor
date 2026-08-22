"""
ChainAudit — Scanner Router
Central dispatcher that detects chain type and routes to the correct scanner.
All scan entry points in api.py should call route_scan() instead of
importing scanner modules directly.
"""

from pathlib import Path

from .ml.mapping import (
    SEVERITY_CONFIDENCE as _SEVERITY_CONFIDENCE,
    SOLANA_TO_EVM_CHECK as _SOLANA_TO_EVM_CHECK,
)


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


# ─────────────────────────────────────────────────────────────────────────────
# EVM scanner
# ─────────────────────────────────────────────────────────────────────────────

def _scan_evm(target: Path, chain: str = "ethereum", ml_only: bool = False) -> dict:
    """Run EVM scan via Slither + L2 rules + ML predictions."""
    import tempfile
    from .evm_scanner import run_slither, parse_slither_report
    from .evm_rules import compute_risk_score

    # No os.chdir here. It used to point the process at the backend directory,
    # which is a process-global mutation — harmless while the API serialised
    # every scan on the event loop, but a race now that scans run concurrently
    # in a threadpool. run_slither already sets the subprocess cwd explicitly,
    # so nothing needed the chdir.
    #
    # For the same reason each scan gets its own Slither output file rather than
    # sharing one module-level path.
    with tempfile.TemporaryDirectory(prefix="chainaudit_slither_") as tmp:
        slither_json = Path(tmp) / "slither.json"

        ok = run_slither(str(target), json_path=slither_json)
        if not ok:
            return {
                "status": "error",
                "chain": chain,
                "error": "Slither failed — possible syntax error or unsupported pragma",
                "risk_score": 0,
                "total_findings": 0,
                "findings": [],
            }

        findings = parse_slither_report(target=str(target), json_path=slither_json)
    risk_score = compute_risk_score(findings)

    # ML predictions
    findings = _add_ml_predictions_evm(findings, target)

    # `exploit_simulation` used to be reported here. It ran `forge test` with the
    # working directory pinned to the package, never the contract under scan, and
    # the repo contains no foundry.toml or test files — so it executed nothing
    # relevant while spawning the one subprocess in the codebase without a
    # timeout. Removed rather than left as a field that always meant nothing.
    # `ml_only` is retained as a no-op flag so the CLI surface is unchanged.
    return {
        "status": "success",
        "chain": chain,
        "risk_score": risk_score,
        "total_findings": len(findings),
        "findings": findings,
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
    import shutil as _shutil
    import tempfile
    from .solana_scanner import scan_solana

    # scan_solana expects a directory and recurses it, so a single file is
    # copied into an isolated directory to stop findings bleeding in from
    # siblings. That directory is scoped to this call: the previous mkdtemp()
    # was never cleaned up, so on the server every Rust scan left a permanent
    # copy of the user's uploaded source on disk.
    if not target.is_file():
        return _finish_solana(scan_solana(target), target)

    with tempfile.TemporaryDirectory(prefix="chainaudit_solana_") as tmp:
        tmp_dir = Path(tmp)
        _shutil.copy2(target, tmp_dir)
        report = scan_solana(tmp_dir)
        # Findings carry paths inside the temp dir; rewrite them to bare
        # filenames so no server-side path is exposed and nothing dangles.
        _normalise_file_paths(report, tmp_dir)
        return _finish_solana(report, tmp_dir)


def _normalise_file_paths(report: dict, tmp_dir: Path) -> None:
    """Replace temp-dir paths in findings with plain file names."""
    for finding in report.get("findings", []):
        affected = finding.get("files_affected")
        if affected:
            finding["files_affected"] = [Path(p).name for p in affected]


def _finish_solana(report: dict, target: Path) -> dict:
    report["findings"] = _add_ml_predictions_solana(
        report.get("findings", []), target
    )
    report["total_findings"] = len(report.get("findings", []))
    return report


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
