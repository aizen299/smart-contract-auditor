"""
ChainAudit CLI — Production-quality smart contract security scanner.

Usage:
    chainaudit scan <target> [--json] [--ml-only] [--recursive]
"""

import argparse
import json
import os
import sys
import uuid
import zipfile
import tempfile
import shutil
from datetime import datetime
from pathlib import Path

# Ensure backend/ is always on the path regardless of where CLI is invoked from
_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from chainaudit.scanner import run_slither, parse_slither_report
from chainaudit.rules import compute_risk_score
from chainaudit.exploit_simulator import run_foundry_tests

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

try:
    from chainaudit.ml.predictor import predictor as ml_predictor
    HAS_ML = True
except ImportError:
    HAS_ML = False

console = Console() if HAS_RICH else None

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold orange1",
    "MEDIUM": "bold yellow",
    "LOW": "bold cyan",
}

EXIT_CRITICAL = 1
EXIT_OK = 0

_TEMP_DIRS: list[str] = []


def _cleanup_temp_dirs() -> None:
    for d in _TEMP_DIRS:
        shutil.rmtree(d, ignore_errors=True)


import atexit
atexit.register(_cleanup_temp_dirs)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print(msg: str, style: str = "") -> None:
    if HAS_RICH and console:
        console.print(msg, style=style)
    else:
        import re
        clean = re.sub(r"\[/?[^\]]+\]", "", msg)
        print(clean)


def _severity_color(sev: str) -> str:
    return SEVERITY_COLORS.get(sev.upper(), "white")


def _risk_label(score: int) -> str:
    if score >= 80: return "CRITICAL RISK"
    if score >= 60: return "HIGH RISK"
    if score >= 40: return "MEDIUM RISK"
    if score >= 20: return "LOW RISK"
    return "MINIMAL RISK"


def _risk_style(score: int) -> str:
    if score >= 80: return "bold red"
    if score >= 60: return "bold orange1"
    if score >= 40: return "bold yellow"
    if score >= 20: return "bold cyan"
    return "bold green"


# ---------------------------------------------------------------------------
# ML predictions — unified for both EVM and Solana findings
# ---------------------------------------------------------------------------

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
    "CRITICAL": 0.87,
    "HIGH":     0.74,
    "MEDIUM":   0.58,
    "LOW":      0.42,
}

# Slither check names → what the ML model was trained on
_SLITHER_TO_ML = {
    "reentrancy-no-eth":  "reentrancy-eth",
    "reentrancy-benign":  "reentrancy-eth",
    "reentrancy-eth":     "reentrancy-eth",
    "unchecked-transfer": "unchecked-transfer",
    "unchecked-send":     "unchecked-lowlevel",
    "unchecked-lowlevel": "unchecked-lowlevel",
    "timestamp":          "timestamp",
    "weak-prng":          "weak-prng",
    "incorrect-equality": "incorrect-equality",
    "tx-origin":          "tx-origin",
    "suicidal":           "suicidal",
    "assembly":           "assembly",
    "events-access":      "events-access",
    "events-maths":       "events-maths",
}

# ML model was trained with title case: "High", "Medium", "Low"
_TITLE_CASE = {"high": "High", "medium": "Medium", "low": "Low"}


def _normalize_level(val: str) -> str:
    """Convert HIGH/MEDIUM/LOW/high/medium/low → High/Medium/Low (title case)."""
    return _TITLE_CASE.get(val.strip().lower(), "Medium")


def _add_ml_predictions(findings: list[dict], contract_size: int = 0,
                        is_solana: bool = False) -> list[dict]:
    """
    Attach ml_exploitability and ml_confidence to every finding.
    Works for both EVM (Slither) and Solana (pattern scanner) findings.

    The ML model was trained with:
      - check:      lowercase string  e.g. "reentrancy-eth"
      - impact:     title case string e.g. "High" / "Medium" / "Low"
      - confidence: title case string e.g. "High" / "Medium" / "Low"
    """
    for f in findings:
        try:
            if is_solana:
                # Map Solana rule ID → closest EVM check
                rule_id = f.get("rule_id", f.get("check", "")).lower().replace("_", "-")
                evm_check = _SOLANA_TO_EVM_CHECK.get(rule_id, "")

                if evm_check and HAS_ML:
                    # Solana findings only have 'confidence', use it for both fields
                    conf_raw = f.get("confidence", "Medium")
                    level = _normalize_level(conf_raw)
                    evm_finding = {
                        "check":      evm_check,
                        "impact":     level,
                        "confidence": level,
                    }
                    result = ml_predictor.predict(evm_finding, contract_size or 500)
                    f["ml_exploitability"] = result.get("exploitability", "unknown")
                    f["ml_confidence"]     = result.get("confidence", 0.0)
                else:
                    # No mapping — fall back to severity-based estimate
                    sev = f.get("severity", "LOW")
                    f["ml_exploitability"] = sev
                    f["ml_confidence"]     = _SEVERITY_CONFIDENCE.get(sev, 0.5)

            else:
                # EVM path — finding dict has 'impact' AND 'confidence' fields
                if HAS_ML:
                    raw_check = f.get("check", "").lower()
                    check = _SLITHER_TO_ML.get(raw_check, raw_check)

                    # ✅ Read 'impact' from the 'impact' field (NOT confidence)
                    # ✅ Normalize to title case that the model expects
                    impact     = f.get("impact", "Medium").strip().capitalize()
                    confidence = f.get("confidence", "Medium").strip().capitalize()

                    evm_finding = {
                        "check":      check,
                        "impact":     impact,      # e.g. "Medium"
                        "confidence": confidence,  # e.g. "Medium"
                    }
                    result = ml_predictor.predict(evm_finding, contract_size)
                    f["ml_exploitability"] = result.get("exploitability", "unknown")
                    f["ml_confidence"]     = result.get("confidence", 0.0)
                else:
                    f["ml_exploitability"] = "unknown"
                    f["ml_confidence"]     = 0.0

        except Exception:
            f["ml_exploitability"] = "unknown"
            f["ml_confidence"]     = 0.0

    return findings


# ---------------------------------------------------------------------------
# File collection helpers
# ---------------------------------------------------------------------------

def _collect_sol_files(target: Path, recursive: bool) -> list[Path]:
    """Return all .sol files from a .sol file, .zip archive, or directory."""

    if target.suffix == ".zip":
        if not target.exists():
            _print(f"[red]Error:[/red] '{target}' does not exist.")
            sys.exit(2)

        extract_dir = tempfile.mkdtemp(prefix="chainaudit_")
        _TEMP_DIRS.append(extract_dir)

        try:
            with zipfile.ZipFile(target) as zf:
                zf.extractall(extract_dir)
        except zipfile.BadZipFile:
            _print(f"[red]Error:[/red] '{target}' is not a valid zip file.")
            sys.exit(2)

        files = [
            f for f in Path(extract_dir).rglob("*.sol")
            if "node_modules" not in str(f)
            and "/lib/" not in str(f)
            and "/test/" not in str(f)
            and "/mocks/" not in str(f)
            and not f.name.startswith(".")
            and "__MACOSX" not in str(f)
        ]

        if not files:
            _print("[yellow]Warning:[/yellow] No Solidity files found in zip.")
            sys.exit(0)

        return sorted(files)

    if target.is_file():
        if target.suffix != ".sol":
            _print(f"[red]Error:[/red] '{target}' is not a .sol or .zip file.")
            sys.exit(2)
        return [target]

    if not target.exists():
        _print(f"[red]Error:[/red] '{target}' does not exist.")
        sys.exit(2)

    if not target.is_dir():
        _print(f"[red]Error:[/red] '{target}' is not a file or directory.")
        sys.exit(2)

    pattern = "**/*.sol" if recursive else "*.sol"
    files = [
        f for f in target.glob(pattern)
        if "node_modules" not in str(f)
        and "/lib/" not in str(f)
        and not f.name.startswith(".")
    ]

    if not files:
        _print(f"[yellow]Warning:[/yellow] No .sol files found in '{target}'.")
        sys.exit(0)

    return sorted(files)


def _collect_rs_files_from_dir(target: Path, recursive: bool) -> list[Path]:
    """Collect all .rs files from a directory, excluding Rust build artifacts."""
    pattern = "**/*.rs" if recursive else "*.rs"
    return sorted([
        f for f in target.glob(pattern)
        if "target" not in f.parts
        and not f.name.startswith(".")
    ])


# ---------------------------------------------------------------------------
# Scan a single EVM .sol file
# ---------------------------------------------------------------------------

def _scan_file(sol_file: Path, ml_only: bool) -> dict:
    scan_id = str(uuid.uuid4())
    original_dir = os.getcwd()
    os.chdir(_BACKEND_DIR)

    try:
        slither_ok = run_slither(str(sol_file))
        if not slither_ok:
            return {
                "file": sol_file.name,
                "status": "error",
                "error": "Slither failed — possible syntax error or unsupported pragma",
                "findings": [],
                "risk_score": 0,
                "total_findings": 0,
            }

        findings = parse_slither_report(target=str(sol_file))
        risk_score = compute_risk_score(findings)
        contract_size = len(sol_file.read_text(errors="ignore"))

        findings = _add_ml_predictions(findings, contract_size, is_solana=False)

        simulation = {"success": False, "stdout": "", "stderr": "skipped"}
        if not ml_only:
            try:
                simulation = run_foundry_tests(verbose=False)
            except Exception as e:
                simulation = {"success": False, "stdout": "", "stderr": str(e)}

        return {
            "scan_id": scan_id,
            "file": sol_file.name,
            "status": "success",
            "generated": datetime.utcnow().isoformat(),
            "risk_score": risk_score,
            "total_findings": len(findings),
            "findings": findings,
            "exploit_simulation": simulation,
        }
    finally:
        os.chdir(original_dir)


# ---------------------------------------------------------------------------
# Scan a single Solana .rs file
# ---------------------------------------------------------------------------

def _scan_rs_file(rs_file: Path) -> dict:
    """Scan one .rs file and add ML predictions."""
    original_dir = os.getcwd()
    os.chdir(_BACKEND_DIR)

    try:
        from chainaudit.solana_scanner import scan_solana
        report = scan_solana(rs_file)
    except ImportError as e:
        os.chdir(original_dir)
        return {
            "file": rs_file.name,
            "status": "error",
            "error": f"Solana scanner not available: {e}",
            "chain": "solana",
            "risk_score": 0,
            "total_findings": 0,
            "findings": [],
        }
    finally:
        os.chdir(original_dir)

    report["file"] = rs_file.name

    contract_size = len(rs_file.read_text(errors="ignore")) if rs_file.is_file() else 500
    report["findings"] = _add_ml_predictions(
        report.get("findings", []), contract_size, is_solana=True
    )
    report["total_findings"] = len(report.get("findings", []))

    return report


# ---------------------------------------------------------------------------
# Human-readable output
# ---------------------------------------------------------------------------

def _format_ml(f: dict) -> str:
    ml_exp  = f.get("ml_exploitability", "")
    ml_conf = f.get("ml_confidence", 0.0)
    if not ml_exp or ml_exp in ("unknown", "—", ""):
        return "—"
    pct = int(ml_conf * 100)
    return f"{ml_exp} ({pct}%)"


def _print_report(report: dict, show_file: bool = False) -> None:
    if not HAS_RICH or not console:
        _print_report_plain(report, show_file)
        return

    if report.get("status") == "error":
        label = f"\n{report.get('file', '')}" if show_file else ""
        console.print(Panel(
            f"[red]{report.get('error', report.get('reason', 'Unknown error'))}[/red]{label}",
            title="[bold red]Scan Failed[/bold red]",
            border_style="red",
        ))
        return

    risk     = report.get("risk_score", 0)
    rl       = _risk_label(risk)
    rs       = _risk_style(risk)
    findings = report.get("findings", [])

    chain      = report.get("chain", "evm")
    is_anchor  = report.get("is_anchor", False)
    chain_suffix = ""
    if chain == "solana":
        chain_suffix = "  · SOLANA"
        if is_anchor:
            chain_suffix += "  · ANCHOR"

    header = Text()
    if show_file:
        header.append(f"{report.get('file', '')}\n", style="bold white")
    header.append("Risk Score: ", style="white")
    header.append(f"{risk}/100", style=rs)
    header.append(f"  [{rl}]{chain_suffix}", style=rs)
    header.append(f"\nFindings: {len(findings)}", style="white")

    console.print(Panel(header, title="[bold]ChainAudit Report[/bold]", border_style="green"))

    if not findings:
        console.print("  [green]✓ No vulnerabilities detected.[/green]\n")
        return

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white")
    table.add_column("#",            style="dim", width=4)
    table.add_column("Title",        min_width=28)
    table.add_column("Severity",     width=10)
    table.add_column("Confidence",   width=11)
    table.add_column("Occurrences",  width=12)
    table.add_column("ML Prediction",width=22)

    for i, f in enumerate(findings, 1):
        sev      = f.get("severity", "LOW")
        sc       = _severity_color(sev)
        ml_str   = _format_ml(f)
        ml_sev   = f.get("ml_exploitability", "")
        ml_color = _severity_color(ml_sev) if ml_sev and ml_sev not in ("unknown", "—", "") else "dim"

        table.add_row(
            str(i),
            f.get("title", "Unknown"),
            f"[{sc}]{sev}[/{sc}]",
            f.get("confidence", "—"),
            str(f.get("occurrences", 1)),
            f"[{ml_color}]{ml_str}[/{ml_color}]",
        )

    console.print(table)

    for i, f in enumerate(findings, 1):
        sev   = f.get("severity", "LOW")
        color = _severity_color(sev)
        console.print(f"\n  [{color}][{i}] {f.get('title', '')}[/{color}]")
        console.print(f"  [dim]Description:[/dim] {f.get('description', '')}")
        console.print(f"  [green]Fix:[/green] {f.get('fix', '')}")

    console.print()


def _print_report_plain(report: dict, show_file: bool = False) -> None:
    sep = "-" * 60
    if show_file:
        print(f"\nFile: {report.get('file', '')}")
    print(sep)
    if report.get("status") == "error":
        print(f"ERROR: {report.get('error', report.get('reason', 'Unknown'))}")
        print(sep)
        return
    print(f"Risk Score : {report.get('risk_score', 0)}/100")
    print(f"Findings   : {report.get('total_findings', 0)}")
    print(sep)
    for i, f in enumerate(report.get("findings", []), 1):
        ml_str = _format_ml(f)
        print(f"[{i}] {f.get('title')} | {f.get('severity')} | ML: {ml_str}")
        print(f"    {f.get('description', '')}")
        print(f"    Fix: {f.get('fix', '')}")
    print(sep)


def _print_multi_summary(reports: list[dict]) -> None:
    if not HAS_RICH or not console:
        for r in reports:
            _print_report_plain(r, show_file=True)
        return

    console.print(Panel(
        f"[bold white]Multi-Contract Scan[/bold white]  [dim]{len(reports)} files[/dim]",
        border_style="green",
    ))

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white")
    table.add_column("File",     min_width=30)
    table.add_column("Chain",    width=10)
    table.add_column("Score",    width=7)
    table.add_column("Findings", width=10)
    table.add_column("Status",   width=10)

    for r in reports:
        chain       = r.get("chain", "evm").upper()
        chain_color = "yellow" if chain == "SOLANA" else "cyan"
        if r.get("status") == "error":
            table.add_row(
                Path(r.get("file", "unknown")).name,
                f"[{chain_color}]{chain}[/{chain_color}]",
                "—", "—", "[red]error[/red]",
            )
            continue

        risk = r.get("risk_score", 0)
        rs   = _risk_style(risk)
        table.add_row(
            Path(r.get("file", "unknown")).name,
            f"[{chain_color}]{chain}[/{chain_color}]",
            f"[{rs}]{risk}[/{rs}]",
            str(r.get("total_findings", 0)),
            "[green]ok[/green]",
        )

    console.print(table)

    for r in reports:
        if r.get("status") == "success" and r.get("findings"):
            _print_report(r, show_file=True)


# ---------------------------------------------------------------------------
# Shared output helper
# ---------------------------------------------------------------------------

def _output_results(reports: list[dict], args: argparse.Namespace) -> None:
    if args.json:
        if len(reports) == 1:
            print(json.dumps(reports[0], indent=2))
        else:
            output = {
                "type": "multi",
                "total_files": len(reports),
                "scanned": sum(1 for r in reports if r.get("status") == "success"),
                "has_evm":     any(r.get("chain", "evm") != "solana" for r in reports),
                "has_solana":  any(r.get("chain") == "solana" for r in reports),
                "overall_risk_score": max(
                    (r["risk_score"] for r in reports if r.get("status") == "success"),
                    default=0,
                ),
                "total_findings": sum(r.get("total_findings", 0) for r in reports),
                "files": reports,
            }
            print(json.dumps(output, indent=2))
    else:
        if len(reports) == 1:
            _print_report(reports[0])
        else:
            _print_multi_summary(reports)


# ---------------------------------------------------------------------------
# Zip handler
# ---------------------------------------------------------------------------

def _handle_zip(zip_path: Path, args: argparse.Namespace) -> int:
    if not zip_path.exists():
        _print(f"[red]Error:[/red] '{zip_path}' does not exist.")
        return 2

    extract_dir = tempfile.mkdtemp(prefix="chainaudit_")
    _TEMP_DIRS.append(extract_dir)

    try:
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(extract_dir)
    except zipfile.BadZipFile:
        _print(f"[red]Error:[/red] '{zip_path}' is not a valid zip file.")
        return 2

    extract_path = Path(extract_dir)

    sol_files = sorted([
        f for f in extract_path.rglob("*.sol")
        if "node_modules" not in str(f) and "__MACOSX" not in str(f)
        and not f.name.startswith(".")
    ])
    rs_files = sorted([
        f for f in extract_path.rglob("*.rs")
        if "target" not in f.parts and "__MACOSX" not in str(f)
        and not f.name.startswith(".")
    ])

    if not sol_files and not rs_files:
        _print("[yellow]Warning:[/yellow] No Solidity or Rust files found in zip.")
        return 0

    reports      = []
    has_critical = False
    total        = len(sol_files) + len(rs_files)

    if not args.json:
        parts = []
        if sol_files: parts.append(f"{len(sol_files)} Solidity")
        if rs_files:  parts.append(f"{len(rs_files)} Rust")
        _print(f"\n[bold green]ChainAudit[/bold green] scanning {total} file(s) from zip ({', '.join(parts)})...\n")

    for sol_file in sol_files:
        if not args.json:
            _print(f"  [dim]→ {sol_file.name}[/dim]")
        report = _scan_file(sol_file, ml_only=args.ml_only)
        reports.append(report)
        if report.get("status") == "success" and any(
            f.get("severity") == "CRITICAL" for f in report.get("findings", [])
        ):
            has_critical = True

    for rs_file in rs_files:
        if not args.json:
            _print(f"  [dim]→ {rs_file.name} [yellow](Solana)[/yellow][/dim]")
        report = _scan_rs_file(rs_file)
        reports.append(report)
        if any(f.get("severity") == "CRITICAL" for f in report.get("findings", [])):
            has_critical = True

    _output_results(reports, args)
    return EXIT_CRITICAL if has_critical else EXIT_OK


# ---------------------------------------------------------------------------
# Directory handler
# ---------------------------------------------------------------------------

def _handle_directory(target: Path, args: argparse.Namespace) -> int:
    sol_files = sorted([
        f for f in (target.rglob("*.sol") if args.recursive else target.glob("*.sol"))
        if "node_modules" not in str(f) and "/lib/" not in str(f)
        and not f.name.startswith(".")
    ])
    rs_files = sorted([
        f for f in (target.rglob("*.rs") if args.recursive else target.glob("*.rs"))
        if "target" not in f.parts and not f.name.startswith(".")
    ])

    if not sol_files and not rs_files:
        _print(f"[yellow]Warning:[/yellow] No .sol or .rs files found in '{target}'.")
        return EXIT_OK

    total = len(sol_files) + len(rs_files)

    if not args.json:
        parts = []
        if sol_files: parts.append(f"{len(sol_files)} Solidity")
        if rs_files:  parts.append(f"{len(rs_files)} Rust")
        _print(f"\n[bold green]ChainAudit[/bold green] scanning {total} file(s) ({', '.join(parts)})...\n")

    reports      = []
    has_critical = False

    for sol_file in sol_files:
        if not args.json:
            _print(f"  [dim]→ {sol_file.name}[/dim]")
        report = _scan_file(sol_file, ml_only=args.ml_only)
        reports.append(report)
        if report.get("status") == "success" and any(
            f.get("severity") == "CRITICAL" for f in report.get("findings", [])
        ):
            has_critical = True

    for rs_file in rs_files:
        if not args.json:
            _print(f"  [dim]→ {rs_file.name} [yellow](Solana)[/yellow][/dim]")
        report = _scan_rs_file(rs_file)
        reports.append(report)
        if any(f.get("severity") == "CRITICAL" for f in report.get("findings", [])):
            has_critical = True

    _output_results(reports, args)
    return EXIT_CRITICAL if has_critical else EXIT_OK


# ---------------------------------------------------------------------------
# Main scan command
# ---------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.target).expanduser().resolve()

    if not target.exists():
        _print(f"[red]Error:[/red] '{target}' does not exist.")
        return 2

    # ZIP
    if target.suffix == ".zip":
        return _handle_zip(target, args)

    # Single .rs file
    if target.is_file() and target.suffix == ".rs":
        if not args.json:
            _print(f"\n[bold green]ChainAudit[/bold green] detected [bold yellow]Solana/Rust[/bold yellow] — running Rust scanner...\n")
        report = _scan_rs_file(target)
        _output_results([report], args)
        has_critical = any(f.get("severity") == "CRITICAL" for f in report.get("findings", []))
        return EXIT_CRITICAL if has_critical else EXIT_OK

    # Single .sol file
    if target.is_file() and target.suffix == ".sol":
        if not args.json:
            _print(f"\n[bold green]ChainAudit[/bold green] scanning 1 file...\n")
        report = _scan_file(target, ml_only=args.ml_only)
        _output_results([report], args)
        has_critical = any(f.get("severity") == "CRITICAL" for f in report.get("findings", []))
        return EXIT_CRITICAL if has_critical else EXIT_OK

    # Unsupported file type
    if target.is_file():
        _print(f"[red]Error:[/red] Unsupported file type '{target.suffix}'. Use .sol, .rs, or .zip")
        return 2

    # Directory
    if target.is_dir():
        return _handle_directory(target, args)

    _print(f"[red]Error:[/red] '{target}' is not a valid file or directory.")
    return 2


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chainaudit",
        description="ChainAudit — Smart contract security scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  chainaudit scan contract.sol
  chainaudit scan contract.sol --json
  chainaudit scan contract.sol --ml-only
  chainaudit scan ./contracts --recursive
  chainaudit scan contracts.zip
  chainaudit scan program.rs

Web app: https://chainaudit.vercel.app
        """,
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.1.5",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")
    subparsers.required = True

    scan_parser = subparsers.add_parser("scan", help="Scan a .sol file, .rs file, .zip, or directory")
    scan_parser.add_argument("target", help="Path to a .sol file, .rs file, .zip archive, or directory")
    scan_parser.add_argument("--json",      action="store_true", help="Output full report as JSON")
    scan_parser.add_argument("--ml-only",   action="store_true", dest="ml_only",
                             help="Skip exploit simulation, run ML prediction only")
    scan_parser.add_argument("--recursive", action="store_true",
                             help="Recursively scan all files in a directory")

    return parser


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    try:
        if args.command == "scan":
            sys.exit(cmd_scan(args))
        else:
            parser.print_help()
            sys.exit(2)
    except KeyboardInterrupt:
        _print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)
    except Exception as e:
        _print(f"\n[red]Unexpected error:[/red] {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
