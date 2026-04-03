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

# ---------------------------------------------------------------------------
# FIX: Import resolution for both installed package AND repo dev mode
#
# Problem: The original code used `from chainaudit.xxx import ...` which
# only works when running directly from the repo root (where `src/` exists as
# a real directory on the filesystem). After `pip install`, the package is
# installed as `chainaudit` — there is no `src` package at all, so Python
# raises ModuleNotFoundError: No module named 'src'.
#
# Fix: Import as `chainaudit.xxx` (the installed package name), which works
# in both cases:
#   - Installed via pip:    resolves to site-packages/chainaudit/
#   - Dev mode (pip install -e .):  resolves to src/chainaudit/ via .pth file
#
# The sys.path manipulation below is ONLY kept as a last-resort fallback for
# running cli.py directly as a script (e.g. `python src/chainaudit/cli.py`).
# It is NOT needed for the `chainaudit` console_scripts entrypoint.
# ---------------------------------------------------------------------------

def _ensure_importable() -> None:
    """
    Fallback path injection — only activates when cli.py is run directly
    as a script rather than through the installed `chainaudit` entrypoint.
    Detected by checking if `chainaudit` is already importable.
    """
    try:
        import chainaudit  # noqa: F401 — already installed, nothing to do
    except ImportError:
        # Running as a raw script from repo root — add backend/ to sys.path
        _backend_dir = Path(__file__).resolve().parent.parent.parent
        if str(_backend_dir) not in sys.path:
            sys.path.insert(0, str(_backend_dir))

_ensure_importable()

from chainaudit.scanner_router import route_scan, route_zip_scan  # noqa: E402

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

# Chain display labels and rich colors for CLI output
_CHAIN_DISPLAY: dict[str, tuple[str, str]] = {
    # chain_key: (label, rich_color)
    "solana":    ("SOLANA",    "yellow"),
    "ethereum":  ("ETHEREUM",  "cyan"),
    "arbitrum":  ("ARBITRUM",  "blue"),
    "optimism":  ("OPTIMISM",  "red"),
    "base":      ("BASE",      "bright_blue"),
    "polygon":   ("POLYGON",   "magenta"),
    "bnb":       ("BNB",       "bright_yellow"),
    "avalanche": ("AVAX",      "red"),
    "l2":        ("L2",        "cyan"),
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


def _chain_label(chain: str) -> str:
    """Return display label for a chain key, e.g. 'arbitrum' → 'ARBITRUM'."""
    return _CHAIN_DISPLAY.get(chain.lower(), (chain.upper(), "cyan"))[0]


def _chain_color(chain: str) -> str:
    """Return rich color string for a chain key."""
    return _CHAIN_DISPLAY.get(chain.lower(), (chain.upper(), "cyan"))[1]


def _chain_suffix(chain: str, is_anchor: bool = False) -> str:
    """
    Return the chain suffix string for report headers.
    Ethereum returns empty string (it's the default, no need to annotate).
    All other chains return '  · LABEL' (plus '  · ANCHOR' for Solana anchors).
    """
    label = _CHAIN_DISPLAY.get(chain.lower(), (chain.upper() if chain else "", "cyan"))[0]
    if not label or chain.lower() == "ethereum":
        return ""
    suffix = f"  · {label}"
    if chain.lower() == "solana" and is_anchor:
        suffix += "  · ANCHOR"
    return suffix


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
                    sev = f.get("severity", "LOW")
                    f["ml_exploitability"] = sev
                    f["ml_confidence"]     = _SEVERITY_CONFIDENCE.get(sev, 0.5)

            else:
                # EVM path — finding dict has 'impact' AND 'confidence' fields
                if HAS_ML:
                    raw_check = f.get("check", "").lower()
                    check = _SLITHER_TO_ML.get(raw_check, raw_check)

                    impact     = f.get("impact", "Medium").strip().capitalize()
                    confidence = f.get("confidence", "Medium").strip().capitalize()

                    evm_finding = {
                        "check":      check,
                        "impact":     impact,
                        "confidence": confidence,
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
    try:
        result = route_scan(sol_file, ml_only=ml_only)
        result["file"] = sol_file.name
        return result
    except Exception as e:
        return {
            "file": sol_file.name,
            "status": "error",
            "error": str(e),
            "findings": [],
            "risk_score": 0,
            "total_findings": 0,
        }


# ---------------------------------------------------------------------------
# Scan a single Solana .rs file
# ---------------------------------------------------------------------------

def _scan_rs_file(rs_file: Path) -> dict:
    """Scan one .rs file via scanner_router and add ML predictions."""
    try:
        report = route_scan(rs_file)
        report["file"] = rs_file.name
        contract_size = len(rs_file.read_text(errors="ignore")) if rs_file.is_file() else 500
        report["findings"] = _add_ml_predictions(
            report.get("findings", []), contract_size, is_solana=True
        )
        report["total_findings"] = len(report.get("findings", []))
        return report
    except Exception as e:
        return {
            "file": rs_file.name,
            "status": "error",
            "error": str(e),
            "chain": "solana",
            "risk_score": 0,
            "total_findings": 0,
            "findings": [],
        }


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

    risk      = report.get("risk_score", 0)
    rl        = _risk_label(risk)
    rs        = _risk_style(risk)
    findings  = report.get("findings", [])
    chain     = report.get("chain", "ethereum")
    is_anchor = report.get("is_anchor", False)
    suffix    = _chain_suffix(chain, is_anchor)

    header = Text()
    if show_file:
        header.append(f"{report.get('file', '')}\n", style="bold white")
    header.append("Risk Score: ", style="white")
    header.append(f"{risk}/100", style=rs)
    header.append(f"  [{rl}]{suffix}", style=rs)
    header.append(f"\nFindings: {len(findings)}", style="white")

    console.print(Panel(header, title="[bold]ChainAudit Report[/bold]", border_style="green"))

    if not findings:
        console.print("  [green]✓ No vulnerabilities detected.[/green]\n")
        return

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white")
    table.add_column("#",             style="dim", width=4)
    table.add_column("Title",         min_width=28)
    table.add_column("Severity",      width=10)
    table.add_column("Confidence",    width=11)
    table.add_column("Occurrences",   width=12)
    table.add_column("ML Prediction", width=22)

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
    chain  = report.get("chain", "ethereum")
    label  = _chain_label(chain)
    anchor = " · ANCHOR" if report.get("is_anchor") and chain == "solana" else ""
    print(f"Risk Score : {report.get('risk_score', 0)}/100")
    print(f"Chain      : {label}{anchor}")
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
    table.add_column("Chain",    width=12)
    table.add_column("Score",    width=7)
    table.add_column("Findings", width=10)
    table.add_column("Status",   width=10)

    for r in reports:
        chain  = r.get("chain", "ethereum")
        label  = _chain_label(chain)
        color  = _chain_color(chain)

        if r.get("status") == "error":
            table.add_row(
                Path(r.get("file", "unknown")).name,
                f"[{color}]{label}[/{color}]",
                "—", "—", "[red]error[/red]",
            )
            continue

        risk = r.get("risk_score", 0)
        rs   = _risk_style(risk)
        table.add_row(
            Path(r.get("file", "unknown")).name,
            f"[{color}]{label}[/{color}]",
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
                "has_evm":    any(r.get("chain", "ethereum") != "solana" for r in reports),
                "has_solana": any(r.get("chain") == "solana" for r in reports),
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

Supported chains (auto-detected):
  Ethereum · Arbitrum · Optimism · Base · Polygon · BNB · Avalanche · Solana

Web app: https://chainaudit.vercel.app
        """,
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.2.2",
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