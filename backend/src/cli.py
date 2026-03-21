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

from src.scanner import run_slither, parse_slither_report
from src.rules import compute_risk_score
from src.exploit_simulator import run_foundry_tests

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
    from ml.predictor import predictor as ml_predictor
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

# Temp dirs created during zip extraction — cleaned up at exit
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


def _collect_sol_files(target: Path, recursive: bool) -> list[Path]:
    """Return all .sol files from a .sol file, .zip archive, or directory."""

    # --- ZIP ---
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

    # --- Single .sol file ---
    if target.is_file():
        if target.suffix != ".sol":
            _print(f"[red]Error:[/red] '{target}' is not a .sol or .zip file.")
            sys.exit(2)
        return [target]

    # --- Directory ---
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


def _add_ml_predictions(findings: list[dict], contract_size: int) -> list[dict]:
    """Attach ML exploitability predictions to each finding."""
    if not HAS_ML:
        return findings
    for f in findings:
        try:
            result = ml_predictor.predict(f, contract_size)
            f["ml_exploitability"] = result.get("exploitability", "unknown")
            f["ml_confidence"] = result.get("confidence", 0.0)
        except Exception:
            f["ml_exploitability"] = "unknown"
            f["ml_confidence"] = 0.0
    return findings


# ---------------------------------------------------------------------------
# Scan a single file
# ---------------------------------------------------------------------------

def _scan_file(sol_file: Path, ml_only: bool) -> dict:
    """Run the full scan pipeline on a single .sol file."""
    scan_id = str(uuid.uuid4())

    # Change to backend dir so relative imports inside modules work correctly
    original_dir = os.getcwd()
    os.chdir(_BACKEND_DIR)

    try:
        slither_ok = run_slither(str(sol_file))
        if not slither_ok:
            return {
                "file": str(sol_file),
                "status": "error",
                "error": "Slither failed — possible syntax error or unsupported pragma",
                "findings": [],
                "risk_score": 0,
                "total_findings": 0,
            }

        findings = parse_slither_report(target=str(sol_file))
        risk_score = compute_risk_score(findings)

        contract_size = len(sol_file.read_text(errors="ignore"))
        findings = _add_ml_predictions(findings, contract_size)

        simulation = {"success": False, "stdout": "", "stderr": "skipped"}
        if not ml_only:
            try:
                simulation = run_foundry_tests(verbose=False)
            except Exception as e:
                simulation = {"success": False, "stdout": "", "stderr": str(e)}

        return {
            "scan_id": scan_id,
            "file": str(sol_file),
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
# Human-readable output
# ---------------------------------------------------------------------------

def _print_report(report: dict, show_file: bool = False) -> None:
    if not HAS_RICH or not console:
        _print_report_plain(report, show_file)
        return

    if report["status"] == "error":
        label = f"\n{report['file']}" if show_file else ""
        console.print(Panel(
            f"[red]{report['error']}[/red]{label}",
            title="[bold red]Scan Failed[/bold red]",
            border_style="red",
        ))
        return

    risk = report["risk_score"]
    if risk >= 80:
        score_style, risk_label = "bold red", "CRITICAL RISK"
    elif risk >= 60:
        score_style, risk_label = "bold orange1", "HIGH RISK"
    elif risk >= 40:
        score_style, risk_label = "bold yellow", "MEDIUM RISK"
    elif risk >= 20:
        score_style, risk_label = "bold cyan", "LOW RISK"
    else:
        score_style, risk_label = "bold green", "MINIMAL RISK"

    header = Text()
    if show_file:
        header.append(f"{report['file']}\n", style="bold white")
    header.append("Risk Score: ", style="white")
    header.append(f"{risk}/100", style=score_style)
    header.append(f"  [{risk_label}]", style=score_style)
    header.append(f"\nFindings: {report['total_findings']}", style="white")

    console.print(Panel(header, title="[bold]ChainAudit Report[/bold]", border_style="green"))

    if not report["findings"]:
        console.print("  [green]✓ No vulnerabilities detected.[/green]\n")
        return

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white")
    table.add_column("#", style="dim", width=4)
    table.add_column("Title", min_width=28)
    table.add_column("Severity", width=10)
    table.add_column("Confidence", width=11)
    table.add_column("Occurrences", width=12)
    table.add_column("ML Prediction", width=20)

    for i, f in enumerate(report["findings"], 1):
        sev = f.get("severity", "LOW")
        ml_exp = f.get("ml_exploitability", "")
        ml_conf = f.get("ml_confidence", 0.0)
        ml_str = f"{ml_exp} ({int(ml_conf * 100)}%)" if ml_exp and ml_exp != "unknown" else "—"

        table.add_row(
            str(i),
            f["title"],
            f"[{_severity_color(sev)}]{sev}[/{_severity_color(sev)}]",
            f.get("confidence", "—"),
            str(f.get("occurrences", 1)),
            ml_str,
        )

    console.print(table)

    for i, f in enumerate(report["findings"], 1):
        sev = f.get("severity", "LOW")
        color = _severity_color(sev)
        console.print(f"\n  [{color}][{i}] {f['title']}[/{color}]")
        console.print(f"  [dim]Description:[/dim] {f['description']}")
        console.print(f"  [green]Fix:[/green] {f['fix']}")

    console.print()


def _print_report_plain(report: dict, show_file: bool = False) -> None:
    sep = "-" * 60
    if show_file:
        print(f"\nFile: {report['file']}")
    print(sep)
    if report["status"] == "error":
        print(f"ERROR: {report['error']}")
        print(sep)
        return
    print(f"Risk Score : {report['risk_score']}/100")
    print(f"Findings   : {report['total_findings']}")
    print(sep)
    for i, f in enumerate(report["findings"], 1):
        print(f"[{i}] {f['title']} | {f.get('severity')} | {f.get('confidence')}")
        print(f"    {f['description']}")
        print(f"    Fix: {f['fix']}")
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
    table.add_column("File", min_width=30)
    table.add_column("Score", width=7)
    table.add_column("Findings", width=10)
    table.add_column("Status", width=10)

    for r in reports:
        if r["status"] == "error":
            table.add_row(Path(r["file"]).name, "—", "—", "[red]error[/red]")
            continue

        risk = r["risk_score"]
        if risk >= 80:
            score_str = f"[bold red]{risk}[/bold red]"
        elif risk >= 60:
            score_str = f"[bold orange1]{risk}[/bold orange1]"
        elif risk >= 40:
            score_str = f"[bold yellow]{risk}[/bold yellow]"
        else:
            score_str = f"[bold green]{risk}[/bold green]"

        table.add_row(
            Path(r["file"]).name,
            score_str,
            str(r["total_findings"]),
            "[green]ok[/green]",
        )

    console.print(table)

    for r in reports:
        if r["status"] == "success" and r["findings"]:
            _print_report(r, show_file=True)


# ---------------------------------------------------------------------------
# Scan command
# ---------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.target).expanduser().resolve()
    sol_files = _collect_sol_files(target, recursive=args.recursive)
    multi = len(sol_files) > 1

    if not args.json:
        _print(f"\n[bold green]ChainAudit[/bold green] scanning {len(sol_files)} file(s)...\n")

    reports = []
    has_critical = False

    for sol_file in sol_files:
        if not args.json and multi:
            _print(f"  [dim]→ {sol_file.name}[/dim]")

        report = _scan_file(sol_file, ml_only=args.ml_only)
        reports.append(report)

        if report.get("status") == "success":
            if any(f.get("severity") == "CRITICAL" for f in report.get("findings", [])):
                has_critical = True

    if args.json:
        if multi:
            output = {
                "type": "multi",
                "total_files": len(reports),
                "scanned": sum(1 for r in reports if r["status"] == "success"),
                "overall_risk_score": max(
                    (r["risk_score"] for r in reports if r["status"] == "success"), default=0
                ),
                "total_findings": sum(r.get("total_findings", 0) for r in reports),
                "files": reports,
            }
        else:
            output = reports[0]
        print(json.dumps(output, indent=2))
    else:
        if multi:
            _print_multi_summary(reports)
        else:
            _print_report(reports[0])

    return EXIT_CRITICAL if has_critical else EXIT_OK


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


        """,
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0.6",
    )
    

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")
    subparsers.required = True

    scan_parser = subparsers.add_parser("scan", help="Scan a .sol file, .zip, or directory")
    scan_parser.add_argument(
        "target",
        help="Path to a .sol file, .zip archive, or directory of contracts",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Output full report as JSON",
    )
    scan_parser.add_argument(
        "--ml-only",
        action="store_true",
        dest="ml_only",
        help="Skip exploit simulation, run ML prediction only",
    )
    scan_parser.add_argument(
        "--recursive",
        action="store_true",
        help="Recursively scan all .sol files in a directory",
    )

    return parser


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "scan":
            exit_code = cmd_scan(args)
            sys.exit(exit_code)
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