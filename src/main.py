import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path

from jinja2 import Template
from rich.console import Console
from rich.table import Table

from scanner import run_slither, parse_slither_report
from exploit_simulator import run_foundry_tests
from rules import RULES

console = Console()


def map_severity(slither_impact: str) -> str:
    if not slither_impact:
        return "LOW"
    impact = slither_impact.upper()
    if impact == "HIGH":
        return "HIGH"
    if impact == "MEDIUM":
        return "MEDIUM"
    return "LOW"


def enrich_findings(slither_findings: list[dict]) -> list[dict]:
    enriched = []

    for f in slither_findings:
        check = (f.get("check") or "").lower()
        rule = None

        if "reentrancy" in check:
            rule = RULES.get("reentrancy")
        elif "tx-origin" in check or "tx.origin" in check:
            rule = RULES.get("tx-origin")
        elif "unchecked" in check or "low-level" in check:
            rule = RULES.get("unchecked-lowlevel")
        elif "access-control" in check or "authorization" in check:
            rule = RULES.get("access-control")

        if rule:
            severity = rule.severity
            title = rule.title
            fix = rule.fix
        else:
            severity = map_severity(f.get("impact"))
            title = f.get("check") or "Unknown Finding"
            fix = "Review and apply best practices."

        enriched.append(
            {
                "check": f.get("check"),
                "impact": f.get("impact"),
                "confidence": f.get("confidence"),
                "description": f.get("description"),
                "severity": severity,
                "title": title,
                "fix": fix,
            }
        )

    return enriched


def calculate_risk_score(findings: list[dict]) -> int:
    score = 0
    for f in findings:
        sev = f["severity"]
        if sev == "CRITICAL":
            score += 40
        elif sev == "HIGH":
            score += 25
        elif sev == "MEDIUM":
            score += 15
        elif sev == "LOW":
            score += 5
    return min(score, 100)


def print_summary(findings: list[dict]):
    table = Table(title="Audit Findings Summary")
    table.add_column("Severity", style="bold")
    table.add_column("Title")
    table.add_column("Check")
    table.add_column("Confidence")

    if not findings:
        table.add_row("-", "No findings", "-", "-")
        console.print(table)
        return

    for f in findings:
        table.add_row(
            f["severity"],
            f["title"],
            str(f["check"]),
            str(f["confidence"]),
        )

    console.print(table)


def build_html(report: dict) -> str:
    html_template = Template("""
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <title>Smart Contract Audit Report</title>
  <style>
    body { font-family: Arial, sans-serif; padding: 20px; }
    .card { border: 1px solid #ddd; border-radius: 12px; padding: 14px; margin: 12px 0; }
    .sev { font-weight: bold; }
    .CRITICAL { color: red; }
    .HIGH { color: darkorange; }
    .MEDIUM { color: goldenrod; }
    .LOW { color: green; }
    code { background: #f2f2f2; padding: 2px 6px; border-radius: 6px; }
  </style>
</head>
<body>
  <h1>Smart Contract Audit Report</h1>

  <p><b>Target:</b> {{ target }}</p>
  <p><b>Generated:</b> {{ timestamp }}</p>
  <p><b>Total Findings:</b> {{ total_findings }}</p>
  <p><b>Risk Score:</b> {{ risk_score }}/100</p>
  <p><b>Exploit Simulation:</b> {{ "PASSED ✅" if exploit_success else "FAILED ❌" }}</p>

  {% for f in findings %}
  <div class="card">
    <div class="sev {{ f.severity }}">Severity: {{ f.severity }}</div>
    <p><b>Title:</b> {{ f.title }}</p>
    <p><b>Tool Check:</b> <code>{{ f.check }}</code></p>
    <p><b>Impact:</b> {{ f.impact }}</p>
    <p><b>Confidence:</b> {{ f.confidence }}</p>
    <p><b>Description:</b> {{ f.description }}</p>
    <p><b>Fix:</b> {{ f.fix }}</p>
  </div>
  {% endfor %}
</body>
</html>
""")

    return html_template.render(**report)


def auto_open_file(path: Path):
    try:
        subprocess.run(["explorer.exe", str(path)], check=False)
    except Exception:
        pass


def parse_args():
    parser = argparse.ArgumentParser(description="Smart Contract Auditor 😈")
    parser.add_argument(
        "--target",
        default="contracts",
        help="Target file or folder to scan (default: contracts)",
    )
    parser.add_argument(
        "--out",
        default="reports",
        help="Output folder for reports (default: reports)",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Auto-open HTML report after generation",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    target = args.target
    out_dir = Path(args.out)
    out_dir.mkdir(exist_ok=True)

    console.print("\n[bold cyan]Smart Contract Auditor[/bold cyan] 😈\n")
    console.print(f"[bold]Target:[/bold] {target}")
    console.print("Running Slither scan...\n")

    run_slither(target)

    # If slither.json exists, scan worked
    if not Path("reports/slither.json").exists():
        console.print("[bold red]Slither scan failed (no slither.json generated)[/bold red]")
        return

    slither_findings = parse_slither_report()
    enriched = enrich_findings(slither_findings)

    print_summary(enriched)

    risk_score = calculate_risk_score(enriched)

    if risk_score >= 70:
        console.print(f"\n[bold red]Overall Risk Score: {risk_score}/100 (HIGH RISK)[/bold red]")
    elif risk_score >= 40:
        console.print(f"\n[bold yellow]Overall Risk Score: {risk_score}/100 (MEDIUM RISK)[/bold yellow]")
    else:
        console.print(f"\n[bold green]Overall Risk Score: {risk_score}/100 (LOW RISK)[/bold green]")

    console.print("\n[bold yellow]Running exploit simulation (Foundry tests)...[/bold yellow]")
    sim = run_foundry_tests(verbose=True)

    exploit_success = bool(sim.get("success"))

    if exploit_success:
        console.print("[bold green]Exploit simulation PASSED[/bold green] ✅")
    else:
        console.print("[bold red]Exploit simulation FAILED[/bold red] ❌")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target_name = Path(target).name.replace(".sol", "")
    report_name = f"{safe_target_name}_audit_{timestamp}"

    report = {
        "target": target,
        "timestamp": timestamp,
        "total_findings": len(enriched),
        "risk_score": risk_score,
        "exploit_success": exploit_success,
        "findings": enriched,
    }

    json_path = out_dir / f"{report_name}.json"
    html_path = out_dir / f"{report_name}.html"

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    html_path.write_text(build_html(report), encoding="utf-8")

    console.print("\n[bold green]Reports generated:[/bold green]")
    console.print(f" - {json_path}")
    console.print(f" - {html_path}\n")

    if args.open:
        auto_open_file(html_path)


if __name__ == "__main__":
    main()
