import json
from datetime import datetime
from pathlib import Path
from jinja2 import Template


HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Smart Contract Audit Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 30px; }
    h1 { margin-bottom: 5px; }
    .meta { margin-bottom: 20px; }
    .card { border: 1px solid #ddd; padding: 18px; border-radius: 10px; margin-bottom: 16px; }
    .critical { color: #b00020; font-weight: bold; }
    .high { color: #d97706; font-weight: bold; }
    .medium { color: #2563eb; font-weight: bold; }
    .low { color: #16a34a; font-weight: bold; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 999px; background: #f2f2f2; font-size: 12px; }
    code { background: #f6f6f6; padding: 2px 6px; border-radius: 6px; }
    .score { font-size: 20px; font-weight: bold; }
  </style>
</head>
<body>

<h1>Smart Contract Audit Report</h1>

<div class="meta">
  <p><b>Project:</b> {{ project }}</p>
  <p><b>Target:</b> {{ target }}</p>
  <p><b>Generated:</b> {{ generated }}</p>
  <p><b>Total Findings:</b> {{ total_findings }}</p>
  <p class="score"><b>Risk Score:</b> {{ risk_score }}/100</p>
  <p><b>Exploit Simulation:</b> {{ "PASSED ✅" if exploit_simulation.success else "FAILED ❌" }}</p>
</div>

{% for f in findings %}
<div class="card">
  <div>
    <span class="{% if f.severity == 'CRITICAL' %}critical{% elif f.severity == 'HIGH' %}high{% elif f.severity == 'MEDIUM' %}medium{% else %}low{% endif %}">
      Severity: {{ f.severity }}
    </span>
  </div>

  <p><b>Title:</b> {{ f.title }}</p>
  <p><b>Tool Check:</b> <span class="badge">{{ f.check }}</span></p>
  <p><b>Impact:</b> {{ f.impact }}</p>
  <p><b>Confidence:</b> {{ f.confidence }}</p>

  <p><b>Description:</b> {{ f.description }}</p>
  <p><b>Fix:</b> {{ f.fix }}</p>
</div>
{% endfor %}

</body>
</html>
"""


def _safe_name(name: str) -> str:
    # make filename safe
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)


def build_report(project: str, findings: list[dict], target: str, risk_score: int, exploit_simulation: dict):
    return {
        "project": project,
        "target": target,
        "generated": datetime.utcnow().isoformat(),
        "total_findings": len(findings),
        "risk_score": risk_score,
        "findings": findings,
        "exploit_simulation": exploit_simulation,
    }


def save_json(report: dict, out_path: Path):
    out_path.parent.mkdir(exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def save_html(report: dict, out_path: Path):
    out_path.parent.mkdir(exist_ok=True)
    template = Template(HTML_TEMPLATE)
    html = template.render(**report)
    out_path.write_text(html, encoding="utf-8")
