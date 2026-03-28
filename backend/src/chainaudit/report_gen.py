import json
from pathlib import Path
from jinja2 import Template

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Audit Report</title>
</head>
<body>
<h1>Smart Contract Audit</h1>

<p><b>Target:</b> {{ target }}</p>
<p><b>Risk Score:</b> {{ risk_score }}/100</p>
<p><b>Total Findings:</b> {{ total_findings }}</p>

{% for f in findings %}
<div>
  <h3>{{ f.title }} ({{ f.severity }})</h3>
  <p>{{ f.description }}</p>
  <p><b>Fix:</b> {{ f.fix }}</p>
</div>
{% endfor %}

</body>
</html>
"""


def save_json(report: dict, scan_id: str):
    REPORTS_DIR.mkdir(exist_ok=True)
    out_path = REPORTS_DIR / f"{scan_id}.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def save_html(report: dict, scan_id: str):
    REPORTS_DIR.mkdir(exist_ok=True)
    out_path = REPORTS_DIR / f"{scan_id}.html"
    html = Template(HTML_TEMPLATE).render(**report)
    out_path.write_text(html, encoding="utf-8")