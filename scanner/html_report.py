"""Self-contained HTML report generation for authorized discovery results."""
from __future__ import annotations

import html
from pathlib import Path
from typing import Any


def generate_html_report(results: dict[str, Any], filepath: str) -> None:
    """Write an escaped, standalone HTML report from structured scan results."""
    rows: list[str] = []
    risk_counts: dict[str, int] = {}
    host_count = len(results.get("targets", {}))

    for target, data in results.get("targets", {}).items():
        for item in data.get("open_ports", []):
            risk = str(item.get("risk", "INFO"))
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
            rows.append(
                "<tr>"
                f"<td>{html.escape(str(target))}</td>"
                f"<td>{html.escape(str(data.get('ip', '')))}</td>"
                f"<td>{html.escape(str(item.get('port', '')))}</td>"
                f"<td>{html.escape(str(item.get('service', 'unknown')))}</td>"
                f"<td>{html.escape(str(item.get('protocol', 'tcp')))}</td>"
                f"<td>{html.escape(str(item.get('product', '')))}</td>"
                f"<td>{html.escape(str(item.get('version', '')))}</td>"
                f"<td><span class=\"risk risk-{html.escape(risk.lower())}\">{html.escape(risk)}</span></td>"
                f"<td>{html.escape(str(item.get('confidence', '')))}</td>"
                f"<td>{html.escape(str(item.get('banner', '')))}</td>"
                "</tr>"
            )

    risk_summary = " ".join(
        f"<span class=\"summary\"><b>{html.escape(k)}</b> {v}</span>"
        for k, v in sorted(risk_counts.items())
    ) or "<span class=\"summary\">No open ports</span>"

    table = "".join(rows) or '<tr><td colspan="10" class="empty">No open ports discovered.</td></tr>'
    title = html.escape(str(results.get("report_title", "Advanced Port Scanner Report")))
    out = Path(filepath)
    out.parent.mkdir(parents=True, exist_ok=True)
    content = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
body{{margin:0;background:#080c10;color:#e8edf3;font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}}
main{{max-width:1400px;margin:auto;padding:36px 5% 60px}}
h1{{margin:0 0 8px}}h2{{margin-top:32px;color:#00e5ff;font-size:16px;letter-spacing:.08em;text-transform:uppercase}}
.card{{background:#0d131b;border:1px solid #1c2938;border-radius:12px;padding:20px;margin:16px 0}}
.meta{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.meta div{{background:#091019;border:1px solid #1c2938;border-radius:9px;padding:14px}}
small{{display:block;color:#7f8da0;margin-bottom:4px}}table{{width:100%;border-collapse:collapse;font-size:12px}}th,td{{padding:10px 8px;text-align:left;border-bottom:1px solid #1c2938;vertical-align:top}}th{{color:#7f8da0;text-transform:uppercase;letter-spacing:.06em}}
.risk{{padding:3px 7px;border-radius:99px;font-weight:700}}.risk-high,.risk-critical{{color:#ff7a92;background:#ff5c7715}}.risk-medium{{color:#ffd166;background:#ffd16615}}.risk-low{{color:#00d084;background:#00d08415}}.risk-info{{color:#00e5ff;background:#00e5ff15}}.summary{{display:inline-block;margin-right:18px;color:#b7c2d0}}.empty{{text-align:center;color:#7f8da0;padding:28px}}.notice{{color:#ffd166;background:#ffd16612;border:1px solid #ffd16630;border-radius:8px;padding:12px}}
@media(max-width:800px){{.meta{{grid-template-columns:1fr 1fr}}table{{min-width:1000px}}}}
</style>
</head>
<body><main>
<h1>{title}</h1>
<div class="notice">Authorized use only. This report is for defensive network discovery. Risk metadata is informational and is not proof of a vulnerability.</div>
<div class="card meta">
<div><small>Schema</small><strong>{html.escape(str(results.get('schema_version','1.0')))}</strong></div>
<div><small>Scan Time</small><strong>{html.escape(str(results.get('scan_time','N/A')))}</strong></div>
<div><small>Duration</small><strong>{html.escape(str(results.get('duration','N/A')))}</strong></div>
<div><small>Hosts / Open Ports</small><strong>{host_count} / {html.escape(str(results.get('total_open',0)))}</strong></div>
</div>
<h2>Risk Overview</h2><div class="card">{risk_summary}</div>
<h2>Discovered Services</h2>
<div class="card" style="overflow:auto"><table><thead><tr><th>Target</th><th>IP</th><th>Port</th><th>Service</th><th>Protocol</th><th>Product</th><th>Version</th><th>Risk</th><th>Confidence</th><th>Banner</th></tr></thead><tbody>{table}</tbody></table></div>
<h2>Methodology</h2><div class="card">TCP reachability checks with optional lightweight, protocol-aware banner identification. OS information is heuristic. Validate findings independently before taking remediation action.</div>
</main></body></html>"""
    out.write_text(content, encoding="utf-8")
