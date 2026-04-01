import html
import os


class HTMLReporter:
    SEVERITY_COLORS = {
        "info": "#3b82f6",
        "low": "#22c55e",
        "medium": "#f59e0b",
        "high": "#ef4444",
        "critical": "#7c3aed",
    }

    def _badge(self, severity):
        color = self.SEVERITY_COLORS.get(severity, "#6b7280")
        return (
            f"<span style='display:inline-block;padding:0.2rem 0.55rem;"
            f"border-radius:999px;background:{color};color:white;"
            f"font-size:0.8rem;font-weight:bold;text-transform:uppercase;'>"
            f"{html.escape(severity)}</span>"
        )

    def save_html(self, ctx):
        os.makedirs("reports", exist_ok=True)

        filename = os.path.join("reports", f"{ctx.scan_id}.html")
        json_name = f"{ctx.scan_id}.json"
        md_name = f"{ctx.scan_id}.md"
        graph_json_name = f"{ctx.scan_id}_graph.json"
        graph_html_name = f"{ctx.scan_id}_graph.html"
        graph_txt_name = f"{ctx.scan_id}_graph_summary.txt"

        all_findings = []
        for category, items in ctx.findings.items():
            for item in items:
                all_findings.append(item)

        severity_rank = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }

        top_findings = sorted(
            all_findings,
            key=lambda x: severity_rank.get(x.get("severity", "info"), 0),
            reverse=True,
        )[:20]

        top_findings_html = []
        if top_findings:
            top_findings_html.append("<ul>")
            for item in top_findings:
                sev = item.get("severity", "info")
                top_findings_html.append(
                    "<li style='margin-bottom:0.6rem;'>"
                    f"{self._badge(sev)} "
                    f"<strong>{html.escape(str(item.get('target')))}</strong> — "
                    f"{html.escape(str(item.get('summary')))}"
                    "</li>"
                )
            top_findings_html.append("</ul>")
        else:
            top_findings_html.append("<p>No findings recorded.</p>")

        findings_html = []
        for category, items in ctx.findings.items():
            findings_html.append(f"<h2>{html.escape(category)}</h2>")
            findings_html.append("<div class='card'>")
            findings_html.append("<ul>")
            for item in items[:250]:
                sev = item.get("severity", "info")
                findings_html.append(
                    "<li style='margin-bottom:0.6rem;'>"
                    f"{self._badge(sev)} "
                    f"<strong>{html.escape(str(item.get('target')))}</strong> — "
                    f"{html.escape(str(item.get('summary')))}"
                    "</li>"
                )
            findings_html.append("</ul>")
            findings_html.append("</div>")

        results_html = []
        for target, result in ctx.results.items():
            results_html.append("<details class='card'>")
            results_html.append(f"<summary><strong>{html.escape(str(target))}</strong></summary>")
            results_html.append(f"<pre>{html.escape(str(result))}</pre>")
            results_html.append("</details>")

        doc = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Recon Scan Report</title>
<style>
body {{
  font-family: Arial, sans-serif;
  margin: 2rem;
  background: #f7f7f7;
  color: #222;
}}
.card {{
  background: white;
  padding: 1rem;
  border-radius: 10px;
  margin-bottom: 1rem;
  box-shadow: 0 1px 4px rgba(0,0,0,0.08);
}}
pre {{
  white-space: pre-wrap;
  word-break: break-word;
  background: #fafafa;
  padding: 1rem;
  border-radius: 8px;
}}
h1, h2 {{
  color: #111;
}}
.links a {{
  margin-right: 1rem;
}}
summary {{
  cursor: pointer;
}}
</style>
</head>
<body>
<h1>Recon Scan Report</h1>

<div class="card">
<p><strong>Scan ID:</strong> {html.escape(ctx.scan_id)}</p>
<p><strong>Profile:</strong> {html.escape(ctx.profile)}</p>
<p><strong>Targets:</strong> {ctx.targets_done}/{ctx.targets_total}</p>
<p><strong>Modules Run:</strong> {ctx.modules_run}</p>
<p><strong>Open Ports:</strong> {ctx.open_ports}</p>
<p><strong>Web Services:</strong> {ctx.web_services}</p>
<p><strong>Subdomains:</strong> {ctx.subdomains}</p>
<p><strong>Vulnerabilities:</strong> {ctx.vulnerabilities}</p>
<p><strong>Errors:</strong> {ctx.errors}</p>
<p><strong>Elapsed:</strong> {ctx.elapsed}s</p>
</div>

<div class="card links">
<h2>Artifacts</h2>
<p>
<a href="{html.escape(json_name)}">{html.escape(json_name)}</a>
<a href="{html.escape(md_name)}">{html.escape(md_name)}</a>
<a href="{html.escape(graph_json_name)}">{html.escape(graph_json_name)}</a>
<a href="{html.escape(graph_html_name)}">{html.escape(graph_html_name)}</a>
<a href="{html.escape(graph_txt_name)}">{html.escape(graph_txt_name)}</a>
</p>
</div>

<div class="card">
<h2>Top Findings</h2>
{''.join(top_findings_html)}
</div>

<div>
<h2>Findings by Category</h2>
{''.join(findings_html)}
</div>

<div>
<h2>Per-Target Results</h2>
{''.join(results_html)}
</div>
</body>
</html>
"""
        with open(filename, "w", encoding="utf-8") as f:
            f.write(doc)

        return filename