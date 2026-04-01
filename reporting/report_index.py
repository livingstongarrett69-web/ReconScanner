import json
import os
from datetime import datetime


class ReportIndex:
    def __init__(self, index_file="reports/index.json"):
        self.index_file = index_file
        os.makedirs("reports", exist_ok=True)

    def append(self, ctx, json_report=None, html_report=None):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "scan_id": ctx.scan_id,
            "profile": ctx.profile,
            "targets_total": ctx.targets_total,
            "targets_done": ctx.targets_done,
            "modules_run": ctx.modules_run,
            "errors": ctx.errors,
            "open_ports": ctx.open_ports,
            "web_services": ctx.web_services,
            "vulnerabilities": ctx.vulnerabilities,
            "subdomains": ctx.subdomains,
            "elapsed": ctx.elapsed,
            "json_report": json_report,
            "html_report": html_report,
        }

        data = []
        if os.path.exists(self.index_file):
            try:
                with open(self.index_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                data = []

        data.append(entry)

        with open(self.index_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return self.index_file