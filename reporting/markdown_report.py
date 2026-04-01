import json
import os


class Reporter:
    def save_json(self, ctx):
        os.makedirs("reports", exist_ok=True)

        filename = os.path.join(
            "reports",
            f"{ctx.scan_id}.json"
        )

        payload = {
            "scan_id": ctx.scan_id,
            "profile": ctx.profile,
            "elapsed": ctx.elapsed,
            "targets": {
                "total": ctx.targets_total,
                "done": ctx.targets_done,
            },
            "stats": {
                "modules_run": ctx.modules_run,
                "errors": ctx.errors,
                "open_ports": ctx.open_ports,
                "web_services": ctx.web_services,
                "vulnerabilities": ctx.vulnerabilities,
                "subdomains": ctx.subdomains,
            },
            "results": ctx.results,
            "findings": dict(ctx.findings),
        }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        return filename