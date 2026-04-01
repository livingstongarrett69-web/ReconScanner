import time
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table


class ScanDashboard:
    def __init__(self, ctx):
        self.ctx = ctx

    def build_metrics(self):
        table = Table(title="Recon Scan Status")
        table.add_column("Metric")
        table.add_column("Value")

        table.add_row("Scan ID", self.ctx.scan_id)
        table.add_row("Profile", self.ctx.profile)
        table.add_row("Targets", f"{self.ctx.targets_done}/{self.ctx.targets_total}")
        table.add_row("Modules Run", str(self.ctx.modules_run))
        table.add_row("Open Ports", str(self.ctx.open_ports))
        table.add_row("Web Services", str(self.ctx.web_services))
        table.add_row("Subdomains", str(self.ctx.subdomains))
        table.add_row("Vulnerabilities", str(self.ctx.vulnerabilities))
        table.add_row("Errors", str(self.ctx.errors))
        table.add_row("Elapsed", f"{self.ctx.elapsed}s")
        table.add_row("Targets/sec", str(self.ctx.targets_per_second))

        return table

    def build_recent_findings(self):
        table = Table(title="Recent Findings")
        table.add_column("Category")
        table.add_column("Target")
        table.add_column("Summary")

        if not self.ctx.recent_findings:
            table.add_row("-", "-", "-")
            return table

        for item in list(self.ctx.recent_findings)[-8:]:
            table.add_row(
                item.get("category", "-"),
                item.get("target", "-"),
                item.get("summary", "-")[:90]
            )

        return table

    def build_top_categories(self):
        table = Table(title="Top Finding Categories")
        table.add_column("Category")
        table.add_column("Count")

        if not self.ctx.findings:
            table.add_row("-", "0")
            return table

        ranked = sorted(
            ((k, len(v)) for k, v in self.ctx.findings.items()),
            key=lambda x: x[1],
            reverse=True
        )[:8]

        for category, count in ranked:
            table.add_row(category, str(count))

        return table

    def build(self):
        return Group(
            Panel(self.build_metrics()),
            Panel(self.build_recent_findings()),
            Panel(self.build_top_categories()),
        )

    def run(self):
        with Live(self.build(), refresh_per_second=4) as live:
            while not self.ctx.scan_complete:
                live.update(self.build())
                time.sleep(0.25)

            live.update(self.build())