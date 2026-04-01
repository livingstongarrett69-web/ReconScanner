import time
import uuid
from collections import defaultdict, deque

from graph.recon_graph import ReconGraph


class ScanContext:
    def __init__(self, profile="normal"):
        self.scan_id = str(uuid.uuid4())[:8]
        self.profile = profile
        self.start_time = time.time()
        self.scan_complete = False

        self.targets_total = 0
        self.targets_done = 0
        self.modules_run = 0
        self.errors = 0

        self.open_ports = 0
        self.web_services = 0
        self.vulnerabilities = 0
        self.subdomains = 0

        self.results = {}
        self.findings = defaultdict(list)
        self.recent_findings = deque(maxlen=15)
        self.runtime = {}

        self.graph = ReconGraph()

    @property
    def elapsed(self):
        return round(time.time() - self.start_time, 2)

    @property
    def targets_per_second(self):
        if self.elapsed <= 0:
            return 0
        return round(self.targets_done / self.elapsed, 2)

    def add_finding(self, category, finding):
        record = {"category": category, **finding}
        self.findings[category].append(record)
        self.recent_findings.append(record)

        target = finding.get("target")
        self.graph.add_node(target)
        self.graph.add_node(category)
        self.graph.add_edge(target, category, label="has_finding")

        if category == "open_port":
            self.open_ports += 1
            port = finding.get("data", {}).get("port")
            if port is not None:
                self.graph.add_node(f"port:{port}")
                self.graph.add_edge(target, f"port:{port}", label="open")
        elif category == "web_service":
            self.web_services += 1
        elif category == "vulnerability":
            self.vulnerabilities += 1
        elif category == "subdomain":
            self.subdomains += 1
            sub = finding.get("data", {}).get("subdomain")
            if sub:
                self.graph.add_node(sub)
                self.graph.add_edge(target, sub, label="subdomain")