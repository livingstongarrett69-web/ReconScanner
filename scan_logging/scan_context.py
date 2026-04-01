class ScanContext:

    def __init__(self, scan_id, logger):

        self.scan_id = scan_id
        self.logger = logger

        self.targets_total = 0
        self.targets_done = 0

        self.modules_run = 0

        self.open_ports = 0
        self.web_services = 0
        self.vulnerabilities = 0

        self.errors = 0