from interfaces.module import ScanModule


class ServiceDetector(ScanModule):

    name = "service_detector"
    stage = "SERVICE"
    dependencies = ["port_scanner"]
    required_context_keys = ["open_ports"]
    enabled = True

    PORT_MAP = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        139: "netbios",
        143: "imap",
        443: "https",
        445: "smb",
        3306: "mysql",
        3389: "rdp",
        5900: "vnc",
    }

    async def run(self, target, context):

        ports = context.get("open_ports", [])
        banners = context.get("banners", {})
        headers = context.get("http_headers", [])

        services = {}

        for port in ports:

            service = self.PORT_MAP.get(port, "unknown")

            banner = banners.get(port, "").lower()

            if "openssh" in banner:
                service = "ssh"
            elif "smtp" in banner:
                service = "smtp"

            services[port] = service

            context["ctx"].add_finding("service", {
                "target": target,
                "summary": f"{service} on port {port}",
                "data": {"port": port, "service": service}
            })

        context["services"] = services

        return {"services": services}