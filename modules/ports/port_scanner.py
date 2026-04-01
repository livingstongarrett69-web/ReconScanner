import asyncio
from interfaces.module import ScanModule


class PortScanner(ScanModule):
    name = "port_scanner"
    stage = "PORT_SCAN"
    dependencies = ["host_discovery"]
    required_context_keys = []
    enabled = True
    timeout = 1

    DEFAULT_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
        443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443
    ]

    async def _check_port(self, target, port):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return port
        except Exception:
            return None

    async def run(self, target, context):
        host_state = context.get("host_discovery", {})
        if not host_state.get("alive", False):
            result = {"open_ports": []}
            context["open_ports"] = []
            context["port_scanner"] = result
            return result

        ports = context.get("scan_ports", self.DEFAULT_PORTS)

        tasks = [self._check_port(target, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports = sorted(
            port for port in results
            if isinstance(port, int)
        )

        result = {"open_ports": open_ports}

        context["open_ports"] = open_ports
        context["port_scanner"] = result

        for port in open_ports:
            context["ctx"].add_finding("open_port", {
                "target": target,
                "summary": f"Port {port} open",
                "data": {"port": port}
            })

        return result