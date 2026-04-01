import asyncio
from interfaces.module import ScanModule


class HostDiscovery(ScanModule):
    name = "host_discovery"
    stage = "DISCOVERY"
    dependencies = []
    required_context_keys = []
    enabled = True
    timeout = 1

    COMMON_CHECK_PORTS = [80, 443, 22]

    async def _probe_port(self, target, port):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def run(self, target, context):
        checks = [self._probe_port(target, port) for port in self.COMMON_CHECK_PORTS]
        results = await asyncio.gather(*checks, return_exceptions=True)

        alive = any(r is True for r in results)

        result = {"alive": alive}
        context["alive"] = alive
        context["host_discovery"] = result

        if alive:
            context["ctx"].add_finding("host_alive", {
                "target": target,
                "summary": f"{target} appears reachable",
                "data": {"alive": True}
            })

        return result