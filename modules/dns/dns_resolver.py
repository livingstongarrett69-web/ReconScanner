import asyncio
import socket
from interfaces.module import ScanModule


class DNSResolver(ScanModule):
    name = "dns_resolver"
    stage = "DNS"
    dependencies = []
    required_context_keys = []
    enabled = True
    timeout = 3

    def _looks_like_ip(self, value):
        parts = value.split(".")
        if len(parts) != 4:
            return False
        return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

    async def _reverse_lookup(self, target):
        try:
            loop = asyncio.get_running_loop()
            host, _, _ = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, target),
                timeout=self.timeout
            )
            return host
        except Exception:
            return None

    async def _forward_lookup(self, target):
        try:
            loop = asyncio.get_running_loop()
            _, _, ips = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname_ex, target),
                timeout=self.timeout
            )
            return ips
        except Exception:
            return []

    async def run(self, target, context):
        result = {}

        if self._looks_like_ip(target):
            hostname = await self._reverse_lookup(target)
            result["reverse_dns"] = hostname

            if hostname:
                context["ctx"].add_finding("reverse_dns", {
                    "target": target,
                    "summary": f"{target} -> {hostname}",
                    "data": {"hostname": hostname}
                })
        else:
            ips = await self._forward_lookup(target)
            result["resolved_ips"] = ips

            for ip in ips:
                context["ctx"].add_finding("resolved_ip", {
                    "target": target,
                    "summary": f"{target} -> {ip}",
                    "data": {"ip": ip}
                })

        context["dns"] = result
        context["dns_resolver"] = result
        return result