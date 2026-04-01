import asyncio
import socket
from interfaces.module import ScanModule


class ReverseDNS(ScanModule):

    name = "reverse_dns"
    stage = "DNS"
    dependencies = []
    enabled = True
    timeout = 3

    async def run(self, target, context):

        try:

            loop = asyncio.get_running_loop()

            hostname, _, _ = await loop.run_in_executor(
                None,
                socket.gethostbyaddr,
                target
            )

            context["ctx"].add_finding("reverse_dns", {
                "target": target,
                "summary": f"{target} -> {hostname}",
                "data": {"hostname": hostname}
            })

            return {"hostname": hostname}

        except Exception:

            return {"hostname": None}