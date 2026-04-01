import asyncio
from interfaces.module import ScanModule


class BannerGrabber(ScanModule):
    name = "banner_grabber"
    stage = "SERVICE"
    dependencies = ["port_scanner"]
    required_context_keys = ["open_ports"]
    enabled = True
    timeout = 2

    BANNER_PORTS = {21, 22, 25, 110, 143}

    async def _grab(self, target, port):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=self.timeout
            )

            banner = b""
            try:
                banner = await asyncio.wait_for(reader.read(512), timeout=1)
            except Exception:
                pass

            if port in (25, 110, 143):
                try:
                    writer.write(b"QUIT\r\n")
                    await writer.drain()
                except Exception:
                    pass

            writer.close()
            await writer.wait_closed()

            text = banner.decode(errors="ignore").strip()
            return text if text else None

        except Exception:
            return None

    async def run(self, target, context):
        open_ports = context.get("open_ports", [])
        interesting = [p for p in open_ports if p in self.BANNER_PORTS]

        if not interesting:
            return {"banners": {}}

        tasks = [self._grab(target, port) for port in interesting]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        banners = {}
        for port, banner in zip(interesting, results):
            if isinstance(banner, str) and banner:
                banners[port] = banner
                context["ctx"].add_finding("banner", {
                    "target": target,
                    "port": port,
                    "summary": f"Banner on {port}: {banner[:80]}",
                    "data": {"banner": banner}
                })

        context["banners"] = banners
        return {"banners": banners}