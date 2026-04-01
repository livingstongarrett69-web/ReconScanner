import aiohttp
from interfaces.module import ScanModule


class AdminPanelFinder(ScanModule):
    name = "admin_panel_finder"
    stage = "WEB"
    dependencies = ["http_probe"]
    required_context_keys = ["web_targets"]
    enabled = True
    timeout = 4

    COMMON_PATHS = [
        "/admin",
        "/login",
        "/wp-admin",
        "/administrator",
        "/dashboard",
        "/user/login",
        "/admin/login",
        "/signin",
        "/manage",
    ]

    async def _check(self, session, base_url, path):
        url = base_url.rstrip("/") + path
        try:
            async with session.get(url, allow_redirects=True) as resp:
                if resp.status in (200, 401, 403):
                    return {
                        "url": str(resp.url),
                        "status": resp.status,
                    }
        except Exception:
            return None

        return None

    async def run(self, target, context):
        web_targets = context.get("web_targets", [])
        if not web_targets:
            return {"admin_panels": []}

        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(ssl=False)

        findings = []

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            tasks = []
            for base in web_targets:
                for path in self.COMMON_PATHS:
                    tasks.append(self._check(session, base, path))

            results = await asyncio.gather(*tasks, return_exceptions=True)

        for item in results:
            if isinstance(item, dict):
                findings.append(item)
                context["ctx"].add_finding("admin_panel", {
                    "target": target,
                    "summary": f"{item['url']} -> {item['status']}",
                    "data": item
                })

        context["admin_panels"] = findings
        context["admin_panel_finder"] = {"admin_panels": findings}

        return {"admin_panels": findings}