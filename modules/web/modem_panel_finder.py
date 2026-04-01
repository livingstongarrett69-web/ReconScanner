import aiohttp
from interfaces.module import ScanModule


class ModemPanelFinder(ScanModule):
    name = "modem_panel_finder"
    stage = "WEB"
    dependencies = ["http_probe"]
    required_context_keys = ["web_targets"]
    enabled = True
    timeout = 4

    COMMON_PATHS = [
        "/",
        "/index.html",
        "/status",
        "/overview",
        "/system",
        "/network",
        "/internet",
        "/wan",
        "/mobile",
        "/lte",
        "/5g",
        "/apn",
        "/sim",
        "/sms",
        "/advanced",
        "/login",
        "/admin",
    ]

    KEYWORDS = [
        "lte",
        "5g",
        "4g",
        "hotspot",
        "mobile broadband",
        "sim",
        "apn",
        "signal strength",
        "operator",
        "roaming",
        "imei",
        "iccid",
    ]

    async def _check(self, session, base_url, path):
        url = base_url.rstrip("/") + path
        try:
            async with session.get(url, allow_redirects=True) as resp:
                body = await resp.text(errors="ignore")
                text = body.lower()

                hits = [k for k in self.KEYWORDS if k in text]
                if resp.status in (200, 401, 403) and hits:
                    return {
                        "url": str(resp.url),
                        "status": resp.status,
                        "hits": sorted(set(hits)),
                    }
        except Exception:
            return None

        return None

    async def run(self, target, context):
        web_targets = context.get("web_targets", [])
        if not web_targets:
            return {"modem_panels": []}

        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(ssl=False)

        findings = []

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            tasks = []
            for base in web_targets:
                for path in self.COMMON_PATHS:
                    tasks.append(self._check(session, base, path))

            results = await asyncio.gather(*tasks, return_exceptions=True)

        seen = set()
        for item in results:
            if isinstance(item, dict):
                key = item["url"]
                if key in seen:
                    continue
                seen.add(key)
                findings.append(item)

                context["ctx"].add_finding("modem_panel", {
                    "target": target,
                    "summary": f"Possible modem/cellular panel at {item['url']}",
                    "severity": "info",
                    "data": item,
                })

        context["modem_panel_finder"] = {"modem_panels": findings}
        return {"modem_panels": findings}