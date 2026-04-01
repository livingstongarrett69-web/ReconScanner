import aiohttp
from interfaces.module import ScanModule


class HTTPHeaders(ScanModule):
    name = "http_headers"
    stage = "WEB"
    dependencies = ["http_probe"]
    required_context_keys = ["web_targets"]
    enabled = True
    timeout = 4

    async def _fetch_headers(self, session, url):
        try:
            async with session.get(url, allow_redirects=True) as resp:
                return {
                    "url": str(resp.url),
                    "status": resp.status,
                    "headers": dict(resp.headers),
                }
        except Exception:
            return None

    async def run(self, target, context):
        web_targets = context.get("web_targets", [])
        if not web_targets:
            return {"headers": []}

        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(ssl=False)

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            tasks = [self._fetch_headers(session, url) for url in web_targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        headers = [r for r in results if isinstance(r, dict)]
        context["http_headers"] = headers

        for item in headers:
            context["ctx"].add_finding("http_headers", {
                "target": target,
                "summary": f"{item['url']} -> {item['status']}",
                "data": {
                    "server": item["headers"].get("Server"),
                    "powered_by": item["headers"].get("X-Powered-By"),
                }
            })

        return {"headers": headers}