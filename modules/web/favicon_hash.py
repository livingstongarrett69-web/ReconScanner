import aiohttp
import base64
import mmh3
from interfaces.module import ScanModule


class FaviconHash(ScanModule):
    name = "favicon_hash"
    stage = "WEB"
    dependencies = ["http_probe"]
    required_context_keys = ["web_targets"]
    enabled = True
    timeout = 4

    async def _fetch_favicon(self, session, base_url):
        url = base_url.rstrip("/") + "/favicon.ico"
        try:
            async with session.get(url, allow_redirects=True) as resp:
                if resp.status == 200:
                    content = await resp.read()
                    return {
                        "url": str(resp.url),
                        "content": content,
                    }
        except Exception:
            return None
        return None

    async def run(self, target, context):
        web_targets = context.get("web_targets", [])
        if not web_targets:
            return {"favicons": []}

        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(ssl=False)

        findings = []

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            tasks = [self._fetch_favicon(session, url) for url in web_targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for item in results:
            if isinstance(item, dict):
                try:
                    b64 = base64.encodebytes(item["content"])
                    icon_hash = mmh3.hash(b64)
                    finding = {
                        "url": item["url"],
                        "hash": icon_hash,
                    }
                    findings.append(finding)

                    context["ctx"].add_finding("favicon_hash", {
                        "target": target,
                        "summary": f"{item['url']} -> {icon_hash}",
                        "data": finding
                    })
                except Exception:
                    continue

        context["favicon_hashes"] = findings
        context["favicon_hash"] = {"favicons": findings}
        return {"favicons": findings}