import aiohttp
from bs4 import BeautifulSoup

from interfaces.module import ScanModule


class WebCrawler(ScanModule):
    name = "web_crawler"
    stage = "WEB"
    dependencies = ["http_probe"]
    enabled = True

    async def _fetch(self, session, url):
        try:
            async with session.get(url, allow_redirects=True) as resp:
                body = await resp.text(errors="ignore")
                return str(resp.url), body
        except Exception:
            return None, None

    async def run(self, target, context):
        web_targets = context.get("web_targets", [])
        crawl_depth = context.get("crawl_depth", 1)

        if not web_targets or crawl_depth <= 0:
            return {"endpoints": []}

        timeout = aiohttp.ClientTimeout(total=context.get("http_timeout", 5))
        connector = aiohttp.TCPConnector(ssl=False)

        endpoints = set()

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            for url in web_targets:
                final_url, html = await self._fetch(session, url)
                if not html:
                    continue

                soup = BeautifulSoup(html, "html.parser")

                for link in soup.find_all("a", href=True):
                    href = link["href"].strip()

                    if href.startswith("#") or href.startswith("javascript:"):
                        continue

                    endpoints.add(href)

        endpoint_list = sorted(endpoints)
        context["endpoints"] = endpoint_list

        context.setdefault("findings", []).extend(
            {
                "type": "endpoint",
                "target": target,
                "endpoint": ep
            }
            for ep in endpoint_list
        )

        return {"endpoints": endpoint_list}