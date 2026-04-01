import re
from interfaces.module import ScanModule


class TitleProbe(ScanModule):
    name = "title_probe"
    stage = "WEB"
    dependencies = ["http_probe"]
    required_context_keys = ["http_responses"]
    enabled = True

    async def run(self, target, context):
        responses = context.get("http_responses", [])
        titles = []

        for response in responses:
            body = response.get("body", "")
            match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
            if match:
                title = " ".join(match.group(1).split())
                item = {
                    "url": response.get("url"),
                    "title": title
                }
                titles.append(item)

                context["ctx"].add_finding("web_title", {
                    "target": target,
                    "summary": f"{item['url']} -> {title}",
                    "data": item
                })

        context["titles"] = titles
        return {"titles": titles}