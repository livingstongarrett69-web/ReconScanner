from interfaces.module import ScanModule


class TitleCluster(ScanModule):

    name = "title_cluster"
    stage = "WEB"
    dependencies = ["title_probe"]
    required_context_keys = ["titles"]
    enabled = True

    async def run(self, target, context):

        titles = context.get("titles", [])

        clusters = {}

        for item in titles:

            title = item["title"]

            clusters.setdefault(title, []).append(item["url"])

        context["title_clusters"] = clusters

        return {"clusters": clusters}