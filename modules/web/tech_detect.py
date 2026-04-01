import re
from interfaces.module import ScanModule


class TechDetect(ScanModule):
    name = "tech_detect"
    stage = "WEB"
    dependencies = ["http_probe"]
    required_context_keys = ["http_responses"]
    enabled = True

    HEADER_SIGNATURES = {
        "server": [
            ("nginx", "Nginx"),
            ("apache", "Apache"),
            ("iis", "Microsoft IIS"),
            ("cloudflare", "Cloudflare"),
            ("gunicorn", "Gunicorn"),
            ("caddy", "Caddy"),
        ],
        "x-powered-by": [
            ("php", "PHP"),
            ("express", "Express"),
            ("asp.net", "ASP.NET"),
            ("next.js", "Next.js"),
        ],
    }

    BODY_SIGNATURES = [
        (r"wp-content|wordpress", "WordPress"),
        (r"drupal-settings-json|drupal", "Drupal"),
        (r"joomla!", "Joomla"),
        (r"/cdn-cgi/", "Cloudflare"),
        (r"react", "React"),
        (r"vue", "Vue.js"),
        (r"angular", "Angular"),
        (r"bootstrap", "Bootstrap"),
    ]

    async def run(self, target, context):
        responses = context.get("http_responses", [])
        technologies = set()

        for response in responses:
            headers = {
                str(k).lower(): str(v).lower()
                for k, v in response.get("headers", {}).items()
            }
            body = response.get("body", "").lower()

            for header_name, patterns in self.HEADER_SIGNATURES.items():
                header_value = headers.get(header_name, "")
                for needle, tech_name in patterns:
                    if needle in header_value:
                        technologies.add(tech_name)

            for pattern, tech_name in self.BODY_SIGNATURES:
                if re.search(pattern, body):
                    technologies.add(tech_name)

        tech_list = sorted(technologies)
        result = {"technologies": tech_list}

        context["technologies"] = tech_list
        context["tech_detect"] = result

        for tech in tech_list:
            context["ctx"].add_finding("technology", {
                "target": target,
                "summary": f"Detected {tech}",
                "data": {"technology": tech}
            })

        return result