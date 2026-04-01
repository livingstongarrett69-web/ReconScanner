from interfaces.module import ScanModule


class CellularDetector(ScanModule):
    name = "cellular_detector"
    stage = "FINGERPRINT"
    dependencies = ["http_probe"]
    required_context_keys = ["http_responses"]
    enabled = True

    BODY_KEYWORDS = [
        "lte",
        "4g",
        "5g",
        "mobile hotspot",
        "hotspot",
        "modem",
        "sim card",
        "iccid",
        "imsi",
        "signal strength",
        "apn",
        "roaming",
        "wan type",
        "cellular",
        "mobile network",
    ]

    HEADER_KEYWORDS = [
        "huawei",
        "zte",
        "teltonika",
        "sierra wireless",
        "netgear",
        "cradlepoint",
        "mikrotik",
        "inseego",
        "peplink",
    ]

    async def run(self, target, context):
        responses = context.get("http_responses", [])
        findings = []

        for response in responses:
            body = response.get("body", "").lower()
            headers = {
                str(k).lower(): str(v).lower()
                for k, v in response.get("headers", {}).items()
            }

            score = 0
            matched = []

            for word in self.BODY_KEYWORDS:
                if word in body:
                    score += 1
                    matched.append(word)

            for _, value in headers.items():
                for word in self.HEADER_KEYWORDS:
                    if word in value:
                        score += 2
                        matched.append(word)

            if score >= 2:
                record = {
                    "target": target,
                    "url": response.get("url"),
                    "score": score,
                    "matched_indicators": sorted(set(matched)),
                    "classification": "probable_cellular_device",
                }
                findings.append(record)

                context["ctx"].add_finding("cellular_device", {
                    "target": target,
                    "summary": f"Probable cellular device at {response.get('url')}",
                    "severity": "info",
                    "data": record,
                })

        context["cellular_detector"] = {"findings": findings}
        return {"findings": findings}