from interfaces.module import ScanModule


class CellularVendorFingerprint(ScanModule):
    name = "cellular_vendor_fingerprint"
    stage = "FINGERPRINT"
    dependencies = ["http_probe"]
    required_context_keys = ["http_responses"]
    enabled = True

    VENDOR_PATTERNS = {
        "Huawei": ["huawei", "hilink"],
        "ZTE": ["zte"],
        "Teltonika": ["teltonika", "rut"],
        "Sierra Wireless": ["sierra wireless", "airlink"],
        "Netgear": ["netgear", "nighthawk", "mr1100", "m1"],
        "Cradlepoint": ["cradlepoint"],
        "Peplink": ["peplink", "pepwave"],
        "Inseego": ["inseego", "novatel"],
        "MikroTik": ["mikrotik", "routeros"],
    }

    async def run(self, target, context):
        responses = context.get("http_responses", [])
        vendors = []

        for response in responses:
            body = response.get("body", "").lower()
            headers = {
                str(k).lower(): str(v).lower()
                for k, v in response.get("headers", {}).items()
            }

            blob = " ".join([body] + list(headers.values()))

            for vendor, patterns in self.VENDOR_PATTERNS.items():
                if any(p in blob for p in patterns):
                    record = {
                        "target": target,
                        "url": response.get("url"),
                        "vendor": vendor,
                        "evidence": [p for p in patterns if p in blob],
                    }
                    vendors.append(record)

                    context["ctx"].add_finding("cellular_vendor", {
                        "target": target,
                        "summary": f"Probable vendor {vendor} at {response.get('url')}",
                        "severity": "info",
                        "data": record,
                    })

        context["cellular_vendor_fingerprint"] = {"vendors": vendors}
        return {"vendors": vendors}