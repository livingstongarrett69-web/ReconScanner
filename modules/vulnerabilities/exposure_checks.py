from interfaces.module import ScanModule


class ExposureChecks(ScanModule):
    name = "exposure_checks"
    stage = "VULNERABILITY"
    dependencies = ["port_scanner"]
    required_context_keys = ["open_ports"]
    enabled = True

    PORT_RULES = {
        21: ("FTP_EXPOSED", "medium", "FTP exposed; check anonymous access and weak credentials."),
        23: ("TELNET_EXPOSED", "high", "Telnet exposed; plaintext authentication risk."),
        445: ("SMB_EXPOSED", "medium", "SMB exposed; verify signing and guest access."),
        3389: ("RDP_EXPOSED", "medium", "RDP exposed; verify MFA and access restrictions."),
        5900: ("VNC_EXPOSED", "high", "VNC exposed; verify authentication and encryption."),
    }

    async def run(self, target, context):
        findings = []

        for port in context.get("open_ports", []):
            if port in self.PORT_RULES:
                vuln_id, severity, desc = self.PORT_RULES[port]
                findings.append({
                    "id": vuln_id,
                    "severity": severity,
                    "description": desc,
                    "port": port,
                })

        headers = context.get("http_headers", [])
        for item in headers:
            hdrs = {k.lower(): v for k, v in item.get("headers", {}).items()}

            if "strict-transport-security" not in hdrs and str(item.get("url", "")).startswith("https://"):
                findings.append({
                    "id": "MISSING_HSTS",
                    "severity": "low",
                    "description": "HTTPS service missing HSTS header.",
                    "url": item.get("url"),
                })

            if "content-security-policy" not in hdrs:
                findings.append({
                    "id": "MISSING_CSP",
                    "severity": "low",
                    "description": "Response missing Content-Security-Policy header.",
                    "url": item.get("url"),
                })

        context["exposure_checks"] = findings

        for finding in findings:
            context["ctx"].add_finding("vulnerability", {
                "target": target,
                "summary": f"{finding['id']} ({finding['severity']})",
                "data": finding
            })

        return {"exposures": findings}