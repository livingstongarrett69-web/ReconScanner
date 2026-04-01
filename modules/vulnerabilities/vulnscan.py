from interfaces.module import ScanModule


class VulnScan(ScanModule):
    name = "vulnscan"
    stage = "VULNERABILITY"
    dependencies = ["port_scanner"]
    enabled = True

    PORT_BASED_CHECKS = {
        21: {
            "id": "FTP_EXPOSED",
            "severity": "medium",
            "description": "FTP service exposed; verify anonymous access and weak credentials."
        },
        23: {
            "id": "TELNET_EXPOSED",
            "severity": "high",
            "description": "Telnet service exposed; plaintext credentials are likely at risk."
        },
        445: {
            "id": "SMB_EXPOSED",
            "severity": "medium",
            "description": "SMB exposed; verify signing, guest access, and legacy protocol support."
        },
        3389: {
            "id": "RDP_EXPOSED",
            "severity": "medium",
            "description": "RDP exposed; verify MFA, NLA, and access controls."
        },
        5900: {
            "id": "VNC_EXPOSED",
            "severity": "high",
            "description": "VNC exposed; verify authentication and encryption settings."
        },
    }

    TECHNOLOGY_CHECKS = {
        "WordPress": {
            "id": "WORDPRESS_DETECTED",
            "severity": "info",
            "description": "WordPress detected; verify version, plugins, themes, and admin exposure."
        },
        "Drupal": {
            "id": "DRUPAL_DETECTED",
            "severity": "info",
            "description": "Drupal detected; verify version and module exposure."
        },
        "Joomla": {
            "id": "JOOMLA_DETECTED",
            "severity": "info",
            "description": "Joomla detected; verify extensions and admin exposure."
        },
    }

    async def run(self, target, context):
        findings = []

        open_ports = context.get("open_ports", [])
        technologies = context.get("technologies", [])

        for port in open_ports:
            check = self.PORT_BASED_CHECKS.get(port)
            if check:
                findings.append({
                    "type": "port_exposure",
                    "target": target,
                    "port": port,
                    **check
                })

        for tech in technologies:
            check = self.TECHNOLOGY_CHECKS.get(tech)
            if check:
                findings.append({
                    "type": "technology_exposure",
                    "target": target,
                    "technology": tech,
                    **check
                })

        context["vulnerabilities"] = findings
        context.setdefault("findings", []).extend(findings)

        if "ctx" in context:
            context["ctx"].vulnerabilities += len(findings)

        return {"vulnerabilities": findings}