from utils.finding import build_finding


class CorrelationEngine:
    def correlate(self, ctx):
        derived = []

        admin_panels = ctx.findings.get("admin_panel", [])
        vulns = ctx.findings.get("vulnerability", [])

        admin_targets = {item["target"] for item in admin_panels}
        csp_targets = {
            item["target"]
            for item in vulns
            if item["data"].get("id") == "MISSING_CSP"
        }

        for target in sorted(admin_targets & csp_targets):
            derived.append(
                build_finding(
                    category="correlated_risk",
                    target=target,
                    summary="Admin panel discovered on host with weak web security headers",
                    severity="medium",
                    data={"signals": ["admin_panel", "MISSING_CSP"]},
                )
            )

        open_ports = ctx.findings.get("open_port", [])
        by_target = {}
        for finding in open_ports:
            by_target.setdefault(finding["target"], set()).add(
                finding["data"].get("port")
            )

        for target, ports in by_target.items():
            if 3389 in ports and 445 in ports:
                derived.append(
                    build_finding(
                        category="correlated_risk",
                        target=target,
                        summary="Host exposes both RDP and SMB",
                        severity="medium",
                        data={"ports": [3389, 445]},
                    )
                )

        cellular_devices = ctx.findings.get("cellular_device", [])
        modem_panels = ctx.findings.get("modem_panel", [])
        cellular_vendors = ctx.findings.get("cellular_vendor", [])

        cd_targets = {item["target"] for item in cellular_devices}
        mp_targets = {item["target"] for item in modem_panels}
        cv_targets = {item["target"] for item in cellular_vendors}

        for target in sorted(cd_targets & mp_targets):
            derived.append(
                build_finding(
                    category="correlated_risk",
                    target=target,
                    summary="Multiple signals indicate a probable cellular management interface",
                    severity="medium",
                    data={"signals": ["cellular_device", "modem_panel"]},
                )
            )

        for target in sorted(cd_targets & cv_targets):
            derived.append(
                build_finding(
                    category="correlated_risk",
                    target=target,
                    summary="Probable cellular device with vendor fingerprint identified",
                    severity="info",
                    data={"signals": ["cellular_device", "cellular_vendor"]},
                )
            )

        for item in derived:
            ctx.add_finding("correlated_risk", item)

        return derived