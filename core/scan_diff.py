class ScanDiff:
    def compare(self, old_scan, new_scan):
        diff = {
            "new_hosts": [],
            "removed_hosts": [],
            "new_ports": [],
            "new_services": [],
            "new_vulnerabilities": [],
        }

        old_targets = set(old_scan["results"].keys())
        new_targets = set(new_scan["results"].keys())

        diff["new_hosts"] = list(new_targets - old_targets)
        diff["removed_hosts"] = list(old_targets - new_targets)

        for target in new_targets & old_targets:
            old_data = old_scan["results"].get(target, {})
            new_data = new_scan["results"].get(target, {})

            old_ports = set(old_data.get("port_scanner", {}).get("open_ports", []))
            new_ports = set(new_data.get("port_scanner", {}).get("open_ports", []))

            for port in new_ports - old_ports:
                diff["new_ports"].append({
                    "target": target,
                    "port": port
                })

            old_services = set(old_data.get("services", {}).values())
            new_services = set(new_data.get("services", {}).values())

            for service in new_services - old_services:
                diff["new_services"].append({
                    "target": target,
                    "service": service
                })

        return diff