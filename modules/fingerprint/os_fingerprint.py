from interfaces.module import ScanModule


class OSFingerprint(ScanModule):
    name = "os_fingerprint"
    stage = "FINGERPRINT"
    dependencies = ["port_scanner"]
    enabled = True

    WINDOWS_PORTS = {135, 139, 445, 3389}
    LINUX_PORTS = {22, 111}
    NETWORK_DEVICE_PORTS = {23, 161, 162}

    async def run(self, target, context):
        open_ports = set(context.get("open_ports", []))
        guess = "unknown"

        if open_ports & self.WINDOWS_PORTS:
            guess = "windows-like"
        elif open_ports & self.LINUX_PORTS:
            guess = "linux/unix-like"
        elif open_ports & NETWORK_DEVICE_PORTS:
            guess = "network-device-like"

        result = {"os_guess": guess}

        context["os_fingerprint"] = result

        if guess != "unknown":
            context.setdefault("findings", []).append({
                "type": "os_guess",
                "target": target,
                "guess": guess
            })

        return result