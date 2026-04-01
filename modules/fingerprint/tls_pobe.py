import asyncio
import ssl
from interfaces.module import ScanModule


class TLSProbe(ScanModule):
    name = "tls_probe"
    stage = "FINGERPRINT"
    dependencies = ["port_scanner"]
    required_context_keys = ["open_ports"]
    enabled = True
    timeout = 4

    TLS_PORTS = [443, 8443, 993, 995]

    async def _probe(self, target, port):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port, ssl=ctx, server_hostname=target),
                timeout=self.timeout
            )

            ssl_obj = writer.get_extra_info("ssl_object")
            cert = ssl_obj.getpeercert() if ssl_obj else None

            writer.close()
            await writer.wait_closed()

            if not cert:
                return None

            return {
                "port": port,
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "notBefore": cert.get("notBefore"),
                "notAfter": cert.get("notAfter"),
                "subjectAltName": cert.get("subjectAltName"),
            }

        except Exception:
            return None

    async def run(self, target, context):
        open_ports = context.get("open_ports", [])
        candidates = [p for p in open_ports if p in self.TLS_PORTS]

        if not candidates:
            return {"tls": []}

        tasks = [self._probe(target, port) for port in candidates]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        tls_info = [r for r in results if isinstance(r, dict)]

        for item in tls_info:
            context["ctx"].add_finding("tls", {
                "target": target,
                "summary": f"TLS on {item['port']}",
                "data": item
            })

        context["tls"] = tls_info
        return {"tls": tls_info}