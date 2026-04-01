import asyncio
import socket
from interfaces.module import ScanModule


class SubdomainEnum(ScanModule):

    name = "subdomain_enum"
    stage = "DISCOVERY"

    async def resolve(self, sub):

        try:
            socket.gethostbyname(sub)
            return sub
        except:
            return None

    async def run(self, target, context):

        wordlist = [
            "www",
            "api",
            "dev",
            "staging",
            "admin",
            "mail"
        ]

        tasks = []

        for w in wordlist:
            sub = f"{w}.{target}"
            tasks.append(self.resolve(sub))

        results = await asyncio.gather(*tasks)

        subs = [s for s in results if s]

        context["subdomains"] = subs

        return subs