from interfaces.module import ScanModule
import socket


class AttackSurfaceMapper(ScanModule):

    name = "attack_surface"
    stage = "DISCOVERY"

    async def run(self, target, context):

        surface = {}

        try:
            ip = socket.gethostbyname(target)
            surface["ip"] = ip

        except:
            surface["ip"] = None

        context["attack_surface"] = surface

        return surface