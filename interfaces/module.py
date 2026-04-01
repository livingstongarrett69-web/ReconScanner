from abc import ABC, abstractmethod


class ScanModule(ABC):
    name = "base_module"
    stage = "DISCOVERY"
    dependencies = []
    required_context_keys = []
    enabled = True
    timeout = 3

    async def setup(self, context):
        return None

    @abstractmethod
    async def run(self, target, context):
        raise NotImplementedError

    async def cleanup(self, context):
        return None