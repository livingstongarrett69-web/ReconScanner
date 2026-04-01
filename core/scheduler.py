import asyncio


class Scheduler:
    def __init__(self, target_limit=50, module_limit=300):
        self.target_sem = asyncio.Semaphore(target_limit)
        self.module_sem = asyncio.Semaphore(module_limit)

    async def run_target(self, coro):
        async with self.target_sem:
            return await coro

    async def run_module(self, coro):
        async with self.module_sem:
            return await coro