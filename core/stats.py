# core/stats.py
import threading

class ScanStats:

    def __init__(self):

        self.targets = 0
        self.modules = 0
        self.errors = 0

    def target_scanned(self):
        self.targets += 1

    def module_run(self):
        self.modules += 1

    def module_failed(self):
        self.errors += 1

    def summary(self):

        return {
            "targets": self.targets,
            "modules": self.modules,
            "errors": self.errors

        logger.info(f"Scan stats: {stats.summary()}")
        }

    # Increment methods
    def inc_hosts(self, count=1):
        with self.lock:
            self.hosts_scanned += count

    def inc_open(self, count=1):
        with self.lock:
            self.ports_open += count

    def inc_plugins(self, count=1):
        with self.lock:
            self.plugins_run += count