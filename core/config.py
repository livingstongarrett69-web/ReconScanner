import json
import os

class Config:
    def __init__(self, config_path=None):
        self.defaults = {
            "ports": [21, 22, 80, 443, 8080],
            "concurrency": 100,
            "timeout": 3,
            "report_format": ["json"],
        }
        self.config = self.defaults.copy()
        if config_path:
            self.load(config_path)

    def load(self, path):
        if not os.path.exists(path):
            print(f"[!] Config file not found: {path}")
            return
        try:
            with open(path, "r") as f:
                data = json.load(f)
                self.config.update(data)
        except Exception as e:
            print(f"[ERROR] Failed to load config: {e}")

    def get(self, key, default=None):
        return self.config.get(key, default)