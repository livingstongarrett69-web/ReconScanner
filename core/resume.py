import json
import os


class ScanResume:
    STATE_FILE = "reports/scan_state.json"

    def save_state(self, ctx):
        os.makedirs("reports", exist_ok=True)

        data = {
            "scan_id": ctx.scan_id,
            "profile": ctx.profile,
            "completed_targets": ctx.targets_done,
            "results": ctx.results,
        }

        with open(self.STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def load_state(self):
        if not os.path.exists(self.STATE_FILE):
            return None

        with open(self.STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)