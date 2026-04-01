import os
import json
from datetime import datetime


class DiffReporter:

    def save(self, diff):

        os.makedirs("reports", exist_ok=True)

        filename = os.path.join(
            "reports",
            f"scan_diff_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )

        with open(filename, "w") as f:
            json.dump(diff, f, indent=2)

        return filename