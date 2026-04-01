import json
import os
from datetime import datetime


def export_graph(graph):
    os.makedirs("reports", exist_ok=True)

    filename = os.path.join(
        "reports",
        f"graph_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(graph.as_dict(), f, indent=2)

    return filename