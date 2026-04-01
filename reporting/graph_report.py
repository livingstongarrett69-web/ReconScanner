import os
from datetime import datetime


class GraphReporter:
    def save_text(self, graph_dict):
        os.makedirs("reports", exist_ok=True)

        filename = os.path.join(
            "reports",
            f"graph_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )

        with open(filename, "w", encoding="utf-8") as f:
            f.write("Recon Graph Summary\n")
            f.write("===================\n\n")
            f.write(f"Nodes: {len(graph_dict.get('nodes', []))}\n")
            f.write(f"Edges: {len(graph_dict.get('edges', []))}\n\n")

            f.write("Edges:\n")
            for edge in graph_dict.get("edges", []):
                f.write(
                    f"- {edge['source']} --[{edge.get('label', 'related')}]--> {edge['target']}\n"
                )

        return filename