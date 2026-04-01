import json
import os
from datetime import datetime


class GraphView:
    def save_html(self, graph_dict):
        os.makedirs("reports", exist_ok=True)

        filename = os.path.join(
            "reports",
            f"graph_view_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )

        nodes = [{"id": node, "label": node} for node in graph_dict.get("nodes", [])]
        edges = [
            {
                "from": edge["source"],
                "to": edge["target"],
                "label": edge.get("label", "")
            }
            for edge in graph_dict.get("edges", [])
        ]

        doc = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Recon Graph</title>
  <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; background: #111; color: #eee; }}
    #network {{ width: 100vw; height: 100vh; background: #1a1a1a; }}
  </style>
</head>
<body>
  <div id="network"></div>
  <script>
    const nodes = new vis.DataSet({json.dumps(nodes)});
    const edges = new vis.DataSet({json.dumps(edges)});
    const container = document.getElementById("network");
    const data = {{ nodes, edges }};
    const options = {{
      physics: {{ stabilization: false }},
      nodes: {{
        shape: "dot",
        size: 14,
        font: {{ color: "#fff" }}
      }},
      edges: {{
        font: {{ color: "#ccc", strokeWidth: 0 }},
        color: "#888",
        arrows: "to"
      }},
      interaction: {{
        hover: true,
        navigationButtons: true,
        keyboard: true
      }}
    }};
    new vis.Network(container, data, options);
  </script>
</body>
</html>
"""
        with open(filename, "w", encoding="utf-8") as f:
            f.write(doc)

        return filename