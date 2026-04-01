class ReconGraph:
    def __init__(self):
        self.nodes = set()
        self.edges = []

    def add_node(self, node):
        self.nodes.add(str(node))

    def add_edge(self, source, target, label="related"):
        self.nodes.add(str(source))
        self.nodes.add(str(target))
        self.edges.append({
            "source": str(source),
            "target": str(target),
            "label": label,
        })

    def as_dict(self):
        return {
            "nodes": sorted(self.nodes),
            "edges": self.edges,
        }