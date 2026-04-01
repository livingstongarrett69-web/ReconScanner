class DependencyGraph:
    def __init__(self):
        self.edges = {}

    def add_module(self, module):
        self.edges[module.name] = {
            "stage": getattr(module, "stage", "UNKNOWN"),
            "dependencies": list(getattr(module, "dependencies", [])),
            "required_context_keys": list(getattr(module, "required_context_keys", [])),
        }

    def as_dict(self):
        return self.edges