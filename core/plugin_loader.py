import importlib
import inspect
import pkgutil

from interfaces.module import ScanModule
from core.pipeline import STAGES


class PluginLoader:
    def __init__(self, module_path="modules"):
        self.module_path = module_path
        self.loaded = []
        self.failed = []

    def _validate(self, obj):
        if not inspect.isclass(obj):
            return False, "not class"
        if obj is ScanModule:
            return False, "base class"
        if not issubclass(obj, ScanModule):
            return False, "not ScanModule"
        if inspect.isabstract(obj):
            return False, "abstract"
        if getattr(obj, "stage", None) not in STAGES:
            return False, f"invalid stage {getattr(obj, 'stage', None)}"
        if not inspect.iscoroutinefunction(obj.run):
            return False, "run not async"
        return True, None

    def load_modules(self):
        modules = []
        self.loaded = []
        self.failed = []

        for _, name, _ in pkgutil.walk_packages([self.module_path], self.module_path + "."):
            try:
                mod = importlib.import_module(name)

                for _, obj in inspect.getmembers(mod):
                    valid, reason = self._validate(obj)
                    if not valid:
                        continue

                    instance = obj()
                    modules.append(instance)
                    self.loaded.append({
                        "module": instance.name,
                        "stage": instance.stage,
                        "source": name,
                    })

            except Exception as e:
                self.failed.append({
                    "source": name,
                    "error": str(e),
                })

        return modules