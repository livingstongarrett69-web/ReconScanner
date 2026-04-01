from core.plugin_loader import PluginLoader


def test_loader_runs():

    loader = PluginLoader()

    modules = loader.load_modules()

    assert isinstance(modules, list)