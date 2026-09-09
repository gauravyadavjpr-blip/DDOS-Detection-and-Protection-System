import importlib

from ddos_detector.config import ConfigLoader


def test_package_and_entrypoint_exist():
    pkg = importlib.import_module("ddos_detector")
    assert hasattr(pkg, "RealTimeDDoSMonitor")

    app_mod = importlib.import_module("ddos_detector.app")
    assert hasattr(app_mod, "RealTimeDDoSMonitor")


def test_config_loader_strips_inline_comments():
    loader = ConfigLoader("config.ini")
    assert loader.get("Detection", "RateLimit", fallback="50") == "50"
    assert loader.get("Mitigation", "BlockDuration", fallback="600") == "600"
