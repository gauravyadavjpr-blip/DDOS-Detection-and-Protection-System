import configparser
from pathlib import Path


class ConfigLoader:
    """Small configuration wrapper for config.ini."""

    def __init__(self, filename: str = "config.ini"):
        self.config = configparser.ConfigParser(inline_comment_prefixes=(";", "#"))
        self.filename = Path(filename)
        self.config.read(self.filename, encoding="utf-8")

    def get(self, section: str, option: str, fallback=None):
        if self.config.has_option(section, option):
            value = self.config.get(section, option, fallback=fallback)
            return str(value).strip()
        return fallback


def load_config(filename: str = "config.ini") -> ConfigLoader:
    return ConfigLoader(filename)
