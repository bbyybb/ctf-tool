# -*- coding: utf-8 -*-
"""统一配置管理"""
import json
import os

_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".ctf-tool")
_CONFIG_FILE = os.path.join(_CONFIG_DIR, "config.json")

_DEFAULTS = {
    "timeout": 10,
    "proxy": "",
    "output_dir": "",
    "max_history": 500,
    "verify_ssl": False,
    "user_agent": "",
}

class ConfigManager:
    def __init__(self):
        self._config = dict(_DEFAULTS)
        self.load()

    def load(self):
        try:
            if os.path.isfile(_CONFIG_FILE):
                with open(_CONFIG_FILE, 'r', encoding='utf-8') as f:
                    saved = json.load(f)
                self._config.update(saved)
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning("Failed to load config: %s", e)

    def save(self):
        os.makedirs(_CONFIG_DIR, exist_ok=True)
        with open(_CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(self._config, f, indent=2, ensure_ascii=False)

    def get(self, key: str, default=None):
        return self._config.get(key, default if default is not None else _DEFAULTS.get(key))

    def set(self, key: str, value):
        self._config[key] = value
        self.save()

    def all(self) -> dict:
        return dict(self._config)

config = ConfigManager()
