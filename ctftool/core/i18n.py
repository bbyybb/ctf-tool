# -*- coding: utf-8 -*-
"""i18n 国际化模块 — 中英文翻译字典 + 语言切换"""

import json
import os
import sys
from pathlib import Path

_LANG_CONFIG = os.path.join(os.path.expanduser("~"), ".ctf-tool", "language.json")
_current_lang: str = "en"


def _detect_system_lang() -> str:
    """检测系统语言，检测失败时默认英文"""
    import locale
    try:
        lang = locale.getlocale()[0] or ""
        if not lang:
            # getlocale 返回空时尝试环境变量
            lang = os.environ.get('LANG', os.environ.get('LANGUAGE', ''))
    except Exception:
        return "en"  # 检测失败默认英文
    if not lang:
        return "en"  # 无法获取语言信息默认英文
    lang_lower = lang.lower()
    if "zh" in lang_lower or "chinese" in lang_lower:
        return "zh"
    if "en" in lang_lower or "english" in lang_lower:
        return "en"
    return "en"  # 其他语言默认英文


def get_lang() -> str:
    return _current_lang


def set_lang(lang: str):
    global _current_lang
    _current_lang = lang
    os.makedirs(os.path.dirname(_LANG_CONFIG), exist_ok=True)
    with open(_LANG_CONFIG, 'w', encoding='utf-8') as f:
        json.dump({"language": lang}, f)


def load_lang():
    global _current_lang
    if os.path.isfile(_LANG_CONFIG):
        try:
            with open(_LANG_CONFIG, encoding='utf-8') as f:
                _current_lang = json.load(f).get("language", "en")
                return
        except Exception:
            pass
    _current_lang = _detect_system_lang()


def t(key: str) -> str:
    table = _ZH if _current_lang == "zh" else _EN
    return table.get(key, _EN.get(key, key))


# ===================== 从 JSON 文件加载翻译 =====================

# 兼容 PyInstaller 打包环境：优先使用 sys._MEIPASS 路径
if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    _I18N_DIR = Path(sys._MEIPASS) / "ctftool" / "core"
else:
    _I18N_DIR = Path(__file__).parent


def _load_translations(lang: str) -> dict:
    """加载翻译文件"""
    json_path = _I18N_DIR / f"i18n_{lang}.json"
    if json_path.is_file():
        with open(json_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}


_EN = _load_translations("en")
_ZH = _load_translations("zh")

load_lang()
