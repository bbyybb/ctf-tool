# -*- coding: utf-8 -*-
"""操作历史模块 — 记录用户操作，支持会话保存和恢复"""

import json
import logging
import os
import time

from ctftool.core.i18n import t

logger = logging.getLogger(__name__)


_HISTORY_DIR = os.path.join(os.path.expanduser("~"), ".ctf-tool")
_HISTORY_FILE = os.path.join(_HISTORY_DIR, "history.json")
_MAX_HISTORY = 500  # 最多保存 500 条记录


class HistoryEntry:
    """单条操作记录"""

    def __init__(self, module: str, action: str, input_text: str,
                 output_text: str = "", flags: list[str] = None,
                 timestamp: float = 0):
        self.module = module
        self.action = action
        self.input_text = input_text
        self.output_text = output_text
        self.flags = flags or []
        self.timestamp = timestamp or time.time()

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "action": self.action,
            "input": self.input_text[:1000],  # 限制大小
            "output": self.output_text[:2000],
            "flags": self.flags,
            "timestamp": self.timestamp,
            "time_str": time.strftime("%Y-%m-%d %H:%M:%S",
                                      time.localtime(self.timestamp)),
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'HistoryEntry':
        return cls(
            module=d.get("module", ""),
            action=d.get("action", ""),
            input_text=d.get("input", ""),
            output_text=d.get("output", ""),
            flags=d.get("flags", []),
            timestamp=d.get("timestamp", 0),
        )


class HistoryManager:
    """操作历史管理器"""

    def __init__(self):
        self._entries: list[HistoryEntry] = []
        self._loaded = False

    def add(self, module: str, action: str, input_text: str,
            output_text: str = "", flags: list[str] = None):
        """添加一条操作记录"""
        if not self._loaded:
            self.load()
        entry = HistoryEntry(module, action, input_text, output_text, flags)
        self._entries.append(entry)
        # 超出限制时移除最旧的
        if len(self._entries) > _MAX_HISTORY:
            self._entries = self._entries[-_MAX_HISTORY:]
        self._save()

    def get_recent(self, count: int = 20) -> list[HistoryEntry]:
        """获取最近 N 条操作记录"""
        if not self._loaded:
            self.load()
        return self._entries[-count:]

    def search(self, keyword: str) -> list[HistoryEntry]:
        """搜索历史记录"""
        if not self._loaded:
            self.load()
        keyword = keyword.lower()
        return [
            e for e in self._entries
            if keyword in e.module.lower()
            or keyword in e.action.lower()
            or keyword in e.input_text.lower()
            or keyword in e.output_text.lower()
            or any(keyword in f.lower() for f in e.flags)
        ]

    def get_flags(self) -> list[str]:
        """获取历史中所有发现的 flag（去重）"""
        if not self._loaded:
            self.load()
        all_flags = []
        for e in self._entries:
            for f in e.flags:
                if f not in all_flags:
                    all_flags.append(f)
        return all_flags

    def clear(self):
        """清空历史记录"""
        self._entries.clear()
        self._save()

    def load(self):
        """从文件加载历史记录"""
        self._loaded = True
        if not os.path.isfile(_HISTORY_FILE):
            return
        try:
            with open(_HISTORY_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self._entries = [HistoryEntry.from_dict(d) for d in data]
        except Exception as e:
            logger.warning("Failed to load history: %s", e)
            self._entries = []

    def _save(self):
        """保存历史记录到文件"""
        os.makedirs(_HISTORY_DIR, exist_ok=True)
        try:
            with open(_HISTORY_FILE, 'w', encoding='utf-8') as f:
                json.dump([e.to_dict() for e in self._entries], f,
                         ensure_ascii=False, indent=1)
        except Exception as e:
            logger.warning("Failed to save history: %s", e)

    def format_recent(self, count: int = 20) -> str:
        """格式化最近操作记录为可读文本"""
        entries = self.get_recent(count)
        if not entries:
            return t("msg.no_history")
        lines = [f"=== {t('msg.recent_records').format(len(entries))} ===", ""]
        for i, e in enumerate(reversed(entries)):
            ts = time.strftime("%m-%d %H:%M", time.localtime(e.timestamp))
            flag_mark = f" [Flag: {', '.join(e.flags)}]" if e.flags else ""
            lines.append(
                f"  [{i+1:3d}] {ts} | {e.module}/{e.action} "
                f"| {t('msg.input_label')}: {e.input_text[:40]}...{flag_mark}"
            )
        return "\n".join(lines)


# 全局单例
history = HistoryManager()
