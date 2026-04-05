# -*- coding: utf-8 -*-
"""操作历史模块单元测试"""

import os
import tempfile
from unittest.mock import patch

from ctftool.core.history import HistoryEntry, HistoryManager


class TestHistoryEntry:
    def test_create_entry(self):
        """创建历史条目"""
        entry = HistoryEntry("Crypto", "rot13", "hello", "uryyb")
        assert entry.module == "Crypto"
        assert entry.action == "rot13"
        assert entry.input_text == "hello"
        assert entry.output_text == "uryyb"
        assert entry.timestamp > 0

    def test_to_dict(self):
        """to_dict 返回正确格式"""
        entry = HistoryEntry("Web", "scan", "http://test.com", "ok", ["flag{x}"])
        d = entry.to_dict()
        assert d["module"] == "Web"
        assert d["action"] == "scan"
        assert d["flags"] == ["flag{x}"]
        assert "time_str" in d

    def test_from_dict(self):
        """from_dict 正确恢复"""
        d = {
            "module": "Misc", "action": "morse",
            "input": "hello", "output": ".... . .-.. .-.. ---",
            "flags": [], "timestamp": 1000000
        }
        entry = HistoryEntry.from_dict(d)
        assert entry.module == "Misc"
        assert entry.timestamp == 1000000

    def test_to_dict_truncation(self):
        """to_dict 截断过长文本"""
        entry = HistoryEntry("Test", "act", "x" * 5000, "y" * 5000)
        d = entry.to_dict()
        assert len(d["input"]) <= 1000
        assert len(d["output"]) <= 2000


class TestHistoryManager:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.tmpdir, "history.json")
        self.manager = HistoryManager()
        self.manager._entries = []
        self.manager._loaded = True

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_add_entry(self):
        with patch('ctftool.core.history._HISTORY_DIR', self.tmpdir), \
             patch('ctftool.core.history._HISTORY_FILE', self.config_path):
            self.manager.add("Crypto", "rot13", "hello", "uryyb")
            assert len(self.manager._entries) == 1

    def test_get_recent(self):
        self.manager._entries = []
        with patch('ctftool.core.history._HISTORY_DIR', self.tmpdir), \
             patch('ctftool.core.history._HISTORY_FILE', self.config_path):
            for i in range(10):
                self.manager.add("Test", f"action_{i}", f"input_{i}")
            recent = self.manager.get_recent(5)
            assert len(recent) == 5

    def test_search(self):
        with patch('ctftool.core.history._HISTORY_DIR', self.tmpdir), \
             patch('ctftool.core.history._HISTORY_FILE', self.config_path):
            self.manager.add("Crypto", "rot13", "flag_search_test")
            self.manager.add("Web", "scan", "http://example.com")
            results = self.manager.search("flag_search")
            assert len(results) == 1
            assert results[0].module == "Crypto"

    def test_get_flags(self):
        with patch('ctftool.core.history._HISTORY_DIR', self.tmpdir), \
             patch('ctftool.core.history._HISTORY_FILE', self.config_path):
            self.manager.add("Crypto", "decode", "text", "out", ["flag{a}"])
            self.manager.add("Web", "scan", "url", "out", ["flag{b}"])
            flags = self.manager.get_flags()
            assert "flag{a}" in flags
            assert "flag{b}" in flags

    def test_clear(self):
        with patch('ctftool.core.history._HISTORY_DIR', self.tmpdir), \
             patch('ctftool.core.history._HISTORY_FILE', self.config_path):
            self.manager.add("Test", "act", "inp")
            self.manager.clear()
            assert len(self.manager._entries) == 0

    def test_save_and_load(self):
        """保存后加载能恢复数据"""
        with patch('ctftool.core.history._HISTORY_DIR', self.tmpdir), \
             patch('ctftool.core.history._HISTORY_FILE', self.config_path):
            self.manager.add("Crypto", "rot13", "hello", "uryyb", ["flag{test}"])
            # 创建新 manager 并加载
            manager2 = HistoryManager()
            manager2._loaded = False
        with patch('ctftool.core.history._HISTORY_DIR', self.tmpdir), \
             patch('ctftool.core.history._HISTORY_FILE', self.config_path):
            manager2.load()
            assert len(manager2._entries) == 1
            assert manager2._entries[0].module == "Crypto"
            assert manager2._entries[0].flags == ["flag{test}"]

    def test_load_no_file(self):
        """配置文件不存在时不崩溃"""
        with patch('ctftool.core.history._HISTORY_FILE', '/nonexistent/path/history.json'):
            manager = HistoryManager()
            manager.load()
            assert len(manager._entries) == 0

    def test_format_recent(self):
        """格式化输出"""
        with patch('ctftool.core.history._HISTORY_DIR', self.tmpdir), \
             patch('ctftool.core.history._HISTORY_FILE', self.config_path):
            self.manager.add("Crypto", "rot13", "hello", "uryyb")
            text = self.manager.format_recent()
            assert "Crypto" in text
            assert "rot13" in text

    def test_format_recent_empty(self):
        """无记录时的输出"""
        text = self.manager.format_recent()
        assert "暂无" in text or "No operation" in text

    def test_max_history_limit(self):
        """超过最大条目数时截断"""
        with patch('ctftool.core.history._HISTORY_DIR', self.tmpdir), \
             patch('ctftool.core.history._HISTORY_FILE', self.config_path), \
             patch('ctftool.core.history._MAX_HISTORY', 5):
            for i in range(10):
                self.manager.add("Test", f"act_{i}", f"inp_{i}")
            assert len(self.manager._entries) <= 5
