# -*- coding: utf-8 -*-
"""自定义 TUI 组件"""

from textual.events import Click
from textual.widgets import Static, TextArea

from ctftool.core.i18n import t


class FlagBar(Static):
    """底部 Flag 显示栏（点击可复制所有 flag）"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._flags: list[str] = []
        self._show_copied = False
        self._copy_failed = False

    def render(self) -> str:
        if self._copy_failed:
            return f" [!] Copy failed (clipboard tool unavailable) ({len(self._flags)} flags)"
        if self._show_copied:
            return f" [OK] All flags copied! ({len(self._flags)} flags)"
        if self._flags:
            flag_text = " | ".join(self._flags[-3:])
            count = len(self._flags)
            return f" [F] {count} Flag: {flag_text}    (click to copy)"
        return " [?] Flag..."

    def on_click(self, event: Click) -> None:
        """点击复制所有 flag 到剪贴板"""
        if self._flags:
            try:
                import subprocess
                text = "\n".join(self._flags)
                # 跨平台剪贴板写入
                import sys
                if sys.platform == 'win32':
                    process = subprocess.Popen(['clip'], stdin=subprocess.PIPE)
                    process.communicate(text.encode('utf-16-le'))
                elif sys.platform == 'darwin':
                    process = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
                    process.communicate(text.encode('utf-8'))
                else:
                    process = subprocess.Popen(['xclip', '-selection', 'clipboard'],
                                               stdin=subprocess.PIPE)
                    process.communicate(text.encode('utf-8'))
                self._show_copied = True
                self.refresh()
                self.set_timer(1.5, self._restore_display)
            except Exception:
                self._copy_failed = True
                self.refresh()
                self.set_timer(1.5, self._restore_display)

    def _restore_display(self) -> None:
        self._show_copied = False
        self._copy_failed = False
        self.refresh()

    def add_flag(self, flag: str):
        if flag not in self._flags:
            self._flags.append(flag)
            self.refresh()
            self.add_class("has-flag")

    def clear_flags(self):
        self._flags.clear()
        self.refresh()
        self.remove_class("has-flag")

    def get_all_flags(self) -> list[str]:
        return self._flags.copy()


class OutputPanel(TextArea):
    """可复制的输出面板（基于 TextArea read_only）"""

    def __init__(self, **kwargs):
        super().__init__(read_only=True, **kwargs)
        self._default_text = t("msg.waiting_output")
        self.load_text(self._default_text)

    def set_output(self, text: str):
        self.read_only = False
        self.load_text(text)
        self.read_only = True

    def append_output(self, text: str):
        self.read_only = False
        current = self.text
        if current == self._default_text:
            self.load_text(text)
        else:
            self.load_text(current + "\n" + text)
        self.read_only = True

    def clear(self):
        self.read_only = False
        self.load_text(self._default_text)
        self.read_only = True
