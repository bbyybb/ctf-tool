# -*- coding: utf-8 -*-
"""CTF Tool TUI 主应用"""

import os

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Footer,
    Header,
    Label,
    ListItem,
    ListView,
    Static,
)

from ctftool import __version__
from ctftool.ui.screens import (
    AutoScanScreen,
    BlockchainScreen,
    CryptoScreen,
    ForensicsScreen,
    MiscScreen,
    PwnScreen,
    ReverseScreen,
    RSAScreen,
    WebScreen,
)
from ctftool.ui.widgets import FlagBar

CSS_PATH = os.path.join(os.path.dirname(__file__), "ui", "styles.tcss")


class CTFToolApp(App):
    """CTF 全能工具 TUI 应用"""

    TITLE = f"CTF Tool v{__version__}"
    SUB_TITLE = "全场景 CTF 检测与 Flag 发现工具"
    CSS_PATH = CSS_PATH

    BINDINGS = [
        Binding("1", "open_crypto", "密码学", show=True),
        Binding("2", "open_web", "Web安全", show=True),
        Binding("3", "open_forensics", "取证", show=True),
        Binding("4", "open_reverse", "逆向", show=True),
        Binding("5", "open_blockchain", "区块链", show=True),
        Binding("6", "open_pwn", "Pwn", show=True),
        Binding("7", "open_misc", "杂项", show=True),
        Binding("8", "open_rsa", "RSA", show=True),
        Binding("0", "open_autoscan", "自动扫描", show=True),
        Binding("q", "quit", "退出", show=True),
    ]

    SCREENS = {
        "crypto": CryptoScreen,
        "web": WebScreen,
        "forensics": ForensicsScreen,
        "reverse": ReverseScreen,
        "blockchain": BlockchainScreen,
        "pwn": PwnScreen,
        "misc": MiscScreen,
        "rsa": RSAScreen,
        "autoscan": AutoScanScreen,
    }

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._shared_data: str | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Static(" ◆ CTF Tool", id="logo")
                yield Static("─" * 24)
                yield ListView(
                    ListItem(Label(" [0] 🔍 自动扫描"), id="nav-autoscan"),
                    ListItem(Label(" [1] 🔐 密码学"), id="nav-crypto"),
                    ListItem(Label(" [2] 🌐 Web 安全"), id="nav-web"),
                    ListItem(Label(" [3] 🔎 取证分析"), id="nav-forensics"),
                    ListItem(Label(" [4] ⚙ 逆向工程"), id="nav-reverse"),
                    ListItem(Label(" [5] ⛓ 区块链"), id="nav-blockchain"),
                    ListItem(Label(" [6] 💥 Pwn"), id="nav-pwn"),
                    ListItem(Label(" [7] 🧩 杂项工具"), id="nav-misc"),
                    ListItem(Label(" [8] 🔑 RSA 攻击"), id="nav-rsa"),
                    id="nav-list",
                )
                yield Static("─" * 24)
                yield Static(" 快捷键: 数字 0-8")
                yield Static(" 退出: Q")
            with Vertical(id="main-content"):
                yield Static(WELCOME_TEXT.format(ver=__version__), id="welcome")
        self.flag_bar = FlagBar(id="flag-bar")
        yield self.flag_bar
        yield Footer()

    def on_list_view_selected(self, event: ListView.Selected):
        """侧边栏导航点击"""
        item_id = event.item.id
        screen_map = {
            "nav-autoscan": "autoscan",
            "nav-crypto": "crypto",
            "nav-web": "web",
            "nav-forensics": "forensics",
            "nav-reverse": "reverse",
            "nav-blockchain": "blockchain",
            "nav-pwn": "pwn",
            "nav-misc": "misc",
            "nav-rsa": "rsa",
        }
        screen = screen_map.get(item_id)
        if screen:
            self.push_screen(screen)

    def action_open_crypto(self):
        self.push_screen("crypto")

    def action_open_web(self):
        self.push_screen("web")

    def action_open_forensics(self):
        self.push_screen("forensics")

    def action_open_reverse(self):
        self.push_screen("reverse")

    def action_open_blockchain(self):
        self.push_screen("blockchain")

    def action_open_pwn(self):
        self.push_screen("pwn")

    def action_open_misc(self):
        self.push_screen("misc")

    def action_open_rsa(self):
        self.push_screen("rsa")

    def action_open_autoscan(self):
        self.push_screen("autoscan")


WELCOME_TEXT = """
  _____ _____ _____   _____ ___   ___  _
 / ____|_   _|  ___| |_   _/ _ \\ / _ \\| |
| |      | | | |_      | || | | | | | | |
| |      | | |  _|     | || | | | | | | |
| |____  | | | |       | || |_| | |_| | |____
 \\_____| |_| |_|       |_| \\___/ \\___/|______|  v{ver}

          CTF Multi-Tool  --  Flag Hunter

==========================================================

 [0] Auto Scan  - URL/File/Text auto detect & scan all
 [1] Crypto     - Base64/Hex/Caesar/Vigenere/AES/DES/XOR
                  RSA attacks / Hash crack / Frequency
 [2] Web        - SQLi/XSS/LFI/CMDi/SSRF/SSTI detect
                  JWT forge & crack / Dir scan
 [3] Forensics  - File ID / Stego / PCAP / Strings
                  ZIP crack & fake decrypt / File carve
 [4] Reverse    - PE/ELF analysis / checksec / Disasm
                  .pyc decompile / Entropy
 [5] Pwn        - Overflow / FmtStr / ROP / Shellcode
                  pwntools & ret2libc templates
 [6] Misc       - Morse / Braille / Brainfuck / JWT
                  Base convert / QR / Wordlist
 [7] RSA        - Small e / Common modulus / Wiener
                  Fermat / dp leak / Hastad broadcast

==========================================================

 Keys: 0-7 open modules | Q quit
 In modules: Ctrl+R run | Ctrl+S export | Ctrl+T send to Crypto | Esc back
 All output auto-scanned for flag{...} patterns
"""
