# -*- coding: utf-8 -*-
"""CTF Tool - 全场景 CTF 检测与 Flag 发现工具

使用方法:
    python main.py          # 启动 GUI 界面
    python main.py --tui    # 启动 TUI 界面（终端）
    python main.py --help   # 查看帮助
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

HELP_TEXT = """
CTF Tool v1.0.0 - 全场景 CTF 检测与 Flag 发现工具

使用方法:
    python main.py              启动 GUI 桌面界面 (PyQt6)
    python main.py --tui        启动 TUI 终端界面 (Textual)
    python main.py cli <module> <action> <input>   CLI 命令行模式
    python main.py --version    显示版本号

模块:
    [0] 自动扫描  - 智能调度，自动检测并运行所有相关模块
    [1] 密码学    - Base64/Hex/Caesar/Vigenere/AES/DES/XOR/RSA/哈希
    [2] Web 安全  - SQLi/XSS/LFI/CMDi/SSRF/SSTI/JWT/目录扫描
    [3] 取证分析  - 文件识别/隐写术/元数据/ZIP爆破/PCAP/文件修复
    [4] 逆向工程  - PE/ELF分析/checksec/反汇编/pyc反编译
    [5] Pwn       - 缓冲区溢出/格式化字符串/ROP/Shellcode/pwntools
    [6] 杂项      - 进制转换/摩尔斯/盲文/Brainfuck/JWT/社工字典
    [7] RSA 攻击  - 小指数/共模/Wiener/Fermat/dp泄露/Hastad

依赖安装:
    pip install -r requirements.txt
"""

_INTEGRITY_WARNING = """
=========================================
WARNING: Attribution integrity check failed.

The donation/support information in this software has been
modified or removed. This is a violation of the project's
contribution guidelines.

Please restore the original files or re-clone from:
  https://github.com/bbyybb/ctf-tool

Errors:
{errors}
=========================================
"""


def _check_integrity():
    """启动时完整性校验 — 校验不通过则阻止程序运行"""
    try:
        from ctftool.core.integrity import verify_integrity
        passed, errors = verify_integrity(strict=True)
        if not passed:
            msg = _INTEGRITY_WARNING.format(errors="\n".join(f"  - {e}" for e in errors))
            print(msg, file=sys.stderr)
            # GUI 模式下弹窗后退出
            try:
                from PyQt6.QtWidgets import QApplication, QMessageBox
                app = QApplication.instance() or QApplication(sys.argv)
                QMessageBox.critical(
                    None, "Integrity Check Failed",
                    "Attribution integrity check failed.\n"
                    "The program cannot start.\n\n"
                    "Please restore original files or re-clone from:\n"
                    "https://github.com/bbyybb/ctf-tool\n\n"
                    + "\n".join(errors[:10])
                )
            except Exception:
                pass
            sys.exit(78)  # EX_CONFIG
    except ImportError:
        # integrity.py 本身被删除 — 同样阻止运行
        print(
            "FATAL: ctftool/core/integrity.py is missing.\n"
            "The program cannot start without the integrity module.\n"
            "Please re-clone from: https://github.com/bbyybb/ctf-tool",
            file=sys.stderr,
        )
        sys.exit(78)


def main():
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg == "--help" or arg == "-h":
            from ctftool import __version__
            print(HELP_TEXT.replace("v1.0.0", f"v{__version__}"))
            return
        if arg == "--version" or arg == "-V":
            from ctftool import __version__
            print(f"CTF Tool v{__version__}")
            return
        if arg == "--tui":
            _check_integrity()
            from ctftool.app import CTFToolApp
            app = CTFToolApp()
            app.run()
            return
        if arg == "cli":
            _check_integrity()
            from ctftool.cli import cli_main
            cli_main()
            return

    # 默认启动 GUI
    _check_integrity()
    from ctftool.gui import main as gui_main
    gui_main()


if __name__ == "__main__":
    main()
