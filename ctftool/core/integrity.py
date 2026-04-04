# -*- coding: utf-8 -*-
"""完整性校验模块 — 打赏信息防篡改保护

三层防护体系:
  Layer 1: 本模块 — 启动时校验图片哈希/README标记/FUNDING.yml/代码自检
  Layer 2: GUI 深度集成 — 打赏按钮/弹窗/底栏从本模块读取数据
  Layer 3: CI — GitHub Actions attribution-check job

行为: 校验不通过时程序拒绝启动 (exit code 78)。
警告: 移除或修改本文件将导致程序无法运行。
"""

import hashlib
import inspect
import os
import sys

# ==================== 作者信息 (编码混淆) ====================
# Base: "bbyybb"  Author-CN: "CTF-Tool Contributors"
_A_PARTS = [chr(98), chr(98), chr(121), chr(121), chr(98), chr(98)]
_AC_PARTS = [chr(67), chr(84), chr(70), chr(45), chr(84), chr(111),
             chr(111), chr(108), chr(32), chr(67), chr(111), chr(110),
             chr(116), chr(114), chr(105), chr(98), chr(117), chr(116),
             chr(111), chr(114), chr(115)]
_BMC_PARTS = list("buymeacoffee.com/") + _A_PARTS
_SPONSOR_PARTS = list("github.com/sponsors/") + _A_PARTS

AUTHOR = ''.join(_A_PARTS)
AUTHOR_CN = ''.join(_AC_PARTS)
BMC_URL = "https://www." + ''.join(_BMC_PARTS)
SPONSOR_URL = "https://" + ''.join(_SPONSOR_PARTS)

# ==================== 文件哈希 ====================
EXPECTED_HASHES = {
    "docs/wechat_pay.jpg": "686b9d5bba59d6831580984cb93804543f346d943f2baf4a94216fd13438f1e6",
    "docs/alipay.jpg": "510155042b703d23f7eeabc04496097a7cc13772c5712c8d0716bab5962172dd",
    "docs/bmc_qr.png": "bfd20ef305007c3dacf30dde49ce8f0fe4d7ac3ffcc86ac1f83bc1e75cccfcd6",
}

# ==================== README 必须包含的标记 ====================
README_MARKERS = [
    ''.join(_BMC_PARTS),        # buymeacoffee.com/bbyybb
    ''.join(_SPONSOR_PARTS[len("github.com/"):]),  # sponsors/bbyybb
    "wechat_pay.jpg",
    "alipay.jpg",
    "bmc_qr.png",
]

# ==================== 自检签名 ====================
# 本模块必须包含的关键函数/变量名（防止被清空或替换为空壳）
_SELF_CHECK_TOKENS = [
    "verify_integrity",
    "EXPECTED_HASHES",
    "README_MARKERS",
    "AUTHOR",
    "BMC_URL",
    "SPONSOR_URL",
    "_compute_signature",
    "_verify_images",
    "_verify_readme",
    "_verify_funding",
    "_verify_self",
    "_is_frozen",
    "_EXPECTED_SIG",
]


def _is_frozen() -> bool:
    """检测是否在 PyInstaller 打包环境中运行"""
    return getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')


def _get_project_root() -> str:
    """获取项目根目录（兼容 PyInstaller 打包环境）"""
    if _is_frozen():
        return sys._MEIPASS
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _sha256_file(filepath: str) -> str:
    """计算文件 SHA-256"""
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def _compute_signature() -> str:
    """计算作者信息组合签名"""
    combined = f"{AUTHOR}|{BMC_URL}|{SPONSOR_URL}"
    return hashlib.sha256(combined.encode()).hexdigest()[:16]


# 硬编码的期望签名（基于原始作者信息计算）
# 修改作者信息会导致签名不匹配，程序拒绝启动
_EXPECTED_SIG = "f44319c84fbc77c5"


def _verify_images(root: str) -> list[str]:
    """校验二维码图片哈希"""
    errors = []
    for rel_path, expected_hash in EXPECTED_HASHES.items():
        filepath = os.path.join(root, rel_path)
        if not os.path.isfile(filepath):
            errors.append(f"Missing: {rel_path}")
            continue
        actual = _sha256_file(filepath)
        if actual != expected_hash:
            errors.append(f"Tampered: {rel_path} (hash mismatch)")
    return errors


def _verify_readme(root: str) -> list[str]:
    """校验 README.md 中的打赏标记"""
    errors = []
    readme_path = os.path.join(root, "README.md")
    if not os.path.isfile(readme_path):
        return ["Missing: README.md"]
    with open(readme_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    for marker in README_MARKERS:
        if marker not in content:
            errors.append(f"README.md missing marker: {marker}")
    return errors


def _verify_funding(root: str) -> list[str]:
    """校验 .github/FUNDING.yml"""
    errors = []
    funding_path = os.path.join(root, ".github", "FUNDING.yml")
    if not os.path.isfile(funding_path):
        errors.append("Missing: .github/FUNDING.yml")
        return errors
    with open(funding_path, 'r', encoding='utf-8') as f:
        content = f.read()
    if AUTHOR not in content:
        errors.append("FUNDING.yml missing author reference")
    return errors


def _verify_self() -> list[str]:
    """自检：验证本模块源码包含所有关键标记"""
    if _is_frozen():
        return []  # PyInstaller 打包后无源码，跳过自检
    errors = []
    try:
        source = inspect.getsource(inspect.getmodule(_verify_self))
        for token in _SELF_CHECK_TOKENS:
            if token not in source:
                errors.append(f"Self-check failed: missing '{token}'")
    except Exception:
        errors.append("Self-check failed: cannot read source")
    return errors


def _verify_gui_integration() -> list[str]:
    """校验 GUI 代码中是否保留了打赏入口"""
    if _is_frozen():
        return []  # 打包后无源码，GUI 标记已在编译时固化
    errors = []

    # 方式1: 通过 inspect 读取已加载模块的源码（PyInstaller 兼容）
    try:
        import ctftool.gui as gui_mod
        content = inspect.getsource(gui_mod)
    except Exception:
        # 方式2: 直接读取文件（开发环境）
        root = _get_project_root()
        gui_path = os.path.join(root, "ctftool", "gui.py")
        if not os.path.isfile(gui_path):
            return []
        with open(gui_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

    gui_markers = ["_show_donate", "donate_btn", "btn.support", "buymeacoffee", "sponsors"]
    for marker in gui_markers:
        if marker not in content:
            errors.append(f"gui.py missing marker: {marker}")
    return errors


def verify_integrity(strict: bool = True) -> tuple[bool, list[str]]:
    """执行完整的防篡改校验

    Args:
        strict: True 时校验所有文件，False 时仅校验代码和签名

    Returns:
        (passed, errors): 是否通过，错误列表
    """
    root = _get_project_root()
    all_errors = []

    # 1. 自检
    all_errors.extend(_verify_self())

    # 2. 签名验证（与硬编码期望值比对）
    sig = _compute_signature()
    if sig != _EXPECTED_SIG:
        all_errors.append(
            f"Signature mismatch: author info tampered "
            f"(got {sig}, expected {_EXPECTED_SIG})"
        )

    # 3. GUI 集成校验
    all_errors.extend(_verify_gui_integration())

    if strict:
        # 4. 图片哈希校验（PyInstaller 打包后图片在 _MEIPASS/docs/）
        all_errors.extend(_verify_images(root))

        # 5-6: README 和 FUNDING.yml 仅在源码环境校验
        #       PyInstaller 打包后这些文件不在包内
        if not _is_frozen():
            all_errors.extend(_verify_readme(root))
            all_errors.extend(_verify_funding(root))

    return (len(all_errors) == 0, all_errors)


def get_footer_text() -> str:
    """生成底栏版权文本"""
    from ctftool import __version__
    return (
        f"CTF-Tool v{__version__} | made by: 白白LOVE尹尹 | "
        f"{BMC_URL} | {SPONSOR_URL}"
    )
