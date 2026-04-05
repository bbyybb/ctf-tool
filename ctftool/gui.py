# -*- coding: utf-8 -*-
"""CTF Tool - PyQt6 GUI 主应用"""

import html
import json
import os
import re
import sys
import time
from typing import Callable, Optional

from PyQt6.QtCore import QSize, Qt, QThread, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices, QFont, QIcon, QPixmap
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QStatusBar,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ctftool.core.flag_finder import flag_finder
from ctftool.core.history import history
from ctftool.core.i18n import get_lang, set_lang, t

# ===================== 跨平台字体 =====================
_MONO_FAMILIES = ["Consolas", "SF Mono", "Menlo", "DejaVu Sans Mono", "monospace"]
_MONO_CSS = "Consolas, 'SF Mono', Menlo, 'DejaVu Sans Mono', monospace"


def _mono_font(size: int = 10) -> QFont:
    """返回跨平台等宽字体"""
    f = QFont(_MONO_FAMILIES[0], size)
    f.setFamilies(_MONO_FAMILIES)
    return f


# ===================== 异步工作线程 =====================

class WorkerThread(QThread):
    """通用异步工作线程"""
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, func: Callable, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            result = self.func(*self.args, **self.kwargs)
            self.finished.emit(str(result))
        except Exception as e:
            self.error.emit(f"Error: {e}")


def _clean_curl_cmd(curl_cmd: str) -> str:
    """清理粘贴的 curl 命令 — 处理行续符、多余换行和空白

    支持 3 种常见 curl 格式：
    1. Chrome DevTools: -H + --data-raw (bash 格式，\\ 续行)
    2. Chrome DevTools: -H + --data
    3. Postman: --header + --data + --location
    以及 Windows cmd 格式（^ 续行）
    """
    import re
    # 移除 bash 行续符 \ + 换行（含可选空白）
    cleaned = re.sub(r'\\\s*\n', ' ', curl_cmd)
    cleaned = re.sub(r'\\\s*\r\n', ' ', cleaned)
    # 移除 Windows cmd 行续符 ^ + 换行
    cleaned = re.sub(r'\^\s*\n', ' ', cleaned)
    cleaned = re.sub(r'\^\s*\r\n', ' ', cleaned)
    # 移除残留的换行符
    cleaned = cleaned.replace('\r\n', ' ').replace('\n', ' ').replace('\r', ' ')
    # 清理多余空格
    cleaned = ' '.join(cleaned.split())
    return cleaned.strip()


def _parse_curl_fields(curl_cmd: str) -> tuple:
    """从 curl 命令中解析 URL、headers、POST data

    Returns: (url, headers_list, data_str)
    """
    import shlex
    cleaned = _clean_curl_cmd(curl_cmd)
    url = ""
    headers = []
    data = ""
    try:
        parts = shlex.split(cleaned)
    except ValueError:
        return url, headers, data
    i = 0
    while i < len(parts):
        tok = parts[i]
        if tok == 'curl':
            i += 1
            continue
        if tok in ('-H', '--header') and i + 1 < len(parts):
            i += 1
            headers.append(parts[i])
        elif tok in ('-d', '--data', '--data-raw', '--data-urlencode', '--data-binary') and i + 1 < len(parts):
            i += 1
            data = parts[i]
        elif tok in ('-X', '--request', '-x', '--proxy', '-u', '--user',
                     '-A', '--user-agent', '-b', '--cookie', '-o', '--output'):
            i += 1  # 跳过带参数的选项
        elif tok.startswith('-'):
            pass  # 跳过无参数选项（-k, --compressed, --location 等）
        elif not url:
            if tok.startswith('http://') or tok.startswith('https://'):
                url = tok
        i += 1
    return url, headers, data


# ===================== 模块面板基类 =====================

class ModulePanel(QWidget):
    """通用模块面板"""

    flag_found = pyqtSignal(str)
    send_to_crypto = pyqtSignal(str)
    flags_cleared = pyqtSignal()

    module_name: str = ""
    actions: list[tuple[str, str]] = []
    show_file_btn: bool = True       # 是否显示"选择文件"按钮
    show_send_crypto: bool = True    # 是否显示"发送到密码学"按钮
    input_placeholder: str = ""      # 输入框自定义占位提示

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker: Optional[WorkerThread] = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        # 功能选择（带搜索过滤）
        action_row = QHBoxLayout()
        action_row.addWidget(QLabel(t("label.action")))
        self.action_combo = QComboBox()
        self.action_combo.addItem(t("hint.select_action"), "")
        for i18n_key, method in self.actions:
            self.action_combo.addItem(t(i18n_key), method)
        self.action_combo.setMinimumWidth(250)
        action_row.addWidget(self.action_combo, 1)
        # 搜索过滤框
        self._filter_input = QLineEdit()
        self._filter_input.setPlaceholderText(t("hint.filter_action"))
        self._filter_input.setFixedWidth(160)
        self._filter_input.setClearButtonEnabled(True)
        self._filter_input.textChanged.connect(self._filter_actions)
        action_row.addWidget(self._filter_input)
        layout.addLayout(action_row)

        # 保存完整 action 列表用于过滤恢复
        self._all_actions = [(self.action_combo.itemText(i), self.action_combo.itemData(i))
                             for i in range(self.action_combo.count())]

        # 当用户切换操作时，动态更新参数区域
        self.action_combo.currentIndexChanged.connect(self._on_action_changed)

        # 输入区
        input_group = QGroupBox(t("label.input"))
        input_layout = QVBoxLayout(input_group)
        self.input_text = QTextEdit()
        self.input_text.setMaximumHeight(120)
        self.input_text.setPlaceholderText(self.input_placeholder or t("hint.input"))
        input_layout.addWidget(self.input_text)

        # 参数区
        self.params_layout = QGridLayout()
        self._setup_params()
        if self.params_layout.count() > 0:
            input_layout.addLayout(self.params_layout)

        # 文件选择按钮（仅文件类模块显示）
        if self.show_file_btn:
            file_row = QHBoxLayout()
            self.file_btn = QPushButton(t("btn.select_file"))
            self.file_btn.clicked.connect(self._select_file)
            self.file_btn.setFixedWidth(120)
            file_row.addWidget(self.file_btn)
            file_row.addStretch()
            input_layout.addLayout(file_row)

        layout.addWidget(input_group)

        # 按钮行
        btn_row = QHBoxLayout()
        self.run_btn = QPushButton(t("btn.run"))
        self.run_btn.setStyleSheet(
            "QPushButton { background-color: #2563eb; color: white; "
            "padding: 8px 20px; border-radius: 4px; font-weight: bold; }"
            "QPushButton:hover { background-color: #1d4ed8; }"
        )
        self.run_btn.clicked.connect(self._on_run)
        btn_row.addWidget(self.run_btn)

        self.copy_btn = QPushButton(t("btn.copy"))
        self.copy_btn.clicked.connect(self._copy_output)
        btn_row.addWidget(self.copy_btn)

        self.export_btn = QPushButton(t("btn.export"))
        self.export_btn.clicked.connect(self._export_output)
        btn_row.addWidget(self.export_btn)

        if self.show_send_crypto:
            self.send_btn = QPushButton(t("btn.send_crypto"))
            self.send_btn.clicked.connect(self._send_to_crypto)
            btn_row.addWidget(self.send_btn)

        btn_row.addStretch()
        layout.addLayout(btn_row)

        # 输出区
        output_group = QGroupBox(t("label.output"))
        output_layout = QVBoxLayout(output_group)
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(_mono_font(10))
        self.output_text.setPlaceholderText(t("hint.output"))
        output_layout.addWidget(self.output_text)
        layout.addWidget(output_group, 1)

        # 初始化参数可见性
        self._on_action_changed(0)

    def _setup_params(self):
        """子类重写以添加参数字段"""
        pass

    def _filter_actions(self, text: str):
        """根据搜索关键词过滤操作下拉框"""
        self.action_combo.blockSignals(True)
        self.action_combo.clear()
        keyword = text.strip().lower()
        for label, data in self._all_actions:
            if not keyword or keyword in label.lower():
                self.action_combo.addItem(label, data)
        self.action_combo.blockSignals(False)
        if self.action_combo.count() > 0:
            self.action_combo.setCurrentIndex(0)

    def _on_action_changed(self, index):
        """当操作切换时，更新参数区域的提示和可见性。子类可重写。"""
        action = self.action_combo.currentData()
        if not action:
            return
        # 更新输入框提示（如果子类定义了 ACTION_PARAMS）
        if hasattr(self, 'ACTION_PARAMS') and action in self.ACTION_PARAMS:
            config = self.ACTION_PARAMS[action]
            if "input_hint" in config:
                self.input_text.setPlaceholderText(config["input_hint"])

    def _select_file(self):
        path, _ = QFileDialog.getOpenFileName(self, t("dlg.select_file"))
        if path:
            self.input_text.setPlainText(path)

    def _on_run(self):
        action = self.action_combo.currentData()
        if not action:
            self.output_text.setPlainText(t("msg.select_action"))
            return
        # 每次执行前清零旧 flag
        from ctftool.core.flag_finder import flag_finder
        flag_finder.clear()
        self.flags_cleared.emit()
        self.output_text.setPlainText(t("msg.processing"))
        self.run_btn.setEnabled(False)
        self._execute(action)

    def _execute(self, action: str):
        """子类重写以实现具体逻辑"""
        pass

    # 高亮规则：(正则, 前景色)
    HIGHLIGHT_RULES = [
        (r'(flag\{[^\}]+\}|ctf\{[^\}]+\}|FLAG\{[^\}]+\}|CTF\{[^\}]+\})', '#a6e3a1'),  # flag - 绿色
        (r'(https?://[^\s<>"]+)', '#89b4fa'),  # URL - 蓝色
        (r'(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b)', '#f9e2af'),  # IP:PORT - 黄色
        (r'(\[\+\]|\[!\])', '#a6e3a1'),  # 成功标记 - 绿色
        (r'(\[-\]|\[ERR\])', '#f38ba8'),  # 错误标记 - 红色
        (r'(\[\?\]|\[\*\]|\[i\])', '#89b4fa'),  # 信息标记 - 蓝色
        (r'(===.+===)', '#cba6f7'),  # 分隔标题 - 紫色
    ]

    def _set_highlighted_output(self, text: str):
        """对输出文本应用语法高亮，以 HTML 形式显示"""
        escaped = html.escape(text)
        for pattern, color in self.HIGHLIGHT_RULES:
            escaped = re.sub(pattern, rf'<span style="color:{color}">\1</span>', escaped)
        self.output_text.setHtml(
            f'<pre style="font-family:{_MONO_CSS}; font-size:10pt; '
            f'color:#cdd6f4; white-space:pre-wrap;">{escaped}</pre>'
        )

    def _on_result(self, result: str):
        # 自动检测 Flag 并追加提示
        flags = flag_finder.search_with_decode(result)
        if flags:
            flag_hint = f"\n{'=' * 50}\n"
            flag_hint += f"[!] {t('msg.flag_auto_found')} ({len(flags)}):\n"
            for f in flags:
                flag_hint += f"    >> {f}\n"
            flag_hint += f"{'=' * 50}"
            result = result + flag_hint
        self._set_highlighted_output(result)
        self.run_btn.setEnabled(True)
        self._check_flags(result)
        # 记录操作历史
        action = self.action_combo.currentData() or ""
        module_name = self.__class__.__name__.replace("Panel", "").lower()
        history.add(module_name, action, self.get_input()[:200], result, flags)

    def _on_error(self, error: str):
        self._set_highlighted_output(error)
        self.run_btn.setEnabled(True)

    def _check_flags(self, text: str):
        flags = flag_finder.search_with_decode(text)
        for f in flags:
            self.flag_found.emit(f)

    def _copy_output(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.output_text.toPlainText())

    def _export_output(self):
        text = self.output_text.toPlainText()
        if not text:
            return
        filepath, _ = QFileDialog.getSaveFileName(
            self, t("dlg.export_title"), f"ctf_result_{time.strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt)"
        )
        if filepath:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(text)

    def _send_to_crypto(self):
        text = self.output_text.toPlainText()
        if text:
            self.send_to_crypto.emit(text)

    def _on_progress(self, text: str):
        """实时进度更新（用于长耗时操作如时间盲注）"""
        self._set_highlighted_output(text)

    def _run_async(self, func, *args):
        if self.worker and self.worker.isRunning():
            return  # 上一个任务还在运行
        self.worker = WorkerThread(func, *args)
        self.worker.finished.connect(self._on_result)
        self.worker.error.connect(self._on_error)
        self.worker.progress.connect(self._on_progress)
        self._progress_emit = self.worker.progress.emit
        self.worker.start()

    def get_input(self) -> str:
        return self.input_text.toPlainText().strip()

    def set_input(self, text: str):
        self.input_text.setPlainText(text)


# ===================== 密码学面板 =====================

class CryptoPanel(ModulePanel):
    module_name = "mod.crypto"
    show_file_btn = False
    show_send_crypto = False
    input_placeholder = "输入密文/编码文本 | Enter ciphertext or encoded text"
    actions = [
        ("act.auto_decode", "auto_decode"),
        ("act.base64_encode", "base64_encode"), ("act.base64_decode", "base64_decode"),
        ("act.base32_encode", "base32_encode"), ("act.base32_decode", "base32_decode"),
        ("act.base58_decode", "base58_decode"), ("act.base85_decode", "base85_decode"),
        ("act.hex_encode", "hex_encode"), ("act.hex_decode", "hex_decode"),
        ("act.url_encode", "url_encode"), ("act.url_decode", "url_decode"),
        ("act.caesar_bruteforce", "caesar_bruteforce"), ("act.rot13", "rot13"),
        ("act.vigenere_decrypt", "vigenere_decrypt"),
        ("act.affine_decrypt", "affine_decrypt"), ("act.affine_bruteforce", "affine_bruteforce"),
        ("act.rail_fence_bruteforce", "rail_fence_bruteforce"),
        ("act.atbash", "atbash"), ("act.bacon_decode", "bacon_decode"),
        ("act.xor_single_byte_bruteforce", "xor_single_byte_bruteforce"),
        ("act.xor_decrypt", "xor_decrypt"), ("act.rc4", "rc4"),
        ("act.aes_ecb_decrypt", "aes_ecb_decrypt"),
        ("act.aes_cbc_decrypt", "aes_cbc_decrypt"),
        ("act.des_ecb_decrypt", "des_ecb_decrypt"),
        ("act.identify_hash", "identify_hash"), ("act.hash_crack_dict", "hash_crack_dict"),
        ("act.compute_hash", "compute_hash"), ("act.frequency_analysis", "frequency_analysis"),
        ("act.binary_decode", "binary_decode"), ("act.binary_encode", "binary_encode"),
        ("act.octal_decode", "octal_decode"),
        ("act.html_entity_decode", "html_entity_decode"), ("act.unicode_decode", "unicode_decode"),
        ("act.caesar_decrypt", "caesar_decrypt"),
        ("act.vigenere_encrypt", "vigenere_encrypt"), ("act.vigenere_key_length", "vigenere_key_length"),
        ("act.rail_fence_decrypt", "rail_fence_decrypt"),
        ("act.playfair_encrypt", "playfair_encrypt"), ("act.playfair_decrypt", "playfair_decrypt"),
        ("act.polybius_encrypt", "polybius_encrypt"), ("act.polybius_decrypt", "polybius_decrypt"),
        ("act.xor_auto_crack", "xor_auto_crack"), ("act.padding_oracle_helper", "padding_oracle_helper"),
        ("act.rot47", "rot47"),
        ("act.base58_encode", "base58_encode"), ("act.base85_encode", "base85_encode"),
        ("act.base91_encode", "base91_encode"), ("act.base91_decode", "base91_decode"),
        ("act.base62_encode", "base62_encode"), ("act.base62_decode", "base62_decode"),
        ("act.hill_encrypt", "hill_encrypt"), ("act.hill_decrypt", "hill_decrypt"),
        ("act.columnar_transposition_encrypt", "columnar_transposition_encrypt"),
        ("act.columnar_transposition_decrypt", "columnar_transposition_decrypt"),
        ("act.aes_ecb_encrypt", "aes_ecb_encrypt"), ("act.aes_cbc_encrypt", "aes_cbc_encrypt"),
        ("act.des_ecb_encrypt", "des_ecb_encrypt"),
        ("act.aes_ctr_encrypt", "aes_ctr_encrypt"), ("act.aes_ctr_decrypt", "aes_ctr_decrypt"),
        ("act.triple_des_decrypt", "triple_des_decrypt"), ("act.triple_des_encrypt", "triple_des_encrypt"),
        ("act.blowfish_decrypt", "blowfish_decrypt"), ("act.blowfish_encrypt", "blowfish_encrypt"),
        ("act.crc32", "crc32"), ("act.hmac_compute", "hmac_compute"),
        ("act.hash_length_extension", "hash_length_extension"),
        ("act.hash_crack_online", "hash_crack_online"),
        ("act.ecc_point_add", "ecc_point_add"),
        ("act.dlp_bsgs", "dlp_bsgs"), ("act.dlp_pohlig_hellman", "dlp_pohlig_hellman"),
        ("act.mt19937_predict", "mt19937_predict"),
        ("act.substitution_auto_crack", "substitution_auto_crack"),
        ("act.adfgvx_decrypt", "adfgvx_decrypt"),
        ("act.bifid_decrypt", "bifid_decrypt"), ("act.bifid_encrypt", "bifid_encrypt"),
        ("act.four_square_decrypt", "four_square_decrypt"),
        ("act.chinese_remainder_theorem", "chinese_remainder_theorem"),
        ("act.autokey_decrypt", "autokey_decrypt"), ("act.nihilist_decrypt", "nihilist_decrypt"),
        ("act.book_cipher_decode", "book_cipher_decode"), ("act.rabbit_decrypt", "rabbit_decrypt"),
        ("act.detect_encoding", "detect_encoding"),
        ("act.rsa_coppersmith_helper", "rsa_coppersmith_helper"),
        ("act.rsa_boneh_durfee_helper", "rsa_boneh_durfee_helper"),
        ("act.rsa_import_key", "rsa_import_key"),
        ("act.hash_collision_generate", "hash_collision_generate"),
        ("act.password_strength", "password_strength"),
    ]

    def _setup_params(self):
        self._key_label = QLabel(t("label.key"))
        self.params_layout.addWidget(self._key_label, 0, 0)
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText(t("hint.key"))
        self.params_layout.addWidget(self.key_input, 0, 1)
        self._iv_label = QLabel(t("label.iv"))
        self.params_layout.addWidget(self._iv_label, 0, 2)
        self.iv_input = QLineEdit()
        self.iv_input.setPlaceholderText(t("hint.iv"))
        self.params_layout.addWidget(self.iv_input, 0, 3)

    def _on_action_changed(self, index):
        action = self.action_combo.currentData()
        if not action:
            return

        # 不需要 key/iv 的操作
        NO_KEY = {
            'auto_decode', 'base64_encode', 'base64_decode', 'base32_encode', 'base32_decode',
            'hex_encode', 'hex_decode', 'url_encode', 'url_decode', 'html_entity_decode',
            'unicode_decode', 'binary_decode', 'binary_encode', 'octal_decode',
            'base58_decode', 'base58_encode', 'base85_decode', 'base85_encode',
            'base91_encode', 'base91_decode', 'base62_encode', 'base62_decode',
            'caesar_bruteforce', 'rot13', 'rot47', 'vigenere_key_length',
            'rail_fence_bruteforce', 'atbash', 'bacon_decode', 'affine_bruteforce',
            'xor_single_byte_bruteforce', 'xor_auto_crack', 'substitution_auto_crack',
            'identify_hash', 'compute_hash', 'frequency_analysis', 'crc32',
            'polybius_encrypt', 'polybius_decrypt', 'bifid_encrypt', 'bifid_decrypt',
            'chinese_remainder_theorem', 'mt19937_predict', 'detect_encoding',
            'hash_crack_online', 'hash_crack_dict', 'padding_oracle_helper',
            'ecc_point_add', 'dlp_bsgs', 'dlp_pohlig_hellman',
            'rsa_coppersmith_helper', 'rsa_boneh_durfee_helper',
            'rsa_import_key', 'hash_collision_generate', 'password_strength',
        }

        # 需要 key + iv 的操作
        KEY_IV = {
            'aes_ecb_encrypt', 'aes_ecb_decrypt', 'aes_cbc_encrypt', 'aes_cbc_decrypt',
            'des_ecb_encrypt', 'des_ecb_decrypt',
            'aes_ctr_encrypt', 'aes_ctr_decrypt',
        }

        if action in NO_KEY:
            self.key_input.setVisible(False)
            self.iv_input.setVisible(False)
            self._key_label.setVisible(False)
            self._iv_label.setVisible(False)
        elif action in KEY_IV:
            self.key_input.setVisible(True)
            self.iv_input.setVisible(True)
            self._key_label.setVisible(True)
            self._iv_label.setVisible(True)
            self.key_input.setPlaceholderText("密钥 (hex) | Key (hex)")
            self.iv_input.setPlaceholderText("IV/Nonce (hex)")
        else:
            # 需要 key 但不需要 iv
            self.key_input.setVisible(True)
            self.iv_input.setVisible(False)
            self._key_label.setVisible(True)
            self._iv_label.setVisible(False)
            # 根据操作设置 key 提示
            hints = {
                'vigenere_decrypt': "密钥 | Key (letters)",
                'vigenere_encrypt': "密钥 | Key (letters)",
                'affine_decrypt': "a,b (如 5,8)",
                'hill_encrypt': "矩阵 (如 6,24,1,16 for 2x2)",
                'hill_decrypt': "矩阵 (如 6,24,1,16 for 2x2)",
                'four_square_decrypt': "key1,key2",
                'hmac_compute': "HMAC 密钥 | Key",
                'hash_length_extension': "密钥长度 (数字) | Key length",
                'caesar_decrypt': "偏移量 (数字) | Shift",
                'rail_fence_decrypt': "栏数 (数字) | Rails",
                'xor_decrypt': "密钥 (hex) | Key (hex)",
                'book_cipher_decode': "密码本文本 | Book text",
            }
            self.key_input.setPlaceholderText(hints.get(action, "密钥 | Key"))

    def _execute(self, action):
        text = self.get_input()
        if not text:
            self._on_result(t("msg.no_input"))
            return
        key = self.key_input.text().strip()
        iv = self.iv_input.text().strip()
        self._run_async(self._do, action, text, key, iv)

    def _do(self, action, text, key, iv):
        from ctftool.modules.crypto import CryptoModule
        crypto = CryptoModule()
        # 需要 key 但 key 为空时给出友好提示
        KEY_REQUIRED = {
            'caesar_decrypt', 'rail_fence_decrypt',
            'vigenere_decrypt', 'vigenere_encrypt', 'affine_decrypt', 'xor_decrypt', 'rc4',
            'playfair_encrypt', 'playfair_decrypt', 'hill_encrypt', 'hill_decrypt',
            'columnar_transposition_encrypt', 'columnar_transposition_decrypt',
            'adfgvx_decrypt', 'four_square_decrypt', 'hmac_compute', 'rabbit_decrypt',
            'autokey_decrypt', 'nihilist_decrypt', 'book_cipher_decode',
            'blowfish_decrypt', 'blowfish_encrypt',
            'aes_ecb_encrypt', 'aes_ecb_decrypt', 'aes_cbc_encrypt', 'aes_cbc_decrypt',
            'aes_ctr_encrypt', 'aes_ctr_decrypt', 'des_ecb_encrypt', 'des_ecb_decrypt',
            'triple_des_encrypt', 'triple_des_decrypt',
        }
        if action in KEY_REQUIRED and not key:
            return t("msg.no_input") + ": Key"
        if action == "caesar_decrypt" and key:
            return crypto.caesar_decrypt(text, int(key))
        if action == "rail_fence_decrypt" and key:
            return crypto.rail_fence_decrypt(text, int(key))
        if action == "vigenere_decrypt" and key:
            return crypto.vigenere_decrypt(text, key)
        if action == "affine_decrypt" and key:
            parts = key.split(',')
            if len(parts) != 2:
                return "Affine: a,b (e.g. 5,8)"
            return crypto.affine_decrypt(text, int(parts[0].strip()), int(parts[1].strip()))
        if action == "xor_decrypt" and key:
            return crypto.xor_decrypt(text, key)
        if action == "rc4" and key:
            return crypto.rc4(text, key)
        if action in ("aes_ecb_decrypt", "aes_cbc_decrypt", "des_ecb_decrypt",
                      "aes_ecb_encrypt", "aes_cbc_encrypt", "des_ecb_encrypt"):
            return getattr(crypto, action)(text, key, iv)
        if action in ("aes_ctr_encrypt", "aes_ctr_decrypt"):
            return getattr(crypto, action)(text, key, iv)
        if action in ("triple_des_decrypt", "triple_des_encrypt"):
            return getattr(crypto, action)(text, key)
        if action in ("vigenere_encrypt",) and key:
            return crypto.vigenere_encrypt(text, key)
        if action in ("autokey_decrypt", "nihilist_decrypt") and key:
            return getattr(crypto, action)(text, key)
        if action in ("blowfish_decrypt", "blowfish_encrypt") and key:
            return getattr(crypto, action)(text, key)
        if action == "book_cipher_decode" and key:
            return crypto.book_cipher_decode(text, key)
        # 需要 key 的古典密码
        elif action in ('playfair_encrypt', 'playfair_decrypt', 'columnar_transposition_encrypt',
                         'columnar_transposition_decrypt', 'adfgvx_decrypt',
                         'rabbit_decrypt') and key:
            result = getattr(crypto, action)(text, key)
        elif action == 'four_square_decrypt' and key:
            parts = key.split(',')
            if len(parts) == 2:
                result = getattr(crypto, action)(text, parts[0].strip(), parts[1].strip())
            else:
                result = "Four-square 需要两个密钥，用逗号分隔: key1,key2"
        elif action in ('hill_encrypt', 'hill_decrypt') and key:
            result = getattr(crypto, action)(text, key)
        elif action == 'hmac_compute' and key:
            result = crypto.hmac_compute(text, key)
        elif action == 'hash_length_extension':
            # 格式: known_hash|known_data|append_data 在 text 中, key_length 在 key 中
            parts = text.split('|')
            if len(parts) >= 3:
                kl = int(key) if key else 0
                result = crypto.hash_length_extension(parts[0], parts[1], parts[2], kl)
            else:
                result = "格式: 已知哈希|已知数据|追加数据, Key 栏填密钥长度"
        else:
            result = getattr(crypto, action)(text)
        return result


# ===================== Web 安全面板 =====================

class WebPanel(ModulePanel):
    module_name = "mod.web"
    show_file_btn = False
    input_placeholder = "输入 URL 或 JWT Token | Enter URL or JWT Token"
    actions = [
        ("act.analyze_headers", "analyze_headers"), ("act.check_robots", "check_robots"),
        ("act.check_git_leak", "check_git_leak"), ("act.dir_scan", "dir_scan"),
        ("act.detect_sqli", "detect_sqli"), ("act.detect_xss", "detect_xss"),
        ("act.detect_lfi", "detect_lfi"), ("act.detect_cmdi", "detect_cmdi"),
        ("act.detect_ssrf", "detect_ssrf"), ("act.detect_ssti", "detect_ssti"),
        ("act.gen_sqli", "gen_sqli"), ("act.gen_xss", "gen_xss"),
        ("act.gen_ssti", "gen_ssti"),
        ("act.jwt_forge_none", "jwt_forge_none"), ("act.jwt_crack", "jwt_crack"),
        ("act.generate_payload", "generate_payload"),
        ("act.detect_xxe", "detect_xxe"), ("act.detect_cors", "detect_cors"),
        ("act.detect_open_redirect", "detect_open_redirect"), ("act.detect_crlf", "detect_crlf"),
        ("act.detect_path_traversal", "detect_path_traversal"),
        ("act.detect_http_smuggling", "detect_http_smuggling"),
        ("act.detect_waf", "detect_waf"),
        ("act.deserialize_helper", "deserialize_helper"),
        ("act.prototype_pollution_helper", "prototype_pollution_helper"),
        ("act.race_condition_helper", "race_condition_helper"),
        ("act.configure", "configure"), ("act.parse_curl", "parse_curl"),
        ("act.subdomain_enum", "subdomain_enum"), ("act.fingerprint", "fingerprint"),
        ("act.info_gather", "info_gather"),
        ("act.detect_svn_leak", "detect_svn_leak"), ("act.detect_ds_store", "detect_ds_store"),
        ("act.detect_backup_files", "detect_backup_files"), ("act.detect_env_leak", "detect_env_leak"),
        ("act.detect_graphql", "detect_graphql"), ("act.detect_host_injection", "detect_host_injection"),
        ("act.detect_jsonp", "detect_jsonp"),
        ("act.detect_swagger", "detect_swagger"),
        ("act.dir_listing_crawl", "dir_listing_crawl"),
        ("act.sqli_auto_exploit", "sqli_auto_exploit"),
        ("act.sqli_time_blind", "sqli_time_blind"),
        ("act.detect_csrf", "detect_csrf"),
        ("act.file_upload_helper", "file_upload_helper"),
    ]

    def _setup_params(self):
        self._curl_label = QLabel("curl:")
        self.params_layout.addWidget(self._curl_label, 0, 0)
        self.curl_input = QTextEdit()
        self.curl_input.setMaximumHeight(60)
        self.curl_input.setPlaceholderText("curl 'https://...' -H 'Cookie: ...' -d 'data'  (paste multiline curl here)")
        self.curl_input.setFont(_mono_font(9))
        self.params_layout.addWidget(self.curl_input, 0, 1, 1, 3)
        # 解析按钮
        self._parse_btn = QPushButton(t("btn.parse_curl"))
        self._parse_btn.setFixedWidth(80)
        self._parse_btn.clicked.connect(self._parse_curl_to_fields)
        self.params_layout.addWidget(self._parse_btn, 0, 4)
        self._headers_label = QLabel("Headers:")
        self.params_layout.addWidget(self._headers_label, 1, 0)
        self.headers_input = QLineEdit()
        self.headers_input.setPlaceholderText("Cookie: session=abc; X-Token: xxx")
        self.params_layout.addWidget(self.headers_input, 1, 1, 1, 4)
        self._data_label = QLabel("POST Data:")
        self.params_layout.addWidget(self._data_label, 2, 0)
        self.data_input = QLineEdit()
        self.data_input.setPlaceholderText("username=admin&password=123")
        self.params_layout.addWidget(self.data_input, 2, 1, 1, 4)

    def _parse_curl_to_fields(self):
        """点击解析按钮时自动解析 curl 命令并填充 URL/Headers/POST Data"""
        curl_cmd = self.curl_input.toPlainText().strip()
        if not curl_cmd:
            return
        url, headers, data = _parse_curl_fields(curl_cmd)
        if url:
            self.input_text.setPlainText(url)
        if headers:
            self.headers_input.setText("; ".join(headers))
        if data:
            self.data_input.setText(data)
        self.params_layout.addWidget(self.data_input, 2, 1, 1, 3)

    def _on_action_changed(self, index):
        action = self.action_combo.currentData()
        if not action:
            return
        NO_INPUT = {'prototype_pollution_helper', 'race_condition_helper', 'deserialize_helper', 'file_upload_helper'}
        JWT_INPUT = {'jwt_forge_none', 'jwt_crack'}
        PAYLOAD_GEN = {'generate_payload', 'gen_sqli', 'gen_xss', 'gen_ssti'}
        CONFIG_INPUT = {'configure', 'parse_curl'}
        DOMAIN_INPUT = {'subdomain_enum'}

        # 主输入框提示
        if action in NO_INPUT:
            self.input_text.setPlaceholderText("无需输入 | No input needed")
        elif action in JWT_INPUT:
            self.input_text.setPlaceholderText("JWT Token (eyJhbGci...)")
        elif action in PAYLOAD_GEN:
            self.input_text.setPlaceholderText("Payload 类型 (sqli/xss/ssti/lfi/cmdi) | 或留空使用默认")
        elif action in CONFIG_INPUT:
            self.input_text.setPlaceholderText("curl 命令 | curl command")
        elif action in DOMAIN_INPUT:
            self.input_text.setPlaceholderText("域名 (如 example.com) | Domain")
        else:
            self.input_text.setPlaceholderText("URL (如 http://target.com/?id=1)")

        # curl/headers/data 输入框：只在 URL 检测类操作时显示
        show_web_params = action not in (NO_INPUT | JWT_INPUT | PAYLOAD_GEN | CONFIG_INPUT | DOMAIN_INPUT)
        self.curl_input.setVisible(show_web_params)
        self.headers_input.setVisible(show_web_params)
        self.data_input.setVisible(show_web_params)
        self._curl_label.setVisible(show_web_params)
        self._headers_label.setVisible(show_web_params)
        self._data_label.setVisible(show_web_params)

    def _execute(self, action):
        text = self.get_input()
        curl_cmd = self.curl_input.toPlainText().strip()
        headers_str = self.headers_input.text().strip()
        data_str = self.data_input.text().strip()
        # 如果有 curl 命令，解析并始终覆盖 URL/headers/data
        if curl_cmd:
            url, headers, data = _parse_curl_fields(curl_cmd)
            if url:
                text = url
                self.input_text.setPlainText(text)
            if headers:
                headers_str = "; ".join(headers)
                self.headers_input.setText(headers_str)
            if data:
                data_str = data
                self.data_input.setText(data_str)
        no_input = ('prototype_pollution_helper', 'race_condition_helper',
                    'deserialize_helper', 'file_upload_helper')
        if action in no_input:
            self._run_async(self._do, action, "", "", "", "")
        else:
            self._run_async(self._do, action, text, curl_cmd, headers_str, data_str)

    def _do(self, action, text, curl_cmd="", headers_str="", data_str=""):
        from ctftool.modules.web import WebModule
        web = WebModule()
        # 应用 curl 配置（同时传递 Cookie/Header 等）
        if curl_cmd:
            web.parse_curl(curl_cmd)
        elif headers_str:
            # 解析简单 headers
            headers = {}
            for h in headers_str.split(';'):
                if ':' in h:
                    k, v = h.split(':', 1)
                    headers[k.strip()] = v.strip()
            web.configure(headers=headers)
        if action.startswith("gen_"):
            return web.generate_payload(action[4:])
        if action == "jwt_forge_none":
            return web.jwt_forge_none(text)
        if action == "jwt_crack":
            return web.jwt_crack(text)
        no_input = ("prototype_pollution_helper", "race_condition_helper",
                    "deserialize_helper", "file_upload_helper")
        if action in no_input:
            return getattr(web, action)()
        # sqli_time_blind 支持进度回调
        if action == "sqli_time_blind":
            return web.sqli_time_blind(text, progress_callback=getattr(self, '_progress_emit', None))
        # 支持 POST data 参数
        if data_str and hasattr(web, action):
            import inspect
            sig = inspect.signature(getattr(web, action))
            if 'data' in sig.parameters:
                return getattr(web, action)(text, data=data_str)
        return getattr(web, action)(text)


# ===================== 取证面板 =====================

class ForensicsPanel(ModulePanel):
    module_name = "mod.forensics"
    input_placeholder = "输入文件路径或点击选择文件 | Enter file path or click Select File"
    actions = [
        ("act.identify_file", "identify_file"), ("act.extract_strings", "extract_strings"),
        ("act.extract_metadata", "extract_metadata"), ("act.detect_stego", "detect_stego"),
        ("act.png_crc_fix", "png_crc_fix"), ("act.split_channels", "split_channels"),
        ("act.binwalk_scan", "binwalk_scan"), ("act.binwalk_extract", "binwalk_extract"),
        ("act.hex_view", "hex_view"), ("act.file_diff", "file_diff"),
        ("act.zip_crack", "zip_crack"), ("act.zip_fake_decrypt", "zip_fake_decrypt"),
        ("act.fix_file_header", "fix_file_header"),
        ("act.pcap_analyze", "pcap_analyze"), ("act.usb_keyboard_decode", "usb_keyboard_decode"),
        ("act.usb_mouse_decode", "usb_mouse_decode"),
        ("act.rar_crack", "rar_crack"),
        ("act.gif_frame_extract", "gif_frame_extract"),
        ("act.lsb_extract_advanced", "lsb_extract_advanced"), ("act.lsb_encode", "lsb_encode"),
        ("act.audio_spectrogram", "audio_spectrogram"),
        ("act.pdf_analyze", "pdf_analyze"),
        ("act.pcap_extract_http", "pcap_extract_http"), ("act.pcap_extract_files", "pcap_extract_files"),
        ("act.bit_plane_analysis", "bit_plane_analysis"),
        ("act.dtmf_decode", "dtmf_decode"),
        ("act.office_analyze", "office_analyze"),
        ("act.memory_dump_analyze", "memory_dump_analyze"),
        ("act.detect_ntfs_ads", "detect_ntfs_ads"),
        ("act.detect_exif_tampering", "detect_exif_tampering"),
        ("act.analyze_disk_image", "analyze_disk_image"),
        ("act.analyze_email", "analyze_email"),
        ("act.analyze_registry", "analyze_registry"),
        ("act.file_timeline", "file_timeline"),
        ("act.detect_dns_tunnel", "detect_dns_tunnel"),
        ("act.file_carve", "file_carve"),
        ("act.steghide_extract", "steghide_extract"), ("act.zsteg_scan", "zsteg_scan"),
        ("act.blind_watermark_extract", "blind_watermark_extract"),
        ("act.apng_extract", "apng_extract"), ("act.sstv_decode_helper", "sstv_decode_helper"),
        ("act.stego_full_scan", "stego_full_scan"),
        ("act.file_carve_precise", "file_carve_precise"),
        ("act.memory_forensics_enhanced", "memory_forensics_enhanced"),
    ]

    def _setup_params(self):
        self._extra_label = QLabel(t("label.file2"))
        self.params_layout.addWidget(self._extra_label, 0, 0)
        self.extra_input = QLineEdit()
        self.extra_input.setPlaceholderText(t("hint.file2"))
        self.params_layout.addWidget(self.extra_input, 0, 1)

    def _on_action_changed(self, index):
        action = self.action_combo.currentData()
        if not action:
            return

        NEED_EXTRA = {'file_diff', 'zip_crack', 'rar_crack', 'lsb_encode', 'hex_view', 'steghide_extract'}
        self.extra_input.setVisible(action in NEED_EXTRA)
        self._extra_label.setVisible(action in NEED_EXTRA)

        hints = {
            'file_diff': "第二个文件路径 | Second file path",
            'zip_crack': "字典路径 (可选) | Wordlist path (optional)",
            'rar_crack': "字典路径 (可选) | Wordlist path (optional)",
            'lsb_encode': "要隐藏的文本 | Secret text to hide",
            'hex_view': "偏移,长度 (如 0,512) | offset,length",
            'steghide_extract': "密码或字典路径 (可选) | Password or wordlist path",
        }
        self.extra_input.setPlaceholderText(hints.get(action, ""))

    def _execute(self, action):
        filepath = self.get_input()
        if not filepath:
            self._on_result(t("msg.enter_file"))
            return
        extra = self.extra_input.text().strip()
        self._run_async(self._do, action, filepath, extra)

    def _do(self, action, filepath, extra):
        from ctftool.modules.forensics import ForensicsModule
        f = ForensicsModule()
        if action == "file_diff":
            return f.file_diff(filepath, extra) if extra else t("msg.need_file2")
        if action == "zip_crack":
            return f.zip_crack(filepath, extra or None)
        elif action == 'rar_crack':
            return f.rar_crack(filepath, extra or None)
        elif action == 'lsb_encode':
            if not extra:
                return "LSB 隐写写入需要在参数栏输入要隐藏的文本"
            return f.lsb_encode(filepath, extra)
        elif action == 'hex_view' and extra:
            parts = extra.split(',')
            offset = int(parts[0].strip()) if parts else 0
            length = int(parts[1].strip()) if len(parts) > 1 else 512
            return f.hex_view(filepath, offset, length)
        elif action == 'steghide_extract':
            return f.steghide_extract(filepath, extra or "")
        return getattr(f, action)(filepath)


# ===================== 逆向面板 =====================

class ReversePanel(ModulePanel):
    module_name = "mod.reverse"
    show_send_crypto = False
    input_placeholder = "输入二进制文件路径 | Enter binary file path"
    actions = [
        ("act.analyze_binary", "analyze_binary"), ("act.check_elf_protections", "check_elf_protections"),
        ("act.extract_strings_ascii", "extract_strings_ascii"),
        ("act.extract_strings_utf16", "extract_strings_utf16"),
        ("act.disassemble", "disassemble"), ("act.decompile_pyc", "decompile_pyc"),
        ("act.extract_strings_from_binary", "extract_strings_from_binary"),
        ("act.check_pe_protections", "check_pe_protections"),
        ("act.detect_packer", "detect_packer"),
        ("act.list_imports_exports", "list_imports_exports"),
        ("act.analyze_apk", "analyze_apk"),
        ("act.analyze_dotnet", "analyze_dotnet"),
        ("act.analyze_go_binary", "analyze_go_binary"),
        ("act.yara_scan", "yara_scan"),
        ("act.deobfuscate_strings", "deobfuscate_strings"),
        ("act.analyze_rust_binary", "analyze_rust_binary"),
        ("act.analyze_ipa", "analyze_ipa"),
    ]

    def _setup_params(self):
        self._offset_label = QLabel(t("label.offset"))
        self.params_layout.addWidget(self._offset_label, 0, 0)
        self.offset_input = QLineEdit()
        self.offset_input.setPlaceholderText(t("hint.offset"))
        self.params_layout.addWidget(self.offset_input, 0, 1)

    def _on_action_changed(self, index):
        action = self.action_combo.currentData()
        if not action:
            return
        need_offset = action == 'disassemble'
        self.offset_input.setVisible(need_offset)
        self._offset_label.setVisible(need_offset)

    def _execute(self, action):
        filepath = self.get_input()
        if not filepath:
            self._on_result(t("msg.enter_file"))
            return
        offset_str = self.offset_input.text().strip()
        self._run_async(self._do, action, filepath, offset_str)

    def _do(self, action, filepath, offset_str):
        from ctftool.modules.reverse import ReverseModule
        r = ReverseModule()
        offset = int(offset_str, 16) if offset_str else 0
        if action == "extract_strings_ascii":
            return r.extract_strings_from_binary(filepath, encoding="ascii")
        if action == "extract_strings_utf16":
            return r.extract_strings_from_binary(filepath, encoding="utf16")
        if action == "disassemble":
            return r.disassemble(filepath, offset=offset)
        return getattr(r, action)(filepath)


# ===================== 区块链面板 =====================

class BlockchainPanel(ModulePanel):
    module_name = "mod.blockchain"
    show_file_btn = False
    show_send_crypto = False
    input_placeholder = "输入 Solidity 源码 / ABI 数据 / 字节码 | Enter Solidity source / ABI data / bytecode"
    actions = [
        ("act.analyze_contract", "analyze_contract"),
        ("act.detect_reentrancy", "detect_reentrancy"),
        ("act.detect_integer_overflow", "detect_integer_overflow"),
        ("act.detect_tx_origin", "detect_tx_origin"),
        ("act.detect_selfdestruct", "detect_selfdestruct"),
        ("act.detect_unchecked_call", "detect_unchecked_call"),
        ("act.abi_decode", "abi_decode"),
        ("act.abi_encode", "abi_encode"),
        ("act.selector_lookup", "selector_lookup"),
        ("act.disasm_bytecode", "disasm_bytecode"),
        ("act.storage_layout_helper", "storage_layout_helper"),
        ("act.flashloan_template", "flashloan_template"),
        ("act.reentrancy_exploit_template", "reentrancy_exploit_template"),
        ("act.evm_puzzle_helper", "evm_puzzle_helper"),
        ("act.common_patterns", "common_patterns"),
    ]

    NO_INPUT = {'flashloan_template', 'reentrancy_exploit_template',
                'evm_puzzle_helper', 'common_patterns'}

    def _on_action_changed(self, index):
        action = self.action_combo.currentData()
        if not action:
            return
        if action in self.NO_INPUT:
            self.input_text.setPlaceholderText("无需输入，直接运行 | No input needed, just run")
        elif action in ('abi_decode', 'disasm_bytecode'):
            self.input_text.setPlaceholderText("输入十六进制数据 | Enter hex data (e.g., 0x60606040...)")
        elif action in ('abi_encode', 'selector_lookup'):
            self.input_text.setPlaceholderText(
                "输入函数签名 | e.g., transfer(address,uint256)")
        elif action == 'storage_layout_helper':
            self.input_text.setPlaceholderText(
                "输入变量声明 | e.g., uint256 x;\\naddress owner;")
        else:
            self.input_text.setPlaceholderText("输入 Solidity 源码 | Enter Solidity source code")

    def _execute(self, action):
        text = self.get_input()
        self._run_async(self._do, action, text)

    def _do(self, action, text):
        from ctftool.modules.blockchain import BlockchainModule
        bc = BlockchainModule()
        return getattr(bc, action)(text)


# ===================== Pwn 面板 =====================

class PwnPanel(ModulePanel):
    module_name = "mod.pwn"
    show_send_crypto = False
    input_placeholder = "输入文本/地址/文件路径 | Enter text, address, or file path"
    actions = [
        ("act.generate_pattern", "generate_pattern"), ("act.find_pattern_offset", "find_pattern_offset"),
        ("act.generate_padding", "generate_padding"),
        ("act.format_string_read", "format_string_read"), ("act.format_string_write", "format_string_write"),
        ("act.find_format_offset", "find_format_offset"),
        ("act.find_rop_gadgets", "find_rop_gadgets"), ("act.shellcode_template", "shellcode_template"),
        ("act.addr_convert", "addr_convert"),
        ("act.pwntools_template", "pwntools_template"), ("act.ret2libc_template", "ret2libc_template"),
        ("act.ret2syscall_template", "ret2syscall_template"),
        ("act.srop_template", "srop_template"),
        ("act.check_bad_chars", "check_bad_chars"),
        ("act.got_overwrite_template", "got_overwrite_template"),
        ("act.heap_exploit_template", "heap_exploit_template"),
        ("act.one_gadget_helper", "one_gadget_helper"),
        ("act.ret2csu_template", "ret2csu_template"),
        ("act.stack_pivot_template", "stack_pivot_template"),
        ("act.seccomp_helper", "seccomp_helper"),
        ("act.io_file_template", "io_file_template"),
        ("act.house_of_orange_template", "house_of_orange_template"),
        ("act.auto_ret2text", "auto_ret2text"),
        ("act.auto_ret2shellcode", "auto_ret2shellcode"),
        ("act.auto_pwn_analyze", "auto_pwn_analyze"),
    ]

    def _setup_params(self):
        self._length_label = QLabel(t("label.length"))
        self.params_layout.addWidget(self._length_label, 0, 0)
        self.length_input = QLineEdit()
        self.length_input.setPlaceholderText(t("hint.length"))
        self.params_layout.addWidget(self.length_input, 0, 1)
        self._addr_label = QLabel(t("label.addr"))
        self.params_layout.addWidget(self._addr_label, 0, 2)
        self.addr_input = QLineEdit()
        self.addr_input.setPlaceholderText(t("hint.addr"))
        self.params_layout.addWidget(self.addr_input, 0, 3)
        self._arch_label = QLabel(t("label.arch2"))
        self.params_layout.addWidget(self._arch_label, 1, 0)
        self.arch_combo = QComboBox()
        self.arch_combo.addItem("x86 (32-bit)", "x86")
        self.arch_combo.addItem("x64 (64-bit)", "x64")
        # Remote 连接信息（auto_pwn_* 使用）
        self._remote_label = QLabel("Remote:")
        self.params_layout.addWidget(self._remote_label, 1, 2)
        self.remote_input = QLineEdit()
        self.remote_input.setPlaceholderText("nc host port / host:port")
        self.params_layout.addWidget(self.remote_input, 1, 3)
        self.params_layout.addWidget(self.arch_combo, 1, 1)

    def _on_action_changed(self, index):
        action = self.action_combo.currentData()
        if not action:
            return

        NEED_LENGTH = {'generate_pattern', 'generate_padding', 'format_string_read', 'format_string_write'}
        NEED_ADDR = {'generate_padding', 'format_string_read', 'format_string_write'}
        NEED_ARCH = {'generate_padding', 'format_string_read', 'format_string_write',
                     'shellcode_template', 'pwntools_template', 'ret2libc_template',
                     'ret2syscall_template', 'srop_template', 'got_overwrite_template',
                     'ret2csu_template', 'stack_pivot_template'}
        NEED_REMOTE = {'auto_ret2text', 'auto_ret2shellcode', 'auto_pwn_analyze'}

        self.length_input.setVisible(action in NEED_LENGTH)
        self._length_label.setVisible(action in NEED_LENGTH)
        self.addr_input.setVisible(action in NEED_ADDR)
        self._addr_label.setVisible(action in NEED_ADDR)
        self.arch_combo.setVisible(action in NEED_ARCH)
        self._arch_label.setVisible(action in NEED_ARCH)
        self.remote_input.setVisible(action in NEED_REMOTE)
        self._remote_label.setVisible(action in NEED_REMOTE)

    def _execute(self, action):
        # 主线程中读取所有 Qt 控件值
        text = self.get_input()
        length_str = self.length_input.text().strip()
        addr = self.addr_input.text().strip()
        arch = self.arch_combo.currentData()
        remote_str = self.remote_input.text().strip()
        self._run_async(self._do, action, text, length_str, addr, arch, remote_str)

    def _do(self, action, text, length_str, addr, arch, remote_str=""):
        from ctftool.modules.pwn import PwnModule
        pwn = PwnModule()
        # auto_* 分析方法
        if action in ("auto_ret2text", "auto_ret2shellcode", "auto_pwn_analyze"):
            if not text:
                return t("msg.enter_file")
            return getattr(pwn, action)(text, remote_str)
        if action == "generate_pattern":
            return pwn.generate_pattern(int(length_str) if length_str else 200)
        if action == "find_pattern_offset":
            return pwn.find_pattern_offset(text or addr)
        if action == "generate_padding":
            return pwn.generate_padding(int(length_str) if length_str else 0, addr or "0xdeadbeef", arch)
        if action == "format_string_read":
            return pwn.format_string_read(int(length_str) if length_str else 7, addr or "0x08048000", arch)
        if action == "format_string_write":
            try:
                val = int(text, 16) if text else 0
            except ValueError:
                return "写入值格式错误，需要十六进制 (如 0x41414141)"
            return pwn.format_string_write(int(length_str) if length_str else 7, addr or "0x08048000", val, arch)
        if action == "find_format_offset":
            return pwn.find_format_offset()
        if action == "find_rop_gadgets":
            return pwn.find_rop_gadgets(text)
        if action == "shellcode_template":
            os_type = "linux" if not text or "linux" in text.lower() else "windows"
            return pwn.shellcode_template(os_type, arch)
        if action == "addr_convert":
            return pwn.addr_convert(text or addr)
        if action == "pwntools_template":
            return pwn.pwntools_template(text or "target", arch)
        if action == "ret2libc_template":
            return pwn.ret2libc_template(arch)
        if action in ("ret2syscall_template", "srop_template", "got_overwrite_template",
                       "ret2csu_template", "stack_pivot_template"):
            return getattr(pwn, action)(arch)
        if action in ("seccomp_helper", "io_file_template", "house_of_orange_template"):
            return getattr(pwn, action)()
        if action == "check_bad_chars":
            return pwn.check_bad_chars(text)
        if action == "heap_exploit_template":
            return pwn.heap_exploit_template(text or "fastbin")
        if action == "one_gadget_helper":
            return pwn.one_gadget_helper()
        return f"{t('msg.unknown_action')}: {action}"


# ===================== 杂项面板 =====================

class MiscPanel(ModulePanel):
    module_name = "mod.misc"
    input_placeholder = "输入文本/编码/文件路径 | Enter text, encoding, or file path"
    actions = [
        ("act.base_convert", "base_convert"),
        ("act.morse_encode", "morse_encode"), ("act.morse_decode", "morse_decode"),
        ("act.braille_decode", "braille_decode"), ("act.braille_encode", "braille_encode"),
        ("act.qr_decode", "qr_decode"),
        ("act.ascii_table", "ascii_table"), ("act.char_convert", "char_convert"),
        ("act.rot_all", "rot_all"),
        ("act.t9_decode", "t9_decode"), ("act.keyboard_coord_decode", "keyboard_coord_decode"),
        ("act.php_serialize_decode", "php_serialize_decode"),
        ("act.zwc_decode", "zwc_decode"), ("act.zwc_encode", "zwc_encode"),
        ("act.brainfuck_execute", "brainfuck_execute"), ("act.ook_decode", "ook_decode"),
        ("act.jwt_decode", "jwt_decode"), ("act.gen_wordlist", "gen_wordlist"),
        ("act.core_values_decode", "core_values_decode"), ("act.core_values_encode", "core_values_encode"),
        ("act.pigpen_decode", "pigpen_decode"),
        ("act.dna_decode", "dna_decode"), ("act.dna_encode", "dna_encode"),
        ("act.barcode_decode", "barcode_decode"),
        ("act.ook_execute", "ook_execute"),
        ("act.rot47", "rot47"),
        ("act.whitespace_execute", "whitespace_execute"),
        ("act.base100_encode", "base100_encode"), ("act.base100_decode", "base100_decode"),
        ("act.tap_code_encode", "tap_code_encode"), ("act.tap_code_decode", "tap_code_decode"),
        ("act.bacon_encode", "bacon_encode"),
        ("act.vigenere_auto_crack", "vigenere_auto_crack"),
        ("act.qr_generate", "qr_generate"),
        ("act.semaphore_decode", "semaphore_decode"), ("act.semaphore_encode", "semaphore_encode"),
        ("act.nato_decode", "nato_decode"), ("act.nato_encode", "nato_encode"),
        ("act.coord_convert", "coord_convert"),
        ("act.leet_decode", "leet_decode"), ("act.leet_encode", "leet_encode"),
        ("act.baudot_decode", "baudot_decode"),
        ("act.emoji_cipher_decode", "emoji_cipher_decode"), ("act.emoji_cipher_encode", "emoji_cipher_encode"),
        ("act.manchester_decode", "manchester_decode"), ("act.manchester_encode", "manchester_encode"),
        ("act.color_hex_decode", "color_hex_decode"),
        ("act.dancing_men_decode", "dancing_men_decode"),
        ("act.word_frequency", "word_frequency"),
        ("act.enigma_decrypt", "enigma_decrypt"),
        ("act.pixel_extract", "pixel_extract"),
        ("act.keyboard_layout_convert", "keyboard_layout_convert"),
        ("act.timestamp_convert", "timestamp_convert"),
        ("act.qr_batch_decode", "qr_batch_decode"),
        ("act.ocr_extract", "ocr_extract"),
        ("act.uuencode", "uuencode"), ("act.uudecode", "uudecode"),
        ("act.xxencode", "xxencode"), ("act.xxdecode", "xxdecode"),
        ("act.quoted_printable_encode", "quoted_printable_encode"),
        ("act.quoted_printable_decode", "quoted_printable_decode"),
        ("act.audio_morse_decode", "audio_morse_decode"),
        ("act.piet_helper", "piet_helper"),
        ("act.malbolge_execute", "malbolge_execute"),
        ("act.ebcdic_to_ascii", "ebcdic_to_ascii"), ("act.ascii_to_ebcdic", "ascii_to_ebcdic"),
    ]

    def _setup_params(self):
        self.kw_input = QLineEdit()
        self.kw_input.setPlaceholderText(t("hint.keywords"))
        self._kw_label = QLabel(t("label.keywords"))
        self.params_layout.addWidget(self._kw_label, 0, 0)
        self.params_layout.addWidget(self.kw_input, 0, 1)

    def _on_action_changed(self, index):
        action = self.action_combo.currentData()
        if not action:
            return
        # keywords 输入只在 gen_wordlist 时显示
        show_kw = action == 'gen_wordlist'
        self.kw_input.setVisible(show_kw)
        self._kw_label.setVisible(show_kw)

        # 文件类操作
        FILE_ACTIONS = {'qr_decode', 'barcode_decode', 'pixel_extract', 'ocr_extract', 'qr_batch_decode',
                        'audio_morse_decode', 'piet_helper'}
        NO_INPUT = {'ascii_table'}

        if action in FILE_ACTIONS:
            self.input_text.setPlaceholderText("文件/目录路径 | File/directory path")
        elif action in NO_INPUT:
            self.input_text.setPlaceholderText("无需输入 | No input needed")
        elif action == 'gen_wordlist':
            self.input_text.setPlaceholderText("姓名 | Name")
        elif action == 'enigma_decrypt':
            self.input_text.setPlaceholderText("明文/密文 (配置格式: text|rotors|reflector|positions|plugboard)")
        elif action == 'keyboard_layout_convert':
            self.input_text.setPlaceholderText("文本 (格式: text|from_layout|to_layout, 如 hello|qwerty|dvorak)")
        elif action == 'zwc_encode':
            self.input_text.setPlaceholderText("格式: 载体文本|隐藏文本 | carrier|secret")
        elif action == 'timestamp_convert':
            self.input_text.setPlaceholderText("时间戳 (Unix/Windows/日期字符串) | Timestamp")
        elif action == 'coord_convert':
            self.input_text.setPlaceholderText("坐标 (如 39.9042,116.4074 或 39°54'15\"N,116°24'27\"E)")
        else:
            self.input_text.setPlaceholderText("输入文本/编码 | Enter text or encoding")

    def _execute(self, action):
        text = self.get_input()
        keywords = self.kw_input.text().strip()
        self._run_async(self._do, action, text, keywords)

    def _do(self, action, text, keywords):
        from ctftool.modules.misc import MiscModule
        m = MiscModule()
        if action == "gen_wordlist":
            parts = keywords.split(',') if keywords else []
            return m.generate_wordlist(
                parts[0] if parts else "",
                parts[1] if len(parts) > 1 else "",
                parts[2:] if len(parts) > 2 else None,
            )
        if action == "ascii_table":
            return m.ascii_table()
        if not text:
            return t("msg.no_input")
        # 需要从 text 中解析多个参数的方法（用 | 分隔）
        if action == "zwc_encode" and '|' in text:
            parts = text.split('|', 1)
            return m.zwc_encode(parts[1].strip(), parts[0].strip())
        if action == "enigma_decrypt" and '|' in text:
            parts = text.split('|', 1)
            return m.enigma_decrypt(parts[0].strip(), parts[1].strip())
        if action == "keyboard_layout_convert" and '|' in text:
            parts = text.split('|')
            txt = parts[0].strip()
            from_l = parts[1].strip() if len(parts) > 1 else "qwerty"
            to_l = parts[2].strip() if len(parts) > 2 else "dvorak"
            return m.keyboard_layout_convert(txt, from_l, to_l)
        return getattr(m, action)(text)


# ===================== RSA 面板 =====================

class RSAPanel(ModulePanel):
    module_name = "mod.rsa"
    show_file_btn = False
    show_send_crypto = False
    input_placeholder = "RSA 参数在下方输入 | Enter RSA parameters below"
    actions = [
        ("act.small_e", "small_e"), ("act.common_modulus", "common_modulus"),
        ("act.wiener", "wiener"), ("act.fermat", "fermat"),
        ("act.pollard_p1", "pollard_p1"), ("act.factordb", "factordb"),
        ("act.dp_leak", "dp_leak"), ("act.hastad", "hastad"),
        ("act.pollard_rho", "pollard_rho"), ("act.direct", "direct"),
        ("act.rsa_auto_attack", "rsa_auto_attack"),
        ("act.dq_leak", "dq_leak"), ("act.multi_prime", "multi_prime"),
        ("act.rabin_decrypt", "rabin_decrypt"),
        ("act.rsa_batch_gcd", "rsa_batch_gcd"),
        ("act.rsa_franklin_reiter", "rsa_franklin_reiter"),
        ("act.rsa_williams_p1", "rsa_williams_p1"),
    ]

    def _setup_params(self):
        self.n_input = QLineEdit()
        self.n_input.setPlaceholderText(t("rsa.hint_n"))
        self.e_input = QLineEdit()
        self.e_input.setPlaceholderText(t("rsa.hint_e"))
        self.c_input = QLineEdit()
        self.c_input.setPlaceholderText(t("rsa.hint_c"))
        self.extra_input = QLineEdit()
        self.extra_input.setPlaceholderText(t("rsa.hint_extra"))
        self.params_layout.addWidget(QLabel("n ="), 0, 0)
        self.params_layout.addWidget(self.n_input, 0, 1)
        self.params_layout.addWidget(QLabel("e ="), 0, 2)
        self.params_layout.addWidget(self.e_input, 0, 3)
        self.params_layout.addWidget(QLabel("c ="), 1, 0)
        self.params_layout.addWidget(self.c_input, 1, 1)
        self._extra_label = QLabel("Extra:")
        self.params_layout.addWidget(self._extra_label, 1, 2)
        self.params_layout.addWidget(self.extra_input, 1, 3)

    def _on_action_changed(self, index):
        action = self.action_combo.currentData()
        if not action:
            return
        # extra 输入框：根据攻击方式显示不同提示，不需要时隐藏
        NEED_EXTRA = {
            'common_modulus': "e2,c2",
            'dp_leak': "dp 值 | dp value",
            'dq_leak': "dq 值 | dq value",
            'direct': "p,q",
            'multi_prime': "p1,p2,p3,... (逗号分隔)",
            'hastad': "n2,c2;n3,c3;... (分号分隔各组)",
            'rabin_decrypt': "p,q",
            'rsa_batch_gcd': "n1,n2,n3,... (逗号分隔多个 n)",
            'rsa_franklin_reiter': "c2,a,b (c2 为第二组密文, m2=a*m1+b)",
        }
        if action in NEED_EXTRA:
            self.extra_input.setVisible(True)
            self._extra_label.setVisible(True)
            self.extra_input.setPlaceholderText(NEED_EXTRA[action])
        else:
            self.extra_input.setVisible(False)
            self._extra_label.setVisible(False)

    def _execute(self, action):
        # 主线程中读取所有 Qt 控件值，避免在工作线程中访问 Qt 控件
        n_str = self.n_input.text().strip() or "0"
        e_str = self.e_input.text().strip() or "0"
        c_str = self.c_input.text().strip() or "0"
        extra = self.extra_input.text().strip()
        self._run_async(self._do, action, n_str, e_str, c_str, extra)

    def _do(self, action, n_str, e_str, c_str, extra):
        from ctftool.modules.crypto import CryptoModule
        crypto = CryptoModule()
        try:
            n = int(n_str)
            e = int(e_str)
            c = int(c_str)
        except ValueError:
            return "参数格式错误: n/e/c 必须为整数"
        if action == "small_e":
            return crypto.rsa_decrypt_small_e(c, e, n)
        if action == "common_modulus":
            parts = extra.split(',')
            if len(parts) != 2:
                return t("msg.rsa_need_extra")
            return crypto.rsa_common_modulus(c, int(parts[1].strip()), e, int(parts[0].strip()), n)
        if action == "wiener":
            return crypto.rsa_wiener(e, n, c)
        if action == "fermat":
            return crypto.rsa_fermat(n, e, c)
        if action == "pollard_p1":
            return crypto.rsa_pollard_p1(n, e, c)
        if action == "factordb":
            return crypto.rsa_factordb(n, e, c)
        if action == "dp_leak":
            return crypto.rsa_dp_leak(n, e, c, int(extra) if extra else 0)
        if action == "hastad":
            return crypto.rsa_hastad(e, c, n, extra)
        if action == "pollard_rho":
            return crypto.rsa_pollard_rho(n, e, c)
        if action == "direct":
            parts = extra.split(',')
            if len(parts) != 2:
                return t("msg.rsa_need_extra")  # Extra 需要 p,q
            return crypto.rsa_decrypt_direct(int(parts[0].strip()), int(parts[1].strip()), e, c)
        if action == "rsa_auto_attack":
            return crypto.rsa_auto_attack(n, e, c)
        if action == "dq_leak":
            return crypto.rsa_dq_leak(n, e, c, int(extra) if extra else 0)
        if action == "multi_prime":
            return crypto.rsa_decrypt_multi_prime(extra, e, c)
        if action == "rabin_decrypt":
            parts = extra.split(',')
            if len(parts) != 2:
                return t("msg.rsa_need_extra")  # Extra 需要 p,q
            return crypto.rabin_decrypt(c, int(parts[0].strip()), int(parts[1].strip()))
        if action == "rsa_batch_gcd":
            return crypto.rsa_batch_gcd(extra or str(n), e, c)
        if action == "rsa_franklin_reiter":
            parts = extra.split(',')
            if len(parts) < 1:
                return t("msg.rsa_need_extra")
            c2 = int(parts[0].strip())
            a = int(parts[1].strip()) if len(parts) > 1 else 1
            b = int(parts[2].strip()) if len(parts) > 2 else 1
            return crypto.rsa_franklin_reiter(c, c2, e, n, a, b)
        if action == "rsa_williams_p1":
            return crypto.rsa_williams_p1(n, e, c)
        return f"{t('msg.unknown_action')}: {action}"


# ===================== 自动扫描面板 =====================

class AutoScanPanel(QWidget):
    flag_found = pyqtSignal(str)
    flags_cleared = pyqtSignal()  # 新扫描开始时通知清零

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        layout = QVBoxLayout(self)

        # 扫描类型
        type_row = QHBoxLayout()
        type_row.addWidget(QLabel(t("label.scan_type")))
        self.type_combo = QComboBox()
        self.type_combo.addItem(t("scan.url"), "url")
        self.type_combo.addItem(t("scan.file"), "file")
        self.type_combo.addItem(t("scan.text"), "text")
        type_row.addWidget(self.type_combo, 1)
        layout.addLayout(type_row)

        # curl 配置（多行输入 + 解析按钮）
        curl_row = QHBoxLayout()
        curl_row.addWidget(QLabel("curl:"))
        self.curl_input = QTextEdit()
        self.curl_input.setMaximumHeight(60)
        self.curl_input.setPlaceholderText(t("hint.curl_cmd") + "  (paste multiline curl here)")
        self.curl_input.setFont(_mono_font(9))
        curl_row.addWidget(self.curl_input, 1)
        self._parse_btn = QPushButton(t("btn.parse_curl"))
        self._parse_btn.setFixedWidth(80)
        self._parse_btn.clicked.connect(self._parse_curl_to_fields)
        curl_row.addWidget(self._parse_btn)
        layout.addLayout(curl_row)

        # Headers + POST Data（curl 解析后回显，只读）
        extra_row = QHBoxLayout()
        extra_row.addWidget(QLabel("Headers:"))
        self.headers_input = QLineEdit()
        self.headers_input.setPlaceholderText("Cookie: session=abc; X-Token: xxx")
        extra_row.addWidget(self.headers_input, 1)
        extra_row.addWidget(QLabel("POST:"))
        self.data_input = QLineEdit()
        self.data_input.setPlaceholderText("username=admin&password=123")
        extra_row.addWidget(self.data_input, 1)
        layout.addLayout(extra_row)

        # 目标输入
        self.target_input = QTextEdit()
        self.target_input.setMaximumHeight(80)
        self.target_input.setPlaceholderText(t("label.target"))
        layout.addWidget(self.target_input)

        # 按钮
        btn_row = QHBoxLayout()
        self.scan_btn = QPushButton(t("btn.start_scan"))
        self.scan_btn.setStyleSheet(
            "QPushButton { background-color: #16a34a; color: white; "
            "padding: 8px 20px; border-radius: 4px; font-weight: bold; }"
            "QPushButton:hover { background-color: #15803d; }"
        )
        self.scan_btn.clicked.connect(self._start_scan)
        btn_row.addWidget(self.scan_btn)
        self.file_btn = QPushButton(t("btn.select_file"))
        self.file_btn.clicked.connect(self._select_file)
        btn_row.addWidget(self.file_btn)

        self.copy_btn = QPushButton(t("btn.copy"))
        self.copy_btn.clicked.connect(self._copy_output)
        btn_row.addWidget(self.copy_btn)

        self.export_btn = QPushButton(t("btn.export"))
        self.export_btn.clicked.connect(self._export_output)
        btn_row.addWidget(self.export_btn)

        btn_row.addStretch()
        layout.addLayout(btn_row)

        # 进度条
        from PyQt6.QtWidgets import QProgressBar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet(
            "QProgressBar { background-color: #313244; border: 1px solid #45475a;"
            " border-radius: 4px; text-align: center; color: #cdd6f4; }"
            "QProgressBar::chunk { background-color: #89b4fa;"
            " border-radius: 3px; }"
        )
        layout.addWidget(self.progress_bar)

        # 输出
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(_mono_font(10))
        layout.addWidget(self.output_text, 1)

    def _select_file(self):
        path, _ = QFileDialog.getOpenFileName(self, t("dlg.select_file"))
        if path:
            self.target_input.setPlainText(path)
            self.type_combo.setCurrentIndex(1)  # 自动切换到"文件扫描"

    def _parse_curl_to_fields(self):
        """按 Enter 时自动解析 curl 并填充 URL/Headers/POST Data"""
        curl_cmd = self.curl_input.toPlainText().strip()
        if not curl_cmd:
            return
        url, headers, data = _parse_curl_fields(curl_cmd)
        if url:
            self.target_input.setPlainText(url)
            self.type_combo.setCurrentIndex(0)  # 切换到 URL 扫描
        if headers:
            self.headers_input.setText("; ".join(headers))
        if data:
            self.data_input.setText(data)

    def _start_scan(self):
        target = self.target_input.toPlainText().strip()
        scan_type = self.type_combo.currentData()
        curl_cmd = self.curl_input.toPlainText().strip()
        # 如果有 curl 命令，始终重新解析并覆盖
        if curl_cmd:
            url, headers, data = _parse_curl_fields(curl_cmd)
            if url:
                target = url
                self.target_input.setPlainText(target)
                self.type_combo.setCurrentIndex(0)
            if headers:
                self.headers_input.setText("; ".join(headers))
            if data:
                self.data_input.setText(data)
        if not target:
            self.output_text.setPlainText(t("msg.enter_target"))
            return
        # 新扫描前清除旧结果和 flag
        from ctftool.core.flag_finder import flag_finder
        flag_finder.clear()
        self.flags_cleared.emit()
        self.output_text.setPlainText(t("msg.scanning") + "\n")
        self.scan_btn.setEnabled(False)
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setVisible(True)
        self.worker = WorkerThread(self._do_scan, scan_type, target, curl_cmd)
        self.worker.finished.connect(self._on_done)
        self.worker.error.connect(self._on_error)
        self.worker.start()

    def _do_scan(self, scan_type, target, curl_cmd=""):
        from ctftool.core.scanner import AutoScanner
        scanner = AutoScanner()
        if curl_cmd:
            scanner.configure_web(curl_cmd=curl_cmd)
        lines = []

        def on_result(result):
            status = "[OK]" if result.success else "[ERR]"
            line = f"{status} {result.module} - {result.action}"
            if result.flags:
                line += f"\n    Flag: {', '.join(result.flags)}"
            if result.error:
                line += f"\n    {result.error}"
            lines.append(line)

        if scan_type == "url":
            results = scanner.scan_url(target, callback=on_result)
        elif scan_type == "file":
            results = scanner.scan_file(target, callback=on_result)
        else:
            results = scanner.scan_text(target, callback=on_result)

        all_flags = scanner.get_all_flags()
        summary = f"\n{'='*50}\nScan done: {len(results)} checks"
        if all_flags:
            summary += f"\nFlags found ({len(all_flags)}):\n"
            summary += "\n".join(f"  {f}" for f in all_flags)
        else:
            summary += "\nNo flags found"
        lines.append(summary)
        return "\n".join(lines)

    # 高亮规则：(正则, 前景色) — 与 ModulePanel 保持一致
    HIGHLIGHT_RULES = [
        (r'(flag\{[^\}]+\}|ctf\{[^\}]+\}|FLAG\{[^\}]+\}|CTF\{[^\}]+\})', '#a6e3a1'),
        (r'(https?://[^\s<>"]+)', '#89b4fa'),
        (r'(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b)', '#f9e2af'),
        (r'(\[\+\]|\[!\])', '#a6e3a1'),
        (r'(\[-\]|\[ERR\])', '#f38ba8'),
        (r'(\[\?\]|\[\*\]|\[i\])', '#89b4fa'),
        (r'(===.+===)', '#cba6f7'),
    ]

    def _set_highlighted_output(self, text: str):
        """对输出文本应用语法高亮，以 HTML 形式显示"""
        escaped = html.escape(text)
        for pattern, color in self.HIGHLIGHT_RULES:
            escaped = re.sub(pattern, rf'<span style="color:{color}">\1</span>', escaped)
        self.output_text.setHtml(
            f'<pre style="font-family:{_MONO_CSS}; font-size:10pt; '
            f'color:#cdd6f4; white-space:pre-wrap;">{escaped}</pre>'
        )

    def _on_done(self, result):
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 100)
        self._set_highlighted_output(result)
        self.scan_btn.setEnabled(True)
        flags = flag_finder.search_with_decode(result)
        for f in flags:
            self.flag_found.emit(f)

    def _copy_output(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.output_text.toPlainText())

    def _export_output(self):
        text = self.output_text.toPlainText()
        if not text:
            return
        filepath, _ = QFileDialog.getSaveFileName(
            self, t("dlg.export_title"), f"scan_result_{time.strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;JSON (*.json);;HTML (*.html)"
        )
        if filepath:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(text)

    def _on_error(self, error):
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 100)
        current = self.output_text.toPlainText()
        self._set_highlighted_output(current + f"\nError: {error}")
        self.scan_btn.setEnabled(True)


# ===================== 主窗口 =====================

DARK_STYLE = """
QMainWindow, QWidget { background-color: #1e1e2e; color: #cdd6f4; }
QGroupBox { border: 1px solid #45475a; border-radius: 6px; margin-top: 8px;
  padding-top: 16px; font-weight: bold; color: #89b4fa; }
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; }
QTextEdit { background-color: #181825; color: #cdd6f4; border: 1px solid #45475a;
  border-radius: 4px; padding: 4px; selection-background-color: #585b70; }
QLineEdit { background-color: #181825; color: #cdd6f4; border: 1px solid #45475a;
  border-radius: 4px; padding: 4px; }
QComboBox { background-color: #181825; color: #cdd6f4; border: 1px solid #45475a;
  border-radius: 4px; padding: 4px; }
QComboBox::drop-down { border: none; }
QComboBox QAbstractItemView { background-color: #181825; color: #cdd6f4;
  selection-background-color: #45475a; }
QPushButton { background-color: #313244; color: #cdd6f4; border: 1px solid #45475a;
  border-radius: 4px; padding: 6px 12px; }
QPushButton:hover { background-color: #45475a; }
QListWidget { background-color: #11111b; color: #cdd6f4; border: none;
  font-size: 13px; outline: 0; }
QListWidget::item { padding: 10px 12px; border-bottom: 1px solid #1e1e2e; }
QListWidget::item:selected { background-color: #313244; color: #89b4fa; }
QListWidget::item:hover { background-color: #1e1e2e; }
QStatusBar { background-color: #11111b; color: #a6e3a1; font-size: 13px;
  border-top: 1px solid #45475a; }
QLabel { color: #cdd6f4; }
QSplitter::handle { background-color: #45475a; width: 2px; }
"""


CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".ctf-tool")
FLAG_CONFIG_FILE = os.path.join(CONFIG_DIR, "flag_patterns.json")


def _load_custom_flag_patterns() -> list[str]:
    """从磁盘加载用户自定义 flag 模式"""
    if os.path.isfile(FLAG_CONFIG_FILE):
        with open(FLAG_CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []


def _save_custom_flag_patterns(patterns: list[str]):
    """保存用户自定义 flag 模式到磁盘"""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(FLAG_CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(patterns, f, ensure_ascii=False, indent=2)


def _flag_example_to_regex(example: str) -> str:
    """根据 flag 示例自动生成正则表达式

    例如: DASCTF{test_flag_123} -> DASCTF\\{[^\\}]+\\}
    """
    match = re.match(r'^([A-Za-z0-9_]+)\{.*\}$', example.strip())
    if match:
        prefix = re.escape(match.group(1))
        return prefix + r'\{[^\}]+\}'
    return re.escape(example)


class MainWindow(QMainWindow):
    """CTF Tool 主窗口"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle(t("title.window"))
        # 设置窗口图标
        icon_path = os.path.join(
            sys._MEIPASS if getattr(sys, 'frozen', False) else
            os.path.dirname(os.path.dirname(__file__)), "docs", "icon.ico")
        if os.path.isfile(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        self.setMinimumSize(1100, 700)
        self.resize(1280, 800)
        self.found_flags: list[str] = []
        self._shared_data: str | None = None
        self._load_flag_config()
        self._setup_ui()
        self.setStyleSheet(DARK_STYLE)

    def _load_flag_config(self):
        """加载永久存储的自定义 flag 模式"""
        custom = _load_custom_flag_patterns()
        for pattern in custom:
            flag_finder.add_pattern(pattern)

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # 侧边栏
        sidebar = QWidget()
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)

        self.nav_list = QListWidget()
        self.nav_list.setFixedWidth(180)
        self.nav_list.setIconSize(QSize(20, 20))
        self._build_nav_list()
        self.nav_list.currentRowChanged.connect(self._switch_page)
        sidebar_layout.addWidget(self.nav_list, 1)

        # 语言切换按钮
        self.lang_btn = QPushButton(t("btn.lang_switch"))
        self.lang_btn.setStyleSheet(
            "QPushButton { background-color: #45475a; color: #89b4fa; "
            "border: 1px solid #89b4fa; border-radius: 4px; "
            "padding: 8px; font-weight: bold; margin: 8px 8px 0 8px; }"
            "QPushButton:hover { background-color: #585b70; }"
        )
        self.lang_btn.clicked.connect(self._toggle_language)
        sidebar_layout.addWidget(self.lang_btn)

        # 自定义 Flag 按钮
        self.flag_config_btn = QPushButton(t("btn.custom_flag"))
        self.flag_config_btn.setStyleSheet(
            "QPushButton { background-color: #45475a; color: #f9e2af; "
            "border: 1px solid #f9e2af; border-radius: 4px; "
            "padding: 8px; font-weight: bold; margin: 8px 8px 0 8px; }"
            "QPushButton:hover { background-color: #585b70; }"
        )
        self.flag_config_btn.clicked.connect(self._show_flag_config)
        sidebar_layout.addWidget(self.flag_config_btn)

        # 打赏支持按钮
        self.donate_btn = QPushButton(t("btn.support"))
        self.donate_btn.setStyleSheet(
            "QPushButton { background-color: #45475a; color: #f38ba8; "
            "border: 1px solid #f38ba8; border-radius: 4px; "
            "padding: 8px; font-weight: bold; margin: 8px 8px 8px 8px; }"
            "QPushButton:hover { background-color: #585b70; }"
        )
        self.donate_btn.clicked.connect(self._show_donate)
        sidebar_layout.addWidget(self.donate_btn)

        sidebar.setFixedWidth(180)
        splitter.addWidget(sidebar)

        # 页面栈
        self.pages = QStackedWidget()
        self.auto_scan = AutoScanPanel()
        self.crypto = CryptoPanel()
        self.web = WebPanel()
        self.forensics = ForensicsPanel()
        self.reverse = ReversePanel()
        self.blockchain = BlockchainPanel()
        self.pwn = PwnPanel()
        self.misc = MiscPanel()
        self.rsa = RSAPanel()

        panels = [
            self.auto_scan, self.crypto, self.web, self.forensics,
            self.reverse, self.blockchain, self.pwn, self.misc, self.rsa,
        ]
        for panel in panels:
            self.pages.addWidget(panel)
            if hasattr(panel, 'flag_found'):
                panel.flag_found.connect(self._on_flag)
            if hasattr(panel, 'flags_cleared'):
                panel.flags_cleared.connect(self._clear_flags)
            if hasattr(panel, 'send_to_crypto'):
                panel.send_to_crypto.connect(self._receive_to_crypto)

        splitter.addWidget(self.pages)
        splitter.setStretchFactor(1, 1)
        main_layout.addWidget(splitter)

        # 状态栏（含版权信息，点击可复制 flag）
        self.flag_bar = QStatusBar()
        self.flag_bar.setFixedHeight(32)
        self.flag_bar.installEventFilter(self)
        self.setStatusBar(self.flag_bar)
        try:
            from ctftool.core.integrity import get_footer_text
            footer_label = QLabel(get_footer_text())
            footer_label.setStyleSheet("color: #585b70; font-size: 10px;")
            self.flag_bar.addPermanentWidget(footer_label)
        except Exception:
            pass
        self.flag_bar.showMessage(t("hint.waiting"))

        self.nav_list.setCurrentRow(0)

    def _build_nav_list(self):
        """构建导航列表（i18n）"""
        self.nav_list.clear()
        nav_keys = [
            ("0", "nav.autoscan"), ("1", "nav.crypto"), ("2", "nav.web"),
            ("3", "nav.forensics"), ("4", "nav.reverse"), ("5", "nav.blockchain"),
            ("6", "nav.pwn"), ("7", "nav.misc"), ("8", "nav.rsa"),
        ]
        for num, key in nav_keys:
            item = QListWidgetItem(f"[ {num} ]  {t(key)}")
            item.setSizeHint(QSize(170, 42))
            self.nav_list.addItem(item)

    def _switch_page(self, index):
        self.pages.setCurrentIndex(index)

    def _toggle_language(self):
        """切换中英文并实时刷新（保留用户状态）"""
        new_lang = "en" if get_lang() == "zh" else "zh"
        set_lang(new_lang)
        # 保存状态后关闭窗口，由 main() 的事件循环重新创建并恢复
        self._restart_flag = True
        self._saved_state = self._save_state()
        self.close()

    def _save_state(self) -> dict:
        """保存当前界面状态（语言切换前调用）"""
        state = {
            "nav_index": self.nav_list.currentRow(),
            "found_flags": self.found_flags.copy(),
            "panels": {},
        }
        panel_names = ["auto_scan", "crypto", "web", "forensics", "reverse", "pwn", "misc", "rsa"]
        for name in panel_names:
            panel = getattr(self, name, None)
            if panel is None:
                continue
            ps = {}
            # 保存操作选择（通过 data 而非 index，因为重建后 index 可能不同）
            if hasattr(panel, 'action_combo'):
                ps["action_data"] = panel.action_combo.currentData()
            # 保存输入文本
            if hasattr(panel, 'input_text'):
                ps["input"] = panel.input_text.toPlainText()
            # 保存输出（HTML 格式以保留高亮）
            if hasattr(panel, 'output_text'):
                ps["output_html"] = panel.output_text.toHtml()
            # 保存参数字段
            for field in ("key_input", "iv_input", "param_input", "extra_input",
                          "curl_input", "n_input", "e_input", "c_input"):
                widget = getattr(panel, field, None)
                if widget is not None:
                    if hasattr(widget, 'toPlainText'):
                        ps[field] = widget.toPlainText()
                    elif hasattr(widget, 'text'):
                        ps[field] = widget.text()
            # AutoScanPanel 特殊字段
            if hasattr(panel, 'target_input'):
                ps["target"] = panel.target_input.toPlainText()
            if hasattr(panel, 'type_combo'):
                ps["scan_type_index"] = panel.type_combo.currentIndex()
            state["panels"][name] = ps
        return state

    def _restore_state(self, state: dict):
        """恢复界面状态（语言切换后在新窗口调用）"""
        if not state:
            return
        # 恢复 flag 列表
        self.found_flags = state.get("found_flags", [])
        if self.found_flags:
            self._update_flag_bar()
        # 恢复各面板状态
        panel_names = ["auto_scan", "crypto", "web", "forensics", "reverse", "pwn", "misc", "rsa"]
        for name in panel_names:
            panel = getattr(self, name, None)
            ps = state.get("panels", {}).get(name, {})
            if panel is None or not ps:
                continue
            # 恢复操作选择
            if "action_data" in ps and hasattr(panel, 'action_combo'):
                for i in range(panel.action_combo.count()):
                    if panel.action_combo.itemData(i) == ps["action_data"]:
                        panel.action_combo.setCurrentIndex(i)
                        break
            # 恢复输入
            if "input" in ps and hasattr(panel, 'input_text'):
                panel.input_text.setPlainText(ps["input"])
            # 恢复输出
            if "output_html" in ps and hasattr(panel, 'output_text'):
                panel.output_text.setHtml(ps["output_html"])
            # 恢复参数字段
            for field in ("key_input", "iv_input", "param_input", "extra_input",
                          "curl_input", "n_input", "e_input", "c_input"):
                if field in ps:
                    widget = getattr(panel, field, None)
                    if widget is not None:
                        if hasattr(widget, 'setPlainText'):
                            widget.setPlainText(ps[field])
                        elif hasattr(widget, 'setText'):
                            widget.setText(ps[field])
            # AutoScanPanel 特殊字段
            if "target" in ps and hasattr(panel, 'target_input'):
                panel.target_input.setPlainText(ps["target"])
            if "scan_type_index" in ps and hasattr(panel, 'type_combo'):
                panel.type_combo.setCurrentIndex(ps["scan_type_index"])
        # 恢复导航位置（最后设置，触发页面切换）
        nav_idx = state.get("nav_index", 0)
        self.nav_list.setCurrentRow(nav_idx)

    def _clear_flags(self):
        """新扫描开始时清零 flag 状态"""
        self.found_flags.clear()
        self.flag_bar.showMessage(t("hint.waiting"))
        self.flag_bar.setStyleSheet(
            "QStatusBar { background-color: #11111b; color: #a6e3a1; font-size: 13px; "
            "border-top: 1px solid #45475a; }"
        )

    def _on_flag(self, flag: str):
        if flag not in self.found_flags:
            self.found_flags.append(flag)
        self._update_flag_bar()

    def _update_flag_bar(self):
        count = len(self.found_flags)
        display = " | ".join(self.found_flags[-3:])
        self.flag_bar.showMessage(f"  [!] {count} Flag(s): {display}    ({t('hint.click_copy')})")
        self.flag_bar.setStyleSheet(
            "QStatusBar { background-color: #1a4731; color: #a6e3a1; "
            "font-size: 13px; font-weight: bold; border-top: 2px solid #a6e3a1; cursor: pointer; }"
        )

    def _copy_flags(self):
        """复制所有发现的 flag 到剪贴板"""
        if self.found_flags:
            clipboard = QApplication.clipboard()
            clipboard.setText("\n".join(self.found_flags))
            self.flag_bar.showMessage(
                f"  [OK] {t('msg.flags_copied')} ({len(self.found_flags)} flags)")
            # 1.5 秒后恢复显示
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(1500, self._update_flag_bar)

    def eventFilter(self, obj, event):
        """捕获状态栏点击事件 — 点击复制所有 flag"""
        from PyQt6.QtCore import QEvent
        if obj is self.flag_bar and event.type() == QEvent.Type.MouseButtonPress:
            if self.found_flags:
                self._copy_flags()
                return True
        return super().eventFilter(obj, event)

    def _receive_to_crypto(self, text: str):
        self.nav_list.setCurrentRow(1)
        self.crypto.set_input(text)

    def _show_donate(self):
        """显示打赏/支持作者弹窗 — 数据来源于 integrity 模块
        Donation: buymeacoffee + sponsors (integrity markers)
        """
        from ctftool.core.integrity import (
            BMC_URL,
            SPONSOR_URL,
            verify_integrity,
        )

        # 运行时校验
        passed, errors = verify_integrity(strict=False)
        if not passed:
            QMessageBox.critical(
                self, "Integrity Check Failed",
                "Attribution integrity check failed.\n"
                "The donation dialog cannot be opened.\n\n"
                + "\n".join(errors[:5])
            )
            return

        dialog = QDialog(self)
        dialog.setWindowTitle(t("title.donate"))
        dialog.setFixedSize(380, 500)
        dialog.setStyleSheet(DARK_STYLE)
        layout = QVBoxLayout(dialog)

        title = QLabel(t("title.donate_info"))
        title.setWordWrap(True)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 13px; padding: 8px; color: #f9e2af;")
        layout.addWidget(title)

        # Tab 切换 QR 码
        tabs = QTabWidget()
        tabs.setStyleSheet(
            "QTabWidget::pane { border: 1px solid #45475a; border-radius: 4px; }"
            "QTabBar::tab { background: #313244; color: #cdd6f4; padding: 8px 16px; "
            "border-top-left-radius: 4px; border-top-right-radius: 4px; }"
            "QTabBar::tab:selected { background: #45475a; color: #89b4fa; }"
        )

        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            docs_dir = os.path.join(sys._MEIPASS, "docs")
        else:
            docs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "docs")

        tab_items = [("WeChat", "wechat_pay.jpg"), ("Alipay", "alipay.jpg"), ("BuyMeACoffee", "bmc_qr.png")]
        for tab_name, img_file in tab_items:
            tab = QWidget()
            tab_layout = QVBoxLayout(tab)
            tab_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            img_path = os.path.join(docs_dir, img_file)
            if os.path.isfile(img_path):
                pixmap = QPixmap(img_path)
                img_label = QLabel()
                img_label.setPixmap(pixmap.scaled(
                    220, 220,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                ))
                img_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                tab_layout.addWidget(img_label)
            else:
                tab_layout.addWidget(QLabel(f"({img_file} not found)"))
            tabs.addTab(tab, tab_name)
        layout.addWidget(tabs, 1)

        # 链接按钮 — URL 来自 integrity 模块
        links_layout = QHBoxLayout()
        bmc_btn = QPushButton(t("donate.bmc"))
        bmc_btn.setStyleSheet(
            "QPushButton { background-color: #FFDD00; color: #000; "
            "padding: 8px; border-radius: 4px; font-weight: bold; }"
            "QPushButton:hover { background-color: #FFE333; }"
        )
        bmc_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(BMC_URL)))
        links_layout.addWidget(bmc_btn)

        gh_btn = QPushButton(t("donate.github"))
        gh_btn.setStyleSheet(
            "QPushButton { background-color: #238636; color: #fff; "
            "padding: 8px; border-radius: 4px; font-weight: bold; }"
            "QPushButton:hover { background-color: #2ea043; }"
        )
        gh_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(SPONSOR_URL)))
        links_layout.addWidget(gh_btn)
        layout.addLayout(links_layout)

        # 底部 — 作者信息来自 integrity 模块
        footer = QLabel(t("donate.footer"))
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        footer.setStyleSheet("color: #6c7086; padding: 8px;")
        layout.addWidget(footer)

        dialog.exec()

    def _show_flag_config(self):
        """显示自定义 Flag 格式配置弹窗"""
        from PyQt6.QtWidgets import QDialog
        from PyQt6.QtWidgets import QTextEdit as QTE

        dialog = QDialog(self)
        dialog.setWindowTitle(t("title.flag_config"))
        dialog.setMinimumSize(500, 400)
        dialog.setStyleSheet(DARK_STYLE)
        layout = QVBoxLayout(dialog)

        # 说明
        info = QLabel(t("title.flag_config_info"))
        info.setWordWrap(True)
        layout.addWidget(info)

        # 输入框
        input_box = QTE()
        input_box.setPlaceholderText(t("flag.hint_placeholder"))
        input_box.setFont(_mono_font(11))
        # 加载已有配置
        existing = _load_custom_flag_patterns()
        if existing:
            input_box.setPlainText("\n".join(
                f"{t('flag.saved_rule')}{p}" for p in existing
            ))
        layout.addWidget(input_box, 1)

        # 内置格式展示（可折叠）
        from ctftool.core.flag_finder import DEFAULT_FLAG_PATTERNS
        builtin_count = len(DEFAULT_FLAG_PATTERNS)
        builtin_label = QLabel(f"▶ {t('flag.builtin_title')} ({builtin_count})")
        builtin_label.setStyleSheet("color: #89b4fa; cursor: pointer;")
        layout.addWidget(builtin_label)

        builtin_text = QTE()
        builtin_text.setReadOnly(True)
        builtin_text.setMaximumHeight(120)
        builtin_text.setFont(_mono_font(9))
        # 提取前缀名展示
        prefixes = []
        for p in DEFAULT_FLAG_PATTERNS[:-1]:  # 最后一个是通用模式
            prefix = p.split(r'\{')[0].replace('\\', '')
            prefixes.append(prefix + "{...}")
        generic = DEFAULT_FLAG_PATTERNS[-1]
        builtin_display = ", ".join(prefixes)
        builtin_display += f"\n\n{t('flag.generic_pattern')}: {generic}"
        builtin_display += f"\n{t('flag.generic_desc')}"
        builtin_text.setPlainText(builtin_display)
        builtin_text.setVisible(False)
        layout.addWidget(builtin_text)

        # 点击展开/折叠
        def _toggle_builtin():
            vis = not builtin_text.isVisible()
            builtin_text.setVisible(vis)
            builtin_label.setText(
                f"{'▼' if vis else '▶'} {t('flag.builtin_title')} ({builtin_count})"
            )
        builtin_label.mousePressEvent = lambda _: _toggle_builtin()

        # 当前所有规则显示
        custom_count = len(flag_finder._compiled) - builtin_count
        rules_label = QLabel(
            f"{t('flag.total_rules')} {len(flag_finder._compiled)} "
            f"({t('flag.builtin_count')} {builtin_count}, {t('flag.custom_count')} {custom_count})"
        )
        layout.addWidget(rules_label)

        # 按钮
        btn_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        btn_box.accepted.connect(dialog.accept)
        btn_box.rejected.connect(dialog.reject)
        layout.addWidget(btn_box)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            text = input_box.toPlainText()
            new_patterns = []
            for line in text.strip().split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                pattern = _flag_example_to_regex(line)
                new_patterns.append(pattern)
                flag_finder.add_pattern(pattern)

            if new_patterns:
                # 合并并永久保存
                all_custom = _load_custom_flag_patterns()
                for p in new_patterns:
                    if p not in all_custom:
                        all_custom.append(p)
                _save_custom_flag_patterns(all_custom)

                QMessageBox.information(
                    self, t("flag.saved"),
                    f"{len(new_patterns)} {t('flag.rules_added')}\n{FLAG_CONFIG_FILE}\n\n"
                    f"{t('flag.total_rules')} {len(flag_finder._compiled)}"
                )


def main():
    app = QApplication(sys.argv)
    font = QFont("Segoe UI", 10)
    font.setFamilies(["Segoe UI", "PingFang SC", "Noto Sans CJK SC", "Helvetica Neue", "Arial"])
    app.setFont(font)
    # 设置应用图标（影响任务栏）
    icon_path = os.path.join(
        sys._MEIPASS if getattr(sys, 'frozen', False) else
        os.path.dirname(os.path.dirname(__file__)), "docs", "icon.ico")
    if os.path.isfile(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    saved_state = None
    while True:
        window = MainWindow()
        window._restart_flag = False
        if saved_state:
            window._restore_state(saved_state)
        window.show()
        app.exec()
        restart = window._restart_flag
        saved_state = getattr(window, '_saved_state', None) if restart else None
        window.close()
        window.deleteLater()
        if not restart:
            break
    sys.exit(0)
