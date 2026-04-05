# -*- coding: utf-8 -*-
"""TUI 各功能屏幕 — 支持异步执行、结果导出、模块间传递"""

import os
import time
from functools import partial

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    Select,
    Static,
    TextArea,
)

from ctftool.core.flag_finder import flag_finder
from ctftool.core.history import history
from ctftool.core.i18n import t
from ctftool.ui.widgets import OutputPanel

# ======================== 基类 ========================

class ModuleScreen(Screen):
    """通用模块屏幕基类（异步执行）"""

    BINDINGS = [
        ("ctrl+r", "run_action", "执行"),
        ("ctrl+l", "clear_output", "清空输出"),
        ("ctrl+s", "export_result", "导出结果"),
        ("ctrl+t", "send_to_crypto", "发送到密码学"),
        ("escape", "app.pop_screen", "返回"),
    ]

    module_name: str = ""
    actions: list[tuple[str, str]] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static(f" * {t(self.module_name) if '.' in self.module_name else self.module_name}", classes="module-title")
            yield Select(
                [(t(name) if '.' in name else name, method) for name, method in self.actions],
                prompt=t("hint.select_action"),
                id="action-select",
            )
            yield Label(t("label.input") + ":", id="input-label")
            yield TextArea(id="input-text")
            yield from self.compose_params()
            with Horizontal():
                yield Button(t("btn.run") + " (Ctrl+R)", id="run-button", variant="primary")
                yield Button(t("btn.export") + " (Ctrl+S)", id="export-button", variant="default")
                yield Button(t("btn.send_crypto") + " (Ctrl+T)", id="send-crypto-button", variant="default")
            yield OutputPanel(id="output-text")
        yield Footer()

    def compose_params(self):
        """子类重写以添加额外参数"""
        return []

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "run-button":
            # 执行前清零旧 flag
            flag_finder.clear()
            if hasattr(self.app, 'flag_bar'):
                self.app.flag_bar.clear_flags()
            self.action_run_action()
        elif event.button.id == "export-button":
            self.action_export_result()
        elif event.button.id == "send-crypto-button":
            self.action_send_to_crypto()

    def action_clear_output(self):
        self.query_one("#output-text", OutputPanel).clear()

    def action_export_result(self):
        """导出结果到文件"""
        panel = self.query_one("#output-text", OutputPanel)
        text = panel.text
        if not text or text == t("msg.waiting_output"):
            self._set_output(t("msg.no_input"))
            return
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"ctf_result_{timestamp}.txt"
        filepath = os.path.join(os.path.expanduser("~"), "ctf-tool", filename)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(text)
        self._append_output(f"\n[+] {t('msg.exported_to')}: {filepath}")

    def action_send_to_crypto(self):
        """将输出发送到密码学模块的输入"""
        panel = self.query_one("#output-text", OutputPanel)
        text = panel.text
        if text and text != t("msg.waiting_output"):
            if hasattr(self.app, '_shared_data'):
                self.app._shared_data = text
            else:
                self.app._shared_data = text
            self.app.push_screen("crypto")

    def _get_input(self) -> str:
        return self.query_one("#input-text", TextArea).text.strip()

    def _set_output(self, text: str):
        """设置输出文本并记录历史，自动检测 Flag"""
        # 自动检测 Flag 并追加提示
        flags = flag_finder.search_with_decode(text)
        if flags:
            flag_hint = f"\n{'=' * 50}\n"
            flag_hint += f"[!] {t('msg.flag_auto_found')} ({len(flags)}):\n"
            for f in flags:
                flag_hint += f"    >> {f}\n"
            flag_hint += f"{'=' * 50}"
            text = text + flag_hint
        panel = self.query_one("#output-text", OutputPanel)
        panel.set_output(text)
        self._check_flags(text)
        # 记录操作历史
        try:
            select = self.query_one("#action-select", Select)
            action = select.value if select.value != Select.BLANK else ""
            module_name = self.module_name.replace("mod.", "")
            flags = flag_finder.search(text)
            history.add(module_name, action, "", text[:500], flags)
        except Exception:
            pass

    def _append_output(self, text: str):
        panel = self.query_one("#output-text", OutputPanel)
        panel.append_output(text)
        self._check_flags(text)

    def _check_flags(self, text: str):
        flags = flag_finder.search_with_decode(text)
        if flags and hasattr(self.app, 'flag_bar'):
            for f in flags:
                self.app.flag_bar.add_flag(f)

    def on_mount(self):
        """挂载时检查是否有共享数据传入"""
        if hasattr(self.app, '_shared_data') and self.app._shared_data:
            try:
                self.query_one("#input-text", TextArea).load_text(self.app._shared_data)
            except Exception:
                pass
            self.app._shared_data = None


# ======================== 密码学 ========================

class CryptoScreen(ModuleScreen):
    module_name = "mod.crypto"
    actions = [
        ("act.auto_decode", "auto_decode"),
        ("act.base64_encode", "base64_encode"),
        ("act.base64_decode", "base64_decode"),
        ("act.base32_encode", "base32_encode"),
        ("act.base32_decode", "base32_decode"),
        ("act.base58_decode", "base58_decode"),
        ("act.base58_encode", "base58_encode"),
        ("act.base85_decode", "base85_decode"),
        ("act.base85_encode", "base85_encode"),
        ("act.hex_encode", "hex_encode"),
        ("act.hex_decode", "hex_decode"),
        ("act.url_encode", "url_encode"),
        ("act.url_decode", "url_decode"),
        ("act.html_entity_decode", "html_entity_decode"),
        ("act.unicode_decode", "unicode_decode"),
        ("act.binary_decode", "binary_decode"),
        ("act.binary_encode", "binary_encode"),
        ("act.octal_decode", "octal_decode"),
        ("act.caesar_bruteforce", "caesar_bruteforce"),
        ("act.caesar_decrypt", "caesar_decrypt"),
        ("act.rot13", "rot13"),
        ("act.rot47", "rot47"),
        ("act.vigenere_decrypt", "vigenere_decrypt"),
        ("act.vigenere_encrypt", "vigenere_encrypt"),
        ("act.vigenere_key_length", "vigenere_key_length"),
        ("act.rail_fence_decrypt", "rail_fence_decrypt"),
        ("act.rail_fence_bruteforce", "rail_fence_bruteforce"),
        ("act.atbash", "atbash"),
        ("act.bacon_decode", "bacon_decode"),
        ("act.affine_decrypt", "affine_decrypt"),
        ("act.affine_bruteforce", "affine_bruteforce"),
        ("act.xor_single_byte_bruteforce", "xor_single_byte_bruteforce"),
        ("act.xor_decrypt", "xor_decrypt"),
        ("act.xor_auto_crack", "xor_auto_crack"),
        ("act.rc4", "rc4"),
        ("act.aes_ecb_decrypt", "aes_ecb_decrypt"),
        ("act.aes_ecb_encrypt", "aes_ecb_encrypt"),
        ("act.aes_cbc_decrypt", "aes_cbc_decrypt"),
        ("act.aes_cbc_encrypt", "aes_cbc_encrypt"),
        ("act.aes_ctr_encrypt", "aes_ctr_encrypt"),
        ("act.aes_ctr_decrypt", "aes_ctr_decrypt"),
        ("act.des_ecb_decrypt", "des_ecb_decrypt"),
        ("act.des_ecb_encrypt", "des_ecb_encrypt"),
        ("act.triple_des_decrypt", "triple_des_decrypt"),
        ("act.triple_des_encrypt", "triple_des_encrypt"),
        ("act.blowfish_decrypt", "blowfish_decrypt"),
        ("act.blowfish_encrypt", "blowfish_encrypt"),
        ("act.identify_hash", "identify_hash"),
        ("act.hash_crack_dict", "hash_crack_dict"),
        ("act.hash_crack_online", "hash_crack_online"),
        ("act.compute_hash", "compute_hash"),
        ("act.hash_length_extension", "hash_length_extension"),
        ("act.crc32", "crc32"),
        ("act.hmac_compute", "hmac_compute"),
        ("act.frequency_analysis", "frequency_analysis"),
        ("act.playfair_encrypt", "playfair_encrypt"),
        ("act.playfair_decrypt", "playfair_decrypt"),
        ("act.polybius_encrypt", "polybius_encrypt"),
        ("act.polybius_decrypt", "polybius_decrypt"),
        ("act.hill_encrypt", "hill_encrypt"),
        ("act.hill_decrypt", "hill_decrypt"),
        ("act.columnar_transposition_encrypt", "columnar_transposition_encrypt"),
        ("act.columnar_transposition_decrypt", "columnar_transposition_decrypt"),
        ("act.padding_oracle_helper", "padding_oracle_helper"),
        ("act.rsa_decrypt_multi_prime", "rsa_decrypt_multi_prime"),
        ("act.base91_encode", "base91_encode"),
        ("act.base91_decode", "base91_decode"),
        ("act.base62_encode", "base62_encode"),
        ("act.base62_decode", "base62_decode"),
        ("act.ecc_point_add", "ecc_point_add"),
        ("act.dlp_bsgs", "dlp_bsgs"),
        ("act.dlp_pohlig_hellman", "dlp_pohlig_hellman"),
        ("act.mt19937_predict", "mt19937_predict"),
        ("act.substitution_auto_crack", "substitution_auto_crack"),
        ("act.adfgvx_decrypt", "adfgvx_decrypt"),
        ("act.bifid_decrypt", "bifid_decrypt"),
        ("act.bifid_encrypt", "bifid_encrypt"),
        ("act.four_square_decrypt", "four_square_decrypt"),
        ("act.chinese_remainder_theorem", "chinese_remainder_theorem"),
        ("act.rsa_dq_leak", "rsa_dq_leak"),
        ("act.autokey_decrypt", "autokey_decrypt"),
        ("act.nihilist_decrypt", "nihilist_decrypt"),
        ("act.book_cipher_decode", "book_cipher_decode"),
        ("act.rabbit_decrypt", "rabbit_decrypt"),
        ("act.rsa_auto_attack", "rsa_auto_attack"),
        ("act.detect_encoding", "detect_encoding"),
        ("act.rsa_coppersmith_helper", "rsa_coppersmith_helper"),
        ("act.rsa_boneh_durfee_helper", "rsa_boneh_durfee_helper"),
        ("act.rsa_import_key", "rsa_import_key"),
        ("act.hash_collision_generate", "hash_collision_generate"),
        ("act.password_strength", "password_strength"),
    ]

    def compose_params(self):
        with Horizontal(id="params-area"):
            yield Label(t("label.key"), classes="param-label")
            yield Input(placeholder=t("hint.key"), id="param-key", classes="param-input")
        with Horizontal():
            yield Label(t("label.iv"), classes="param-label")
            yield Input(placeholder=t("hint.iv"), id="param-iv", classes="param-input")

    def action_run_action(self):
        select = self.query_one("#action-select", Select)
        action = select.value
        if action == Select.BLANK:
            self._set_output(t("msg.select_action"))
            return
        text = self._get_input()
        if not text:
            self._set_output(t("msg.no_input"))
            return
        key = self.query_one("#param-key", Input).value.strip()
        iv = self.query_one("#param-iv", Input).value.strip()
        self._set_output(t("msg.processing"))
        self.run_worker(partial(self._do_crypto, action, text, key, iv), thread=True)

    def _do_crypto(self, action, text, key, iv):
        from ctftool.modules.crypto import CryptoModule
        crypto = CryptoModule()
        try:
            if action == "vigenere_decrypt" and key:
                result = crypto.vigenere_decrypt(text, key)
            elif action == "affine_decrypt" and key:
                parts = key.split(',')
                a, b = int(parts[0].strip()), int(parts[1].strip())
                result = crypto.affine_decrypt(text, a, b)
            elif action == "xor_decrypt" and key:
                result = crypto.xor_decrypt(text, key)
            elif action in ("aes_ecb_decrypt", "aes_cbc_decrypt", "des_ecb_decrypt",
                           "aes_ecb_encrypt", "aes_cbc_encrypt", "des_ecb_encrypt"):
                result = getattr(crypto, action)(text, key, iv)
            elif hasattr(crypto, action):
                result = getattr(crypto, action)(text)
            else:
                result = f"{t('msg.unknown_action')}: {action}"
            self.app.call_from_thread(self._set_output, result)
        except Exception as e:
            self.app.call_from_thread(self._set_output, f"错误: {e}")


# ======================== Web 安全 ========================

class WebScreen(ModuleScreen):
    module_name = "mod.web"
    actions = [
        ("act.analyze_headers", "analyze_headers"),
        ("act.check_robots", "check_robots"),
        ("act.check_git_leak", "check_git_leak"),
        ("act.dir_scan", "dir_scan"),
        ("act.detect_sqli", "detect_sqli"),
        ("act.detect_xss", "detect_xss"),
        ("act.detect_lfi", "detect_lfi"),
        ("act.detect_cmdi", "detect_cmdi"),
        ("act.detect_ssrf", "detect_ssrf"),
        ("act.detect_ssti", "detect_ssti"),
        ("act.detect_xxe", "detect_xxe"),
        ("act.detect_cors", "detect_cors"),
        ("act.detect_open_redirect", "detect_open_redirect"),
        ("act.detect_crlf", "detect_crlf"),
        ("act.detect_path_traversal", "detect_path_traversal"),
        ("act.detect_http_smuggling", "detect_http_smuggling"),
        ("act.detect_waf", "detect_waf"),
        ("act.gen_sqli", "gen_sqli"),
        ("act.gen_xss", "gen_xss"),
        ("act.gen_ssti", "gen_ssti"),
        ("act.jwt_forge_none", "jwt_forge_none"),
        ("act.jwt_crack", "jwt_crack"),
        ("act.generate_payload", "generate_payload"),
        ("act.deserialize_helper", "deserialize_helper"),
        ("act.prototype_pollution_helper", "prototype_pollution_helper"),
        ("act.race_condition_helper", "race_condition_helper"),
        ("act.configure", "configure"),
        ("act.parse_curl", "parse_curl"),
        ("act.subdomain_enum", "subdomain_enum"),
        ("act.fingerprint", "fingerprint"),
        ("act.info_gather", "info_gather"),
        ("act.detect_svn_leak", "detect_svn_leak"),
        ("act.detect_ds_store", "detect_ds_store"),
        ("act.detect_backup_files", "detect_backup_files"),
        ("act.detect_env_leak", "detect_env_leak"),
        ("act.detect_graphql", "detect_graphql"),
        ("act.detect_host_injection", "detect_host_injection"),
        ("act.detect_jsonp", "detect_jsonp"),
        ("act.detect_swagger", "detect_swagger"),
        ("act.dir_listing_crawl", "dir_listing_crawl"),
        ("act.sqli_auto_exploit", "sqli_auto_exploit"),
        ("act.sqli_time_blind", "sqli_time_blind"),
        ("act.detect_csrf", "detect_csrf"),
        ("act.file_upload_helper", "file_upload_helper"),
    ]

    def action_run_action(self):
        select = self.query_one("#action-select", Select)
        action = select.value
        if action == Select.BLANK:
            self._set_output(t("msg.select_action"))
            return
        text = self._get_input()
        no_input_actions = {
            'deserialize_helper', 'prototype_pollution_helper',
            'race_condition_helper', 'file_upload_helper',
        }
        if not text and action not in no_input_actions:
            self._set_output(t("msg.enter_target"))
            return
        self._set_output(t("msg.scanning"))
        self.run_worker(partial(self._do_web, action, text), thread=True)

    def _do_web(self, action, text):
        from ctftool.modules.web import WebModule
        web = WebModule()
        no_input_actions = {
            'deserialize_helper', 'prototype_pollution_helper',
            'race_condition_helper', 'file_upload_helper',
        }
        try:
            if action.startswith("gen_"):
                result = web.generate_payload(action[4:])
            elif action == "jwt_forge_none":
                result = web.jwt_forge_none(text)
            elif action == "jwt_crack":
                result = web.jwt_crack(text)
            elif action in no_input_actions:
                result = getattr(web, action)()
            elif hasattr(web, action):
                result = getattr(web, action)(text)
            else:
                result = f"{t('msg.unknown_action')}: {action}"
            self.app.call_from_thread(self._set_output, result)
        except Exception as e:
            self.app.call_from_thread(self._set_output, f"错误: {e}")


# ======================== 取证分析 ========================

class ForensicsScreen(ModuleScreen):
    module_name = "mod.forensics"
    actions = [
        ("act.identify_file", "identify_file"),
        ("act.extract_strings", "extract_strings"),
        ("act.extract_metadata", "extract_metadata"),
        ("act.detect_stego", "detect_stego"),
        ("act.binwalk_scan", "binwalk_scan"),
        ("act.binwalk_extract", "binwalk_extract"),
        ("act.hex_view", "hex_view"),
        ("act.file_diff", "file_diff"),
        ("act.zip_crack", "zip_crack"),
        ("act.rar_crack", "rar_crack"),
        ("act.zip_fake_decrypt", "zip_fake_decrypt"),
        ("act.fix_file_header", "fix_file_header"),
        ("act.pcap_analyze", "pcap_analyze"),
        ("act.pcap_extract_http", "pcap_extract_http"),
        ("act.pcap_extract_files", "pcap_extract_files"),
        ("act.png_crc_fix", "png_crc_fix"),
        ("act.usb_keyboard_decode", "usb_keyboard_decode"),
        ("act.usb_mouse_decode", "usb_mouse_decode"),
        ("act.split_channels", "split_channels"),
        ("act.gif_frame_extract", "gif_frame_extract"),
        ("act.lsb_extract_advanced", "lsb_extract_advanced"),
        ("act.lsb_encode", "lsb_encode"),
        ("act.bit_plane_analysis", "bit_plane_analysis"),
        ("act.audio_spectrogram", "audio_spectrogram"),
        ("act.pdf_analyze", "pdf_analyze"),
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
        ("act.steghide_extract", "steghide_extract"),
        ("act.zsteg_scan", "zsteg_scan"),
        ("act.blind_watermark_extract", "blind_watermark_extract"),
        ("act.apng_extract", "apng_extract"),
        ("act.sstv_decode_helper", "sstv_decode_helper"),
        ("act.stego_full_scan", "stego_full_scan"),
        ("act.file_carve_precise", "file_carve_precise"),
        ("act.memory_forensics_enhanced", "memory_forensics_enhanced"),
    ]

    def compose_params(self):
        with Horizontal(id="params-area"):
            yield Label(t("label.extra"), classes="param-label")
            yield Input(
                placeholder=t("hint.file2"),
                id="param-extra", classes="param-input"
            )

    def action_run_action(self):
        select = self.query_one("#action-select", Select)
        action = select.value
        if action == Select.BLANK:
            self._set_output(t("msg.select_action"))
            return
        filepath = self._get_input()
        if not filepath:
            self._set_output(t("msg.enter_file"))
            return
        extra = self.query_one("#param-extra", Input).value.strip()
        self._set_output(t("msg.scanning"))
        self.run_worker(partial(self._do_forensics, action, filepath, extra), thread=True)

    def _do_forensics(self, action, filepath, extra):
        from ctftool.modules.forensics import ForensicsModule
        forensics = ForensicsModule()
        try:
            if action == "file_diff":
                if not extra:
                    result = t("msg.need_file2")
                else:
                    result = forensics.file_diff(filepath, extra)
            elif action == "zip_crack":
                result = forensics.zip_crack(filepath, extra or None)
            elif action == "steghide_extract":
                result = forensics.steghide_extract(filepath, extra or "")
            elif action == "zip_fake_decrypt":
                result = forensics.zip_fake_decrypt(filepath)
            elif action == "fix_file_header":
                result = forensics.fix_file_header(filepath)
            elif action == "pcap_analyze":
                result = forensics.pcap_analyze(filepath)
            elif action == "binwalk_extract":
                result = forensics.binwalk_extract(filepath)
            elif hasattr(forensics, action):
                result = getattr(forensics, action)(filepath)
            else:
                result = f"{t('msg.unknown_action')}: {action}"
            self.app.call_from_thread(self._set_output, result)
        except Exception as e:
            self.app.call_from_thread(self._set_output, f"错误: {e}")


# ======================== 逆向工程 ========================

class ReverseScreen(ModuleScreen):
    module_name = "mod.reverse"
    actions = [
        ("act.analyze_binary", "analyze_binary"),
        ("act.extract_strings_ascii", "extract_strings_ascii"),
        ("act.extract_strings_utf16", "extract_strings_utf16"),
        ("act.disassemble", "disassemble"),
        ("act.check_elf_protections", "check_elf_protections"),
        ("act.check_pe_protections", "check_pe_protections"),
        ("act.decompile_pyc", "decompile_pyc"),
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

    def compose_params(self):
        with Horizontal(id="params-area"):
            yield Label(t("label.offset"), classes="param-label")
            yield Input(placeholder=t("hint.offset"), id="param-offset", classes="param-input")

    def action_run_action(self):
        select = self.query_one("#action-select", Select)
        action = select.value
        if action == Select.BLANK:
            self._set_output(t("msg.select_action"))
            return
        filepath = self._get_input()
        if not filepath:
            self._set_output(t("msg.enter_file"))
            return
        offset_str = self.query_one("#param-offset", Input).value.strip()
        self._set_output(t("msg.scanning"))
        self.run_worker(partial(self._do_reverse, action, filepath, offset_str), thread=True)

    def _do_reverse(self, action, filepath, offset_str):
        from ctftool.modules.reverse import ReverseModule
        reverse = ReverseModule()
        try:
            offset = int(offset_str, 16) if offset_str else 0
            if action == "analyze_binary":
                result = reverse.analyze_binary(filepath)
            elif action == "check_elf_protections":
                result = reverse.check_elf_protections(filepath)
            elif action == "extract_strings_ascii":
                result = reverse.extract_strings_from_binary(filepath, encoding="ascii")
            elif action == "extract_strings_utf16":
                result = reverse.extract_strings_from_binary(filepath, encoding="utf16")
            elif action == "disassemble":
                result = reverse.disassemble(filepath, offset=offset)
            elif action == "decompile_pyc":
                result = reverse.decompile_pyc(filepath)
            elif hasattr(reverse, action):
                result = getattr(reverse, action)(filepath)
            else:
                result = f"{t('msg.unknown_action')}: {action}"
            self.app.call_from_thread(self._set_output, result)
        except Exception as e:
            self.app.call_from_thread(self._set_output, f"错误: {e}")


# ======================== Blockchain ========================

class BlockchainScreen(ModuleScreen):
    module_name = "mod.blockchain"
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

    def action_run_action(self):
        select = self.query_one("#action-select", Select)
        action = select.value
        if action == Select.BLANK:
            self._set_output(t("msg.select_action"))
            return
        text = self._get_input()
        self._set_output(t("msg.processing"))
        self.run_worker(partial(self._do_blockchain, action, text), thread=True)

    def _do_blockchain(self, action, text):
        from ctftool.modules.blockchain import BlockchainModule
        bc = BlockchainModule()
        try:
            result = getattr(bc, action)(text)
            self.app.call_from_thread(self._set_output, result)
        except Exception as e:
            self.app.call_from_thread(self._set_output, f"错误: {e}")


# ======================== Pwn ========================

class PwnScreen(ModuleScreen):
    module_name = "mod.pwn"
    actions = [
        ("act.generate_pattern", "generate_pattern"),
        ("act.find_pattern_offset", "find_pattern_offset"),
        ("act.generate_padding", "generate_padding"),
        ("act.format_string_read", "format_string_read"),
        ("act.format_string_write", "format_string_write"),
        ("act.find_format_offset", "find_format_offset"),
        ("act.find_rop_gadgets", "find_rop_gadgets"),
        ("act.shellcode_template", "shellcode_template"),
        ("act.addr_convert", "addr_convert"),
        ("act.pwntools_template", "pwntools_template"),
        ("act.ret2libc_template", "ret2libc_template"),
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

    def compose_params(self):
        with Vertical(id="params-area"):
            with Horizontal():
                yield Label(t("label.length"), classes="param-label")
                yield Input(placeholder=t("hint.length"), id="param-length", classes="param-input")
            with Horizontal():
                yield Label(t("label.addr"), classes="param-label")
                yield Input(placeholder=t("hint.addr"), id="param-addr", classes="param-input")
            with Horizontal():
                yield Label(t("label.arch"), classes="param-label")
                yield Select(
                    [("x86 (32)", "x86"), ("x64 (64)", "x64")],
                    value="x86", id="param-arch",
                )

    def action_run_action(self):
        text = self._get_input()
        select = self.query_one("#action-select", Select)
        action = select.value
        if action == Select.BLANK:
            self._set_output(t("msg.select_action"))
            return
        length_str = self.query_one("#param-length", Input).value.strip()
        addr = self.query_one("#param-addr", Input).value.strip()
        arch_select = self.query_one("#param-arch", Select)
        arch = arch_select.value if arch_select.value != Select.BLANK else "x86"
        self._set_output(t("msg.processing"))
        self.run_worker(partial(self._do_pwn, action, text, length_str, addr, arch), thread=True)

    def _do_pwn(self, action, text, length_str, addr, arch):
        from ctftool.modules.pwn import PwnModule
        pwn = PwnModule()
        try:
            if action in ("auto_ret2text", "auto_ret2shellcode", "auto_pwn_analyze"):
                result = getattr(pwn, action)(text, addr)  # addr 栏复用为 remote
                self._set_output(result)
                return
            if action == "generate_pattern":
                length = int(length_str) if length_str else 200
                result = pwn.generate_pattern(length)
            elif action == "find_pattern_offset":
                result = pwn.find_pattern_offset(text or addr)
            elif action == "generate_padding":
                offset = int(length_str) if length_str else 0
                result = pwn.generate_padding(offset, addr or "0xdeadbeef", arch)
            elif action == "format_string_read":
                offset = int(length_str) if length_str else 7
                result = pwn.format_string_read(offset, addr or "0x08048000", arch)
            elif action == "format_string_write":
                offset = int(length_str) if length_str else 7
                value = int(text, 16) if text else 0
                result = pwn.format_string_write(offset, addr or "0x08048000", value, arch)
            elif action == "find_format_offset":
                result = pwn.find_format_offset()
            elif action == "find_rop_gadgets":
                result = pwn.find_rop_gadgets(text)
            elif action == "shellcode_template":
                os_type = "linux" if not text or "linux" in text.lower() else "windows"
                result = pwn.shellcode_template(os_type, arch)
            elif action == "addr_convert":
                result = pwn.addr_convert(text or addr)
            elif action == "pwntools_template":
                result = pwn.pwntools_template(text or "target", arch)
            elif action == "ret2libc_template":
                result = pwn.ret2libc_template(arch)
            elif action in ("ret2syscall_template", "srop_template",
                            "got_overwrite_template", "ret2csu_template",
                            "stack_pivot_template"):
                result = getattr(pwn, action)(arch)
            elif action in ("seccomp_helper", "io_file_template",
                            "house_of_orange_template"):
                result = getattr(pwn, action)()
            elif action == "check_bad_chars":
                result = pwn.check_bad_chars(text)
            elif action == "heap_exploit_template":
                result = pwn.heap_exploit_template(text or "fastbin_dup")
            elif action == "one_gadget_helper":
                result = pwn.one_gadget_helper()
            else:
                result = f"{t('msg.unknown_action')}: {action}"
            self.app.call_from_thread(self._set_output, result)
            self.app.call_from_thread(self._check_flags, result)
        except Exception as e:
            self.app.call_from_thread(self._set_output, f"错误: {e}")


# ======================== 杂项 ========================

class MiscScreen(ModuleScreen):
    module_name = "mod.misc"
    actions = [
        ("act.base_convert", "base_convert"),
        ("act.morse_encode", "morse_encode"),
        ("act.morse_decode", "morse_decode"),
        ("act.braille_decode", "braille_decode"),
        ("act.braille_encode", "braille_encode"),
        ("act.core_values_decode", "core_values_decode"),
        ("act.core_values_encode", "core_values_encode"),
        ("act.pigpen_decode", "pigpen_decode"),
        ("act.dna_decode", "dna_decode"),
        ("act.dna_encode", "dna_encode"),
        ("act.ascii_table", "ascii_table"),
        ("act.char_convert", "char_convert"),
        ("act.rot_all", "rot_all"),
        ("act.qr_decode", "qr_decode"),
        ("act.qr_generate", "qr_generate"),
        ("act.qr_batch_decode", "qr_batch_decode"),
        ("act.barcode_decode", "barcode_decode"),
        ("act.ook_decode", "ook_decode"),
        ("act.ook_execute", "ook_execute"),
        ("act.brainfuck_execute", "brainfuck_execute"),
        ("act.generate_wordlist", "generate_wordlist"),
        ("act.jwt_decode", "jwt_decode"),
        ("act.t9_decode", "t9_decode"),
        ("act.keyboard_coord_decode", "keyboard_coord_decode"),
        ("act.php_serialize_decode", "php_serialize_decode"),
        ("act.zwc_decode", "zwc_decode"),
        ("act.zwc_encode", "zwc_encode"),
        ("act.rot47", "rot47"),
        ("act.whitespace_execute", "whitespace_execute"),
        ("act.base100_encode", "base100_encode"),
        ("act.base100_decode", "base100_decode"),
        ("act.tap_code_encode", "tap_code_encode"),
        ("act.tap_code_decode", "tap_code_decode"),
        ("act.bacon_encode", "bacon_encode"),
        ("act.vigenere_auto_crack", "vigenere_auto_crack"),
        ("act.semaphore_decode", "semaphore_decode"),
        ("act.semaphore_encode", "semaphore_encode"),
        ("act.nato_decode", "nato_decode"),
        ("act.nato_encode", "nato_encode"),
        ("act.coord_convert", "coord_convert"),
        ("act.leet_decode", "leet_decode"),
        ("act.leet_encode", "leet_encode"),
        ("act.baudot_decode", "baudot_decode"),
        ("act.emoji_cipher_decode", "emoji_cipher_decode"),
        ("act.emoji_cipher_encode", "emoji_cipher_encode"),
        ("act.manchester_decode", "manchester_decode"),
        ("act.manchester_encode", "manchester_encode"),
        ("act.color_hex_decode", "color_hex_decode"),
        ("act.dancing_men_decode", "dancing_men_decode"),
        ("act.word_frequency", "word_frequency"),
        ("act.enigma_decrypt", "enigma_decrypt"),
        ("act.pixel_extract", "pixel_extract"),
        ("act.keyboard_layout_convert", "keyboard_layout_convert"),
        ("act.timestamp_convert", "timestamp_convert"),
        ("act.ocr_extract", "ocr_extract"),
        ("act.uuencode", "uuencode"),
        ("act.uudecode", "uudecode"),
        ("act.xxencode", "xxencode"),
        ("act.xxdecode", "xxdecode"),
        ("act.quoted_printable_encode", "quoted_printable_encode"),
        ("act.quoted_printable_decode", "quoted_printable_decode"),
        ("act.audio_morse_decode", "audio_morse_decode"),
        ("act.piet_helper", "piet_helper"),
        ("act.malbolge_execute", "malbolge_execute"),
        ("act.ebcdic_to_ascii", "ebcdic_to_ascii"),
        ("act.ascii_to_ebcdic", "ascii_to_ebcdic"),
    ]

    def compose_params(self):
        with Horizontal(id="params-area"):
            yield Label(t("label.keywords"), classes="param-label")
            yield Input(placeholder=t("hint.keywords"), id="param-keywords", classes="param-input")

    def action_run_action(self):
        text = self._get_input()
        select = self.query_one("#action-select", Select)
        action = select.value
        if action == Select.BLANK:
            self._set_output(t("msg.select_action"))
            return
        keywords_str = self.query_one("#param-keywords", Input).value.strip()
        self._set_output(t("msg.processing"))
        self.run_worker(partial(self._do_misc, action, text, keywords_str), thread=True)

    def _do_misc(self, action, text, keywords_str):
        from ctftool.modules.misc import MiscModule
        misc = MiscModule()
        try:
            if action in ("gen_wordlist", "generate_wordlist"):
                parts = keywords_str.split(',') if keywords_str else []
                name = parts[0] if parts else ""
                birthday = parts[1] if len(parts) > 1 else ""
                keywords = parts[2:] if len(parts) > 2 else None
                result = misc.generate_wordlist(name, birthday, keywords)
            elif action == "ascii_table":
                result = misc.ascii_table()
            elif hasattr(misc, action):
                if not text:
                    self.app.call_from_thread(self._set_output, t("msg.no_input"))
                    return
                result = getattr(misc, action)(text)
            else:
                result = f"{t('msg.unknown_action')}: {action}"
            self.app.call_from_thread(self._set_output, result)
            self.app.call_from_thread(self._check_flags, result)
        except Exception as e:
            self.app.call_from_thread(self._set_output, f"错误: {e}")


# ======================== 自动扫描 ========================

class AutoScanScreen(Screen):
    BINDINGS = [
        ("ctrl+r", "run_scan", "开始扫描"),
        ("ctrl+s", "export_result", "导出结果"),
        ("escape", "app.pop_screen", "返回"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static(f" * {t('nav.autoscan')}", classes="module-title")
            yield Select(
                [
                    (t("scan.url"), "url"),
                    (t("scan.file"), "file"),
                    (t("scan.text"), "text"),
                ],
                prompt=t("label.scan_type"),
                id="scan-type",
            )
            yield Label("curl:")
            yield Input(placeholder="curl 'https://...' -H 'Cookie: ...'", id="curl-input")
            yield Label(t("label.target"))
            yield TextArea(id="target-input")
            with Horizontal():
                yield Button(t("btn.start_scan") + " (Ctrl+R)", id="scan-button", variant="success")
                yield Button(t("btn.export") + " (Ctrl+S)", id="export-button", variant="default")
            yield OutputPanel(id="scan-output-text")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "scan-button":
            # 新扫描前清零旧 flag
            flag_finder.clear()
            if hasattr(self.app, 'flag_bar'):
                self.app.flag_bar.clear_flags()
            self.action_run_scan()
        elif event.button.id == "export-button":
            self.action_export_result()

    def action_run_scan(self):
        scan_type = self.query_one("#scan-type", Select).value
        target = self.query_one("#target-input", TextArea).text.strip()
        curl_cmd = self.query_one("#curl-input", Input).value.strip()
        output = self.query_one("#scan-output-text", OutputPanel)
        if scan_type == Select.BLANK:
            output.set_output(t("msg.select_scan_type"))
            return
        if not target:
            output.set_output(t("msg.enter_target"))
            return
        output.set_output(t("msg.scanning") + "\n")
        self.run_worker(partial(self._do_scan, scan_type, target, curl_cmd), thread=True)

    def _do_scan(self, scan_type, target, curl_cmd=""):
        from ctftool.core.scanner import AutoScanner
        scanner = AutoScanner()
        if curl_cmd:
            scanner.configure_web(curl_cmd=curl_cmd)
        output = self.query_one("#scan-output-text", OutputPanel)

        def on_result(result):
            status = "[OK]" if result.success else "[ERR]"
            text = f"{status} {result.module} - {result.action}"
            if result.flags:
                text += f"\n    Flag: {', '.join(result.flags)}"
            if result.error:
                text += f"\n    {result.error}"
            self.app.call_from_thread(output.append_output, text)

        try:
            if scan_type == "url":
                results = scanner.scan_url(target, callback=on_result)
            elif scan_type == "file":
                results = scanner.scan_file(target, callback=on_result)
            elif scan_type == "text":
                results = scanner.scan_text(target, callback=on_result)
            else:
                return

            all_flags = scanner.get_all_flags()
            summary = f"\n{'='*50}\n done {len(results)} checks"
            if all_flags:
                summary += f"\n {len(all_flags)} Flag(s):\n"
                summary += "\n".join(f"  {f}" for f in all_flags)
                if hasattr(self.app, 'flag_bar'):
                    for f in all_flags:
                        self.app.call_from_thread(self.app.flag_bar.add_flag, f)
            else:
                summary += "\nNo flags found"
            self.app.call_from_thread(output.append_output, summary)
        except Exception as e:
            self.app.call_from_thread(output.append_output, f"\nError: {e}")

    def action_export_result(self):
        panel = self.query_one("#scan-output-text", OutputPanel)
        text = panel.text
        if not text or text == t("msg.waiting_output"):
            return
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(os.path.expanduser("~"), "ctf-tool", f"scan_{timestamp}.txt")
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(text)
        panel.append_output(f"\n[+] exported: {filepath}")


# ======================== RSA 攻击 ========================

class RSAScreen(ModuleScreen):
    module_name = "mod.rsa"
    actions = [
        ("act.small_e", "small_e"),
        ("act.common_modulus", "common_modulus"),
        ("act.wiener", "wiener"),
        ("act.fermat", "fermat"),
        ("act.pollard_p1", "pollard_p1"),
        ("act.pollard_rho", "pollard_rho"),
        ("act.dp_leak", "dp_leak"),
        ("act.dq_leak", "dq_leak"),
        ("act.hastad", "hastad"),
        ("act.factordb", "factordb"),
        ("act.direct", "direct"),
        ("act.rsa_auto_attack", "rsa_auto_attack"),
        ("act.multi_prime", "multi_prime"),
        ("act.rabin_decrypt", "rabin_decrypt"),
        ("act.rsa_batch_gcd", "rsa_batch_gcd"),
        ("act.rsa_franklin_reiter", "rsa_franklin_reiter"),
        ("act.rsa_williams_p1", "rsa_williams_p1"),
    ]

    def compose_params(self):
        with Vertical(id="params-area"):
            with Horizontal():
                yield Label("n =", classes="param-label")
                yield Input(placeholder=t("rsa.hint_n"), id="param-n", classes="param-input")
            with Horizontal():
                yield Label("e =", classes="param-label")
                yield Input(placeholder=t("rsa.hint_e"), id="param-e", classes="param-input")
            with Horizontal():
                yield Label("c =", classes="param-label")
                yield Input(placeholder=t("rsa.hint_c"), id="param-c", classes="param-input")
            with Horizontal():
                yield Label(t("label.extra"), classes="param-label")
                yield Input(
                    placeholder=t("rsa.hint_extra"),
                    id="param-extra", classes="param-input"
                )

    def action_run_action(self):
        select = self.query_one("#action-select", Select)
        action = select.value
        if action == Select.BLANK:
            self._set_output(t("msg.select_action"))
            return
        try:
            n = int(self.query_one("#param-n", Input).value.strip() or "0")
            e = int(self.query_one("#param-e", Input).value.strip() or "0")
            c = int(self.query_one("#param-c", Input).value.strip() or "0")
            extra = self.query_one("#param-extra", Input).value.strip()
        except ValueError as ve:
            self._set_output(f"参数格式错误: {ve}")
            return
        self._set_output(t("msg.scanning")  + "...")
        self.run_worker(partial(self._do_rsa, action, n, e, c, extra), thread=True)

    def _do_rsa(self, action, n, e, c, extra):
        from ctftool.modules.crypto import CryptoModule
        crypto = CryptoModule()
        try:
            if action == "small_e":
                result = crypto.rsa_decrypt_small_e(c, e, n)
            elif action == "common_modulus":
                parts = extra.split(',')
                if len(parts) != 2:
                    result = t("msg.rsa_need_extra")
                else:
                    e2, c2 = int(parts[0].strip()), int(parts[1].strip())
                    result = crypto.rsa_common_modulus(c, c2, e, e2, n)
            elif action == "wiener":
                result = crypto.rsa_wiener(e, n, c)
            elif action == "fermat":
                result = crypto.rsa_fermat(n, e, c)
            elif action == "pollard_p1":
                result = crypto.rsa_pollard_p1(n, e, c)
            elif action == "pollard_rho":
                result = crypto.rsa_pollard_rho(n, e, c)
            elif action == "dp_leak":
                dp = int(extra) if extra else 0
                result = crypto.rsa_dp_leak(n, e, c, dp)
            elif action == "dq_leak":
                dq = int(extra) if extra else 0
                result = crypto.rsa_dq_leak(n, e, c, dq)
            elif action == "hastad":
                result = crypto.rsa_hastad(e, c, n, extra)
            elif action == "factordb":
                result = crypto.rsa_factordb(n, e, c)
            elif action == "direct":
                parts = extra.split(',')
                if len(parts) != 2:
                    result = "RSA 直接解密需要在额外参数输入: p,q"
                else:
                    p, q = int(parts[0].strip()), int(parts[1].strip())
                    result = crypto.rsa_decrypt_direct(p, q, e, c)
            elif action == "rsa_auto_attack":
                result = crypto.rsa_auto_attack(n, e, c)
            elif action == "multi_prime":
                result = crypto.rsa_decrypt_multi_prime(n, e, c, extra)
            else:
                result = f"{t('msg.unknown_action')}: {action}"
            self.app.call_from_thread(self._set_output, result)
        except Exception as ex:
            self.app.call_from_thread(self._set_output, f"错误: {ex}")
