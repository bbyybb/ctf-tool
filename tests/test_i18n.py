# -*- coding: utf-8 -*-
"""i18n 国际化模块单元测试"""

import json
import os
import tempfile
from unittest.mock import patch

import ctftool.core.i18n as i18n_module
from ctftool.core.i18n import _detect_system_lang, get_lang, load_lang, set_lang, t


class TestTranslation:
    def setup_method(self):
        """每个测试前保存原始语言，测试后恢复"""
        self._original_lang = get_lang()

    def teardown_method(self):
        i18n_module._current_lang = self._original_lang

    def test_t_known_key_en_not_empty(self):
        """t() 对已知 key 在英文模式下返回非空字符串"""
        i18n_module._current_lang = "en"
        result = t("btn.run")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_t_known_key_zh_not_empty(self):
        """t() 对已知 key 在中文模式下返回非空字符串"""
        i18n_module._current_lang = "zh"
        result = t("btn.run")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_t_en_zh_different(self):
        """t() 在 en 和 zh 模式下对同一 key 返回不同文本"""
        i18n_module._current_lang = "en"
        en_text = t("nav.autoscan")
        i18n_module._current_lang = "zh"
        zh_text = t("nav.autoscan")
        assert en_text != zh_text

    def test_t_multiple_keys_different(self):
        """t() 在 en/zh 切换下对多个 key 均返回不同文本"""
        keys_to_check = ["nav.crypto", "btn.copy", "msg.no_input", "title.window",
                         "flag.saved", "flag.rules_added", "flag.total_rules"]
        for key in keys_to_check:
            i18n_module._current_lang = "en"
            en_text = t(key)
            i18n_module._current_lang = "zh"
            zh_text = t(key)
            assert en_text != zh_text, f"Key '{key}' 在中英文下返回了相同文本"

    def test_t_unknown_key_returns_key(self):
        """t() 对未知 key 返回 key 本身"""
        unknown = "this.key.does.not.exist.xyz"
        i18n_module._current_lang = "en"
        assert t(unknown) == unknown

    def test_t_unknown_key_returns_key_zh(self):
        """t() 在中文模式下对未知 key 也返回 key 本身"""
        unknown = "nonexistent.key.12345"
        i18n_module._current_lang = "zh"
        assert t(unknown) == unknown

    def test_t_empty_key(self):
        """t() 对空字符串 key 返回空字符串（因为字典中不存在空键）"""
        result = t("")
        assert result == ""


class TestGetSetLang:
    def setup_method(self):
        self._original_lang = get_lang()

    def teardown_method(self):
        i18n_module._current_lang = self._original_lang

    def test_get_lang_returns_string(self):
        """get_lang() 返回字符串"""
        lang = get_lang()
        assert isinstance(lang, str)
        assert lang in ("en", "zh")

    def test_set_lang_changes_current(self):
        """set_lang 能切换当前语言（mock 文件写入）"""
        with patch("builtins.open", create=True):
            with patch("os.makedirs"):
                set_lang("zh")
                assert get_lang() == "zh"
                set_lang("en")
                assert get_lang() == "en"

    def test_set_lang_writes_file(self):
        """set_lang 会将语言设置写入 JSON 文件"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "language.json")
            with patch.object(i18n_module, '_LANG_CONFIG', config_path):
                set_lang("zh")
                assert os.path.isfile(config_path)
                with open(config_path, encoding='utf-8') as f:
                    data = json.load(f)
                assert data["language"] == "zh"

    def test_set_lang_roundtrip(self):
        """set_lang 写入后 load_lang 能正确读回"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "language.json")
            with patch.object(i18n_module, '_LANG_CONFIG', config_path):
                set_lang("zh")
                # 重置为 en 来验证 load_lang 能读回 zh
                i18n_module._current_lang = "en"
                load_lang()
                assert get_lang() == "zh"


class TestLoadLang:
    def setup_method(self):
        self._original_lang = get_lang()

    def teardown_method(self):
        i18n_module._current_lang = self._original_lang

    def test_load_lang_no_config_file(self):
        """配置文件不存在时 load_lang 不崩溃，回退到系统语言检测"""
        with patch.object(i18n_module, '_LANG_CONFIG', '/nonexistent/path/language.json'):
            load_lang()
            # 不崩溃即可，语言应为 en 或 zh
            assert get_lang() in ("en", "zh")

    def test_load_lang_corrupted_file(self):
        """配置文件内容损坏时 load_lang 不崩溃"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "language.json")
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write("THIS IS NOT VALID JSON!!!")
            with patch.object(i18n_module, '_LANG_CONFIG', config_path):
                load_lang()
                assert get_lang() in ("en", "zh")

    def test_load_lang_valid_file(self):
        """配置文件有效时 load_lang 能正确加载语言"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "language.json")
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump({"language": "zh"}, f)
            with patch.object(i18n_module, '_LANG_CONFIG', config_path):
                load_lang()
                assert get_lang() == "zh"

    def test_load_lang_missing_key(self):
        """配置文件中缺少 language 键时不崩溃"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "language.json")
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump({"other_key": "value"}, f)
            with patch.object(i18n_module, '_LANG_CONFIG', config_path):
                load_lang()
                # 默认值为 "en"
                assert get_lang() == "en"


class TestDetectSystemLang:
    def test_detect_returns_string(self):
        """_detect_system_lang 返回 en 或 zh"""
        result = _detect_system_lang()
        assert result in ("en", "zh")

    def test_detect_chinese_locale(self):
        """当系统 locale 包含 zh 时返回 zh"""
        with patch("locale.getlocale", return_value=("zh_CN", "UTF-8")):
            assert _detect_system_lang() == "zh"

    def test_detect_english_locale(self):
        """当系统 locale 为英文时返回 en"""
        with patch("locale.getlocale", return_value=("en_US", "UTF-8")):
            assert _detect_system_lang() == "en"

    def test_detect_locale_exception(self):
        """当 getlocale 抛出异常时不崩溃，默认返回 en"""
        with patch("locale.getlocale", side_effect=Exception("locale error")):
            assert _detect_system_lang() == "en"

    def test_detect_locale_none(self):
        """当 getlocale 返回 None 且无环境变量时不崩溃，默认返回 en"""
        with patch("locale.getlocale", return_value=(None, None)), \
             patch.dict(os.environ, {"LANG": "", "LANGUAGE": ""}, clear=False):
            assert _detect_system_lang() == "en"


class TestBatch13Translations:
    """验证批次 1-3 新增功能的 i18n 翻译完整性"""

    BATCH_KEYS = [
        "act.playfair_encrypt", "act.playfair_decrypt",
        "act.polybius_encrypt", "act.polybius_decrypt",
        "act.xor_auto_crack", "act.padding_oracle_helper",
        "act.rot47", "act.base58_encode", "act.base85_encode",
        "act.hill_encrypt", "act.hill_decrypt",
        "act.columnar_transposition_encrypt", "act.columnar_transposition_decrypt",
        "act.aes_ctr_encrypt", "act.aes_ctr_decrypt",
        "act.crc32", "act.hmac_compute",
        "act.rsa_decrypt_multi_prime",
        "act.base91_encode", "act.base91_decode",
        "act.detect_xxe", "act.detect_cors",
        "act.audio_spectrogram", "act.pdf_analyze",
        "act.pcap_extract_http", "act.bit_plane_analysis",
        "act.check_pe_protections",
        "act.heap_exploit_template", "act.one_gadget_helper",
        "act.whitespace_execute",
        "act.base100_encode", "act.base100_decode",
        "act.tap_code_encode", "act.tap_code_decode",
        "act.bacon_encode", "act.vigenere_auto_crack",
        "act.qr_generate",
    ]

    def test_en_translations_exist(self):
        """所有批次 1-3 新增 key 在英文字典中存在"""
        i18n_module._current_lang = "en"
        for key in self.BATCH_KEYS:
            result = t(key)
            assert result != key, f"EN translation missing for '{key}'"

    def test_zh_translations_exist(self):
        """所有批次 1-3 新增 key 在中文字典中存在"""
        i18n_module._current_lang = "zh"
        for key in self.BATCH_KEYS:
            result = t(key)
            assert result != key, f"ZH translation missing for '{key}'"
