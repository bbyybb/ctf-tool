# -*- coding: utf-8 -*-
"""CLI 命令行模式单元测试"""

from io import StringIO
from unittest.mock import patch

from ctftool.cli import build_parser, cmd_crypto, cmd_forensics, cmd_misc, cmd_pwn, cmd_reverse, cmd_web


class TestCLIParser:
    def test_build_parser(self):
        """解析器能正常创建"""
        parser = build_parser()
        assert parser is not None

    def test_crypto_subcommand(self):
        """crypto 子命令解析"""
        parser = build_parser()
        args = parser.parse_args(['crypto', 'rot13', 'hello'])
        assert args.command == 'crypto'
        assert args.action == 'rot13'
        assert args.input == 'hello'

    def test_crypto_with_key(self):
        """crypto 子命令带 key 参数"""
        parser = build_parser()
        args = parser.parse_args(['crypto', 'xor-decrypt', 'data', '--key', 'mykey'])
        assert args.key == 'mykey'

    def test_misc_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(['misc', 'morse-decode', '.... ..'])
        assert args.command == 'misc'
        assert args.action == 'morse-decode'

    def test_pwn_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(['pwn', 'generate-pattern', '100'])
        assert args.command == 'pwn'

    def test_rsa_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(['rsa', 'fermat', '--n', '143', '--e', '7', '--c', '42'])
        assert args.command == 'rsa'
        assert args.n == 143

    def test_scan_text_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(['scan-text', 'ZmxhZ3t0ZXN0fQ=='])
        assert args.command == 'scan-text'
        assert args.scan_type == 'text'

    def test_scan_file_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(['scan-file', '/tmp/test.bin'])
        assert args.command == 'scan-file'
        assert args.scan_type == 'file'


class TestCLIWhitelist:
    """验证批次 1-3 新增方法已加入白名单"""

    def test_crypto_batch_actions(self):
        from ctftool.cli import _CRYPTO_ACTIONS
        new_actions = [
            'playfair_encrypt', 'playfair_decrypt', 'polybius_encrypt', 'polybius_decrypt',
            'xor_auto_crack', 'padding_oracle_helper', 'rot47', 'base58_encode', 'base85_encode',
            'hill_encrypt', 'hill_decrypt', 'columnar_transposition_encrypt', 'columnar_transposition_decrypt',
            'aes_ctr_encrypt', 'aes_ctr_decrypt', 'crc32', 'hmac_compute',
            'rsa_decrypt_multi_prime', 'base91_encode', 'base91_decode',
        ]
        for action in new_actions:
            assert action in _CRYPTO_ACTIONS, f"{action} missing from _CRYPTO_ACTIONS"

    def test_web_batch_actions(self):
        from ctftool.cli import _WEB_ACTIONS
        for action in ['detect_xxe', 'detect_cors']:
            assert action in _WEB_ACTIONS, f"{action} missing from _WEB_ACTIONS"

    def test_forensics_batch_actions(self):
        from ctftool.cli import _FORENSICS_ACTIONS
        for action in ['audio_spectrogram', 'pdf_analyze', 'pcap_extract_http', 'bit_plane_analysis']:
            assert action in _FORENSICS_ACTIONS, f"{action} missing from _FORENSICS_ACTIONS"

    def test_reverse_batch_actions(self):
        from ctftool.cli import _REVERSE_ACTIONS
        assert 'check_pe_protections' in _REVERSE_ACTIONS

    def test_pwn_batch_actions(self):
        from ctftool.cli import _PWN_ACTIONS
        for action in ['heap_exploit_template', 'one_gadget_helper']:
            assert action in _PWN_ACTIONS, f"{action} missing from _PWN_ACTIONS"

    def test_misc_batch_actions(self):
        from ctftool.cli import _MISC_ACTIONS
        new_actions = [
            'rot47', 'whitespace_execute', 'base100_encode', 'base100_decode',
            'tap_code_encode', 'tap_code_decode', 'bacon_encode',
            'vigenere_auto_crack', 'qr_generate',
        ]
        for action in new_actions:
            assert action in _MISC_ACTIONS, f"{action} missing from _MISC_ACTIONS"

    def test_crypto_batch13_actions(self):
        from ctftool.cli import _CRYPTO_ACTIONS
        batch13 = [
            'chinese_remainder_theorem', 'rsa_dq_leak',
            'blowfish_encrypt', 'blowfish_decrypt', 'base62_encode', 'base62_decode',
            'autokey_decrypt', 'nihilist_decrypt', 'book_cipher_decode', 'rabbit_decrypt',
        ]
        for action in batch13:
            assert action in _CRYPTO_ACTIONS, f"{action} missing from _CRYPTO_ACTIONS"

    def test_web_batch13_actions(self):
        from ctftool.cli import _WEB_ACTIONS
        batch13 = [
            'detect_path_traversal', 'prototype_pollution_helper',
            'race_condition_helper', 'detect_waf',
        ]
        for action in batch13:
            assert action in _WEB_ACTIONS, f"{action} missing from _WEB_ACTIONS"

    def test_forensics_batch13_actions(self):
        from ctftool.cli import _FORENSICS_ACTIONS
        batch13 = [
            'detect_exif_tampering', 'analyze_email', 'file_timeline', 'analyze_disk_image',
        ]
        for action in batch13:
            assert action in _FORENSICS_ACTIONS, f"{action} missing from _FORENSICS_ACTIONS"

    def test_reverse_batch13_actions(self):
        from ctftool.cli import _REVERSE_ACTIONS
        batch13 = [
            'analyze_apk', 'analyze_go_binary', 'analyze_rust_binary', 'deobfuscate_strings',
        ]
        for action in batch13:
            assert action in _REVERSE_ACTIONS, f"{action} missing from _REVERSE_ACTIONS"

    def test_pwn_batch13_actions(self):
        from ctftool.cli import _PWN_ACTIONS
        batch13 = [
            'ret2csu_template', 'stack_pivot_template', 'seccomp_helper',
            'io_file_template', 'house_of_orange_template',
        ]
        for action in batch13:
            assert action in _PWN_ACTIONS, f"{action} missing from _PWN_ACTIONS"

    def test_misc_batch13_actions(self):
        from ctftool.cli import _MISC_ACTIONS
        batch13 = [
            'emoji_cipher_encode', 'emoji_cipher_decode',
            'manchester_encode', 'manchester_decode', 'color_hex_decode',
            'dancing_men_decode', 'word_frequency', 'enigma_decrypt',
            'keyboard_layout_convert',
        ]
        for action in batch13:
            assert action in _MISC_ACTIONS, f"{action} missing from _MISC_ACTIONS"


class TestCLIExecution:
    def test_cmd_crypto_rot13(self):
        """CLI crypto rot13 执行"""
        parser = build_parser()
        args = parser.parse_args(['crypto', 'rot13', 'synt{grfg}'])
        # 捕获输出
        with patch('sys.stdout', new_callable=StringIO) as mock_out:
            cmd_crypto(args)
            output = mock_out.getvalue()
        assert 'flag{test}' in output

    def test_cmd_crypto_base64_decode(self):
        """CLI crypto base64-decode 执行"""
        parser = build_parser()
        args = parser.parse_args(['crypto', 'base64-decode', 'aGVsbG8='])
        with patch('sys.stdout', new_callable=StringIO) as mock_out:
            cmd_crypto(args)
            output = mock_out.getvalue()
        assert 'hello' in output

    def test_cmd_misc_morse_decode(self):
        """CLI misc morse-decode 执行"""
        parser = build_parser()
        args = parser.parse_args(['misc', 'morse-decode', '.... . .-.. .-.. ---'])
        with patch('sys.stdout', new_callable=StringIO) as mock_out:
            cmd_misc(args)
            output = mock_out.getvalue()
        assert 'HELLO' in output

    def test_cmd_pwn_generate_pattern(self):
        """CLI pwn generate-pattern 执行"""
        parser = build_parser()
        args = parser.parse_args(['pwn', 'generate-pattern', '50'])
        with patch('sys.stdout', new_callable=StringIO) as mock_out:
            cmd_pwn(args)
            output = mock_out.getvalue()
        assert 'Pattern' in output or '50' in output

    def test_cmd_crypto_unknown_action(self):
        """CLI 未知操作不崩溃"""
        parser = build_parser()
        args = parser.parse_args(['crypto', 'nonexistent-action', 'test'])
        with patch('sys.stdout', new_callable=StringIO) as mock_out:
            cmd_crypto(args)
            output = mock_out.getvalue()
        assert isinstance(output, str)

    def test_cmd_web_generate_payload(self):
        """CLI web generate-payload 执行"""
        parser = build_parser()
        args = parser.parse_args(['web', 'generate-payload', 'sqli'])
        with patch('sys.stdout', new_callable=StringIO) as mock_out:
            cmd_web(args)
            output = mock_out.getvalue()
        assert 'UNION' in output or 'OR' in output

    def test_cmd_web_unknown_action(self):
        """CLI web 未知操作不崩溃"""
        parser = build_parser()
        args = parser.parse_args(['web', 'nonexistent-action', 'test'])
        with patch('sys.stdout', new_callable=StringIO) as mock_out:
            cmd_web(args)
            output = mock_out.getvalue()
        assert isinstance(output, str)

    def test_cmd_forensics_identify_file(self):
        """CLI forensics identify-file 执行"""
        import os
        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix='.txt', delete=False, mode='w')
        tmp.write("test content")
        tmp.close()
        try:
            parser = build_parser()
            args = parser.parse_args(['forensics', 'identify-file', tmp.name])
            with patch('sys.stdout', new_callable=StringIO) as mock_out:
                cmd_forensics(args)
                output = mock_out.getvalue()
            assert isinstance(output, str)
        finally:
            os.unlink(tmp.name)

    def test_cmd_forensics_unknown_action(self):
        """CLI forensics 未知操作不崩溃"""
        parser = build_parser()
        args = parser.parse_args(['forensics', 'nonexistent-action', 'test'])
        with patch('sys.stdout', new_callable=StringIO) as mock_out:
            cmd_forensics(args)
            output = mock_out.getvalue()
        assert isinstance(output, str)

    def test_cmd_reverse_unknown_action(self):
        """CLI reverse 未知操作不崩溃"""
        parser = build_parser()
        args = parser.parse_args(['reverse', 'nonexistent-action', 'test'])
        with patch('sys.stdout', new_callable=StringIO) as mock_out:
            cmd_reverse(args)
            output = mock_out.getvalue()
        assert isinstance(output, str)
