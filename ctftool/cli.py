# -*- coding: utf-8 -*-
"""CTF Tool CLI 命令行模式"""

import argparse
import sys

from ctftool.core.flag_finder import flag_finder
from ctftool.core.history import history
from ctftool.core.i18n import t

# ========== 各模块允许通过 CLI 调用的方法白名单 ==========
_CRYPTO_ACTIONS = {
    'auto_decode', 'base64_encode', 'base64_decode', 'base32_encode', 'base32_decode',
    'hex_encode', 'hex_decode', 'url_encode', 'url_decode', 'html_entity_decode',
    'unicode_decode', 'binary_decode', 'binary_encode', 'octal_decode',
    'base58_decode', 'base85_decode',
    'caesar_bruteforce', 'caesar_decrypt', 'rot13', 'vigenere_decrypt', 'vigenere_encrypt',
    'vigenere_key_length', 'rail_fence_decrypt', 'rail_fence_bruteforce',
    'atbash', 'bacon_decode', 'affine_decrypt', 'affine_bruteforce',
    'xor_single_byte_bruteforce', 'xor_decrypt', 'rc4',
    'aes_ecb_decrypt', 'aes_cbc_decrypt', 'des_ecb_decrypt',
    'aes_ecb_encrypt', 'aes_cbc_encrypt', 'des_ecb_encrypt',
    'identify_hash', 'hash_crack_dict', 'compute_hash', 'hash_length_extension',
    'frequency_analysis',
    'playfair_encrypt', 'playfair_decrypt', 'polybius_encrypt', 'polybius_decrypt',
    'xor_auto_crack', 'padding_oracle_helper', 'rot47', 'base58_encode', 'base85_encode',
    'hill_encrypt', 'hill_decrypt', 'columnar_transposition_encrypt', 'columnar_transposition_decrypt',
    'aes_ctr_encrypt', 'aes_ctr_decrypt', 'crc32', 'hmac_compute',
    'rsa_decrypt_multi_prime', 'base91_encode', 'base91_decode',
    'ecc_point_add', 'dlp_bsgs', 'dlp_pohlig_hellman', 'mt19937_predict',
    'triple_des_decrypt', 'triple_des_encrypt', 'substitution_auto_crack',
    'adfgvx_decrypt', 'bifid_decrypt', 'bifid_encrypt', 'four_square_decrypt',
    'chinese_remainder_theorem', 'rsa_dq_leak',
    'blowfish_decrypt', 'blowfish_encrypt', 'base62_encode', 'base62_decode',
    'autokey_decrypt', 'nihilist_decrypt', 'book_cipher_decode', 'rabbit_decrypt',
    'rsa_auto_attack', 'hash_crack_online', 'detect_encoding',
    'rabin_decrypt', 'rsa_batch_gcd', 'rsa_franklin_reiter',
    'rsa_coppersmith_helper', 'rsa_boneh_durfee_helper', 'rsa_williams_p1',
    'rsa_import_key', 'hash_collision_generate', 'password_strength',
}

_WEB_ACTIONS = {
    'analyze_headers', 'check_robots', 'check_git_leak', 'dir_scan',
    'detect_sqli', 'detect_xss', 'detect_lfi', 'detect_cmdi', 'detect_ssrf', 'detect_ssti',
    'jwt_forge_none', 'jwt_crack', 'generate_payload',
    'detect_xxe', 'detect_cors',
    'detect_open_redirect', 'detect_crlf', 'deserialize_helper',
    'detect_path_traversal', 'detect_http_smuggling',
    'prototype_pollution_helper', 'race_condition_helper', 'detect_waf',
    'configure', 'parse_curl',
    'subdomain_enum', 'fingerprint', 'info_gather',
    'detect_svn_leak', 'detect_ds_store', 'detect_backup_files',
    'detect_env_leak', 'detect_graphql', 'detect_host_injection', 'detect_jsonp',
    'detect_swagger', 'sqli_auto_exploit', 'sqli_time_blind', 'dir_listing_crawl',
    'detect_csrf', 'file_upload_helper',
    'code_audit', 'xxe_payload_helper', 'ssrf_payload_helper', 'waf_bypass_helper',
}

_FORENSICS_ACTIONS = {
    'identify_file', 'extract_strings', 'extract_metadata', 'detect_stego',
    'binwalk_scan', 'binwalk_extract', 'hex_view', 'file_diff',
    'zip_crack', 'rar_crack', 'zip_fake_decrypt', 'fix_file_header',
    'pcap_analyze', 'png_crc_fix', 'usb_keyboard_decode', 'usb_mouse_decode',
    'split_channels', 'gif_frame_extract', 'lsb_extract_advanced',
    'audio_spectrogram', 'pdf_analyze', 'pcap_extract_http', 'bit_plane_analysis',
    'dtmf_decode', 'office_analyze', 'memory_dump_analyze',
    'detect_ntfs_ads', 'detect_exif_tampering', 'analyze_disk_image',
    'analyze_email', 'analyze_registry', 'file_timeline', 'detect_dns_tunnel',
    'pcap_extract_files', 'lsb_encode', 'file_carve',
    'steghide_extract', 'zsteg_scan', 'blind_watermark_extract',
    'apng_extract', 'sstv_decode_helper',
    'stego_full_scan', 'file_carve_precise', 'memory_forensics_enhanced',
    'tool_cheatsheet',
}

_REVERSE_ACTIONS = {
    'analyze_binary', 'extract_strings_from_binary', 'disassemble',
    'check_elf_protections', 'decompile_pyc',
    'check_pe_protections',
    'detect_packer', 'list_imports_exports',
    'analyze_apk', 'analyze_dotnet', 'analyze_go_binary',
    'yara_scan', 'deobfuscate_strings', 'analyze_rust_binary',
    'analyze_ipa', 'tool_cheatsheet',
}

_PWN_ACTIONS = {
    'generate_pattern', 'find_pattern_offset', 'generate_padding',
    'format_string_read', 'format_string_write', 'find_format_offset',
    'find_rop_gadgets', 'shellcode_template', 'addr_convert',
    'pwntools_template', 'ret2libc_template', 'ret2syscall_template',
    'srop_template', 'check_bad_chars', 'got_overwrite_template',
    'heap_exploit_template', 'one_gadget_helper',
    'ret2csu_template', 'stack_pivot_template', 'seccomp_helper',
    'io_file_template', 'house_of_orange_template',
    'auto_ret2text', 'auto_ret2shellcode', 'auto_pwn_analyze',
}

_MISC_ACTIONS = {
    'base_convert', 'morse_encode', 'morse_decode', 'braille_decode', 'braille_encode',
    'core_values_decode', 'core_values_encode', 'pigpen_decode',
    'dna_decode', 'dna_encode', 'ascii_table', 'char_convert', 'rot_all',
    'qr_decode', 'barcode_decode', 'ook_decode', 'ook_execute', 'brainfuck_execute',
    'generate_wordlist', 'jwt_decode', 't9_decode', 'keyboard_coord_decode',
    'php_serialize_decode', 'zwc_decode', 'zwc_encode',
    'rot47', 'whitespace_execute', 'base100_encode', 'base100_decode',
    'tap_code_encode', 'tap_code_decode', 'bacon_encode',
    'vigenere_auto_crack', 'qr_generate',
    'semaphore_decode', 'semaphore_encode', 'nato_decode', 'nato_encode',
    'coord_convert', 'leet_decode', 'leet_encode', 'baudot_decode',
    'emoji_cipher_decode', 'emoji_cipher_encode',
    'manchester_decode', 'manchester_encode', 'color_hex_decode',
    'dancing_men_decode', 'word_frequency', 'enigma_decrypt',
    'pixel_extract', 'keyboard_layout_convert',
    'timestamp_convert', 'qr_batch_decode', 'ocr_extract',
    'uuencode', 'uudecode', 'xxencode', 'xxdecode',
    'quoted_printable_encode', 'quoted_printable_decode',
    'audio_morse_decode', 'piet_helper', 'malbolge_execute',
    'ebcdic_to_ascii', 'ascii_to_ebcdic',
}

_BLOCKCHAIN_ACTIONS = {
    'analyze_contract', 'detect_reentrancy', 'detect_integer_overflow',
    'detect_tx_origin', 'detect_selfdestruct', 'detect_unchecked_call',
    'abi_decode', 'abi_encode', 'selector_lookup',
    'disasm_bytecode', 'storage_layout_helper',
    'flashloan_template', 'reentrancy_exploit_template',
    'evm_puzzle_helper', 'common_patterns',
}


def _highlight_flags(text: str) -> str:
    """高亮显示 flag"""
    flags = flag_finder.search(text)
    for f in flags:
        text = text.replace(f, f"\033[1;32m{f}\033[0m")
    return text


def _record_and_print(module: str, action: str, input_text: str, result: str):
    """记录操作历史并输出结果，自动检测 Flag"""
    flags = flag_finder.search_with_decode(result)
    history.add(module, action, input_text, result, flags)
    print(_highlight_flags(result))
    if flags:
        print(f"\n\033[1;33m{'=' * 50}\033[0m")
        print(f"\033[1;32m[!] {t('msg.flag_auto_found')} ({len(flags)}):\033[0m")
        for f in flags:
            print(f"    \033[1;32m>> {f}\033[0m")
        print(f"\033[1;33m{'=' * 50}\033[0m")


def cmd_crypto(args):
    from ctftool.modules.crypto import CryptoModule
    crypto = CryptoModule()
    action = args.action.replace('-', '_')
    text = args.input

    if action not in _CRYPTO_ACTIONS:
        print(f"{t('msg.unknown_action')}: {action}")
        return

    try:
        # 需要 key 的操作
        if action in ('vigenere_decrypt', 'xor_decrypt', 'rc4',
                       'autokey_decrypt', 'nihilist_decrypt') and args.key:
            result = getattr(crypto, action)(text, args.key)
        elif action in ('aes_ecb_decrypt', 'aes_cbc_decrypt', 'des_ecb_decrypt',
                         'aes_ecb_encrypt', 'aes_cbc_encrypt', 'des_ecb_encrypt'):
            result = getattr(crypto, action)(text, args.key or '', args.iv or '')
        elif action in ('blowfish_decrypt', 'blowfish_encrypt') and args.key:
            result = getattr(crypto, action)(text, args.key)
        elif action == 'affine_decrypt' and args.key:
            parts = args.key.split(',')
            result = crypto.affine_decrypt(text, int(parts[0]), int(parts[1]))
        elif action == 'book_cipher_decode' and args.key:
            result = crypto.book_cipher_decode(text, args.key)
        else:
            result = getattr(crypto, action)(text)
    except (ValueError, IndexError, TypeError) as e:
        result = f"{t('msg.param_error')}: {e}"
    except Exception as e:
        result = f"{t('msg.error_prefix')}: {e}"

    _record_and_print("crypto", action, text, result)


def cmd_web(args):
    from ctftool.modules.web import WebModule
    web = WebModule()
    action = args.action.replace('-', '_')

    if action not in _WEB_ACTIONS and not action.startswith('gen_'):
        print(f"{t('msg.unknown_action')}: {action}")
        return

    try:
        if action.startswith('gen_'):
            result = web.generate_payload(action[4:])
        elif action in ('prototype_pollution_helper', 'race_condition_helper', 'deserialize_helper'):
            result = getattr(web, action)()
        elif action in ('jwt_forge_none', 'jwt_crack'):
            result = getattr(web, action)(args.input)
        else:
            result = getattr(web, action)(args.input)
    except (ValueError, IndexError, TypeError) as e:
        result = f"{t('msg.param_error')}: {e}"
    except Exception as e:
        result = f"{t('msg.error_prefix')}: {e}"

    _record_and_print("web", action, args.input or "", result)


def cmd_forensics(args):
    from ctftool.modules.forensics import ForensicsModule
    forensics = ForensicsModule()
    action = args.action.replace('-', '_')

    if action not in _FORENSICS_ACTIONS:
        print(f"{t('msg.unknown_action')}: {action}")
        return

    try:
        if action == 'file_diff' and args.extra:
            result = forensics.file_diff(args.filepath, args.extra)
        elif action == 'zip_crack':
            result = forensics.zip_crack(args.filepath, args.extra or None)
        else:
            result = getattr(forensics, action)(args.filepath)
    except (ValueError, IndexError, TypeError) as e:
        result = f"{t('msg.param_error')}: {e}"
    except Exception as e:
        result = f"{t('msg.error_prefix')}: {e}"

    _record_and_print("forensics", action, args.filepath or "", result)


def cmd_reverse(args):
    from ctftool.modules.reverse import ReverseModule
    reverse = ReverseModule()
    action = args.action.replace('-', '_')

    if action not in _REVERSE_ACTIONS:
        print(f"{t('msg.unknown_action')}: {action}")
        return

    try:
        result = getattr(reverse, action)(args.filepath)
    except (ValueError, IndexError, TypeError) as e:
        result = f"{t('msg.param_error')}: {e}"
    except Exception as e:
        result = f"{t('msg.error_prefix')}: {e}"

    _record_and_print("reverse", action, args.filepath or "", result)


def cmd_blockchain(args):
    from ctftool.modules.blockchain import BlockchainModule
    blockchain = BlockchainModule()
    action = args.action.replace('-', '_')

    if action not in _BLOCKCHAIN_ACTIONS:
        print(f"{t('msg.unknown_action')}: {action}")
        return

    try:
        result = getattr(blockchain, action)(args.input or "")
    except (ValueError, IndexError, TypeError) as e:
        result = f"{t('msg.param_error')}: {e}"
    except Exception as e:
        result = f"{t('msg.error_prefix')}: {e}"

    _record_and_print("blockchain", action, args.input or "", result)


def cmd_pwn(args):
    from ctftool.modules.pwn import PwnModule
    pwn = PwnModule()
    action = args.action.replace('-', '_')
    arch = args.arch or 'x86'

    if action not in _PWN_ACTIONS:
        print(f"{t('msg.unknown_action')}: {action}")
        return

    try:
        if action == 'generate_pattern':
            length = int(args.input) if args.input else 200
            result = pwn.generate_pattern(length)
        elif action == 'find_pattern_offset':
            result = pwn.find_pattern_offset(args.input)
        elif action == 'generate_padding':
            result = pwn.generate_padding(int(args.length or 0), args.addr or '0xdeadbeef', arch)
        elif action in ('shellcode_template', 'pwntools_template', 'ret2libc_template',
                         'ret2syscall_template', 'srop_template', 'got_overwrite_template',
                         'ret2csu_template', 'stack_pivot_template'):
            result = getattr(pwn, action)(arch)
        elif action == 'find_format_offset':
            result = pwn.find_format_offset()
        elif action in ('seccomp_helper', 'io_file_template', 'house_of_orange_template'):
            result = getattr(pwn, action)()
        elif action == 'find_rop_gadgets':
            result = pwn.find_rop_gadgets(args.input)
        elif action == 'addr_convert':
            result = pwn.addr_convert(args.input)
        elif action == 'check_bad_chars':
            result = pwn.check_bad_chars(args.input)
        else:
            result = getattr(pwn, action)(args.input)
    except (ValueError, IndexError, TypeError) as e:
        result = f"{t('msg.param_error')}: {e}"
    except Exception as e:
        result = f"{t('msg.error_prefix')}: {e}"

    _record_and_print("pwn", action, args.input or "", result)


def cmd_misc(args):
    from ctftool.modules.misc import MiscModule
    misc = MiscModule()
    action = args.action.replace('-', '_')

    if action not in _MISC_ACTIONS and action != 'gen_wordlist':
        print(f"{t('msg.unknown_action')}: {action}")
        return

    try:
        if action == 'gen_wordlist':
            parts = (args.input or '').split(',')
            result = misc.generate_wordlist(parts[0] if parts else '',
                                             parts[1] if len(parts) > 1 else '',
                                             parts[2:] if len(parts) > 2 else None)
        elif action == 'ascii_table':
            result = misc.ascii_table()
        else:
            result = getattr(misc, action)(args.input)
    except (ValueError, IndexError, TypeError) as e:
        result = f"{t('msg.param_error')}: {e}"
    except Exception as e:
        result = f"{t('msg.error_prefix')}: {e}"

    _record_and_print("misc", action, args.input or "", result)


def cmd_rsa(args):
    from ctftool.modules.crypto import CryptoModule
    crypto = CryptoModule()
    attack = args.attack.replace('-', '_')
    n, e, c = args.n or 0, args.e or 0, args.c or 0
    extra = args.extra or ''

    dispatch = {
        'small_e': lambda: crypto.rsa_decrypt_small_e(c, e, n),
        'common_modulus': lambda: crypto.rsa_common_modulus(c, int(extra.split(',')[1]), e, int(extra.split(',')[0]), n),
        'wiener': lambda: crypto.rsa_wiener(e, n, c),
        'fermat': lambda: crypto.rsa_fermat(n, e, c),
        'pollard_p1': lambda: crypto.rsa_pollard_p1(n, e, c),
        'pollard_rho': lambda: crypto.rsa_pollard_rho(n, e, c),
        'dp_leak': lambda: crypto.rsa_dp_leak(n, e, c, int(extra)),
        'hastad': lambda: crypto.rsa_hastad(e, c, n, extra),
        'factordb': lambda: crypto.rsa_factordb(n, e, c),
        'direct': lambda: crypto.rsa_decrypt_direct(int(extra.split(',')[0]), int(extra.split(',')[1]), e, c),
        'dq_leak': lambda: crypto.rsa_dq_leak(n, e, c, int(extra)),
        'multi_prime': lambda: crypto.rsa_decrypt_multi_prime(extra, e, c),
        'rsa_auto_attack': lambda: crypto.rsa_auto_attack(n, e, c),
    }

    if attack in dispatch:
        try:
            result = dispatch[attack]()
        except Exception as ex:
            result = f"错误: {ex}"
    else:
        result = f"{t('msg.unknown_attack')}: {attack}"

    _record_and_print("rsa", attack, f"n={n},e={e},c={c}", result)


def cmd_scan(args):
    from ctftool.core.scanner import AutoScanner
    scanner = AutoScanner()

    if hasattr(args, 'curl') and args.curl:
        scanner.configure_web(curl_cmd=args.curl)

    def on_result(r):
        status = "[OK]" if r.success else "[ERR]"
        print(f"  {status} {r.module} - {r.action}")
        if r.flags:
            for f in r.flags:
                print(f"    \033[1;32mFlag: {f}\033[0m")
        if r.error:
            print(f"    {r.error}")

    if args.scan_type == 'text':
        results = scanner.scan_text(args.target, callback=on_result)
    elif args.scan_type == 'file':
        results = scanner.scan_file(args.target, callback=on_result)
    elif args.scan_type == 'url':
        results = scanner.scan_url(args.target, callback=on_result)

    flags = scanner.get_all_flags()
    print(f"\n{'='*50}")
    print(t("msg.scan_done").format(len(results)))
    if flags:
        print(t("msg.found_flags").format(len(flags)) + ":")
        for f in flags:
            print(f"  \033[1;32m{f}\033[0m")
    else:
        print(t("msg.no_flags"))

    summary = t("msg.scan_summary").format(len(results), len(flags))
    history.add("scanner", args.scan_type, args.target, summary, flags)

    if hasattr(args, 'output') and args.output:
        if args.format == 'json':
            print(scanner.export_json(args.output))
        elif args.format == 'html':
            print(scanner.export_html(args.output))
        else:
            with open(args.output, 'w', encoding='utf-8') as f:
                for r in results:
                    f.write(f"[{'OK' if r.success else 'ERR'}] {r.module} - {r.action}\n")
                    if r.output:
                        f.write(f"{r.output[:500]}\n")
            print(f"{t('msg.exported_to')}: {args.output}")


def cmd_history(args):
    if args.clear:
        history.clear()
        print(t("msg.history_cleared"))
        return
    if args.flags:
        flags = history.get_flags()
        if flags:
            for f in flags:
                print(f"  \033[1;32m{f}\033[0m")
        else:
            print(t("msg.no_flags"))
        return
    if args.search:
        entries = history.search(args.search)
    else:
        entries = history.get_recent(args.limit)
    if not entries:
        print(t("msg.no_history_records"))
        return
    for e in entries:
        print(f"[{e.timestamp}] {e.module}/{e.action}: {e.input[:80]}")
        if e.flags:
            for f in e.flags:
                print(f"  \033[1;32mFlag: {f}\033[0m")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='ctf-tool cli',
        description='CTF Tool CLI - 命令行模式'
    )
    parser.add_argument('--verbose', '-v', action='store_true', help='启用详细日志')
    sub = parser.add_subparsers(dest='command', help='模块')

    # crypto
    p_crypto = sub.add_parser('crypto', help='密码学')
    p_crypto.add_argument('action', help='操作 (如 base64-decode, rot13, caesar-bruteforce)')
    p_crypto.add_argument('input', help='输入文本')
    p_crypto.add_argument('--key', '-k', help='密钥')
    p_crypto.add_argument('--iv', help='IV (AES-CBC)')
    p_crypto.set_defaults(func=cmd_crypto)

    # web
    p_web = sub.add_parser('web', help='Web 安全')
    p_web.add_argument('action', help='操作')
    p_web.add_argument('input', help='URL 或 JWT Token')
    p_web.set_defaults(func=cmd_web)

    # forensics
    p_forensics = sub.add_parser('forensics', help='取证分析')
    p_forensics.add_argument('action', help='操作')
    p_forensics.add_argument('filepath', help='文件路径')
    p_forensics.add_argument('--extra', '-e', help='额外参数')
    p_forensics.set_defaults(func=cmd_forensics)

    # reverse
    p_reverse = sub.add_parser('reverse', help='逆向工程')
    p_reverse.add_argument('action', help='操作')
    p_reverse.add_argument('filepath', help='文件路径')
    p_reverse.set_defaults(func=cmd_reverse)

    # blockchain
    p_bc = sub.add_parser('blockchain', help='区块链安全')
    p_bc.add_argument('action', help='操作')
    p_bc.add_argument('input', nargs='?', default='', help='输入')
    p_bc.set_defaults(func=cmd_blockchain)

    # pwn
    p_pwn = sub.add_parser('pwn', help='Pwn')
    p_pwn.add_argument('action', help='操作')
    p_pwn.add_argument('input', nargs='?', default='', help='输入')
    p_pwn.add_argument('--length', '-l', help='长度/偏移')
    p_pwn.add_argument('--addr', '-a', help='地址')
    p_pwn.add_argument('--arch', default='x86', choices=['x86', 'x64'], help='架构')
    p_pwn.set_defaults(func=cmd_pwn)

    # misc
    p_misc = sub.add_parser('misc', help='杂项')
    p_misc.add_argument('action', help='操作')
    p_misc.add_argument('input', nargs='?', default='', help='输入')
    p_misc.set_defaults(func=cmd_misc)

    # rsa
    p_rsa = sub.add_parser('rsa', help='RSA 攻击')
    p_rsa.add_argument('attack', help='攻击方式 (small-e, fermat, wiener, etc.)')
    p_rsa.add_argument('--n', type=int, default=0, help='模数 N')
    p_rsa.add_argument('--e', type=int, default=0, help='公钥指数 e')
    p_rsa.add_argument('--c', type=int, default=0, help='密文 c')
    p_rsa.add_argument('--extra', help='额外参数')
    p_rsa.set_defaults(func=cmd_rsa)

    # scan-text
    p_st = sub.add_parser('scan-text', help='自动文本扫描')
    p_st.add_argument('target', help='待扫描文本')
    p_st.add_argument('--output', '-o', help='输出文件路径')
    p_st.add_argument('--format', '-f', choices=['text', 'json', 'html'], default='text', help='输出格式')
    p_st.set_defaults(func=cmd_scan, scan_type='text')

    # scan-file
    p_sf = sub.add_parser('scan-file', help='自动文件扫描')
    p_sf.add_argument('target', help='文件路径')
    p_sf.add_argument('--output', '-o', help='输出文件路径')
    p_sf.add_argument('--format', '-f', choices=['text', 'json', 'html'], default='text', help='输出格式')
    p_sf.set_defaults(func=cmd_scan, scan_type='file')

    # scan-url
    p_su = sub.add_parser('scan-url', help='自动 URL 扫描')
    p_su.add_argument('target', help='目标 URL')
    p_su.add_argument('--output', '-o', help='输出文件路径')
    p_su.add_argument('--format', '-f', choices=['text', 'json', 'html'], default='text', help='输出格式')
    p_su.add_argument('--curl', help='curl 命令（自动解析 Cookie/Header）')
    p_su.set_defaults(func=cmd_scan, scan_type='url')

    # history
    p_hist = sub.add_parser('history', help='查看操作历史')
    p_hist.add_argument('--search', '-s', help='搜索关键词')
    p_hist.add_argument('--flags', action='store_true', help='只显示包含 Flag 的记录')
    p_hist.add_argument('--clear', action='store_true', help='清空历史')
    p_hist.add_argument('--limit', '-n', type=int, default=20, help='显示条数')
    p_hist.set_defaults(func=cmd_history)

    return parser


def cli_main():
    """CLI 入口"""
    parser = build_parser()
    args = parser.parse_args(sys.argv[2:])  # 跳过 'main.py' 和 'cli'
    if args.verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG, format='%(name)s %(levelname)s: %(message)s')
    if not args.command:
        parser.print_help()
        return
    args.func(args)
