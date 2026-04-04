# -*- coding: utf-8 -*-
"""密码学模块

覆盖：编码/解码、古典密码、现代密码、哈希识别与碰撞、频率分析。
"""

import base64
import binascii
import hashlib
import math
import os
import re
import string
from collections import Counter
from typing import Optional
from urllib.parse import quote, unquote

from ctftool.core.i18n import t


class CryptoModule:
    """密码学工具集"""

    # ========== 编码/解码 ==========

    def auto_decode(self, text: str) -> str:
        """尝试所有常见编码方式自动解码"""
        results = []
        decoders = [
            ("Base64", self.base64_decode),
            ("Base32", self.base32_decode),
            ("Base16/Hex", self.hex_decode),
            (t("cry.url_decode"), self.url_decode),
            (t("cry.html_entity"), self.html_entity_decode),
            (t("cry.unicode_escape"), self.unicode_decode),
            ("Base58", self.base58_decode),
            ("Base85", self.base85_decode),
            (t("cry.binary"), self.binary_decode),
            (t("cry.octal"), self.octal_decode),
        ]
        for name, decoder in decoders:
            try:
                result = decoder(text)
                if result and result != text and self._is_readable(result):
                    results.append(f"[{name}] {result}")
            except Exception:
                pass
        if not results:
            return t("cry.auto_decode_fail")
        # 检查解码结果中是否含有 flag
        from ctftool.core.flag_finder import flag_finder
        all_decoded_text = '\n'.join(results)
        found_flags = flag_finder.search(all_decoded_text)
        if found_flags:
            results.append(f"\n[!] {t('cry.flag_found')}: {', '.join(found_flags)}")
        return "\n".join(results)

    def base64_encode(self, text: str) -> str:
        return base64.b64encode(text.encode()).decode()

    def base64_decode(self, text: str) -> str:
        # 尝试补齐 padding
        text = text.strip()
        padding = 4 - len(text) % 4
        if padding != 4:
            text += '=' * padding
        return base64.b64decode(text).decode('utf-8', errors='replace')

    def base32_encode(self, text: str) -> str:
        return base64.b32encode(text.encode()).decode()

    def base32_decode(self, text: str) -> str:
        text = text.strip().upper()
        padding = 8 - len(text) % 8
        if padding != 8:
            text += '=' * padding
        return base64.b32decode(text).decode('utf-8', errors='replace')

    def hex_encode(self, text: str) -> str:
        return text.encode().hex()

    def hex_decode(self, text: str) -> str:
        cleaned = text.strip().replace(' ', '').replace('0x', '').replace('\\x', '').replace(':', '')
        return binascii.unhexlify(cleaned).decode('utf-8', errors='replace')

    def url_encode(self, text: str) -> str:
        return quote(text)

    def url_decode(self, text: str) -> str:
        return unquote(text)

    def html_entity_decode(self, text: str) -> str:
        import html
        return html.unescape(text)

    def unicode_decode(self, text: str) -> str:
        """解码 \\uXXXX 或 \\UXXXXXXXX 格式"""
        return text.encode('raw_unicode_escape').decode('unicode_escape')

    def binary_decode(self, text: str) -> str:
        """二进制字符串 → 文本"""
        cleaned = text.replace(' ', '')
        if not all(c in '01' for c in cleaned):
            return ""
        chars = [chr(int(cleaned[i:i+8], 2)) for i in range(0, len(cleaned), 8)]
        return ''.join(chars)

    def binary_encode(self, text: str) -> str:
        return ' '.join(format(ord(c), '08b') for c in text)

    def octal_decode(self, text: str) -> str:
        """八进制字符串 → 文本"""
        parts = text.strip().split()
        if not parts:
            parts = re.findall(r'\\(\d{3})', text)
        if not parts:
            return ""
        return ''.join(chr(int(p, 8)) for p in parts if p)

    # ========== 古典密码 ==========

    def caesar_bruteforce(self, text: str) -> str:
        """Caesar 密码暴力破解（26种偏移）"""
        results = []
        for shift in range(26):
            decoded = self._caesar_shift(text, shift)
            results.append(f"ROT-{shift:2d}: {decoded}")
        return "\n".join(results)

    def caesar_decrypt(self, text: str, shift: int) -> str:
        return self._caesar_shift(text, shift)

    def _caesar_shift(self, text: str, shift: int) -> str:
        result = []
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                result.append(chr((ord(c) - base + shift) % 26 + base))
            else:
                result.append(c)
        return ''.join(result)

    def rot13(self, text: str) -> str:
        return self._caesar_shift(text, 13)

    def vigenere_decrypt(self, ciphertext: str, key: str) -> str:
        """Vigenere 密码解密"""
        result = []
        key_idx = 0
        for c in ciphertext:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                k = ord(key[key_idx % len(key)].upper()) - ord('A')
                result.append(chr((ord(c) - base - k) % 26 + base))
                key_idx += 1
            else:
                result.append(c)
        return ''.join(result)

    def vigenere_encrypt(self, plaintext: str, key: str) -> str:
        """Vigenere 密码加密"""
        result = []
        key_idx = 0
        for c in plaintext:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                k = ord(key[key_idx % len(key)].upper()) - ord('A')
                result.append(chr((ord(c) - base + k) % 26 + base))
                key_idx += 1
            else:
                result.append(c)
        return ''.join(result)

    def vigenere_key_length(self, ciphertext: str) -> str:
        """Vigenere 密码密钥长度推测（Kasiski + 重合指数）"""
        text = ''.join(c.upper() for c in ciphertext if c.isalpha())
        if len(text) < 20:
            return t("cry.text_too_short_key")

        lines = [f"=== {t('cry.vigenere_key_analysis')} ===", ""]

        # 方法1: Kasiski 检验 — 寻找重复片段
        from collections import Counter
        distances = []
        for length in range(3, 6):
            seen = {}
            for i in range(len(text) - length + 1):
                gram = text[i:i+length]
                if gram in seen:
                    distances.append(i - seen[gram])
                seen[gram] = i

        if distances:
            # 计算所有距离的 GCD
            gcd_candidates = Counter()
            for d in distances:
                for k in range(2, min(d+1, 30)):
                    if d % k == 0:
                        gcd_candidates[k] += 1

            lines.append(f"{t('cry.kasiski_test')}:")
            for k, count in gcd_candidates.most_common(10):
                bar = '█' * min(count, 30)
                lines.append(f"  {t('cry.key_length')} {k:2d}: {count:3d} {t('cry.times')} {bar}")

        # 方法2: 重合指数 (IC)
        lines.append(f"\n{t('cry.ic_analysis')}:")
        english_ic = 0.0667
        best_key_len = 2
        best_diff = 1.0

        for key_len in range(2, min(len(text) // 3, 25)):
            groups = ['' for _ in range(key_len)]
            for i, ch in enumerate(text):
                groups[i % key_len] += ch

            avg_ic = 0
            for group in groups:
                n = len(group)
                if n < 2:
                    continue
                freq = Counter(group)
                ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
                avg_ic += ic
            avg_ic /= key_len

            diff = abs(avg_ic - english_ic)
            marker = f" <-- {t('cry.best')}" if diff < best_diff else ""
            if diff < best_diff:
                best_diff = diff
                best_key_len = key_len
            lines.append(f"  {t('cry.key_length')} {key_len:2d}: IC = {avg_ic:.4f}{marker}")

        lines.append(f"\n{t('cry.guessed_key_length')}: {best_key_len}")
        return "\n".join(lines)

    def rail_fence_decrypt(self, ciphertext: str, rails: int) -> str:
        """栅栏密码解密"""
        if rails <= 1:
            return ciphertext
        n = len(ciphertext)
        fence = [['' for _ in range(n)] for _ in range(rails)]
        # 标记位置
        pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
        indices = [pattern[i % len(pattern)] for i in range(n)]
        # 按行填入字符
        idx = 0
        for rail in range(rails):
            for col in range(n):
                if indices[col] == rail:
                    fence[rail][col] = ciphertext[idx]
                    idx += 1
        # 按列读出
        return ''.join(fence[indices[col]][col] for col in range(n))

    def rail_fence_bruteforce(self, ciphertext: str) -> str:
        """栅栏密码暴力破解"""
        results = []
        for rails in range(2, min(len(ciphertext), 20)):
            decoded = self.rail_fence_decrypt(ciphertext, rails)
            results.append(f"{t('cry.rails')}={rails}: {decoded}")
        return "\n".join(results)

    def atbash(self, text: str) -> str:
        """Atbash 密码（字母表反转）"""
        result = []
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                result.append(chr(base + 25 - (ord(c) - base)))
            else:
                result.append(c)
        return ''.join(result)

    def bacon_decode(self, text: str) -> str:
        """培根密码解码（A/B 或 a/b 格式）"""
        bacon_dict = {}
        for i, letter in enumerate(string.ascii_uppercase):
            binary = format(i, '05b').replace('0', 'A').replace('1', 'B')
            bacon_dict[binary] = letter

        cleaned = text.upper().replace(' ', '')
        cleaned = re.sub(r'[^AB]', '', cleaned)
        result = []
        for i in range(0, len(cleaned) - 4, 5):
            chunk = cleaned[i:i+5]
            if chunk in bacon_dict:
                result.append(bacon_dict[chunk])
        return ''.join(result)

    # ========== 现代密码 ==========

    def rsa_decrypt_direct(self, p: int, q: int, e: int, c: int) -> str:
        """RSA 直接解密（已知 p, q, e, c）"""
        n = p * q
        phi = (p - 1) * (q - 1)
        d = self._mod_inverse(e, phi)
        if d is None:
            return t("cry.cannot_calc_d")
        m = pow(c, d, n)
        try:
            text = self._int_to_text(m)
        except Exception:
            text = ""
        return (
            f"=== {t('cry.rsa_direct_decrypt')} ===\n"
            f"n = {n}\np = {p}\nq = {q}\n"
            f"phi = {phi}\nd = {d}\n"
            f"{t('cry.plaintext_int')}: {m}\n{t('cry.plaintext_text')}: {text}"
        )

    def rsa_decrypt_small_e(self, c: int, e: int, n: int) -> str:
        """RSA 小指数攻击（直接对 c 开 e 次方根）"""
        # 尝试直接开 e 次方根
        m = self._iroot(e, c)
        if m is not None and pow(m, e) == c:
            try:
                return f"{t('cry.plaintext_int')}: {m}\n{t('cry.plaintext_text')}: {self._int_to_text(m)}"
            except Exception:
                return f"{t('cry.plaintext_int')}: {m}"
        return t("cry.small_e_fail")

    def rsa_common_modulus(self, c1: int, c2: int, e1: int, e2: int, n: int) -> str:
        """RSA 共模攻击"""
        g, s1, s2 = self._extended_gcd(e1, e2)
        if g != 1:
            return t("cry.common_modulus_fail")
        # 处理负指数：需要先求模逆元
        n1 = c1 if s1 >= 0 else pow(c1, -1, n)
        n2 = c2 if s2 >= 0 else pow(c2, -1, n)
        m = (pow(n1, abs(s1), n) * pow(n2, abs(s2), n)) % n
        try:
            return f"{t('cry.plaintext_int')}: {m}\n{t('cry.plaintext_text')}: {self._int_to_text(m)}"
        except Exception:
            return f"{t('cry.plaintext_int')}: {m}"

    def rsa_wiener(self, e: int, n: int, c: int = 0) -> str:
        """RSA Wiener 攻击（d 较小时），可选自动解密"""
        convergents = self._continued_fraction_convergents(e, n)
        for k, d in convergents:
            if k == 0:
                continue
            if (e * d - 1) % k != 0:
                continue
            phi = (e * d - 1) // k
            b = n - phi + 1
            discriminant = b * b - 4 * n
            if discriminant >= 0:
                sqrt_d = self._isqrt(discriminant)
                if sqrt_d * sqrt_d == discriminant:
                    result = f"{t('cry.wiener_success')}\n{t('cry.private_key')} d = {d}"
                    if c:
                        m = pow(c, d, n)
                        try:
                            text = self._int_to_text(m)
                        except Exception:
                            text = ""
                        result += f"\n{t('cry.plaintext_int')}: {m}\n{t('cry.plaintext_text')}: {text}"
                    return result
        return t("cry.wiener_fail")

    # ========== 哈希 ==========

    def identify_hash(self, hash_str: str) -> str:
        """识别哈希类型"""
        h = hash_str.strip().lower()
        results = []
        if re.match(r'^[a-f0-9]{8}$', h):
            results.append(f"CRC32 (8 {t('cry.hex_chars')})")
        if re.match(r'^[a-f0-9]{32}$', h):
            results.append(f"MD5 / NTLM / MD4 (32 {t('cry.hex_chars')})")
        if re.match(r'^[a-f0-9]{40}$', h):
            results.append(f"SHA-1 / RIPEMD-160 (40 {t('cry.hex_chars')})")
        if re.match(r'^[a-f0-9]{64}$', h):
            results.append(f"SHA-256 (64 {t('cry.hex_chars')})")
        if re.match(r'^[a-f0-9]{128}$', h):
            results.append(f"SHA-512 (128 {t('cry.hex_chars')})")
        if re.match(r'^[a-f0-9]{56}$', h):
            results.append(f"SHA-224 (56 {t('cry.hex_chars')})")
        if re.match(r'^[a-f0-9]{96}$', h):
            results.append(f"SHA-384 (96 {t('cry.hex_chars')})")
        if h.startswith('$2a$') or h.startswith('$2b$') or h.startswith('$2y$'):
            results.append("bcrypt")
        if h.startswith('$6$'):
            results.append("SHA-512 crypt")
        if h.startswith('$5$'):
            results.append("SHA-256 crypt")
        if h.startswith('$1$'):
            results.append("MD5 crypt")
        if not results:
            return f"{t('cry.hash_unknown')} ({t('cry.length')}: {len(h)} {t('cry.chars')})"
        results.append(f"\n=== {t('cry.crack_tips')} ===")
        results.append(f"  [1] {t('cry.crack_tip_local')}")
        results.append("  [2] hashcat: hashcat -m <mode> <hash> <wordlist>")
        results.append("  [3] john: john --format=<format> --wordlist=<wordlist> hash.txt")
        results.append(f"  [4] {t('cry.crack_tip_online')}")
        if any('MD5' in r for r in results):
            results.append(f"  hashcat {t('cry.crack_tip_mode')}")
        return f"{t('cry.possible_hash_types')}:\n" + "\n".join(f"  - {r}" for r in results)

    def hash_crack_dict(self, hash_str: str, wordlist: Optional[list[str]] = None) -> str:
        """使用字典尝试碰撞哈希"""
        if wordlist is None:
            wordlist = self._default_wordlist()

        h = hash_str.strip().lower()
        hash_funcs = {
            32: [("MD5", hashlib.md5)],
            40: [("SHA-1", hashlib.sha1)],
            64: [("SHA-256", hashlib.sha256)],
            128: [("SHA-512", hashlib.sha512)],
        }
        funcs = hash_funcs.get(len(h), [])
        if not funcs:
            return t("cry.unsupported_hash_len")

        for word in wordlist:
            for name, func in funcs:
                if func(word.encode()).hexdigest() == h:
                    return f"{t('cry.crack_success')}\n{t('cry.hash_type')}: {name}\n{t('cry.original')}: {word}"
        return f"{t('cry.crack_fail')} ({t('cry.tried')} {len(wordlist)} {t('cry.words')})"

    def compute_hash(self, text: str) -> str:
        """计算文本的各种哈希值"""
        import zlib
        data = text.encode()
        lines = [
            f"MD5:      {hashlib.md5(data).hexdigest()}",
            f"SHA1:     {hashlib.sha1(data).hexdigest()}",
            f"SHA256:   {hashlib.sha256(data).hexdigest()}",
            f"SHA512:   {hashlib.sha512(data).hexdigest()}",
            f"CRC32:    {zlib.crc32(data) & 0xFFFFFFFF:08x}",
        ]
        try:
            lines.append(f"SHA3-256: {hashlib.sha3_256(data).hexdigest()}")
            lines.append(f"BLAKE2b:  {hashlib.blake2b(data).hexdigest()}")
        except AttributeError:
            pass  # Python < 3.6
        return "\n".join(lines)

    def hash_length_extension(self, known_hash: str, known_data: str,
                               append_data: str, key_length: int = 0) -> str:
        """哈希长度扩展攻击辅助（MD5/SHA1）

        当服务端使用 H(secret + data) 验证时，攻击者可以在不知道 secret 的情况下
        构造 H(secret + data + padding + append_data)。
        """
        import struct

        h = known_hash.strip().lower()
        lines = [f"=== {t('cry.hash_length_ext')} ==="]
        lines.append(f"{t('cry.known_hash')}: {h}")
        lines.append(f"{t('cry.known_data')}: {known_data}")
        lines.append(f"{t('cry.append_data')}: {append_data}")

        if len(h) == 32:
            hash_type = "MD5"
            block_size = 64
        elif len(h) == 40:
            hash_type = "SHA-1"
            block_size = 64
        else:
            return t("cry.only_md5_sha1")

        lines.append(f"{t('cry.hash_type')}: {hash_type}")

        if key_length > 0:
            key_lengths = [key_length]
        else:
            key_lengths = list(range(1, 33))
            lines.append(f"{t('cry.key_len_unknown')}")

        for kl in key_lengths:
            orig_len = kl + len(known_data)
            # 构造 padding (MD5/SHA-1 padding)
            padding = b'\x80'
            padding += b'\x00' * ((block_size - 1 - 8 - (orig_len % block_size)) % block_size)
            if hash_type == "MD5":
                padding += struct.pack('<Q', orig_len * 8)  # 小端
            else:
                padding += struct.pack('>Q', orig_len * 8)  # 大端

            new_data = known_data.encode() + padding + append_data.encode()

            if len(key_lengths) == 1:
                lines.append(f"\n{t('cry.key_length')}: {kl}")
                lines.append(f"Padding (hex): {padding.hex()}")
                lines.append(f"{t('cry.new_message')} (hex): {new_data.hex()}")
                lines.append(f"\n{t('cry.tip_hashpumpy')}")
                lines.append("  pip install hashpumpy")
                lines.append(f"  hashpumpy.hashpump('{h}', '{known_data}', '{append_data}', {kl})")

        if len(key_lengths) > 1:
            lines.append(f"\n{t('cry.need_try_each_keylen')}")
            lines.append(f"{t('cry.recommend_hashpumpy')}:")
            lines.append("  pip install hashpumpy")
            lines.append("  for kl in range(1, 33):")
            lines.append(f"    new_hash, msg = hashpumpy.hashpump('{h}', '{known_data}', '{append_data}', kl)")

        return "\n".join(lines)

    # ========== 频率分析 ==========

    def frequency_analysis(self, text: str) -> str:
        """字母频率分析"""
        letters = [c.lower() for c in text if c.isalpha()]
        if not letters:
            return t("cry.no_letters")
        total = len(letters)
        freq = Counter(letters)
        # 英语字母频率参考
        english_freq = "etaoinshrdlcumwfgypbvkjxqz"

        lines = [f"{t('cry.letter_freq_stats')}:"]
        lines.append(f"{t('cry.letter'):>4} {t('cry.count'):>6} {t('cry.freq'):>8} {t('cry.bar_chart')}")
        lines.append("-" * 50)
        for letter, count in freq.most_common():
            pct = count / total * 100
            bar = '█' * int(pct / 2)
            lines.append(f"   {letter}  {count:>5}  {pct:>6.2f}%  {bar}")

        lines.append(f"\n{t('cry.sorted_by_freq')}: {''.join(c for c, _ in freq.most_common())}")
        lines.append(f"{t('cry.english_ref_freq')}: {english_freq}")
        return "\n".join(lines)

    # ========== 内部工具方法 ==========

    def _is_readable(self, text: str) -> bool:
        """判断文本是否可读"""
        if not text:
            return False
        printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        return printable / len(text) > 0.7

    def _int_to_text(self, n: int) -> str:
        """整数转文本"""
        hex_str = hex(n)[2:]
        if len(hex_str) % 2:
            hex_str = '0' + hex_str
        return binascii.unhexlify(hex_str).decode('utf-8', errors='replace')

    def _iroot(self, k: int, n: int) -> Optional[int]:
        """整数 k 次方根（牛顿法，支持大整数）"""
        if n < 0:
            return None
        if n == 0:
            return 0
        if k == 1:
            return n
        # 牛顿法迭代：x_{n+1} = ((k-1)*x_n + n // x_n^(k-1)) // k
        # 初始猜测：使用位长估算
        bit_len = n.bit_length()
        x = 1 << ((bit_len + k - 1) // k)
        while True:
            xk1 = x ** (k - 1)
            x_new = ((k - 1) * x + n // xk1) // k
            if x_new >= x:
                break
            x = x_new
        # 检查 x 和 x+1
        if x ** k == n:
            return x
        if (x + 1) ** k == n:
            return x + 1
        return None

    def _isqrt(self, n: int) -> int:
        """整数平方根"""
        if n < 0:
            raise ValueError("负数没有平方根")
        if n == 0:
            return 0
        x = n
        y = (x + 1) // 2
        while y < x:
            x = y
            y = (x + n // x) // 2
        return x

    def _extended_gcd(self, a: int, b: int) -> tuple:
        """扩展欧几里得算法（迭代实现，避免大数递归栈溢出）"""
        old_r, r = a, b
        old_s, s = 1, 0
        old_t, t = 0, 1
        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t
        return old_r, old_s, old_t

    def _continued_fraction_convergents(self, e: int, n: int):
        """连分数展开的收敛子"""
        convergents = []
        a, b = e, n
        cf = []
        while b:
            q = a // b
            cf.append(q)
            a, b = b, a - q * b

        p_prev, p_curr = 0, 1
        q_prev, q_curr = 1, 0
        for a_i in cf:
            p_prev, p_curr = p_curr, a_i * p_curr + p_prev
            q_prev, q_curr = q_curr, a_i * q_curr + q_prev
            convergents.append((p_curr, q_curr))
        return convergents

    def _default_wordlist(self) -> list[str]:
        """内置的常见弱口令字典"""
        base = [
            "admin", "password", "123456", "12345678", "qwerty", "abc123",
            "monkey", "master", "dragon", "111111", "baseball", "iloveyou",
            "trustno1", "sunshine", "princess", "football", "shadow", "superman",
            "michael", "ninja", "mustang", "jessica", "letmein", "access",
            "root", "toor", "test", "guest", "info", "secret", "pass",
            "love", "god", "hello", "welcome", "default", "server",
            "flag", "ctf", "hacker", "security", "p@ssw0rd", "admin123",
        ]
        extras = [str(i) for i in range(1000)]
        extras += [f"flag{{{i}}}" for i in range(100)]
        return base + extras

    def _mod_inverse(self, a: int, m: int) -> Optional[int]:
        """求模逆元"""
        g, x, _ = self._extended_gcd(a % m, m)
        if g != 1:
            return None
        return x % m

    # ========== Base58 / Base85 ==========

    def base58_decode(self, text: str) -> str:
        """Base58 解码（Bitcoin 风格）"""
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        text = text.strip()
        n = 0
        for c in text:
            idx = alphabet.index(c)
            n = n * 58 + idx
        result = []
        while n > 0:
            result.append(n & 0xFF)
            n >>= 8
        # 处理前导零
        pad = 0
        for c in text:
            if c == '1':
                pad += 1
            else:
                break
        return bytes(pad * [0] + result[::-1]).decode('utf-8', errors='replace')

    def base85_decode(self, text: str) -> str:
        """Base85 (Ascii85) 解码"""
        return base64.b85decode(text.strip()).decode('utf-8', errors='replace')

    # ========== 仿射密码 ==========

    def affine_decrypt(self, text: str, a: int, b: int) -> str:
        """仿射密码解密: D(x) = a_inv * (x - b) mod 26"""
        a_inv = self._mod_inverse(a, 26)
        if a_inv is None:
            return f"a={a} {t('cry.not_coprime_26')}"
        result = []
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                x = ord(c) - base
                result.append(chr((a_inv * (x - b)) % 26 + base))
            else:
                result.append(c)
        return ''.join(result)

    def affine_bruteforce(self, text: str) -> str:
        """仿射密码暴力破解（遍历所有有效 a,b 组合）"""
        results = []
        valid_a = [a for a in range(1, 26) if math.gcd(a, 26) == 1]
        for a in valid_a:
            for b in range(26):
                decoded = self.affine_decrypt(text, a, b)
                # 检查是否含有常见英文词汇
                lower = decoded.lower()
                if any(w in lower for w in ['the', 'flag', 'and', 'is', 'ctf']):
                    results.append(f"a={a:2d}, b={b:2d}: {decoded}  <-- {t('cry.possible')}")
        if not results:
            results.append(t("cry.affine_no_result"))
            for a in valid_a[:3]:
                for b in range(3):
                    results.append(f"a={a:2d}, b={b:2d}: {self.affine_decrypt(text, a, b)}")
        return f"{t('cry.affine_bruteforce')}:\n" + "\n".join(results)

    # ========== XOR 加解密 ==========

    def xor_single_byte_bruteforce(self, text: str) -> str:
        """单字节 XOR 密钥暴力破解"""
        # 输入可以是 hex 或普通文本
        try:
            data = binascii.unhexlify(text.strip().replace(' ', ''))
        except Exception:
            data = text.encode()

        results = []
        for key in range(256):
            decoded = bytes(b ^ key for b in data)
            try:
                text_result = decoded.decode('utf-8', errors='strict')
                printable_ratio = sum(1 for c in text_result if c.isprintable()) / len(text_result)
                if printable_ratio > 0.8:
                    results.append((printable_ratio, key, text_result))
            except Exception:
                pass

        results.sort(key=lambda x: -x[0])
        lines = [f"{t('cry.xor_single_brute')}:"]
        for ratio, key, text_result in results[:20]:
            lines.append(f"  Key=0x{key:02X} ({key:3d}): {text_result[:80]}")
        if not results:
            lines.append(f"  {t('cry.no_readable_result')}")
        return "\n".join(lines)

    def xor_decrypt(self, text: str, key: str) -> str:
        """多字节 XOR 解密"""
        try:
            data = binascii.unhexlify(text.strip().replace(' ', ''))
        except Exception:
            data = text.encode()
        try:
            key_bytes = binascii.unhexlify(key.replace(' ', ''))
        except Exception:
            key_bytes = key.encode()

        result = bytes(d ^ key_bytes[i % len(key_bytes)] for i, d in enumerate(data))
        return f"{t('cry.xor_decrypt_result')}:\n  Hex: {result.hex()}\n  Text: {result.decode('utf-8', errors='replace')}"

    # ========== RC4 ==========

    def rc4(self, text: str, key: str) -> str:
        """RC4 加解密（对称，加密和解密相同）"""
        try:
            data = binascii.unhexlify(text.strip().replace(' ', ''))
        except Exception:
            data = text.encode()
        key_bytes = key.encode()

        # KSA
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
            S[i], S[j] = S[j], S[i]
        # PRGA
        i = j = 0
        result = bytearray()
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            result.append(byte ^ S[(S[i] + S[j]) % 256])

        return (
            f"=== RC4 ===\n"
            f"{t('cry.key')}: {key}\n"
            f"Hex {t('cry.result')}: {result.hex()}\n"
            f"{t('cry.text_result')}: {bytes(result).decode('utf-8', errors='replace')}"
        )

    # ========== AES / DES 对称加密 ==========

    def aes_ecb_decrypt(self, ciphertext: str, key: str, iv: str = "") -> str:
        """AES-ECB 解密"""
        try:
            from Crypto.Cipher import AES
        except ImportError:
            return t("cry.need_pycryptodome")
        ct = self._parse_cipher_input(ciphertext)
        k = self._parse_key(key, [16, 24, 32])
        cipher = AES.new(k, AES.MODE_ECB)
        pt = cipher.decrypt(ct)
        pt_unpadded = self._pkcs7_unpad(pt)
        return (
            f"=== AES-ECB {t('cry.decrypt')} ===\n"
            f"{t('cry.key')}: {k.hex()}\n"
            f"{t('cry.raw_plaintext')} (hex): {pt.hex()}\n"
            f"{t('cry.unpadded')}: {pt_unpadded.hex()}\n"
            f"{t('cry.text')}: {pt_unpadded.decode('utf-8', errors='replace')}"
        )

    def aes_cbc_decrypt(self, ciphertext: str, key: str, iv: str = "") -> str:
        """AES-CBC 解密"""
        try:
            from Crypto.Cipher import AES
        except ImportError:
            return t("cry.need_pycryptodome")
        ct = self._parse_cipher_input(ciphertext)
        k = self._parse_key(key, [16, 24, 32])
        iv_bytes = binascii.unhexlify(iv) if iv else b'\x00' * 16
        cipher = AES.new(k, AES.MODE_CBC, iv=iv_bytes)
        pt = cipher.decrypt(ct)
        pt_unpadded = self._pkcs7_unpad(pt)
        return (
            f"=== AES-CBC {t('cry.decrypt')} ===\n"
            f"{t('cry.key')}: {k.hex()}\n"
            f"IV: {iv_bytes.hex()}\n"
            f"{t('cry.raw_plaintext')} (hex): {pt.hex()}\n"
            f"{t('cry.unpadded')}: {pt_unpadded.hex()}\n"
            f"{t('cry.text')}: {pt_unpadded.decode('utf-8', errors='replace')}"
        )

    def des_ecb_decrypt(self, ciphertext: str, key: str, iv: str = "") -> str:
        """DES-ECB 解密"""
        try:
            from Crypto.Cipher import DES
        except ImportError:
            return t("cry.need_pycryptodome")
        ct = self._parse_cipher_input(ciphertext)
        k = self._parse_key(key, [8])
        cipher = DES.new(k, DES.MODE_ECB)
        pt = cipher.decrypt(ct)
        pt_unpadded = self._pkcs7_unpad(pt)
        return (
            f"=== DES-ECB {t('cry.decrypt')} ===\n"
            f"{t('cry.key')}: {k.hex()}\n"
            f"{t('cry.text')}: {pt_unpadded.decode('utf-8', errors='replace')}"
        )

    def aes_ecb_encrypt(self, plaintext: str, key: str, iv: str = "") -> str:
        """AES-ECB 加密"""
        try:
            from Crypto.Cipher import AES
        except ImportError:
            return t("cry.need_pycryptodome")
        pt = plaintext.encode('utf-8')
        k = self._parse_key(key, [16, 24, 32])
        # PKCS7 填充
        pad_len = 16 - len(pt) % 16
        pt_padded = pt + bytes([pad_len]) * pad_len
        cipher = AES.new(k, AES.MODE_ECB)
        ct = cipher.encrypt(pt_padded)
        return (
            f"=== AES-ECB {t('cry.encrypt')} ===\n"
            f"{t('cry.key')}: {k.hex()}\n"
            f"{t('cry.ciphertext')} (hex): {ct.hex()}\n"
            f"{t('cry.ciphertext')} (base64): {base64.b64encode(ct).decode()}"
        )

    def aes_cbc_encrypt(self, plaintext: str, key: str, iv: str = "") -> str:
        """AES-CBC 加密"""
        try:
            from Crypto.Cipher import AES
        except ImportError:
            return t("cry.need_pycryptodome")
        pt = plaintext.encode('utf-8')
        k = self._parse_key(key, [16, 24, 32])
        iv_bytes = binascii.unhexlify(iv) if iv else b'\x00' * 16
        # PKCS7 填充
        pad_len = 16 - len(pt) % 16
        pt_padded = pt + bytes([pad_len]) * pad_len
        cipher = AES.new(k, AES.MODE_CBC, iv=iv_bytes)
        ct = cipher.encrypt(pt_padded)
        return (
            f"=== AES-CBC {t('cry.encrypt')} ===\n"
            f"{t('cry.key')}: {k.hex()}\n"
            f"IV: {iv_bytes.hex()}\n"
            f"{t('cry.ciphertext')} (hex): {ct.hex()}\n"
            f"{t('cry.ciphertext')} (base64): {base64.b64encode(ct).decode()}"
        )

    def des_ecb_encrypt(self, plaintext: str, key: str, iv: str = "") -> str:
        """DES-ECB 加密"""
        try:
            from Crypto.Cipher import DES
        except ImportError:
            return t("cry.need_pycryptodome")
        pt = plaintext.encode('utf-8')
        k = self._parse_key(key, [8])
        # PKCS7 填充
        pad_len = 8 - len(pt) % 8
        pt_padded = pt + bytes([pad_len]) * pad_len
        cipher = DES.new(k, DES.MODE_ECB)
        ct = cipher.encrypt(pt_padded)
        return (
            f"=== DES-ECB {t('cry.encrypt')} ===\n"
            f"{t('cry.key')}: {k.hex()}\n"
            f"{t('cry.ciphertext')} (hex): {ct.hex()}\n"
            f"{t('cry.ciphertext')} (base64): {base64.b64encode(ct).decode()}"
        )

    def _parse_cipher_input(self, text: str) -> bytes:
        """解析密文输入（支持 hex 和 base64）"""
        text = text.strip()
        try:
            return binascii.unhexlify(text.replace(' ', ''))
        except Exception:
            pass
        try:
            return base64.b64decode(text)
        except Exception:
            pass
        return text.encode()

    def _parse_key(self, key: str, valid_lengths: list[int]) -> bytes:
        """解析密钥（支持 hex 和文本）"""
        key = key.strip()
        try:
            k = binascii.unhexlify(key.replace(' ', ''))
            if len(k) in valid_lengths:
                return k
        except Exception:
            pass
        k = key.encode()
        target = min(valid_lengths, key=lambda l: abs(l - len(k)))
        if len(k) < target:
            k = k.ljust(target, b'\x00')
        elif len(k) > target:
            k = k[:target]
        return k

    def _pkcs7_unpad(self, data: bytes) -> bytes:
        """PKCS7 去除填充"""
        if not data:
            return data
        pad_len = data[-1]
        if 0 < pad_len <= 16 and all(b == pad_len for b in data[-pad_len:]):
            return data[:-pad_len]
        return data

    # ========== RSA 高级攻击 ==========

    def rsa_fermat(self, n: int, e: int, c: int) -> str:
        """RSA Fermat 分解（p, q 接近时有效）"""
        a = self._isqrt(n) + 1
        for _ in range(1000000):
            b2 = a * a - n
            b = self._isqrt(b2)
            if b * b == b2:
                p = a + b
                q = a - b
                if p * q == n and p > 1 and q > 1:
                    phi = (p - 1) * (q - 1)
                    d = self._mod_inverse(e, phi)
                    if d is None:
                        return f"{t('cry.factor_success')}: p={p}, q={q}\n{t('cry.but_cannot_calc_d')}"
                    m = pow(c, d, n)
                    try:
                        text = self._int_to_text(m)
                    except Exception:
                        text = ""
                    return (
                        f"{t('cry.fermat_success')}\n"
                        f"p = {p}\nq = {q}\n"
                        f"d = {d}\n"
                        f"{t('cry.plaintext_int')}: {m}\n"
                        f"{t('cry.plaintext_text')}: {text}"
                    )
            a += 1
        return t("cry.fermat_fail")

    def rsa_dp_leak(self, n: int, e: int, c: int, dp: int) -> str:
        """RSA dp 泄露攻击"""
        for k in range(1, e):
            p_candidate = (dp * e - 1) // k + 1
            if n % p_candidate == 0:
                p = p_candidate
                q = n // p
                phi = (p - 1) * (q - 1)
                d = self._mod_inverse(e, phi)
                if d is None:
                    continue
                m = pow(c, d, n)
                try:
                    text = self._int_to_text(m)
                except Exception:
                    text = ""
                return (
                    f"{t('cry.dp_leak_success')}\n"
                    f"p = {p}\nq = {q}\nd = {d}\n"
                    f"{t('cry.plaintext_int')}: {m}\n{t('cry.plaintext_text')}: {text}"
                )
        return t("cry.dp_leak_fail")

    def rsa_hastad(self, e: int, c: int, n: int, extra: str) -> str:
        """RSA Hastad 广播攻击（同一明文用不同 n 加密, e 较小）"""
        pairs = [(n, c)]
        if extra:
            parts = extra.split(',')
            for i in range(0, len(parts) - 1, 2):
                pairs.append((int(parts[i].strip()), int(parts[i+1].strip())))
        if len(pairs) < e:
            return f"{t('cry.hastad_need')} {e} {t('cry.pairs')}, {t('cry.current_only')} {len(pairs)} {t('cry.pairs')}"
        # 中国剩余定理
        N_total = 1
        for ni, _ in pairs[:e]:
            N_total *= ni
        result = 0
        for ni, ci in pairs[:e]:
            Ni = N_total // ni
            yi = self._mod_inverse(Ni, ni)
            if yi is None:
                return t("cry.crt_fail")
            result = (result + ci * Ni * yi) % N_total
        # 开 e 次方根
        m = self._iroot(e, result)
        if m is not None and pow(m, e) == result:
            try:
                text = self._int_to_text(m)
            except Exception:
                text = ""
            return f"{t('cry.hastad_success')}\n{t('cry.plaintext_int')}: {m}\n{t('cry.plaintext_text')}: {text}"
        return t("cry.hastad_fail")

    def rsa_factordb(self, n: int, e: int = 0, c: int = 0) -> str:
        """通过 factordb.com 在线查询 n 的分解"""
        try:
            import requests
        except ImportError:
            return t("cry.need_requests")

        url = f"https://factordb.com/api?query={n}"
        try:
            resp = requests.get(url, timeout=15)
            data = resp.json()
        except Exception as ex:
            return f"{t('cry.factordb_fail')}: {ex}"

        status = data.get("status", "")
        status_map = {
            "C": t("cry.composite_partial"),
            "CF": t("cry.composite_full"),
            "FF": t("cry.fully_factored"),
            "P": t("cry.prime"),
            "Prp": t("cry.probable_prime"),
            "U": t("cry.unknown"),
            "Unit": t("cry.unit"),
        }
        lines = [
            f"=== factordb {t('cry.query_result')} ===",
            f"n = {str(n)[:80]}{'...' if len(str(n)) > 80 else ''}",
            f"{t('cry.status')}: {status_map.get(status, status)}",
        ]

        factors = data.get("factors", [])
        if factors:
            lines.append(f"{t('cry.factors')}:")
            factor_values = []
            for factor_str, count in factors:
                f_val = int(factor_str)
                factor_values.append((f_val, int(count)))
                lines.append(f"  {factor_str} (x{count})")

            # 如果分解出恰好两个素因子且给了 e 和 c，自动解密
            primes = [f for f, cnt in factor_values if cnt == 1]
            if len(primes) == 2 and e > 0 and c > 0:
                p, q = primes
                if p * q == n:
                    phi = (p - 1) * (q - 1)
                    d = self._mod_inverse(e, phi)
                    if d:
                        m = pow(c, d, n)
                        try:
                            text = self._int_to_text(m)
                        except Exception:
                            text = ""
                        lines.append(f"\n{t('cry.auto_decrypt')}:")
                        lines.append(f"  p = {p}")
                        lines.append(f"  q = {q}")
                        lines.append(f"  d = {d}")
                        lines.append(f"  {t('cry.plaintext_int')}: {m}")
                        lines.append(f"  {t('cry.plaintext_text')}: {text}")
        else:
            lines.append(t("cry.no_factors"))

        return "\n".join(lines)

    def rsa_pollard_p1(self, n: int, e: int = 0, c: int = 0,
                        B: int = 100000) -> str:
        """RSA Pollard p-1 分解（p-1 光滑时有效）"""
        a = 2
        for j in range(2, B + 1):
            a = pow(a, j, n)
            # 每步检查 GCD（小 B 时开销不大，大 B 时可批量）
            g = math.gcd(a - 1, n)
            if 1 < g < n:
                p = g
                q = n // p
                return self._rsa_format_result("Pollard p-1", p, q, n, e, c)

        # 最终检查
        g = math.gcd(a - 1, n)
        if 1 < g < n:
            p = g
            q = n // p
            return self._rsa_format_result("Pollard p-1", p, q, n, e, c)
        return f"{t('cry.pollard_p1_fail')} (B={B})"

    def rsa_pollard_rho(self, n: int, e: int = 0, c: int = 0) -> str:
        """RSA Pollard rho 分解（通用大数分解）"""
        import math
        import random

        def pollard_rho(n):
            if n % 2 == 0:
                return 2
            x = random.randint(2, n - 1)
            y = x
            c = random.randint(1, n - 1)
            d = 1
            while d == 1:
                x = (x * x + c) % n
                y = (y * y + c) % n
                y = (y * y + c) % n
                d = math.gcd(abs(x - y), n)
            return d if d != n else None

        for _ in range(50):  # 多次尝试不同随机起点
            p = pollard_rho(n)
            if p and p != n:
                q = n // p
                return self._rsa_format_result("Pollard rho", p, q, n, e, c)
        return t("cry.pollard_rho_fail")

    def _rsa_format_result(self, method: str, p: int, q: int,
                            n: int, e: int, c: int) -> str:
        """格式化 RSA 分解+解密结果"""
        lines = [f"{method} {t('cry.factor_success')}!", f"p = {p}", f"q = {q}"]
        if e > 0 and c > 0:
            phi = (p - 1) * (q - 1)
            d = self._mod_inverse(e, phi)
            if d:
                m = pow(c, d, n)
                try:
                    text = self._int_to_text(m)
                except Exception:
                    text = ""
                lines.extend([f"d = {d}", f"{t('cry.plaintext_int')}: {m}", f"{t('cry.plaintext_text')}: {text}"])
        return "\n".join(lines)

    # ========== Playfair 密码 ==========

    def playfair_decrypt(self, ciphertext: str, key: str) -> str:
        """Playfair 密码解密"""
        matrix = self._playfair_matrix(key)
        pos = {}
        for i, c in enumerate(matrix):
            pos[c] = (i // 5, i % 5)

        # 预处理密文
        text = ''.join(c.upper() for c in ciphertext if c.isalpha()).replace('J', 'I')
        if len(text) % 2:
            text += 'X'

        result = []
        for i in range(0, len(text), 2):
            a, b = text[i], text[i+1]
            ra, ca = pos.get(a, (0,0))
            rb, cb = pos.get(b, (0,0))
            if ra == rb:  # 同行
                result.append(matrix[ra * 5 + (ca - 1) % 5])
                result.append(matrix[rb * 5 + (cb - 1) % 5])
            elif ca == cb:  # 同列
                result.append(matrix[((ra - 1) % 5) * 5 + ca])
                result.append(matrix[((rb - 1) % 5) * 5 + cb])
            else:  # 矩形
                result.append(matrix[ra * 5 + cb])
                result.append(matrix[rb * 5 + ca])
        return f"Playfair {t('cry.decrypt_result')}: {''.join(result)}"

    def playfair_encrypt(self, plaintext: str, key: str) -> str:
        """Playfair 密码加密"""
        matrix = self._playfair_matrix(key)
        pos = {}
        for i, c in enumerate(matrix):
            pos[c] = (i // 5, i % 5)

        text = ''.join(c.upper() for c in plaintext if c.isalpha()).replace('J', 'I')
        # 处理相同字母对
        processed = []
        i = 0
        while i < len(text):
            processed.append(text[i])
            if i + 1 < len(text) and text[i] == text[i+1]:
                processed.append('X')
                i += 1
            elif i + 1 < len(text):
                processed.append(text[i+1])
                i += 2
            else:
                processed.append('X')
                i += 1

        result = []
        for i in range(0, len(processed), 2):
            a, b = processed[i], processed[i+1]
            ra, ca = pos.get(a, (0,0))
            rb, cb = pos.get(b, (0,0))
            if ra == rb:
                result.append(matrix[ra * 5 + (ca + 1) % 5])
                result.append(matrix[rb * 5 + (cb + 1) % 5])
            elif ca == cb:
                result.append(matrix[((ra + 1) % 5) * 5 + ca])
                result.append(matrix[((rb + 1) % 5) * 5 + cb])
            else:
                result.append(matrix[ra * 5 + cb])
                result.append(matrix[rb * 5 + ca])
        return f"Playfair {t('cry.encrypt_result')}: {''.join(result)}"

    def _playfair_matrix(self, key: str) -> list:
        """生成 Playfair 5x5 矩阵"""
        key = key.upper().replace('J', 'I')
        seen = set()
        matrix = []
        for c in key + 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
            if c.isalpha() and c not in seen:
                seen.add(c)
                matrix.append(c)
        return matrix

    # ========== Polybius 方阵 ==========

    def polybius_encrypt(self, text: str, key: str = "ABCDE") -> str:
        """Polybius 方阵加密"""
        alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'  # I/J合并
        key = key.upper()[:5]
        text = text.upper().replace('J', 'I')
        result = []
        for c in text:
            if c in alphabet:
                idx = alphabet.index(c)
                result.append(f"{key[idx // 5]}{key[idx % 5]}")
            else:
                result.append(c)
        lines = [f"Polybius {t('cry.encrypt')} ({t('cry.row_col_labels')}: {key}):", ''.join(result)]
        # 也输出数字版本
        num_result = []
        for c in text:
            if c in alphabet:
                idx = alphabet.index(c)
                num_result.append(f"{idx // 5 + 1}{idx % 5 + 1}")
            else:
                num_result.append(c)
        lines.append(f"{t('cry.numeric_ver')}: {''.join(num_result)}")
        return '\n'.join(lines)

    def polybius_decrypt(self, text: str, key: str = "ABCDE") -> str:
        """Polybius 方阵解密"""
        alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
        key = key.upper()[:5]
        # 尝试字母对解密
        result_alpha = []
        i = 0
        text_clean = text.upper().strip()
        while i < len(text_clean):
            if i + 1 < len(text_clean) and text_clean[i] in key and text_clean[i+1] in key:
                row = key.index(text_clean[i])
                col = key.index(text_clean[i+1])
                idx = row * 5 + col
                if idx < 25:
                    result_alpha.append(alphabet[idx])
                i += 2
            else:
                result_alpha.append(text_clean[i])
                i += 1

        # 尝试数字对解密
        result_num = []
        digits = ''.join(c for c in text if c.isdigit())
        for j in range(0, len(digits) - 1, 2):
            row = int(digits[j]) - 1
            col = int(digits[j+1]) - 1
            idx = row * 5 + col
            if 0 <= idx < 25:
                result_num.append(alphabet[idx])

        lines = [f"Polybius {t('cry.decrypt')}:"]
        if result_alpha:
            lines.append(f"  {t('cry.alpha_pair_decrypt')}: {''.join(result_alpha)}")
        if result_num:
            lines.append(f"  {t('cry.num_pair_decrypt')}: {''.join(result_num)}")
        return '\n'.join(lines)

    # ========== XOR 多字节自动破解 ==========

    def xor_auto_crack(self, hex_data: str) -> str:
        """XOR 多字节密钥自动破解（汉明距离 + 频率分析）"""
        # 解析输入
        cleaned = hex_data.replace(' ', '').replace('\\x', '').replace('0x', '')
        try:
            data = bytes.fromhex(cleaned)
        except ValueError:
            data = hex_data.encode()

        if len(data) < 20:
            return t("cry.data_too_short")

        def hamming_distance(a: bytes, b: bytes) -> int:
            return sum(bin(x ^ y).count('1') for x, y in zip(a, b))

        # 1. 推测密钥长度（汉明距离法）
        scores = []
        for keylen in range(2, min(41, len(data) // 4 + 1)):
            chunks = [data[i:i+keylen] for i in range(0, len(data) - keylen, keylen)][:6]
            if len(chunks) < 2:
                continue
            total = 0
            count = 0
            for i in range(len(chunks) - 1):
                total += hamming_distance(chunks[i], chunks[i+1])
                count += 1
            normalized = total / count / keylen
            scores.append((keylen, normalized))

        scores.sort(key=lambda x: x[1])

        lines = [f"=== {t('cry.xor_auto_analysis')} ===", "", f"{t('cry.key_len_guess')}:"]
        for keylen, score in scores[:5]:
            lines.append(f"  {t('cry.length')} {keylen}: {score:.3f}")

        # 2. 对最可能的密钥长度尝试单字节爆破
        if scores:
            best_keylen = scores[0][0]
            key = bytearray()
            for i in range(best_keylen):
                block = bytes(data[j] for j in range(i, len(data), best_keylen))
                best_byte = 0
                best_score = -1
                for b in range(256):
                    decrypted = bytes(c ^ b for c in block)
                    score = sum(1 for c in decrypted if 32 <= c < 127)
                    if score > best_score:
                        best_score = score
                        best_byte = b
                key.append(best_byte)

            decrypted = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
            key_hex = key.hex()
            key_text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in key)

            lines.append(f"\n{t('cry.most_likely_key_len')}: {best_keylen}")
            lines.append(f"{t('cry.guessed_key')} (hex): {key_hex}")
            lines.append(f"{t('cry.guessed_key')} (text): {key_text}")
            lines.append(f"\n{t('cry.decrypt_result')}:")
            decoded = decrypted.decode('utf-8', errors='replace')
            lines.append(decoded[:2000])

        return '\n'.join(lines)

    # ========== Padding Oracle 攻击辅助 ==========

    def padding_oracle_helper(self) -> str:
        """Padding Oracle 攻击辅助 — 生成攻击脚本模板"""
        template = '''=== Padding Oracle 攻击辅助 ===

原理: 利用 CBC 模式解密时的 PKCS7 padding 验证错误信息，
      逐字节推断中间值 (intermediate value)，从而解密密文。

Python 攻击脚本模板:
```python
import requests

URL = "http://target.com/decrypt"
BLOCK_SIZE = 16  # AES = 16, DES = 8

def oracle(iv, ct):
    """发送请求，返回 True 表示 padding 正确"""
    payload = (iv + ct).hex()
    resp = requests.get(f"{URL}?data={payload}")
    return "padding" not in resp.text.lower()  # 根据实际响应调整

def attack_block(prev_block, target_block):
    """解密单个块"""
    intermediate = bytearray(BLOCK_SIZE)
    plaintext = bytearray(BLOCK_SIZE)

    for byte_idx in range(BLOCK_SIZE - 1, -1, -1):
        pad_val = BLOCK_SIZE - byte_idx
        prefix = bytearray(BLOCK_SIZE)
        # 设置已知的 intermediate 字节
        for k in range(byte_idx + 1, BLOCK_SIZE):
            prefix[k] = intermediate[k] ^ pad_val

        for guess in range(256):
            prefix[byte_idx] = guess
            if oracle(bytes(prefix), target_block):
                # 排除误报：改变前一字节再验证
                if byte_idx > 0:
                    prefix[byte_idx - 1] ^= 1
                    if not oracle(bytes(prefix), target_block):
                        continue
                intermediate[byte_idx] = guess ^ pad_val
                plaintext[byte_idx] = intermediate[byte_idx] ^ prev_block[byte_idx]
                break

    return bytes(plaintext)

# 使用示例
ciphertext = bytes.fromhex("YOUR_CIPHERTEXT_HEX")
iv = ciphertext[:BLOCK_SIZE]
blocks = [ciphertext[i:i+BLOCK_SIZE]
          for i in range(0, len(ciphertext), BLOCK_SIZE)]

plaintext = b""
for i in range(1, len(blocks)):
    plaintext += attack_block(blocks[i-1], blocks[i])
print(f"Decrypted: {plaintext}")
```

注意事项:
- 需根据目标响应调整 oracle() 函数的判断逻辑
- 每个字节最多需要 256 次请求，一个块需要 256 × BLOCK_SIZE 次
- 某些 WAF 可能限制请求频率，需添加延迟
- PKCS7 padding 最后一个字节范围: 0x01 - 0x10 (AES)
'''
        return template

    # ========== ROT47 ==========

    def rot47(self, text: str) -> str:
        """ROT47 编码/解码（可打印 ASCII 范围旋转）"""
        result = []
        for c in text:
            n = ord(c)
            if 33 <= n <= 126:
                result.append(chr(33 + (n - 33 + 47) % 94))
            else:
                result.append(c)
        return f"ROT47: {''.join(result)}"

    # ========== Base58 / Base85 编码 ==========

    def base58_encode(self, text: str) -> str:
        """Base58 编码 (Bitcoin 字母表)"""
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        data = text.encode('utf-8')
        n = int.from_bytes(data, 'big')
        result = []
        while n > 0:
            n, r = divmod(n, 58)
            result.append(alphabet[r])
        # 处理前导零字节
        for byte in data:
            if byte == 0:
                result.append(alphabet[0])
            else:
                break
        return f"Base58: {''.join(reversed(result))}"

    def base85_encode(self, text: str) -> str:
        """Base85 编码"""
        import base64
        encoded = base64.b85encode(text.encode('utf-8')).decode('ascii')
        return f"Base85: {encoded}"

    # ========== Hill 密码 ==========

    def hill_decrypt(self, ciphertext: str, key_matrix: str) -> str:
        """Hill 密码解密（2x2 或 3x3 矩阵）"""
        text = ''.join(c.upper() for c in ciphertext if c.isalpha())
        # 解析密钥矩阵（逗号分隔，如 "3,2,5,7" 表示 2x2 矩阵）
        nums = [int(x) for x in key_matrix.split(',')]
        n = 2 if len(nums) == 4 else 3 if len(nums) == 9 else 0
        if n == 0:
            return t("cry.hill_matrix_error")

        matrix = [nums[i*n:(i+1)*n] for i in range(n)]

        # 计算行列式和逆矩阵 (mod 26)
        if n == 2:
            det = (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % 26
        else:
            det = 0
            for c in range(3):
                det += matrix[0][c] * (matrix[1][(c+1)%3] * matrix[2][(c+2)%3] - matrix[1][(c+2)%3] * matrix[2][(c+1)%3])
            det = det % 26

        det_inv = self._mod_inverse(det, 26)
        if det_inv is None:
            return f"{t('cry.hill_det_error')} {det}"

        if n == 2:
            inv = [
                [(matrix[1][1] * det_inv) % 26, (-matrix[0][1] * det_inv) % 26],
                [(-matrix[1][0] * det_inv) % 26, (matrix[0][0] * det_inv) % 26],
            ]
        else:
            # 3x3 伴随矩阵
            adj = [[0]*3 for _ in range(3)]
            for i in range(3):
                for j in range(3):
                    minor = []
                    for r in range(3):
                        for c in range(3):
                            if r != i and c != j:
                                minor.append(matrix[r][c])
                    cofactor = minor[0]*minor[3] - minor[1]*minor[2]
                    adj[j][i] = ((-1)**(i+j) * cofactor * det_inv) % 26
            inv = adj

        # 补齐明文长度
        if len(text) % n:
            text += 'X' * (n - len(text) % n)

        result = []
        for i in range(0, len(text), n):
            block = [ord(text[i+j]) - 65 for j in range(n)]
            for row in inv:
                val = sum(row[j] * block[j] for j in range(n)) % 26
                result.append(chr(val + 65))

        return f"Hill {t('cry.decrypt')} ({n}x{n}): {''.join(result)}"

    def hill_encrypt(self, plaintext: str, key_matrix: str) -> str:
        """Hill 密码加密"""
        text = ''.join(c.upper() for c in plaintext if c.isalpha())
        nums = [int(x) for x in key_matrix.split(',')]
        n = 2 if len(nums) == 4 else 3 if len(nums) == 9 else 0
        if n == 0:
            return t("cry.hill_matrix_error")
        matrix = [nums[i*n:(i+1)*n] for i in range(n)]
        if len(text) % n:
            text += 'X' * (n - len(text) % n)
        result = []
        for i in range(0, len(text), n):
            block = [ord(text[i+j]) - 65 for j in range(n)]
            for row in matrix:
                val = sum(row[j] * block[j] for j in range(n)) % 26
                result.append(chr(val + 65))
        return f"Hill {t('cry.encrypt')} ({n}x{n}): {''.join(result)}"

    # ========== 列置换密码 ==========

    def columnar_transposition_decrypt(self, ciphertext: str, key: str) -> str:
        """列置换密码解密"""
        text = ''.join(c for c in ciphertext if c.isalpha() or c.isdigit())
        key_order = sorted(range(len(key)), key=lambda k: key[k])
        n_cols = len(key)
        n_rows = len(text) // n_cols
        extra = len(text) % n_cols

        # 计算每列的长度
        col_lens = [n_rows + (1 if key_order.index(i) < extra else 0) for i in range(n_cols)]

        # 按密钥顺序填充列
        columns = [''] * n_cols
        pos = 0
        for idx in key_order:
            columns[idx] = text[pos:pos + col_lens[idx]]
            pos += col_lens[idx]

        # 按行读出
        result = []
        for row in range(n_rows + (1 if extra else 0)):
            for col in range(n_cols):
                if row < len(columns[col]):
                    result.append(columns[col][row])

        return f"{t('cry.columnar_decrypt')} ({t('cry.key')}: {key}): {''.join(result)}"

    def columnar_transposition_encrypt(self, plaintext: str, key: str) -> str:
        """列置换密码加密"""
        text = ''.join(c for c in plaintext if c.isalpha() or c.isdigit())
        key_order = sorted(range(len(key)), key=lambda k: key[k])
        n_cols = len(key)

        # 按行填入
        grid = []
        for i in range(0, len(text), n_cols):
            grid.append(text[i:i + n_cols])

        # 按密钥顺序读列
        result = []
        for col_idx in key_order:
            for row in grid:
                if col_idx < len(row):
                    result.append(row[col_idx])

        return f"{t('cry.columnar_encrypt')} ({t('cry.key')}: {key}): {''.join(result)}"

    # ========== AES-CTR 模式 ==========

    def aes_ctr_decrypt(self, ciphertext: str, key: str, nonce: str = '') -> str:
        """AES-CTR 模式解密"""
        from Crypto.Cipher import AES
        data = self._parse_cipher_input(ciphertext)
        key_bytes = self._parse_key(key, [16, 24, 32])
        nonce_bytes = bytes.fromhex(nonce) if nonce else b'\x00' * 8
        if len(nonce_bytes) > 8:
            nonce_bytes = nonce_bytes[:8]
        cipher = AES.new(key_bytes, AES.MODE_CTR, nonce=nonce_bytes)
        plaintext = cipher.decrypt(data)
        return f"AES-CTR {t('cry.decrypt')}:\n  Hex: {plaintext.hex()}\n  Text: {plaintext.decode('utf-8', errors='replace')}"

    def aes_ctr_encrypt(self, plaintext: str, key: str, nonce: str = '') -> str:
        """AES-CTR 模式加密"""
        from Crypto.Cipher import AES
        data = plaintext.encode('utf-8')
        key_bytes = self._parse_key(key, [16, 24, 32])
        nonce_bytes = bytes.fromhex(nonce) if nonce else b'\x00' * 8
        if len(nonce_bytes) > 8:
            nonce_bytes = nonce_bytes[:8]
        cipher = AES.new(key_bytes, AES.MODE_CTR, nonce=nonce_bytes)
        ct = cipher.encrypt(data)
        return f"AES-CTR {t('cry.encrypt')}:\n  Hex: {ct.hex()}\n  Base64: {base64.b64encode(ct).decode()}"

    # ========== CRC32 ==========

    def crc32(self, text: str) -> str:
        """计算 CRC32 校验值"""
        import zlib
        if os.path.isfile(text):
            from ctftool.core.utils import read_file_bytes
            data = read_file_bytes(text)
            label = f"{t('cry.file')}: {text}"
        else:
            data = text.encode('utf-8')
            label = f"{t('cry.text')}: {text[:50]}"
        crc = zlib.crc32(data) & 0xFFFFFFFF
        return f"CRC32 ({label}):\n  {t('cry.hexadecimal')}: {crc:08X}\n  {t('cry.decimal')}: {crc}"

    # ========== HMAC ==========

    def hmac_compute(self, text: str, key: str, algorithm: str = 'sha256') -> str:
        """计算 HMAC"""
        import hashlib
        import hmac as _hmac
        algo_map = {'md5': 'md5', 'sha1': 'sha1', 'sha256': 'sha256', 'sha512': 'sha512'}
        algo = algo_map.get(algorithm.lower(), 'sha256')
        h = _hmac.new(key.encode(), text.encode(), getattr(hashlib, algo))
        return f"HMAC-{algo.upper()}:\n  {t('cry.key')}: {key}\n  {t('cry.digest')}: {h.hexdigest()}"

    # ========== RSA 多素数 ==========

    def rsa_decrypt_multi_prime(self, primes_str: str, e: int, c: int) -> str:
        """RSA 多素数解密 (n = p*q*r*...)"""
        primes = [int(p.strip()) for p in primes_str.split(',')]
        if len(primes) < 2:
            return t("cry.need_2_primes")
        n = 1
        phi = 1
        for p in primes:
            n *= p
            phi *= (p - 1)
        d = self._mod_inverse(e, phi)
        if d is None:
            return f"e={e} {t('cry.not_coprime_phi')}"
        m = pow(c, d, n)
        try:
            text = self._int_to_text(m)
        except Exception:
            text = ""
        lines = [
            f"{t('cry.rsa_multi_prime_success')}",
            f"{t('cry.primes')}: {', '.join(str(p) for p in primes)}",
            f"n = {n}",
            f"phi = {phi}",
            f"d = {d}",
            f"{t('cry.plaintext_int')}: {m}",
        ]
        if text:
            lines.append(f"{t('cry.plaintext_text')}: {text}")
        return '\n'.join(lines)

    # ========== Base91 编解码 ==========

    def base91_encode(self, text: str) -> str:
        """Base91 编码"""
        table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
        data = text.encode('utf-8')
        result = []
        n = 0
        bits = 0
        for byte in data:
            n |= byte << bits
            bits += 8
            if bits > 13:
                val = n & 8191
                if val > 88:
                    n >>= 13
                    bits -= 13
                else:
                    val = n & 16383
                    n >>= 14
                    bits -= 14
                result.append(table[val % 91])
                result.append(table[val // 91])
        if bits:
            result.append(table[n % 91])
            if bits > 7 or n > 90:
                result.append(table[n // 91])
        return f"Base91: {''.join(result)}"

    def base91_decode(self, text: str) -> str:
        """Base91 解码"""
        table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
        dtable = {c: i for i, c in enumerate(table)}
        result = bytearray()
        n = 0
        bits = 0
        v = -1
        for c in text:
            if c not in dtable:
                continue
            if v < 0:
                v = dtable[c]
            else:
                v += dtable[c] * 91
                n |= v << bits
                bits += 13 if (v & 8191) > 88 else 14
                while bits >= 8:
                    result.append(n & 255)
                    n >>= 8
                    bits -= 8
                v = -1
        if v >= 0:
            n |= v << bits
            result.append(n & 255)
        decoded = bytes(result).decode('utf-8', errors='replace')
        return f"Base91 {t('cry.decode')}: {decoded}"

    # ========== 椭圆曲线 (ECC) 基础工具 ==========

    def ecc_point_add(self, params: str) -> str:
        """椭圆曲线点加法 / 信息辅助工具

        参数格式: p,a,b,Gx,Gy,n (曲线参数) 或不传参显示帮助
        """
        if not params or params.strip() == '':
            return '''=== 椭圆曲线密码 (ECC) 辅助 ===

常见 CTF 攻击方法:

1. Smart's Attack (异常曲线, p = #E(Fp)):
   当曲线阶等于素数 p 时, 可在 p-adic 数域上将 ECDLP 转化为普通除法

2. MOV Attack (低嵌入度):
   将 ECDLP 映射到有限域上的 DLP (via Weil/Tate pairing)

3. Pohlig-Hellman (光滑阶):
   当曲线阶可分解为小素数之积时, 分别求解后 CRT 合并

4. Invalid Curve Attack:
   服务端未验证点是否在曲线上时, 可构造低阶曲线上的点

SageMath 攻击脚本:
```python
# Smart's Attack
from sage.all import *
p = ...  # 素数
a, b = ..., ...
E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy)
P = E(Px, Py)
# 如果 E.order() == p:
d = E.lift_x(P.xy()[0]).log(G)  # Smart's attack built-in

# Pohlig-Hellman
d = discrete_log(P, G, operation='+')

# MOV Attack
k = E.embedding_degree()  # 若 k 很小则可攻击
```

Python (纯计算):
```python
# 点加法
def ecc_add(P, Q, a, p):
    if P is None: return Q
    if Q is None: return P
    if P[0] == Q[0] and P[1] != Q[1]: return None
    if P == Q:
        lam = (3*P[0]*P[0] + a) * pow(2*P[1], -1, p) % p
    else:
        lam = (Q[1]-P[1]) * pow(Q[0]-P[0], -1, p) % p
    x = (lam*lam - P[0] - Q[0]) % p
    y = (lam*(P[0]-x) - P[1]) % p
    return (x, y)

# 标量乘法
def ecc_mul(k, P, a, p):
    R = None
    while k > 0:
        if k & 1: R = ecc_add(R, P, a, p)
        P = ecc_add(P, P, a, p)
        k >>= 1
    return R
```
'''

        # 如果传入了参数，尝试解析并做点运算
        parts = [int(x.strip()) for x in params.split(',')]
        if len(parts) >= 6:
            p, a, b, gx, gy = parts[0], parts[1], parts[2], parts[3], parts[4]

            def ecc_add(P, Q):
                if P is None: return Q
                if Q is None: return P
                if P[0] == Q[0] and P[1] != Q[1]: return None
                if P == Q:
                    lam = (3*P[0]*P[0] + a) * pow(2*P[1], -1, p) % p
                else:
                    lam = (Q[1]-P[1]) * pow(Q[0]-P[0], -1, p) % p
                x = (lam*lam - P[0] - Q[0]) % p
                y = (lam*(P[0]-x) - P[1]) % p
                return (x, y)

            G = (gx, gy)
            # 验证点在曲线上
            lhs = (gy * gy) % p
            rhs = (gx**3 + a*gx + b) % p
            on_curve = t("cry.yes") if lhs == rhs else t("cry.no")

            lines = [
                f"{t('cry.elliptic_curve')}: y² = x³ + {a}x + {b} (mod {p})",
                f"{t('cry.base_point')} G = ({gx}, {gy})",
                f"G {t('cry.on_curve')}: {on_curve}",
            ]

            if len(parts) >= 7:
                parts[5]
                k = parts[6] if len(parts) > 6 else 2
                # 计算 kG
                R = None
                Q = G
                kk = k
                while kk > 0:
                    if kk & 1: R = ecc_add(R, Q)
                    Q = ecc_add(Q, Q)
                    kk >>= 1
                if R:
                    lines.append(f"\n{k}G = ({R[0]}, {R[1]})")
                else:
                    lines.append(f"\n{k}G = O ({t('cry.point_at_infinity')})")

            return '\n'.join(lines)

        return t("cry.ecc_param_format")

    # ========== 离散对数 (DLP) ==========

    def dlp_bsgs(self, params: str) -> str:
        """离散对数 Baby-step Giant-step 算法

        参数格式: g,h,p (求解 g^x ≡ h (mod p))
        """
        parts = [int(x.strip()) for x in params.split(',')]
        if len(parts) < 3:
            return t("cry.dlp_param_format")

        g, h, p = parts[0], parts[1], parts[2]

        import math
        m = math.isqrt(p) + 1

        # Baby step: 计算 g^j mod p, j=0..m-1
        table = {}
        power = 1
        for j in range(m):
            table[power] = j
            power = power * g % p

        # Giant step: g^(-m) mod p
        factor = pow(g, -m, p)

        gamma = h
        for i in range(m):
            if gamma in table:
                x = i * m + table[gamma]
                lines = [
                    f"{t('cry.dlp_bsgs_success')}",
                    f"g = {g}, h = {h}, p = {p}",
                    "g^x ≡ h (mod p)",
                    f"x = {x}",
                    f"{t('cry.verify')}: {g}^{x} mod {p} = {pow(g, x, p)}",
                ]
                return '\n'.join(lines)
            gamma = gamma * factor % p

        return f"{t('cry.bsgs_fail')} (x > {m*m})"

    def dlp_pohlig_hellman(self, params: str) -> str:
        """离散对数 Pohlig-Hellman 算法（阶可分解时）

        参数格式: g,h,p,order (order 为 g 的阶)
        """
        parts = [int(x.strip()) for x in params.split(',')]
        if len(parts) < 4:
            return t("cry.pohlig_param_format")

        g, h, p, order = parts[0], parts[1], parts[2], parts[3]

        # 分解 order
        def factorize(n):
            factors = {}
            d = 2
            while d * d <= n:
                while n % d == 0:
                    factors[d] = factors.get(d, 0) + 1
                    n //= d
                d += 1
            if n > 1:
                factors[n] = factors.get(n, 0) + 1
            return factors

        factors = factorize(order)
        lines = [f"{t('cry.order_factored')}: {order} = {' × '.join(f'{p_i}^{e}' for p_i, e in sorted(factors.items()))}"]

        # 对每个素因子幂求解子问题
        import math
        remainders = []
        moduli = []

        for pi, ei in sorted(factors.items()):
            qi = pi ** ei
            gi = pow(g, order // qi, p)
            hi = pow(h, order // qi, p)

            # 用 BSGS 求解子问题
            m = math.isqrt(qi) + 1
            table = {}
            power = 1
            for j in range(m):
                table[power] = j
                power = power * gi % p

            factor_inv = pow(gi, -m, p)
            gamma = hi
            xi = None
            for i in range(m):
                if gamma in table:
                    xi = i * m + table[gamma]
                    break
                gamma = gamma * factor_inv % p

            if xi is not None:
                remainders.append(xi % qi)
                moduli.append(qi)
                lines.append(f"  x ≡ {xi % qi} (mod {qi})")
            else:
                lines.append(f"  {t('cry.subproblem_fail')} mod {qi}")
                return '\n'.join(lines)

        # CRT 合并
        x = remainders[0]
        mod = moduli[0]
        for i in range(1, len(remainders)):
            # x ≡ remainders[i] (mod moduli[i])
            g1 = math.gcd(mod, moduli[i])
            if (remainders[i] - x) % g1 != 0:
                return t("cry.crt_no_solution")
            lcm = mod * moduli[i] // g1
            x = x + mod * ((remainders[i] - x) // g1 * pow(mod // g1, -1, moduli[i] // g1) % (moduli[i] // g1))
            mod = lcm

        x = x % mod
        lines.insert(0, t("cry.pohlig_success"))
        lines.append(f"\nx = {x}")
        lines.append(f"{t('cry.verify')}: {g}^{x} mod {p} = {pow(g, x, p)}")

        return '\n'.join(lines)

    # ========== Mersenne Twister 预测 ==========

    def mt19937_predict(self, outputs: str) -> str:
        """Mersenne Twister (MT19937) 状态恢复与预测

        参数: 逗号分隔的 624 个 32 位整数输出
        """
        nums = [int(x.strip()) for x in outputs.split(',') if x.strip()]

        if len(nums) < 624:
            return f'''=== MT19937 预测 ===

需要 624 个连续输出来恢复完整状态 (当前: {len(nums)} 个)

Python 获取输出示例:
```python
import random
outputs = [random.getrandbits(32) for _ in range(624)]
```

原理: MT19937 的内部状态由 624 个 32 位整数组成。
每次输出经过 "tempering" 变换，该变换可逆。
收集 624 个输出后可逆推完整状态，从而预测后续输出。

常见 CTF 场景:
- random.randint() 生成的 token/key
- 赌博游戏的随机数预测
- 加密中使用了不安全的 PRNG
'''

        # Untemper 函数（逆向 tempering 变换）
        def untemper(y):
            # 逆 y ^= y >> 18
            y ^= y >> 18
            # 逆 y ^= (y << 15) & 0xefc60000
            y ^= (y << 15) & 0xefc60000
            # 逆 y ^= (y << 7) & 0x9d2c5680
            tmp = y
            tmp = y ^ ((tmp << 7) & 0x9d2c5680)
            tmp = y ^ ((tmp << 7) & 0x9d2c5680)
            tmp = y ^ ((tmp << 7) & 0x9d2c5680)
            y = y ^ ((tmp << 7) & 0x9d2c5680)
            # 逆 y ^= y >> 11
            tmp = y ^ (y >> 11)
            y = y ^ (tmp >> 11)
            return y & 0xFFFFFFFF

        # 恢复内部状态
        state = [untemper(nums[i]) for i in range(624)]

        # 生成下一个输出
        def generate(state, index):
            if index >= 624:
                for i in range(624):
                    y = (state[i] & 0x80000000) + (state[(i + 1) % 624] & 0x7FFFFFFF)
                    state[i] = state[(i + 397) % 624] ^ (y >> 1)
                    if y & 1:
                        state[i] ^= 0x9908b0df
                index = 0

            y = state[index]
            y ^= y >> 11
            y ^= (y << 7) & 0x9d2c5680
            y ^= (y << 15) & 0xefc60000
            y ^= y >> 18
            return y & 0xFFFFFFFF, index + 1

        # 预测接下来 10 个输出
        idx = 624
        predictions = []
        for _ in range(10):
            val, idx = generate(state, idx)
            predictions.append(val)

        lines = [
            t("cry.mt_success"),
            f"{t('cry.input')}: {len(nums)} {t('cry.output_values')}",
            "",
            f"{t('cry.next_predictions')}:",
        ]
        for i, val in enumerate(predictions):
            lines.append(f"  [{i+1}] {val}")

        lines.append(f"\n{t('cry.state_first5')}: {state[:5]}")

        return '\n'.join(lines)

    # ========== 3DES ==========

    def triple_des_decrypt(self, ciphertext: str, key: str) -> str:
        """3DES (Triple DES) ECB 解密"""
        from Crypto.Cipher import DES3
        data = self._parse_cipher_input(ciphertext)
        key_bytes = self._parse_key(key, [16, 24])  # 3DES 密钥 16 或 24 字节
        try:
            cipher = DES3.new(key_bytes, DES3.MODE_ECB)
            plaintext = self._pkcs7_unpad(cipher.decrypt(data))
        except Exception as e:
            return f"3DES {t('cry.decrypt_fail')}: {e}"
        return f"3DES-ECB {t('cry.decrypt')}:\n  Hex: {plaintext.hex()}\n  Text: {plaintext.decode('utf-8', errors='replace')}"

    def triple_des_encrypt(self, plaintext: str, key: str) -> str:
        """3DES (Triple DES) ECB 加密"""
        from Crypto.Cipher import DES3
        data = plaintext.encode('utf-8')
        # PKCS7 padding
        pad_len = 8 - len(data) % 8
        data += bytes([pad_len] * pad_len)
        key_bytes = self._parse_key(key, [16, 24])
        try:
            cipher = DES3.new(key_bytes, DES3.MODE_ECB)
            ct = cipher.encrypt(data)
        except Exception as e:
            return f"3DES {t('cry.encrypt_fail')}: {e}"
        return f"3DES-ECB {t('cry.encrypt')}:\n  Hex: {ct.hex()}\n  Base64: {base64.b64encode(ct).decode()}"

    # ========== 替换密码自动破解 ==========

    def substitution_auto_crack(self, ciphertext: str) -> str:
        """替换密码自动破解（频率分析 + 启发式映射）"""
        text = ''.join(c.upper() for c in ciphertext if c.isalpha())
        if len(text) < 50:
            return t("cry.text_too_short_sub")

        # 统计频率
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        sorted_cipher = sorted(freq, key=freq.get, reverse=True)

        # 英文字母频率排序
        english_order = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'

        # 建立映射
        mapping = {}
        for i, c in enumerate(sorted_cipher):
            if i < len(english_order):
                mapping[c] = english_order[i]

        # 应用映射
        result = []
        for c in ciphertext:
            if c.upper() in mapping:
                mapped = mapping[c.upper()]
                result.append(mapped.lower() if c.islower() else mapped)
            else:
                result.append(c)

        lines = [
            f"=== {t('cry.sub_auto_crack')} ===",
            "",
            f"{t('cry.letter_freq_mapping')}:",
        ]
        for c in sorted_cipher:
            pct = freq[c] / len(text) * 100
            mapped = mapping.get(c, '?')
            lines.append(f"  {c} ({pct:5.1f}%) -> {mapped}")

        lines.append(f"\n{t('cry.decrypt_result')} ({t('cry.need_manual_tune')}):")
        lines.append(''.join(result))
        lines.append(f"\n{t('cry.sub_tip')}")

        return '\n'.join(lines)

    # ========== ADFGVX 密码 ==========

    def adfgvx_decrypt(self, ciphertext: str, key: str, square: str = "") -> str:
        """ADFGVX 密码解密

        square: 6x6 Polybius 方阵字符（36字符: A-Z0-9），默认标准顺序
        key: 列置换密钥
        """
        labels = 'ADFGVX'
        if not square:
            square = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        square = square.upper()

        ct = ''.join(c.upper() for c in ciphertext if c.upper() in labels)

        # 1. 逆列置换
        key_upper = key.upper()
        n_cols = len(key_upper)
        n_rows = len(ct) // n_cols
        extra = len(ct) % n_cols

        key_order = sorted(range(n_cols), key=lambda k: key_upper[k])

        col_lens = []
        for i in range(n_cols):
            col_lens.append(n_rows + (1 if key_order.index(i) < extra else 0))

        columns = [''] * n_cols
        pos = 0
        for idx in key_order:
            columns[idx] = ct[pos:pos + col_lens[idx]]
            pos += col_lens[idx]

        # 按行读出
        fractionated = []
        for row in range(n_rows + (1 if extra else 0)):
            for col in range(n_cols):
                if row < len(columns[col]):
                    fractionated.append(columns[col][row])

        # 2. ADFGVX 对查表
        result = []
        for i in range(0, len(fractionated) - 1, 2):
            r = labels.index(fractionated[i]) if fractionated[i] in labels else 0
            c = labels.index(fractionated[i+1]) if fractionated[i+1] in labels else 0
            idx = r * 6 + c
            if idx < len(square):
                result.append(square[idx])

        return f"ADFGVX {t('cry.decrypt')} ({t('cry.key')}: {key}):\n{''.join(result)}"

    # ========== Bifid 密码 ==========

    def bifid_decrypt(self, ciphertext: str, key: str = "") -> str:
        """Bifid 密码解密 (5x5 Polybius)"""
        # 构建 Polybius 方阵
        alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'  # I/J 合并
        if key:
            key = key.upper().replace('J', 'I')
            seen = set()
            matrix = []
            for c in key + alphabet:
                if c.isalpha() and c not in seen:
                    seen.add(c)
                    matrix.append(c)
            alphabet = ''.join(matrix)

        pos = {}
        for i, c in enumerate(alphabet):
            pos[c] = (i // 5, i % 5)

        text = ''.join(c.upper() for c in ciphertext if c.isalpha()).replace('J', 'I')

        # 分解为行列坐标
        rows = [pos[c][0] for c in text if c in pos]
        cols = [pos[c][1] for c in text if c in pos]

        # 交织还原
        combined = rows + cols
        result = []
        n = len(text)
        for i in range(n):
            r = combined[i]
            c = combined[n + i]
            result.append(alphabet[r * 5 + c])

        return f"Bifid {t('cry.decrypt')}: {''.join(result)}"

    def bifid_encrypt(self, plaintext: str, key: str = "") -> str:
        """Bifid 密码加密"""
        alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
        if key:
            key = key.upper().replace('J', 'I')
            seen = set()
            matrix = []
            for c in key + alphabet:
                if c.isalpha() and c not in seen:
                    seen.add(c)
                    matrix.append(c)
            alphabet = ''.join(matrix)

        pos = {}
        for i, c in enumerate(alphabet):
            pos[c] = (i // 5, i % 5)

        text = ''.join(c.upper() for c in plaintext if c.isalpha()).replace('J', 'I')

        rows = [pos[c][0] for c in text if c in pos]
        cols = [pos[c][1] for c in text if c in pos]

        combined = rows + cols
        result = []
        for i in range(0, len(combined) - 1, 2):
            r, c = combined[i], combined[i + 1]
            result.append(alphabet[r * 5 + c])

        return f"Bifid {t('cry.encrypt')}: {''.join(result)}"

    # ========== Four-square 密码 ==========

    def four_square_decrypt(self, ciphertext: str, key1: str, key2: str) -> str:
        """Four-square 密码解密"""
        alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'

        def make_square(key):
            key = key.upper().replace('J', 'I')
            seen = set()
            sq = []
            for c in key + alphabet:
                if c.isalpha() and c not in seen:
                    seen.add(c)
                    sq.append(c)
            return sq

        plain_sq = list(alphabet)  # 标准方阵（左上和右下）
        cipher_sq1 = make_square(key1)  # 右上
        cipher_sq2 = make_square(key2)  # 左下

        text = ''.join(c.upper() for c in ciphertext if c.isalpha()).replace('J', 'I')
        if len(text) % 2:
            text += 'X'

        result = []
        for i in range(0, len(text), 2):
            # 在右上方阵找第一个字母
            if text[i] in cipher_sq1:
                idx1 = cipher_sq1.index(text[i])
            else:
                result.append(text[i])
                result.append(text[i+1])
                continue
            r1, c1 = idx1 // 5, idx1 % 5

            # 在左下方阵找第二个字母
            if text[i+1] in cipher_sq2:
                idx2 = cipher_sq2.index(text[i+1])
            else:
                result.append(text[i])
                result.append(text[i+1])
                continue
            r2, c2 = idx2 // 5, idx2 % 5

            # 从标准方阵中读取（左上取 r1,c2；右下取 r2,c1）
            result.append(plain_sq[r1 * 5 + c2])
            result.append(plain_sq[r2 * 5 + c1])

        return f"Four-square {t('cry.decrypt')}: {''.join(result)}"

    # ========== 中国剩余定理 ==========

    def chinese_remainder_theorem(self, remainders: str) -> str:
        """中国剩余定理求解

        输入格式: "r1,m1;r2,m2;r3,m3" 表示 x ≡ r1 (mod m1), x ≡ r2 (mod m2), ...
        返回最小非负解。
        """
        try:
            pairs = []
            for part in remainders.strip().split(';'):
                r_str, m_str = part.strip().split(',')
                pairs.append((int(r_str.strip()), int(m_str.strip())))
        except Exception:
            return t("cry.crt_input_error")

        if not pairs:
            return t("cry.crt_no_equations")

        # 迭代法求解 CRT
        r, m = pairs[0]
        r = r % m
        for r2, m2 in pairs[1:]:
            r2 = r2 % m2
            g, x, _ = self._extended_gcd(m, m2)
            if (r2 - r) % g != 0:
                return f"{t('cry.crt_incompatible')}: {r} mod {m} & {r2} mod {m2} (gcd={g})"
            lcm = m // g * m2
            r = (r + m * ((r2 - r) // g * x % (m2 // g))) % lcm
            m = lcm

        return f"{t('cry.crt_solution')}: x ≡ {r} (mod {m})\n{t('cry.min_nonneg')}: x = {r}"

    # ========== RSA dq 泄露攻击 ==========

    def rsa_dq_leak(self, n: int, e: int, c: int, dq: int) -> str:
        """RSA dq 泄露攻击"""
        for kq in range(1, e):
            q_candidate = (dq * e - 1) // kq + 1
            if q_candidate > 1 and n % q_candidate == 0:
                q = q_candidate
                p = n // q
                phi = (p - 1) * (q - 1)
                d = self._mod_inverse(e, phi)
                if d is None:
                    continue
                m = pow(c, d, n)
                try:
                    text = self._int_to_text(m)
                except Exception:
                    text = ""
                return (
                    f"{t('cry.dq_leak_success')}\n"
                    f"p = {p}\nq = {q}\nd = {d}\n"
                    f"{t('cry.plaintext_int')}: {m}\n{t('cry.plaintext_text')}: {text}"
                )
        return t("cry.dq_leak_fail")

    # ========== Blowfish 加解密 ==========

    def blowfish_decrypt(self, data: str, key: str) -> str:
        """Blowfish ECB 模式解密

        data: hex 编码的密文
        key: hex 编码的密钥
        """
        try:
            from Crypto.Cipher import Blowfish
        except ImportError:
            return t("cry.need_pycryptodome")
        ct = self._parse_cipher_input(data)
        k = bytes.fromhex(key.strip())
        if not (4 <= len(k) <= 56):
            return t("cry.blowfish_key_len")
        cipher = Blowfish.new(k, Blowfish.MODE_ECB)
        pt = cipher.decrypt(ct)
        pt_unpadded = self._pkcs7_unpad(pt)
        return (
            f"=== Blowfish-ECB {t('cry.decrypt')} ===\n"
            f"{t('cry.key')}: {k.hex()}\n"
            f"{t('cry.text')}: {pt_unpadded.decode('utf-8', errors='replace')}"
        )

    def blowfish_encrypt(self, data: str, key: str) -> str:
        """Blowfish ECB 模式加密

        data: 明文文本
        key: hex 编码的密钥
        """
        try:
            from Crypto.Cipher import Blowfish
        except ImportError:
            return t("cry.need_pycryptodome")
        pt = data.encode('utf-8')
        k = bytes.fromhex(key.strip())
        if not (4 <= len(k) <= 56):
            return t("cry.blowfish_key_len")
        # PKCS7 填充（Blowfish 块大小 8 字节）
        pad_len = 8 - len(pt) % 8
        pt_padded = pt + bytes([pad_len]) * pad_len
        cipher = Blowfish.new(k, Blowfish.MODE_ECB)
        ct = cipher.encrypt(pt_padded)
        return (
            f"=== Blowfish-ECB {t('cry.encrypt')} ===\n"
            f"{t('cry.key')}: {k.hex()}\n"
            f"{t('cry.ciphertext')}(hex): {ct.hex()}\n"
            f"{t('cry.ciphertext')}(base64): {base64.b64encode(ct).decode()}"
        )

    # ========== Base62 编解码 ==========

    def base62_encode(self, text: str) -> str:
        """Base62 编码

        字符集: 0-9A-Za-z
        将输入文本的字节转为大整数，再转换为 Base62 字符串。
        """
        charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        data = text.encode('utf-8')
        if not data:
            return f"Base62 {t('cry.encode')}: ({t('cry.empty_input')})"
        num = int.from_bytes(data, 'big')
        if num == 0:
            # 保留前导零字节
            encoded = charset[0] * len(data)
        else:
            chars = []
            while num > 0:
                num, rem = divmod(num, 62)
                chars.append(charset[rem])
            encoded = ''.join(reversed(chars))
        return f"Base62 {t('cry.encode')}: {encoded}"

    def base62_decode(self, text: str) -> str:
        """Base62 解码

        字符集: 0-9A-Za-z
        将 Base62 字符串还原为字节数据。
        """
        charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        text = text.strip()
        num = 0
        for ch in text:
            if ch not in charset:
                return f"Base62 {t('cry.decode_fail')}: {t('cry.illegal_char')} '{ch}'"
            num = num * 62 + charset.index(ch)
        if num == 0:
            decoded = b'\x00' * len(text)
        else:
            byte_len = (num.bit_length() + 7) // 8
            decoded = num.to_bytes(byte_len, 'big')
        try:
            result = decoded.decode('utf-8')
        except UnicodeDecodeError:
            result = decoded.hex()
        return f"Base62 {t('cry.decode')}: {result}"

    # ========== Autokey 密码 ==========

    def autokey_decrypt(self, text: str, key: str) -> str:
        """Autokey 密码解密（Vigenere 变体）

        密钥由 key + 已解密明文自动延伸。
        只处理字母，保留非字母字符。
        """
        key = key.upper()
        result = []
        key_stream = list(key)
        ki = 0
        for ch in text:
            if ch.isalpha():
                is_upper = ch.isupper()
                c_val = ord(ch.upper()) - ord('A')
                k_val = ord(key_stream[ki]) - ord('A')
                p_val = (c_val - k_val) % 26
                plain_ch = chr(p_val + ord('A'))
                key_stream.append(plain_ch)
                ki += 1
                result.append(plain_ch if is_upper else plain_ch.lower())
            else:
                result.append(ch)
        return f"Autokey {t('cry.decrypt')}: {''.join(result)}"

    # ========== Nihilist 密码 ==========

    def nihilist_decrypt(self, text: str, key: str) -> str:
        """Nihilist 密码解密

        使用 Polybius 5x5 方阵（I/J 合并）。
        输入 text: 空格分隔的两位数字（如 "34 42 21 44"）。
        key: 密钥字符串。
        """
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 无 J

        def char_to_polybius(ch: str) -> int:
            ch = ch.upper()
            if ch == 'J':
                ch = 'I'
            idx = alphabet.index(ch)
            return (idx // 5 + 1) * 10 + (idx % 5 + 1)

        def polybius_to_char(num: int) -> str:
            row = num // 10 - 1
            col = num % 10 - 1
            if 0 <= row < 5 and 0 <= col < 5:
                return alphabet[row * 5 + col]
            return '?'

        # 将密钥转为 Polybius 数字序列
        key = key.upper().replace('J', 'I')
        key_nums = [char_to_polybius(ch) for ch in key if ch in alphabet]
        if not key_nums:
            return f"Nihilist {t('cry.decrypt_fail')}: {t('cry.invalid_key')}"

        try:
            cipher_nums = [int(x) for x in text.strip().split()]
        except ValueError:
            return f"Nihilist {t('cry.decrypt_fail')}: {t('cry.nihilist_input_error')}"

        result = []
        for i, cn in enumerate(cipher_nums):
            kn = key_nums[i % len(key_nums)]
            pn = cn - kn
            result.append(polybius_to_char(pn))

        return f"Nihilist {t('cry.decrypt')}: {''.join(result)}"

    # ========== Book 密码 ==========

    def book_cipher_decode(self, text: str, book: str) -> str:
        """Book/字典密码解码

        text: 位置引用，格式 "1:3:2 2:1:4"（页:行:字）或 "行:字"
        book: 参考文本（按行分割）
        """
        lines = book.strip().split('\n')
        result = []
        for ref in text.strip().split():
            parts = ref.split(':')
            try:
                if len(parts) == 3:
                    # 页:行:字 — 这里简化为忽略页码，直接用行:字
                    _page, line_num, char_num = int(parts[0]), int(parts[1]), int(parts[2])
                    # 将页码和行号组合：(page-1)*若干行 + line_num，简化处理直接用 line_num
                    idx_line = line_num - 1
                    idx_char = char_num - 1
                elif len(parts) == 2:
                    idx_line = int(parts[0]) - 1
                    idx_char = int(parts[1]) - 1
                else:
                    result.append('?')
                    continue

                if 0 <= idx_line < len(lines) and 0 <= idx_char < len(lines[idx_line]):
                    result.append(lines[idx_line][idx_char])
                else:
                    result.append('?')
            except (ValueError, IndexError):
                result.append('?')

        return f"Book {t('cry.decode')}: {''.join(result)}"

    # ========== Rabbit 流密码 ==========

    def rabbit_decrypt(self, data: str, key: str) -> str:
        """Rabbit 流密码解密提示

        Rabbit 是一种高速流密码，纯 Python 实现较为复杂。
        提供在线工具链接和使用说明。
        """
        return (
            f"=== Rabbit 流密码 ===\n"
            f"密文(hex): {data}\n"
            f"密钥: {key}\n\n"
            f"Rabbit 流密码纯 Python 实现较为复杂，建议使用以下在线工具:\n"
            f"1. CyberChef: https://gchq.github.io/CyberChef/#recipe=Rabbit\n"
            f"   操作: 搜索 'Rabbit' -> 粘贴密文和密钥\n"
            f"2. 在线工具: https://www.toolnb.com/tools/rabbit.html\n\n"
            f"CyberChef 使用步骤:\n"
            f"  - 打开 CyberChef 链接\n"
            f"  - 在 Operations 中搜索 'Rabbit'\n"
            f"  - 将密文放入 Input（选择 Hex 格式）\n"
            f"  - 在 Key 字段输入密钥\n"
            f"  - Output 即为解密结果"
        )

    # ========== Rabin 密码 / 批量 GCD / Franklin-Reiter / Coppersmith / Boneh-Durfee / Williams p+1 ==========

    def rabin_decrypt(self, c: int, p: int, q: int) -> str:
        """Rabin 密码解密（e=2），返回 4 个候选明文。
        Rabin decryption (e=2). Returns all 4 candidate plaintexts via CRT.
        """

        def _tonelli_shanks(n: int, p: int) -> int:
            """Tonelli-Shanks 算法：求 n 在模 p 下的平方根。
            Tonelli-Shanks algorithm: compute sqrt(n) mod p.
            """
            if pow(n, (p - 1) // 2, p) != 1:
                raise ValueError(f"n={n} 不是模 p={p} 的二次剩余 / not a quadratic residue mod p")
            if p % 4 == 3:
                return pow(n, (p + 1) // 4, p)
            # 分解 p-1 = Q * 2^S
            Q, S = p - 1, 0
            while Q % 2 == 0:
                Q //= 2
                S += 1
            # 找一个非二次剩余 z
            z = 2
            while pow(z, (p - 1) // 2, p) != p - 1:
                z += 1
            M = S
            c_ts = pow(z, Q, p)
            t_val = pow(n, Q, p)
            R = pow(n, (Q + 1) // 2, p)
            while True:
                if t_val == 1:
                    return R
                # 找最小 i 使 t^(2^i) = 1
                i = 1
                tmp = (t_val * t_val) % p
                while tmp != 1:
                    tmp = (tmp * tmp) % p
                    i += 1
                b = pow(c_ts, 1 << (M - i - 1), p)
                M = i
                c_ts = (b * b) % p
                t_val = (t_val * c_ts) % p
                R = (R * b) % p

        n = p * q
        lines = [
            "=== Rabin 解密 (e=2) ===",
            f"c = {c}", f"p = {p}", f"q = {q}", f"n = {n}", ""
        ]
        try:
            mp = _tonelli_shanks(c % p, p)
            mq = _tonelli_shanks(c % q, q)
        except ValueError as ex:
            lines.append(f"[-] 平方根计算失败 / sqrt failed: {ex}")
            return "\n".join(lines)

        # CRT 组合 4 个候选值
        # 扩展欧几里得求 yp, yq 满足 yp*p + yq*q = 1
        def _extended_gcd(a: int, b: int):
            if a == 0:
                return b, 0, 1
            g, x1, y1 = _extended_gcd(b % a, a)
            return g, y1 - (b // a) * x1, x1

        _, yp, yq = _extended_gcd(p, q)

        roots = []
        for sp, sq in [(mp, mq), (mp, q - mq), (p - mp, mq), (p - mp, q - mq)]:
            r = (yp * p * sq + yq * q * sp) % n
            roots.append(r)

        lines.append("[+] 4 个候选明文 / 4 candidate plaintexts:")
        for idx, r in enumerate(roots, 1):
            try:
                text = self._int_to_text(r)
            except Exception:
                text = "(无法转换 / cannot convert)"
            lines.append(f"  m{idx} = {r}")
            lines.append(f"       text: {text}")
        return "\n".join(lines)

    def rsa_batch_gcd(self, n_list: str, e: int = 65537, c: int = 0) -> str:
        """批量 GCD 攻击：对多个 n 两两求 GCD 寻找共享素因子。
        Batch GCD attack: find shared prime factors among multiple moduli.
        """
        ns = [int(x.strip()) for x in n_list.split(',') if x.strip()]
        if len(ns) < 2:
            return "[-] 至少需要 2 个 n / Need at least 2 moduli"

        lines = ["=== 批量 GCD 攻击 ===", f"共 {len(ns)} 个模数 / {len(ns)} moduli", ""]
        found = []
        for i in range(len(ns)):
            for j in range(i + 1, len(ns)):
                g = math.gcd(ns[i], ns[j])
                if g > 1 and g != ns[i] and g != ns[j]:
                    p = g
                    q_i = ns[i] // p
                    q_j = ns[j] // p
                    lines.append(f"[+] n[{i}] 与 n[{j}] 共享素因子 p = {p}")
                    lines.append(f"    n[{i}] = p * {q_i}")
                    lines.append(f"    n[{j}] = p * {q_j}")
                    found.append((i, ns[i], p, q_i))
                    found.append((j, ns[j], p, q_j))

        if not found:
            lines.append("[-] 未找到共享素因子 / No shared factors found")
            return "\n".join(lines)

        # 如果提供了 e 和 c，尝试用第一个被分解的 n 解密
        if e > 0 and c > 0 and found:
            idx, ni, p, q = found[0]
            lines.append(f"\n--- 使用 n[{idx}] 解密 ---")
            phi = (p - 1) * (q - 1)
            d = self._mod_inverse(e, phi)
            if d:
                m = pow(c, d, ni)
                try:
                    text = self._int_to_text(m)
                except Exception:
                    text = ""
                lines.append(f"d = {d}")
                lines.append(f"{t('cry.plaintext_int')}: {m}")
                lines.append(f"{t('cry.plaintext_text')}: {text}")
            else:
                lines.append("[-] 无法计算 d / Cannot compute d")

        return "\n".join(lines)

    def rsa_franklin_reiter(self, c1: int, c2: int, e: int, n: int,
                            a: int = 1, b: int = 0) -> str:
        """Franklin-Reiter 相关消息攻击（m2 = a*m1 + b, 默认 e=3）。
        Franklin-Reiter related message attack (m2 = a*m1 + b, default e=3).
        """
        lines = [
            "=== Franklin-Reiter 相关消息攻击 ===",
            f"c1 = {c1}", f"c2 = {c2}", f"e = {e}", f"n = {n}",
            f"关系 / relation: m2 = {a}*m1 + {b}", ""
        ]

        if e != 3:
            lines.append("[-] 当前简化实现仅支持 e=3 / Simplified impl supports e=3 only")
            lines.append("建议使用 SageMath 处理 e>3 的情况 / Use SageMath for e>3")
            return "\n".join(lines)

        # e=3 简化版：利用多项式 GCD
        # f1(x) = x^3 - c1, f2(x) = (a*x+b)^3 - c2
        # 通过结式或直接求 GCD 可得 m1
        # 简化：使用数值方法 — 计算 gcd(f1, f2) 在 Z/nZ[x] 上
        # f1 = x^3 - c1
        # f2 = (ax+b)^3 - c2 = a^3*x^3 + 3*a^2*b*x^2 + 3*a*b^2*x + b^3 - c2
        # f2 - a^3*f1 = 3*a^2*b*x^2 + 3*a*b^2*x + (b^3 - c2 + a^3*c1)
        # 继续辗转相除求 GCD

        def _poly_gcd_e3(c1: int, c2: int, a: int, b: int, n: int) -> int:
            """简化的多项式 GCD 求解 m1（e=3 专用）"""
            a3 = pow(a, 3, n)
            # r(x) = f2 - a^3 * f1 = 3*a^2*b*x^2 + 3*a*b^2*x + (b^3 - c2 + a^3*c1)
            r2 = (3 * a * a % n * b) % n
            r1 = (3 * a % n * b % n * b) % n
            r0 = (pow(b, 3, n) - c2 + a3 * c1) % n

            if r2 == 0:
                # r(x) 为一次多项式，直接求根
                if r1 == 0:
                    return -1
                inv_r1 = self._mod_inverse(r1, n)
                if inv_r1 is None:
                    return -1
                return (-r0 * inv_r1) % n

            # f1 = x^3 - c1, 除以 r(x) = r2*x^2 + r1*x + r0
            inv_r2 = self._mod_inverse(r2, n)
            if inv_r2 is None:
                return -1

            # 标准化 r(x) 为首一多项式
            r1_n = (r1 * inv_r2) % n
            r0_n = (r0 * inv_r2) % n

            # x^3 - c1 除以 x^2 + r1_n*x + r0_n
            # x^3 - c1 = (x - r1_n)(x^2 + r1_n*x + r0_n) + 余式
            # 余式: (r1_n^2 - r0_n)*x + (r1_n*r0_n - c1)  ... 不精确，用完整长除法
            # q = x - r1_n
            # 余 = x^3 - c1 - (x - r1_n)*(x^2 + r1_n*x + r0_n)
            #     = x^3 - c1 - x^3 - r1_n*x^2 - r0_n*x + r1_n*x^2 + r1_n^2*x + r1_n*r0_n
            #     = (r1_n*r1_n - r0_n)*x + (r1_n*r0_n - c1)
            s1 = (r1_n * r1_n - r0_n) % n
            s0 = (r1_n * r0_n - c1) % n

            if s1 == 0:
                return -1
            inv_s1 = self._mod_inverse(s1, n)
            if inv_s1 is None:
                return -1
            return (-s0 * inv_s1) % n

        m = _poly_gcd_e3(c1, c2, a, b, n)
        if m < 0:
            lines.append("[-] 求解失败，可能逆元不存在 / Solving failed (inverse may not exist)")
            lines.append("建议使用 SageMath: R.<x>=Zmod(n)[]; gcd(x^e-c1, (a*x+b)^e-c2)")
            return "\n".join(lines)

        # 验证
        if pow(m, e, n) == c1 % n:
            try:
                text = self._int_to_text(m)
            except Exception:
                text = ""
            lines.append("[+] 攻击成功 / Attack succeeded!")
            lines.append(f"m1 = {m}")
            lines.append(f"{t('cry.plaintext_text')}: {text}")
            m2 = (a * m + b) % n
            lines.append(f"m2 = {m2}")
        else:
            lines.append("[-] 验证失败，结果可能不正确 / Verification failed")
            lines.append(f"候选 m1 = {m}")
            lines.append("建议使用 SageMath 进行精确计算")

        return "\n".join(lines)

    def rsa_coppersmith_helper(self) -> str:
        """生成 Coppersmith 攻击的 SageMath 脚本模板。
        Generate SageMath script templates for Coppersmith's attack.
        """
        template = """=== Coppersmith 攻击 SageMath 脚本模板 ===

Coppersmith 攻击需要 LLL 格基规约，纯 Python 实现复杂度极高，建议使用 SageMath。
Coppersmith's attack requires LLL lattice reduction. Use SageMath for best results.

---------- 场景 1: 已知明文高位 / Known high bits of plaintext ----------

# 已知明文的高 (nbits - kbits) 位
n = 0x...  # RSA 模数
e = 3
c = 0x...  # 密文
m_high = 0x...  # 已知的高位部分
kbits = 64  # 未知的低位比特数

PR.<x> = PolynomialRing(Zmod(n))
f = (m_high + x)^e - c
x0 = f.small_roots(X=2^kbits, beta=1)[0]
m = m_high + x0
print("明文 m =", m)
print("明文文本:", bytes.fromhex(hex(int(m))[2:]))

---------- 场景 2: 已知明文低位 / Known low bits of plaintext ----------

n = 0x...
e = 3
c = 0x...
m_low = 0x...  # 已知的低位部分
kbits = 64  # 已知低位的比特数
nbits = 1024  # 明文总比特数

PR.<x> = PolynomialRing(Zmod(n))
f = (x * 2^kbits + m_low)^e - c
x0 = f.small_roots(X=2^(nbits-kbits), beta=1)[0]
m = x0 * 2^kbits + m_low
print("明文 m =", m)
print("明文文本:", bytes.fromhex(hex(int(m))[2:]))

---------- 场景 3: Stereotyped Message / 定型消息攻击 ----------

# 已知明文格式: m = prefix + unknown + suffix
n = 0x...
e = 3
c = 0x...
prefix = b"The secret is: "
suffix = b". Remember it!"
kbits = 64  # unknown 部分的比特数

prefix_int = int.from_bytes(prefix, 'big')
suffix_int = int.from_bytes(suffix, 'big')
# m = prefix_int * 2^(kbits + len(suffix)*8) + x * 2^(len(suffix)*8) + suffix_int
shift_suffix = len(suffix) * 8

PR.<x> = PolynomialRing(Zmod(n))
f = (prefix_int * 2^(kbits + shift_suffix) + x * 2^shift_suffix + suffix_int)^e - c
x0 = f.small_roots(X=2^kbits, beta=1)[0]
print("未知部分 =", hex(int(x0)))
print("完整明文:", prefix + bytes.fromhex(hex(int(x0))[2:]) + suffix)
"""
        return template

    def rsa_boneh_durfee_helper(self) -> str:
        """生成 Boneh-Durfee 攻击的 SageMath 脚本模板。
        Generate SageMath script template for Boneh-Durfee attack (small d).
        """
        template = """=== Boneh-Durfee 攻击 SageMath 脚本模板 ===

适用条件: d < n^0.292（比 Wiener 攻击的 d < n^0.25 范围更大）
Applicable when: d < n^0.292 (wider range than Wiener's d < n^0.25)

方法: 利用 e*d ≡ 1 (mod (p-1)(q-1)) 转化为求解
      x*(A+y) ≡ 1 (mod e)，其中 A = (n+1)/2, x = k, y = (p+q)/2
Method: Transform e*d = 1 + k*(n+1-(p+q)) into solving
        x*(A+y) = 1 (mod e), where A=(n+1)/2, x=k, y=(p+q)/2

---------- SageMath 脚本 ----------

# 建议使用 https://github.com/mimoo/RSA-and-LLL-attacks 中的实现
# Recommended: use the implementation from the above repository

import time

def boneh_durfee(pol, modulus, mm, tt, XX, YY):
    '''Boneh-Durfee 攻击实现（基于 Coppersmith 方法）'''
    PR.<u, x, y> = PolynomialRing(ZZ)
    Q = PR.quotient(x*y + 1 - u)
    polZ = Q(pol).lift()

    UU = XX * YY + 1

    gg = []
    for kk in range(mm + 1):
        for ii in range(mm - kk + 1):
            xshift = x^ii * modulus^(mm - kk) * polZ^kk
            gg.append(xshift)
    for jj in range(1, tt + 1):
        for kk in range(mm // tt * jj, mm + 1):
            yshift = y^jj * polZ^kk * modulus^(mm - kk)
            gg.append(yshift)

    # 构造格并 LLL 规约
    monomials = []
    for polynomial in gg:
        for monomial in polynomial.monomials():
            if monomial not in monomials:
                monomials.append(monomial)
    monomials.sort()

    nn = len(monomials)
    BB = Matrix(ZZ, nn)
    for ii in range(nn):
        for jj in range(nn):
            if monomials[jj] in gg[ii].monomials():
                BB[ii, jj] = gg[ii].monomial_coefficient(monomials[jj]) * \\
                             monomials[jj](UU, XX, YY)

    BB = BB.LLL()

    # 从规约后的格中提取多项式并求解
    PR.<x, y> = PolynomialRing(ZZ)
    found_polynomials = []
    for ii in range(nn):
        poly = 0
        for jj in range(nn):
            poly += monomials[jj](1, x, y) * BB[ii, jj] / monomials[jj](UU, XX, YY)
        if poly.is_zero():
            continue
        found_polynomials.append(poly)
        if len(found_polynomials) >= 2:
            break

    if len(found_polynomials) < 2:
        return 0, 0

    # Groebner 基求解
    ideal = Ideal(found_polynomials)
    I = ideal.groebner_basis()
    if len(I) >= 2:
        x0 = -I[0].constant_coefficient() / I[0].coefficient({x:1})
        y0 = -I[1].constant_coefficient() / I[1].coefficient({y:1})
        return int(x0), int(y0)
    return 0, 0

# ===== 使用方法 =====
N = 0x...  # RSA 模数
e = 0x...  # 公钥指数（非常大）

# 参数设置（根据实际情况调整）
delta = 0.26  # d 的大小约为 N^delta
m = 4   # 格维度参数（越大越慢但成功率越高）
t_param = int((1 - 2 * delta) * m)

Y = int(2 * floor(N^delta))
X = int(floor(N^(0.5)))
A = int((N + 1) / 2)

P.<x, y> = PolynomialRing(Zmod(e))
pol = 1 + x * (A + y)

x0, y0 = boneh_durfee(pol, e, m, t_param, X, Y)
if x0 != 0:
    d = inverse_mod(int(e), int((N + 1 - 2*y0 - 1) * (N + 1 + 2*y0 - 1) // 4))
    print(f"d = {d}")
    # 解密: m = pow(c, d, N)
else:
    print("攻击失败 / Attack failed. 尝试增大 m 或调整 delta")
"""
        return template

    def rsa_williams_p1(self, n: int, e: int = 0, c: int = 0) -> str:
        """Williams p+1 分解算法（p+1 光滑时有效，与 Pollard p-1 互补）。
        Williams p+1 factorization (effective when p+1 is smooth, complementary to Pollard p-1).
        """

        def _lucas_sequence(v: int, n: int, B: int) -> int:
            """计算 Lucas 序列 V_k(v, 1) mod n，k = B! 的逐步累积。
            Compute Lucas sequence V_k(v, 1) mod n with k accumulated as B!.
            """
            # V_0 = 2, V_1 = v
            # V_{2k} = V_k^2 - 2
            # V_{2k+1} = V_k * V_{k+1} - v
            # 使用二进制链乘法计算 V_m mod n
            def _lucas_mul(v_val: int, m: int, n: int) -> int:
                """计算 V_m(v_val, 1) mod n"""
                if m == 0:
                    return 2
                if m == 1:
                    return v_val % n
                # 二进制方法
                vl = v_val % n
                vh = (v_val * v_val - 2) % n
                bits = bin(m)[3:]  # 跳过最高位的 '1'
                for bit in bits:
                    if bit == '1':
                        vl = (vl * vh - v_val) % n
                        vh = (vh * vh - 2) % n
                    else:
                        vh = (vl * vh - v_val) % n
                        vl = (vl * vl - 2) % n
                return vl

            w = v
            for j in range(2, B + 1):
                w = _lucas_mul(w, j, n)
            return w

        lines = ["=== Williams p+1 分解 ===", f"n = {n}", ""]

        # 尝试多个初始值
        import random
        seeds = [3, 5, 7, 11, 13] + [random.randint(2, n - 2) for _ in range(5)]
        B = 50000  # 光滑界

        for v in seeds:
            # 确保 Jacobi 符号 (v^2-4 | n) != 1，否则 v 的选择可能无效
            # 但这需要 n 的因子未知，所以多试几个 v
            w = _lucas_sequence(v, n, B)
            g = math.gcd(w - 2, n)
            if 1 < g < n:
                p = g
                q = n // p
                lines.append(f"[+] Williams p+1 分解成功! (v={v}, B={B})")
                lines.append(self._rsa_format_result("Williams p+1", p, q, n, e, c))
                return "\n".join(lines)

        lines.append(f"[-] Williams p+1 未能分解 (B={B})，建议增大 B 或尝试其他方法")
        return "\n".join(lines)

    # ========== 自动攻击与检测 ==========

    def rsa_auto_attack(self, n: int, e: int, c: int,
                        extra: str = "", n_list: str = "") -> str:
        """RSA 自动攻击 — 依次尝试所有攻击方式。
        RSA auto attack - try all attack methods sequentially.

        参数 extra: 可选的额外参数（如 dp, dq 等），格式 "key=value,key=value"
        参数 n_list: 可选的多个 n（逗号分隔），用于批量 GCD 攻击
        """
        attacks = [
            ("小指数攻击", lambda: self.rsa_decrypt_small_e(c, e, n)),
            ("Wiener 攻击", lambda: self.rsa_wiener(e, n, c)),
            ("Fermat 分解", lambda: self.rsa_fermat(n, e, c)),
            ("Pollard p-1", lambda: self.rsa_pollard_p1(n, e, c)),
            ("Williams p+1", lambda: self.rsa_williams_p1(n, e, c)),
            ("Pollard rho", lambda: self.rsa_pollard_rho(n, e, c)),
            ("factordb 查询", lambda: self.rsa_factordb(n, e, c)),
        ]

        # 解析 extra 参数
        extra_dict = {}
        if extra:
            for part in extra.split(','):
                if '=' in part:
                    k, v = part.split('=', 1)
                    extra_dict[k.strip()] = int(v.strip())

        # 根据条件动态添加攻击
        # Rabin 解密（e==2 且提供了 p, q）
        if e == 2 and 'p' in extra_dict and 'q' in extra_dict:
            attacks.insert(0, ("Rabin 解密 (e=2)", lambda: self.rabin_decrypt(
                c, extra_dict['p'], extra_dict['q'])))

        # dp 泄露攻击
        if 'dp' in extra_dict:
            attacks.insert(0, ("dp 泄露攻击", lambda: self.rsa_dp_leak(
                n, e, c, extra_dict['dp'])))

        # dq 泄露攻击
        if 'dq' in extra_dict:
            attacks.insert(0, ("dq 泄露攻击", lambda: self.rsa_dq_leak(
                n, e, c, extra_dict['dq'])))

        # Hastad 广播攻击（需要 extra 中有额外的 n,c 对）
        if 'hastad_pairs' in extra_dict or (extra and 'n2' in extra_dict):
            # 从 extra_dict 构建 hastad extra 字符串
            hastad_extra_parts = []
            i = 2
            while f'n{i}' in extra_dict and f'c{i}' in extra_dict:
                hastad_extra_parts.append(str(extra_dict[f'n{i}']))
                hastad_extra_parts.append(str(extra_dict[f'c{i}']))
                i += 1
            if hastad_extra_parts:
                hastad_str = ','.join(hastad_extra_parts)
                attacks.insert(0, ("Hastad 广播攻击", lambda: self.rsa_hastad(
                    e, c, n, hastad_str)))

        # 批量 GCD 攻击
        if n_list:
            attacks.insert(0, ("批量 GCD 攻击", lambda: self.rsa_batch_gcd(
                n_list, e, c)))

        lines = ["=== RSA 自动攻击 ===", f"n = {n}", f"e = {e}", f"c = {c}", ""]
        for name, attack in attacks:
            lines.append(f"--- 尝试: {name} ---")
            try:
                result = attack()
                if "成功" in result or "明文" in result or "plaintext" in result.lower():
                    lines.append(f"[+] {name} 成功!")
                    lines.append(result)
                    return "\n".join(lines)
                else:
                    lines.append(f"[-] {name}: 未成功")
            except Exception as ex:
                lines.append(f"[-] {name}: {ex}")
        lines.append("\n所有自动攻击均未成功，建议手动分析或尝试其他方法")
        return "\n".join(lines)

    # ========== RSA 密钥导入 ==========

    def rsa_import_key(self, filepath: str) -> str:
        """从 PEM/DER 文件或 PEM 文本导入 RSA 公钥/私钥，提取参数。
        Import RSA public/private key from PEM/DER file or PEM text, extract parameters.
        """
        filepath = filepath.strip()
        if not filepath:
            return t("cry.rsa_import_empty")

        # 判断是文件路径还是直接粘贴的 PEM 文本
        pem_text = None
        raw_bytes = None
        if filepath.startswith("-----"):
            # 直接是 PEM 文本
            pem_text = filepath
        elif os.path.isfile(filepath):
            with open(filepath, 'rb') as f:
                raw_bytes = f.read()
            # 尝试判断是否为 PEM
            try:
                text_content = raw_bytes.decode('utf-8', errors='strict')
                if '-----BEGIN' in text_content:
                    pem_text = text_content
            except UnicodeDecodeError:
                pass  # DER 格式，保持 raw_bytes
        else:
            return t("cry.rsa_import_file_not_found").format(filepath)

        lines = [f"=== {t('cry.rsa_import_title')} ==="]

        # 优先使用 PyCryptodome 解析
        try:
            from Crypto.PublicKey import RSA
            if pem_text:
                key = RSA.import_key(pem_text)
            else:
                key = RSA.import_key(raw_bytes)

            lines.append(f"{t('cry.rsa_import_method')}: PyCryptodome")
            lines.append(f"{t('cry.rsa_import_key_size')}: {key.size_in_bits()} bits")
            lines.append(f"n = {key.n}")
            lines.append(f"e = {key.e}")
            if key.has_private():
                lines.append(f"d = {key.d}")
                try:
                    lines.append(f"p = {key.p}")
                    lines.append(f"q = {key.q}")
                except AttributeError:
                    pass
            else:
                lines.append(f"({t('cry.rsa_import_public_only')})")
            return "\n".join(lines)
        except ImportError:
            pass
        except Exception as ex:
            lines.append(f"PyCryptodome {t('cry.rsa_import_parse_fail')}: {ex}")

        # PyCryptodome 不可用时，手动解析 PEM + ASN.1 提取 n, e
        if pem_text:
            try:
                n, e, key_bits = self._manual_parse_pem(pem_text)
                lines.append(f"{t('cry.rsa_import_method')}: {t('cry.rsa_import_manual_asn1')}")
                lines.append(f"{t('cry.rsa_import_key_size')}: {key_bits} bits")
                lines.append(f"n = {n}")
                lines.append(f"e = {e}")
                lines.append(f"({t('cry.rsa_import_manual_limit')})")
                return "\n".join(lines)
            except Exception as ex:
                lines.append(f"{t('cry.rsa_import_manual_fail')}: {ex}")

        lines.append(t("cry.rsa_import_all_fail"))
        lines.append(t("cry.rsa_import_install_hint"))
        return "\n".join(lines)

    def _manual_parse_pem(self, pem_text: str):
        """手动解析 PEM 格式公钥，提取 n 和 e（不依赖第三方库）。"""
        # 去除 PEM 头尾，解码 Base64
        pem_lines = []
        in_body = False
        for line in pem_text.strip().splitlines():
            line = line.strip()
            if line.startswith('-----BEGIN'):
                in_body = True
                continue
            if line.startswith('-----END'):
                break
            if in_body:
                pem_lines.append(line)
        der_data = base64.b64decode(''.join(pem_lines))

        # 简单 ASN.1 DER 解析
        def read_asn1_length(data, offset):
            b = data[offset]
            offset += 1
            if b < 0x80:
                return b, offset
            num_bytes = b & 0x7F
            length = 0
            for _ in range(num_bytes):
                length = (length << 8) | data[offset]
                offset += 1
            return length, offset

        def read_asn1_integer(data, offset):
            if data[offset] != 0x02:
                raise ValueError("Expected INTEGER tag (0x02)")
            offset += 1
            length, offset = read_asn1_length(data, offset)
            int_bytes = data[offset:offset + length]
            offset += length
            value = int.from_bytes(int_bytes, 'big')
            return value, offset

        def skip_asn1_element(data, offset):
            offset += 1  # tag
            length, offset = read_asn1_length(data, offset)
            return offset + length

        idx = 0
        # 外层 SEQUENCE
        if der_data[idx] != 0x30:
            raise ValueError("Not a valid ASN.1 SEQUENCE")
        idx += 1
        _, idx = read_asn1_length(der_data, idx)

        # 检查是否是 PKCS#8 SubjectPublicKeyInfo（含 algorithm 标识）
        if der_data[idx] == 0x30:
            # PKCS#8 格式: SEQUENCE { SEQUENCE { OID, NULL }, BIT STRING { SEQUENCE { n, e } } }
            idx = skip_asn1_element(der_data, idx)  # 跳过 algorithm SEQUENCE
            # BIT STRING
            if der_data[idx] == 0x03:
                idx += 1
                length, idx = read_asn1_length(der_data, idx)
                idx += 1  # 跳过 unused bits byte
                # 内层 SEQUENCE
                if der_data[idx] != 0x30:
                    raise ValueError("Expected inner SEQUENCE")
                idx += 1
                _, idx = read_asn1_length(der_data, idx)
                n, idx = read_asn1_integer(der_data, idx)
                e, idx = read_asn1_integer(der_data, idx)
                key_bits = n.bit_length()
                return n, e, key_bits
            else:
                raise ValueError("Expected BIT STRING in SubjectPublicKeyInfo")
        elif der_data[idx] == 0x02:
            # PKCS#1 RSAPublicKey 格式: SEQUENCE { n INTEGER, e INTEGER }
            n, idx = read_asn1_integer(der_data, idx)
            e, idx = read_asn1_integer(der_data, idx)
            key_bits = n.bit_length()
            return n, e, key_bits
        else:
            raise ValueError(f"Unexpected ASN.1 tag: 0x{der_data[idx]:02x}")

    # ========== 哈希碰撞生成 ==========

    def hash_collision_generate(self, hash_type: str = "md5") -> str:
        """哈希碰撞生成/参考工具。
        Hash collision generation / reference tool.
        """
        hash_type = hash_type.strip().lower()
        lines = [f"=== {t('cry.hash_collision_title')} ({hash_type.upper()}) ===", ""]

        if hash_type == "md5":
            lines.append(f"[1] {t('cry.hash_collision_known_md5')}")
            lines.append("")
            # 已知 MD5 碰撞对（Wang & Yu, 2004），十六进制表示
            pair_a = (
                "d131dd02c5e6eec4693d9a0698aff95c"
                "2fcab58712467eab4004583eb8fb7f89"
                "55ad340609f4b30283e488832571415a"
                "085125e8f7cdc99fd91dbdf280373c5b"
                "d8823e3156348f5bae6dacd436c919c6"
                "dd53e2b487da03fd02396306d248cda0"
                "e99f33420f577ee8ce54b67080a80d1e"
                "c69821bcb6a8839396f9652b6ff72a70"
            )
            pair_b = (
                "d131dd02c5e6eec4693d9a0698aff95c"
                "2fcab50712467eab4004583eb8fb7f89"
                "55ad340609f4b30283e4888325f1415a"
                "085125e8f7cdc99fd91dbd7280373c5b"
                "d8823e3156348f5bae6dacd436c919c6"
                "dd53e23487da03fd02396306d248cda0"
                "e99f33420f577ee8ce54b67080280d1e"
                "c69821bcb6a8839396f965ab6ff72a70"
            )
            lines.append(f"  {t('cry.hash_collision_block')} A (hex):")
            lines.append(f"  {pair_a}")
            lines.append(f"  {t('cry.hash_collision_block')} B (hex):")
            lines.append(f"  {pair_b}")
            md5_a = hashlib.md5(bytes.fromhex(pair_a)).hexdigest()
            md5_b = hashlib.md5(bytes.fromhex(pair_b)).hexdigest()
            lines.append(f"  MD5(A) = {md5_a}")
            lines.append(f"  MD5(B) = {md5_b}")
            lines.append(f"  {t('cry.hash_collision_match')}: {md5_a == md5_b}")
            lines.append("")
            lines.append(f"[2] {t('cry.hash_collision_fastcoll')}")
            lines.append("  # fastcoll — MD5 碰撞生成器")
            lines.append("  # https://www.win.tue.nl/hashclash/")
            lines.append("  fastcoll -o file1.bin file2.bin")
            lines.append("  md5sum file1.bin file2.bin  # 相同 MD5")
            lines.append("")
            lines.append(f"[3] {t('cry.hash_collision_prefix')}")
            lines.append("  # 选择前缀碰撞")
            lines.append("  fastcoll -p prefix.bin -o col1.bin col2.bin")
            lines.append("  cat prefix.bin col1.bin > file1.bin")
            lines.append("  cat prefix.bin col2.bin > file2.bin")

        elif hash_type == "sha1":
            lines.append(f"[1] {t('cry.hash_collision_shattered')}")
            lines.append("  # SHAttered — 首个 SHA-1 实际碰撞 (Google, 2017)")
            lines.append("  # https://shattered.io/")
            lines.append("  # shattered-1.pdf 与 shattered-2.pdf 拥有相同 SHA-1")
            lines.append("  SHA-1 = 38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
            lines.append("")
            lines.append(f"[2] {t('cry.hash_collision_shambles')}")
            lines.append("  # SHA-1 is a Shambles — 选择前缀碰撞 (2020)")
            lines.append("  # https://sha-mbles.github.io/")
            lines.append("  # 成本已降至约 $45,000 (GPU 集群)")
            lines.append("")
            lines.append(f"[3] {t('cry.hash_collision_tool_ref')}")
            lines.append("  # HashClash: https://github.com/cr-marcstevens/hashclash")
            lines.append("  # 工具用于差分路径搜索和碰撞生成")

        elif hash_type == "crc32":
            lines.append(f"[1] {t('cry.hash_collision_crc32_info')}")
            lines.append(f"  {t('cry.hash_collision_crc32_space')}")
            lines.append("")
            lines.append(f"[2] {t('cry.hash_collision_crc32_search')}")
            lines.append(f"  {t('cry.hash_collision_crc32_usage')}")
            lines.append("  hash_collision_generate crc32")
            lines.append("")
            # 演示：生成 2 个不同的 4 字节值，使其 CRC32 相同
            import struct
            import zlib
            target_crc = zlib.crc32(b"AAAA") & 0xFFFFFFFF
            lines.append(f"  {t('cry.hash_collision_crc32_demo')}")
            lines.append(f"  {t('cry.hash_collision_crc32_target')}: CRC32(b'AAAA') = 0x{target_crc:08X}")
            found = None
            for i in range(0xFFFFFFFF):
                candidate = struct.pack('<I', i)
                if candidate == b"AAAA":
                    continue
                if (zlib.crc32(candidate) & 0xFFFFFFFF) == target_crc:
                    found = candidate
                    break
            if found:
                lines.append(f"  {t('cry.hash_collision_crc32_found')}: {found.hex()}")
                lines.append(f"  CRC32 = 0x{zlib.crc32(found) & 0xFFFFFFFF:08X}")
            else:
                lines.append(f"  {t('cry.hash_collision_crc32_not_found')}")
            lines.append("")
            lines.append(f"[3] {t('cry.hash_collision_crc32_custom')}")
            lines.append(f"  {t('cry.hash_collision_crc32_custom_hint')}")

        else:
            lines.append(t("cry.hash_collision_unsupported").format(hash_type))
            lines.append(t("cry.hash_collision_supported"))

        return "\n".join(lines)

    # ========== 密码强度评估 ==========

    def password_strength(self, password: str) -> str:
        """密码强度评估：熵、字符分析、常见弱密码检测、暴力破解时间估算。
        Password strength assessment: entropy, charset analysis, common password detection,
        brute-force time estimation.
        """
        if not password:
            return t("cry.pwd_empty")

        lines = [f"=== {t('cry.pwd_title')} ===", f"{t('cry.pwd_password')}: {'*' * len(password)}", ""]

        # ---- 1. 基础属性 ----
        length = len(password)
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

        charset_size = 0
        charset_desc = []
        if has_lower:
            charset_size += 26
            charset_desc.append(t("cry.pwd_lower"))
        if has_upper:
            charset_size += 26
            charset_desc.append(t("cry.pwd_upper"))
        if has_digit:
            charset_size += 10
            charset_desc.append(t("cry.pwd_digit"))
        if has_special:
            charset_size += 33
            charset_desc.append(t("cry.pwd_special"))
        if charset_size == 0:
            charset_size = 256  # 非 ASCII
            charset_desc.append(t("cry.pwd_other"))

        lines.append(f"--- {t('cry.pwd_basic')} ---")
        lines.append(f"{t('cry.pwd_len')}: {length}")
        lines.append(f"{t('cry.pwd_charset')}: {', '.join(charset_desc)} ({t('cry.pwd_charset_size')}: {charset_size})")

        # ---- 2. 香农熵 ----
        freq = Counter(password)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        total_entropy = entropy * length  # 理论位熵
        ideal_entropy = math.log2(charset_size) * length if charset_size > 0 else 0

        lines.append("")
        lines.append(f"--- {t('cry.pwd_entropy')} ---")
        lines.append(f"{t('cry.pwd_shannon')}: {entropy:.4f} bits/{t('cry.pwd_char')}")
        lines.append(f"{t('cry.pwd_total_entropy')}: {total_entropy:.2f} bits")
        lines.append(f"{t('cry.pwd_ideal_entropy')}: {ideal_entropy:.2f} bits")

        # ---- 3. 常见弱密码检测 ----
        common_passwords = [
            "123456", "password", "12345678", "qwerty", "123456789", "12345",
            "1234", "111111", "1234567", "dragon", "123123", "baseball",
            "abc123", "football", "monkey", "letmein", "shadow", "master",
            "666666", "qwertyuiop", "123321", "mustang", "1234567890",
            "michael", "654321", "superman", "1qaz2wsx", "7777777",
            "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1",
            "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster",
            "soccer", "harley", "batman", "andrew", "tigger", "sunshine",
            "iloveyou", "2000", "charlie", "robert", "thomas", "hockey",
            "ranger", "daniel", "starwars", "klaster", "112233", "george",
            "computer", "michelle", "jessica", "pepper", "1111", "zxcvbn",
            "555555", "11111111", "131313", "freedom", "777777", "pass",
            "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua",
            "cheese", "amanda", "summer", "love", "ashley", "nicole",
            "chelsea", "biteme", "matthew", "access", "yankees", "987654321",
            "dallas", "austin", "thunder", "taylor", "matrix", "mobilemail",
            "admin", "passwd", "root", "toor", "changeme", "welcome",
            "p@ssw0rd", "passw0rd", "test", "guest", "default",
        ]
        is_common = password.lower() in common_passwords

        lines.append("")
        lines.append(f"--- {t('cry.pwd_checks')} ---")
        if is_common:
            lines.append(f"[!] {t('cry.pwd_is_common')}")
        else:
            lines.append(f"[+] {t('cry.pwd_not_common')}")

        # ---- 4. 键盘模式检测 ----
        keyboard_patterns = [
            "qwerty", "qwertz", "azerty", "asdfgh", "zxcvbn",
            "qazwsx", "1qaz2wsx", "1234567890", "123456789", "12345678",
            "1234567", "123456", "12345", "1234", "0987654321",
            "abcdef", "abcdefgh", "abc123", "aaa", "zzz",
            "qweasd", "zaqwsx", "qweasdzxc",
        ]
        found_patterns = []
        pw_lower = password.lower()
        for pat in keyboard_patterns:
            if pat in pw_lower:
                found_patterns.append(pat)
            # 也检查反转
            if pat[::-1] in pw_lower and pat[::-1] != pat:
                found_patterns.append(pat[::-1])
        if found_patterns:
            lines.append(f"[!] {t('cry.pwd_keyboard_pattern')}: {', '.join(found_patterns)}")
        else:
            lines.append(f"[+] {t('cry.pwd_no_keyboard_pattern')}")

        # ---- 5. 重复字符检测 ----
        max_repeat = 1
        current_repeat = 1
        for i in range(1, length):
            if password[i] == password[i - 1]:
                current_repeat += 1
                max_repeat = max(max_repeat, current_repeat)
            else:
                current_repeat = 1
        if max_repeat >= 3:
            lines.append(f"[!] {t('cry.pwd_repeat_char')}: {max_repeat} {t('cry.pwd_consecutive')}")
        else:
            lines.append(f"[+] {t('cry.pwd_no_repeat')}")

        # ---- 6. 评分 (0-100) ----
        score = 0
        # 长度分 (最多 30 分)
        score += min(length * 3, 30)
        # 字符类型分 (最多 20 分)
        type_count = sum([has_lower, has_upper, has_digit, has_special])
        score += type_count * 5
        # 熵分 (最多 30 分)
        score += min(int(total_entropy / 2), 30)
        # 扣分
        if is_common:
            score = min(score, 5)
        if found_patterns:
            score -= 15
        if max_repeat >= 3:
            score -= 10
        if length < 6:
            score -= 15
        score = max(0, min(100, score))

        if score < 25:
            level = t("cry.pwd_level_weak")
        elif score < 50:
            level = t("cry.pwd_level_medium")
        elif score < 75:
            level = t("cry.pwd_level_strong")
        else:
            level = t("cry.pwd_level_very_strong")

        lines.append("")
        lines.append(f"--- {t('cry.pwd_score')} ---")
        lines.append(f"{t('cry.pwd_score')}: {score}/100 ({level})")
        bar_filled = score // 5
        bar_empty = 20 - bar_filled
        lines.append(f"[{'█' * bar_filled}{'░' * bar_empty}]")

        # ---- 7. 暴力破解时间估算 ----
        lines.append("")
        lines.append(f"--- {t('cry.pwd_brute_time')} ---")
        total_combinations = charset_size ** length
        # 假设不同攻击速度（次/秒）
        speeds = [
            (t("cry.pwd_speed_online"), 1_000),
            (t("cry.pwd_speed_offline_cpu"), 1_000_000_000),
            (t("cry.pwd_speed_offline_gpu"), 100_000_000_000),
        ]
        for speed_name, speed in speeds:
            seconds = total_combinations / speed / 2  # 平均情况
            lines.append(f"  {speed_name}: {self._format_time(seconds)}")

        # ---- 8. 改进建议 ----
        lines.append("")
        lines.append(f"--- {t('cry.pwd_suggestions')} ---")
        suggestions = []
        if length < 12:
            suggestions.append(t("cry.pwd_suggest_longer"))
        if not has_upper:
            suggestions.append(t("cry.pwd_suggest_upper"))
        if not has_lower:
            suggestions.append(t("cry.pwd_suggest_lower"))
        if not has_digit:
            suggestions.append(t("cry.pwd_suggest_digit"))
        if not has_special:
            suggestions.append(t("cry.pwd_suggest_special"))
        if is_common:
            suggestions.append(t("cry.pwd_suggest_not_common"))
        if found_patterns:
            suggestions.append(t("cry.pwd_suggest_no_pattern"))
        if max_repeat >= 3:
            suggestions.append(t("cry.pwd_suggest_no_repeat"))
        if not suggestions:
            suggestions.append(t("cry.pwd_suggest_good"))
        for i, s in enumerate(suggestions, 1):
            lines.append(f"  {i}. {s}")

        return "\n".join(lines)

    def _format_time(self, seconds: float) -> str:
        """将秒数格式化为人类可读的时间字符串。"""
        if seconds < 0.001:
            return t("cry.pwd_time_instant")
        if seconds < 60:
            return f"{seconds:.2f} {t('cry.pwd_time_seconds')}"
        if seconds < 3600:
            return f"{seconds / 60:.1f} {t('cry.pwd_time_minutes')}"
        if seconds < 86400:
            return f"{seconds / 3600:.1f} {t('cry.pwd_time_hours')}"
        if seconds < 86400 * 365:
            return f"{seconds / 86400:.1f} {t('cry.pwd_time_days')}"
        years = seconds / (86400 * 365.25)
        if years < 1e6:
            return f"{years:.1f} {t('cry.pwd_time_years')}"
        if years < 1e9:
            return f"{years:.2e} {t('cry.pwd_time_years')}"
        return f"{years:.2e} {t('cry.pwd_time_years')} ({t('cry.pwd_time_heat_death')})"

    def hash_crack_online(self, hash_value: str) -> str:
        """在线哈希反查（使用公开 API）"""
        hash_value = hash_value.strip()
        lines = ["=== 在线哈希反查 ===", f"哈希值: {hash_value}"]
        # 识别哈希类型
        hash_type = self.identify_hash(hash_value)
        lines.append(f"类型: {hash_type.split(chr(10))[0] if hash_type else '未知'}")
        # 尝试 nitrxgen API
        try:
            import requests
            resp = requests.get(f"https://www.nitrxgen.net/md5db/{hash_value}", timeout=10)
            if resp.status_code == 200 and resp.text.strip():
                lines.append("\n[+] 查询成功!")
                lines.append(f"原文: {resp.text.strip()}")
                return "\n".join(lines)
        except Exception:
            pass
        lines.append("\n[-] 在线查询未找到结果")
        lines.append("建议: 尝试 cmd5.com / hashcat / john 离线破解")
        return "\n".join(lines)

    def detect_encoding(self, text: str) -> str:
        """自动检测并解码多种编码"""
        text = text.strip()
        lines = ["=== 编码自动检测 ===", f"输入长度: {len(text)} 字符", ""]
        detected = []
        # Base64
        if re.match(r'^[A-Za-z0-9+/]+=*$', text) and len(text) % 4 == 0 and len(text) >= 4:
            try:
                decoded = base64.b64decode(text).decode('utf-8', errors='replace')
                if any(32 <= ord(c) < 127 for c in decoded[:20]):
                    detected.append(("Base64", decoded))
            except Exception:
                pass
        # Base32
        if re.match(r'^[A-Z2-7]+=*$', text) and len(text) >= 8:
            try:
                decoded = base64.b32decode(text).decode('utf-8', errors='replace')
                if any(32 <= ord(c) < 127 for c in decoded[:20]):
                    detected.append(("Base32", decoded))
            except Exception:
                pass
        # Hex
        if re.match(r'^[0-9a-fA-F]+$', text) and len(text) % 2 == 0:
            try:
                decoded = bytes.fromhex(text).decode('utf-8', errors='replace')
                if any(32 <= ord(c) < 127 for c in decoded[:20]):
                    detected.append(("Hex", decoded))
            except Exception:
                pass
        # URL encoding
        if '%' in text:
            from urllib.parse import unquote
            decoded = unquote(text)
            if decoded != text:
                detected.append(("URL 编码", decoded))
        # Base58
        if re.match(r'^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$', text):
            try:
                result = self.base58_decode(text)
                if "Base58" in result:
                    detected.append(("Base58", result.split("\n")[-1] if "\n" in result else result))
            except Exception:
                pass
        if not detected:
            lines.append("未检测到已知编码格式")
        else:
            for enc_type, decoded in detected:
                lines.append(f"[+] 检测到 {enc_type}:")
                lines.append(f"    解码: {decoded[:200]}")
                lines.append("")
        return "\n".join(lines)
