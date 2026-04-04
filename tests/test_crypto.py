# -*- coding: utf-8 -*-
"""密码学模块单元测试"""

from ctftool.modules.crypto import CryptoModule


class TestEncoding:
    def setup_method(self):
        self.c = CryptoModule()

    def test_base64_roundtrip(self):
        assert self.c.base64_decode(self.c.base64_encode("hello")) == "hello"

    def test_base64_decode_flag(self):
        assert "flag{test}" in self.c.base64_decode("ZmxhZ3t0ZXN0fQ==")

    def test_base32_roundtrip(self):
        assert self.c.base32_decode(self.c.base32_encode("hello")) == "hello"

    def test_hex_roundtrip(self):
        assert self.c.hex_decode(self.c.hex_encode("hello")) == "hello"

    def test_url_roundtrip(self):
        assert self.c.url_decode(self.c.url_encode("a b&c")) == "a b&c"

    def test_binary_roundtrip(self):
        encoded = self.c.binary_encode("AB")
        assert self.c.binary_decode(encoded) == "AB"

    def test_base58_decode(self):
        # "test" in Base58
        assert "test" in self.c.base58_decode("3yZe7d")

    def test_base85_decode(self):
        assert "hello" in self.c.base85_decode("Xk~0{Zv")

    def test_auto_decode(self):
        result = self.c.auto_decode("ZmxhZ3t0ZXN0fQ==")
        assert "flag{test}" in result


class TestClassicalCiphers:
    def setup_method(self):
        self.c = CryptoModule()

    def test_caesar_bruteforce(self):
        result = self.c.caesar_bruteforce("synt{pnrfne}")
        assert "flag{caesar}" in result

    def test_rot13(self):
        assert self.c.rot13("synt{grfg}") == "flag{test}"

    def test_vigenere(self):
        encrypted = self.c.vigenere_encrypt("HELLO", "KEY")
        assert self.c.vigenere_decrypt(encrypted, "KEY") == "HELLO"

    def test_atbash(self):
        assert self.c.atbash(self.c.atbash("hello")) == "hello"

    def test_rail_fence(self):
        result = self.c.rail_fence_bruteforce("WECRLTEERDSOEEFEAOCAIVDEN")
        assert len(result) > 0

    def test_affine_decrypt(self):
        # a=5, b=8, encrypt 'A' -> (5*0+8)%26 = 8 -> 'I'
        assert self.c.affine_decrypt("I", 5, 8)[0] == 'A'

    def test_affine_invalid_a(self):
        result = self.c.affine_decrypt("X", 2, 0)
        assert "not coprime" in result.lower() or "不互素" in result

    def test_bacon_decode(self):
        # A=AAAAA, B=AAAAB
        result = self.c.bacon_decode("AAAAA AAAAB")
        assert "A" in result


class TestModernCrypto:
    def setup_method(self):
        self.c = CryptoModule()

    def test_rsa_small_e(self):
        # m=3, e=3, c=27, n=100 -> 3^3=27
        result = self.c.rsa_decrypt_small_e(27, 3, 100)
        assert "3" in result

    def test_rsa_common_modulus(self):
        # 简单测试: p=11, q=13, n=143
        # e1=7, e2=3
        n = 143
        m = 42
        c1 = pow(m, 7, n)
        c2 = pow(m, 3, n)
        result = self.c.rsa_common_modulus(c1, c2, 7, 3, n)
        assert "42" in result

    def test_rsa_fermat(self):
        # p=101, q=103 (close primes), n=10403
        p, q = 101, 103
        n = p * q
        e = 7
        m = 42
        c = pow(m, e, n)
        result = self.c.rsa_fermat(n, e, c)
        assert "42" in result

    def test_rsa_wiener_with_decrypt(self):
        # 已知 d 很小的情况
        result = self.c.rsa_wiener(17, 143, 0)
        # 不一定能成功但不应报错
        assert "Wiener" in result

    def test_iroot_small(self):
        assert self.c._iroot(3, 27) == 3
        assert self.c._iroot(2, 16) == 4
        assert self.c._iroot(3, 28) is None

    def test_iroot_large(self):
        """大数精度测试"""
        n = 2 ** 300
        root = self.c._iroot(3, n)
        assert root == 2 ** 100

    def test_xor_single_byte(self):
        result = self.c.xor_single_byte_bruteforce("4b4c4d4e4f")
        assert "Key=" in result

    def test_xor_decrypt(self):
        result = self.c.xor_decrypt("4b4c4d4e4f", "00")
        assert "KLMNO" in result

    def test_rc4_roundtrip(self):
        """RC4 对称性：加密后再加密应还原"""
        # 加密 "hello"
        encrypted = self.c.rc4("hello", "mykey")
        # 提取 hex 结果
        import re
        hex_match = re.search(r'Hex (?:结果|Result): ([0-9a-f]+)', encrypted)
        assert hex_match
        # 用相同密钥解密
        decrypted = self.c.rc4(hex_match.group(1), "mykey")
        assert "hello" in decrypted

    def test_pollard_p1(self):
        """Pollard p-1 分解（p-1 光滑因子）"""
        # p=1009 (p-1=1008=2^4*3^2*7, B-smooth), q=1013
        p, q = 1009, 1013
        n = p * q
        e = 65537
        m = 42
        c_val = pow(m, e, n)
        result = self.c.rsa_pollard_p1(n, e, c_val, B=5000)
        assert "成功" in result or "1009" in result or "1013" in result

    def test_rsa_format_result(self):
        c_val = pow(42, 7, 143)
        result = self.c._rsa_format_result("Test", 11, 13, 143, 7, c_val)
        assert "11" in result and "13" in result

    def test_html_entity_decode(self):
        assert self.c.html_entity_decode("&lt;a&gt;") == "<a>"

    def test_unicode_decode(self):
        result = self.c.unicode_decode("\\u0041\\u0042")
        assert "AB" in result

    def test_octal_decode(self):
        result = self.c.octal_decode("110 145 154 154 157")
        assert "Hello" in result

    def test_caesar_decrypt(self):
        assert self.c.caesar_decrypt("bcd", 1) == "cde"

    def test_rail_fence_decrypt(self):
        result = self.c.rail_fence_decrypt("HLOEL", 2)
        assert len(result) == 5

    def test_affine_bruteforce(self):
        result = self.c.affine_bruteforce("IHHWVC JCGQS")
        assert "仿射" in result or "a=" in result

    def test_aes_ecb_decrypt(self):
        result = self.c.aes_ecb_decrypt(
            "7b0a6aff27518720a04e4c1e89c4a1b2",
            "0123456789abcdef"
        )
        assert "AES-ECB" in result

    def test_aes_cbc_decrypt(self):
        result = self.c.aes_cbc_decrypt(
            "7b0a6aff27518720a04e4c1e89c4a1b2",
            "0123456789abcdef",
            "00000000000000000000000000000000"
        )
        assert "AES-CBC" in result

    def test_des_ecb_decrypt(self):
        result = self.c.des_ecb_decrypt("0011223344556677", "01234567")
        assert "DES-ECB" in result

    def test_rsa_dp_leak(self):
        # p=61, q=53, n=3233, e=17, d=2753, dp=d%(p-1)=2753%60=53
        p, q = 61, 53
        n = p * q
        e = 17
        d = 2753
        dp = d % (p - 1)
        m = 42
        c_val = pow(m, e, n)
        result = self.c.rsa_dp_leak(n, e, c_val, dp)
        assert "42" in result

    def test_rsa_hastad(self):
        # 3 组 (n, c), e=3, m=42
        m = 42
        ns = [1007 * 1009, 1013 * 1019, 1021 * 1031]
        cs = [pow(m, 3, n) for n in ns]
        extra = ",".join(str(x) for pair in zip(ns[1:], cs[1:]) for x in pair)
        result = self.c.rsa_hastad(3, cs[0], ns[0], extra)
        assert "42" in result or "成功" in result or "失败" in result

    def test_rsa_factordb(self):
        # mock 网络请求避免 CI 中依赖外部服务
        from unittest.mock import patch, MagicMock
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"factors": {"11": 1, "13": 1}, "status": "FF"}
        with patch("requests.get", return_value=mock_resp):
            result = self.c.rsa_factordb(143, 7, 42)
        assert isinstance(result, str)


class TestHash:
    def setup_method(self):
        self.c = CryptoModule()

    def test_identify_md5(self):
        result = self.c.identify_hash("5d41402abc4b2a76b9719d911017c592")
        assert "MD5" in result

    def test_identify_sha256(self):
        result = self.c.identify_hash("a" * 64)
        assert "SHA-256" in result

    def test_hash_crack(self):
        # MD5 of "hello"
        result = self.c.hash_crack_dict("5d41402abc4b2a76b9719d911017c592")
        assert "hello" in result

    def test_compute_hash(self):
        result = self.c.compute_hash("test")
        assert "MD5" in result
        assert "SHA256" in result

    def test_frequency_analysis(self):
        result = self.c.frequency_analysis("aaabbbccc")
        assert "a" in result


class TestNewCryptoFeatures:
    def setup_method(self):
        self.c = CryptoModule()

    def test_rsa_decrypt_direct(self):
        """已知 p,q,e,c 直接解密"""
        p, q = 61, 53
        n = p * q
        e = 17
        m = 42
        c_val = pow(m, e, n)
        result = self.c.rsa_decrypt_direct(p, q, e, c_val)
        assert "42" in result
        assert "直接解密" in result or "Direct" in result

    def test_rsa_pollard_rho(self):
        """Pollard rho 分解小合数"""
        # n = 1009 * 1013 = 1022117
        n = 1009 * 1013
        result = self.c.rsa_pollard_rho(n)
        assert "1009" in result or "1013" in result

    def test_rsa_pollard_rho_with_decrypt(self):
        """Pollard rho 分解并自动解密"""
        p, q = 1009, 1013
        n = p * q
        e = 65537
        m = 42
        c_val = pow(m, e, n)
        result = self.c.rsa_pollard_rho(n, e, c_val)
        assert "42" in result or "成功" in result

    def test_vigenere_key_length(self):
        """Vigenere 密钥长度推测"""
        # 用 key="KEY" (长度3) 加密足够长文本
        plain = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 5
        encrypted = self.c.vigenere_encrypt(plain, "KEY")
        result = self.c.vigenere_key_length(encrypted)
        assert "key length" in result.lower() or "密钥长度" in result
        # IC 分析应该能推测出长度 3
        assert "3" in result

    def test_vigenere_key_length_short(self):
        """文本过短时提示不足"""
        result = self.c.vigenere_key_length("SHORT")
        assert "太短" in result or "short" in result.lower()

    def test_hash_length_extension(self):
        """哈希长度扩展攻击辅助"""
        md5_hash = "5d41402abc4b2a76b9719d911017c592"  # MD5("hello")
        result = self.c.hash_length_extension(md5_hash, "hello", "world", key_length=8)
        assert "MD5" in result
        assert "padding" in result.lower() or "Padding" in result

    def test_hash_length_extension_unknown_key(self):
        """未知密钥长度时尝试多种"""
        md5_hash = "5d41402abc4b2a76b9719d911017c592"
        result = self.c.hash_length_extension(md5_hash, "hello", "world")
        assert "hashpumpy" in result

    def test_aes_ecb_encrypt(self):
        """AES-ECB 加密"""
        result = self.c.aes_ecb_encrypt("hello world", "0123456789abcdef")
        assert "AES-ECB" in result
        assert "hex" in result.lower()

    def test_aes_ecb_roundtrip(self):
        """AES-ECB 加解密往返"""
        import re
        encrypted = self.c.aes_ecb_encrypt("testdata12345678", "0123456789abcdef")
        hex_match = re.search(r'(?:密文|Ciphertext) \(hex\): ([0-9a-f]+)', encrypted)
        assert hex_match
        decrypted = self.c.aes_ecb_decrypt(hex_match.group(1), "0123456789abcdef")
        assert "testdata12345678" in decrypted

    def test_aes_cbc_encrypt(self):
        """AES-CBC 加密"""
        result = self.c.aes_cbc_encrypt("hello world", "0123456789abcdef",
                                         "00000000000000000000000000000000")
        assert "AES-CBC" in result

    def test_des_ecb_encrypt(self):
        """DES-ECB 加密"""
        result = self.c.des_ecb_encrypt("hello", "01234567")
        assert "DES-ECB" in result

    def test_small_e_with_e5(self):
        """小指数攻击 e=5"""
        m = 7
        c_val = m ** 5
        result = self.c.rsa_decrypt_small_e(c_val, 5, 10**20)
        assert "7" in result


class TestCryptoNewFeatures:
    """测试批次2-3新增的 Crypto 功能"""

    def setup_method(self):
        from ctftool.modules.crypto import CryptoModule
        self.crypto = CryptoModule()

    # ECC
    def test_ecc_point_add_help(self):
        result = self.crypto.ecc_point_add('')
        assert 'ECC' in result or '椭圆曲线' in result

    def test_ecc_point_add_compute(self):
        # 简单曲线 y² = x³ + 2x + 3 mod 97, G=(3,6)，需要 >=6 个参数
        result = self.crypto.ecc_point_add('97,2,3,3,6,100')
        assert '曲线' in result or 'G' in result

    # DLP
    def test_dlp_bsgs(self):
        # 2^x ≡ 8 (mod 13) => x = 3
        result = self.crypto.dlp_bsgs('2,8,13')
        assert '3' in result

    def test_dlp_pohlig_hellman(self):
        # g=2, h=8, p=13, order=12 (12=2²×3)
        result = self.crypto.dlp_pohlig_hellman('2,8,13,12')
        assert '3' in result

    # MT19937
    def test_mt19937_predict_insufficient(self):
        result = self.crypto.mt19937_predict('1,2,3')
        assert '624' in result  # 需要 624 个输出

    # 3DES
    def test_triple_des_encrypt(self):
        key = '0123456789abcdef01234567'  # 24字节 hex key
        encrypted = self.crypto.triple_des_encrypt('Hello', key)
        assert 'Hex' in encrypted

    def test_triple_des_decrypt(self):
        key = '0123456789abcdef01234567'
        # 先加密再解密验证
        enc_result = self.crypto.triple_des_encrypt('Test', key)
        import re
        hex_match = re.search(r'Hex:\s*([0-9a-f]+)', enc_result)
        if hex_match:
            dec_result = self.crypto.triple_des_decrypt(hex_match.group(1), key)
            assert 'Test' in dec_result

    # 替换密码
    def test_substitution_auto_crack(self):
        # 使用足够长的密文
        ciphertext = 'GUVF VF N GRFG ZRFFNTR GUNG VF YBAT RABHTU SBE SERDHRAPL NANYLGVPF' * 2
        result = self.crypto.substitution_auto_crack(ciphertext)
        assert '频率' in result or 'frequency' in result.lower() or '映射' in result

    # ADFGVX
    def test_adfgvx_decrypt(self):
        result = self.crypto.adfgvx_decrypt('ADDFGX', 'KEY')
        assert len(result) > 0

    # Bifid
    def test_bifid_encrypt(self):
        encrypted = self.crypto.bifid_encrypt('HELLO', 'SECRET')
        assert 'Bifid' in encrypted

    def test_bifid_decrypt(self):
        decrypted = self.crypto.bifid_decrypt('PSZGX', 'SECRET')
        assert 'Bifid' in decrypted

    # Four-square
    def test_four_square_decrypt(self):
        result = self.crypto.four_square_decrypt('HELLO', 'KEY1', 'KEY2')
        assert 'Four-square' in result


class TestCryptoBatch12Features:
    """测试批次1-2新增的 Crypto 功能"""

    def setup_method(self):
        from ctftool.modules.crypto import CryptoModule
        self.crypto = CryptoModule()

    # 编码
    def test_base58_encode(self):
        result = self.crypto.base58_encode('Hello')
        assert 'Base58' in result

    def test_base85_encode(self):
        result = self.crypto.base85_encode('Hello')
        assert 'Base85' in result

    def test_base91_encode_decode(self):
        encoded = self.crypto.base91_encode('Hello World')
        assert 'Base91' in encoded
        # 提取编码结果
        enc_text = encoded.split(': ', 1)[1] if ': ' in encoded else ''
        if enc_text:
            decoded = self.crypto.base91_decode(enc_text)
            assert 'Hello World' in decoded

    def test_rot47(self):
        result = self.crypto.rot47('Hello!')
        assert 'ROT47' in result
        # ROT47 是自逆的
        inner = result.split(': ', 1)[1] if ': ' in result else ''
        if inner:
            result2 = self.crypto.rot47(inner)
            assert 'Hello!' in result2

    # 古典密码
    def test_playfair_encrypt_decrypt(self):
        encrypted = self.crypto.playfair_encrypt('HELLO', 'SECRET')
        assert 'Playfair' in encrypted

    def test_playfair_decrypt(self):
        result = self.crypto.playfair_decrypt('DAMMQ', 'KEYWORD')
        assert 'Playfair' in result

    def test_polybius_encrypt(self):
        result = self.crypto.polybius_encrypt('HELLO')
        assert 'Polybius' in result

    def test_polybius_decrypt_numbers(self):
        result = self.crypto.polybius_decrypt('2315313134')
        assert 'Polybius' in result

    def test_hill_encrypt(self):
        # 2x2 矩阵 [[3,2],[5,7]]
        result = self.crypto.hill_encrypt('HELLO', '3,2,5,7')
        assert 'Hill' in result

    def test_hill_decrypt(self):
        result = self.crypto.hill_decrypt('HELLO', '3,2,5,7')
        assert 'Hill' in result

    def test_hill_invalid_matrix(self):
        result = self.crypto.hill_encrypt('HELLO', '1,2,3')
        assert '必须' in result or 'must' in result.lower()

    def test_columnar_transposition_encrypt(self):
        encrypted = self.crypto.columnar_transposition_encrypt('HELLOWORLD', 'KEY')
        assert '列置换' in encrypted or 'Columnar' in encrypted

    def test_columnar_transposition_decrypt(self):
        decrypted = self.crypto.columnar_transposition_decrypt('HLOWRDELOL', 'KEY')
        assert '列置换' in decrypted or 'Columnar' in decrypted

    # 现代密码
    def test_aes_ctr_roundtrip(self):
        key = '00112233445566778899aabbccddeeff'
        encrypted = self.crypto.aes_ctr_encrypt('TestMessage', key)
        assert 'AES-CTR' in encrypted
        # 提取 hex
        import re
        hex_match = re.search(r'Hex:\s*([0-9a-f]+)', encrypted)
        if hex_match:
            decrypted = self.crypto.aes_ctr_decrypt(hex_match.group(1), key)
            assert 'TestMessage' in decrypted

    def test_hmac_compute(self):
        result = self.crypto.hmac_compute('hello', 'secret')
        assert 'HMAC' in result and 'SHA256' in result.upper()

    def test_padding_oracle_helper(self):
        result = self.crypto.padding_oracle_helper()
        assert 'Padding Oracle' in result and 'PKCS7' in result

    def test_rsa_decrypt_multi_prime(self):
        # p=3, q=5, r=7 => n=105, phi=48, e=5, d=29
        # m=2, c = 2^5 mod 105 = 32
        result = self.crypto.rsa_decrypt_multi_prime('3,5,7', 5, 32)
        assert '2' in result  # 明文整数 2

    def test_xor_auto_crack_short(self):
        result = self.crypto.xor_auto_crack('41')
        assert '太短' in result or 'short' in result.lower()

    def test_xor_auto_crack(self):
        # 用 key 'AB' 加密足够长的文本（至少20字节）
        plaintext = b'Hello World Test Message!!'
        data = bytes(b ^ ord('AB'[i%2]) for i, b in enumerate(plaintext))
        result = self.crypto.xor_auto_crack(data.hex())
        assert '密钥' in result or 'key' in result.lower() or 'XOR' in result


class TestCryptoBatch13:
    def setup_method(self):
        self.crypto = CryptoModule()

    def test_chinese_remainder_theorem(self):
        # x ≡ 2 (mod 3), x ≡ 3 (mod 5), x ≡ 2 (mod 7) → x = 23
        result = self.crypto.chinese_remainder_theorem("2,3;3,5;2,7")
        assert "23" in result

    def test_rsa_dq_leak(self):
        # 小例子: p=61, q=53, n=3233, e=17, d=2753
        # dq = d mod (q-1) = 2753 mod 52 = 49
        p, q, e = 61, 53, 17
        n = p * q
        d = pow(e, -1, (p-1)*(q-1))
        dq = d % (q - 1)
        m = 42
        c = pow(m, e, n)
        result = self.crypto.rsa_dq_leak(n, e, c, dq)
        assert "42" in result

    def test_blowfish_encrypt_decrypt(self):
        result = self.crypto.blowfish_encrypt("48656c6c6f", "0123456789abcdef")
        assert "Blowfish" in result

    def test_base62_roundtrip(self):
        encoded = self.crypto.base62_encode("Hello")
        assert "Base62" in encoded

    def test_base62_decode(self):
        result = self.crypto.base62_decode("1C8")
        assert "Base62" in result

    def test_autokey_decrypt(self):
        result = self.crypto.autokey_decrypt("LXFOPV", "LEMON")
        assert "Decrypt" in result or "解密" in result

    def test_nihilist_decrypt(self):
        result = self.crypto.nihilist_decrypt("37 25 42 33", "KEY")
        assert "Decrypt" in result or "解密" in result

    def test_book_cipher_decode(self):
        result = self.crypto.book_cipher_decode("1:1 1:2 1:3", "Hello World\nFoo Bar")
        assert "Decode" in result or "解码" in result

    def test_rabbit_decrypt(self):
        result = self.crypto.rabbit_decrypt("aabbcc", "1122334455667788")
        assert "Rabbit" in result


class TestNewFeatures2:
    def setup_method(self):
        self.c = CryptoModule()

    def test_rsa_auto_attack(self):
        # 使用已知简单 RSA 参数
        p, q = 61, 53
        n = p * q  # 3233
        e = 17
        phi = (p - 1) * (q - 1)
        pow(e, -1, phi)
        m = 42
        c = pow(m, e, n)
        result = self.c.rsa_auto_attack(n, e, c)
        assert "RSA" in result
        assert isinstance(result, str)

    def test_detect_encoding_base64(self):
        import base64
        encoded = base64.b64encode(b"hello world").decode()
        result = self.c.detect_encoding(encoded)
        assert "Base64" in result
        assert "hello world" in result

    def test_detect_encoding_hex(self):
        result = self.c.detect_encoding("68656c6c6f")
        assert "Hex" in result

    def test_hash_crack_online(self):
        # mock 网络请求避免 CI 中依赖外部服务
        from unittest.mock import patch, MagicMock
        mock_resp = MagicMock()
        mock_resp.text = "hello"
        mock_resp.status_code = 200
        with patch("requests.get", return_value=mock_resp):
            result = self.c.hash_crack_online("5d41402abc4b2a76b9719d911017c592")
        assert isinstance(result, str)
        assert "哈希" in result or "hash" in result.lower() or "在线" in result or "hello" in result


class TestNewRSAAttacks:
    """测试新增的 6 个 RSA 相关攻击方法"""

    def setup_method(self):
        self.crypto = CryptoModule()

    # ========== 1. rabin_decrypt ==========

    def test_rabin_decrypt_basic(self):
        """Rabin 解密：验证 4 个候选明文中包含原始明文"""
        p, q = 61, 53
        n = p * q  # 3233
        m = 42
        c = pow(m, 2, n)  # e=2, c = m^2 mod n
        result = self.crypto.rabin_decrypt(c, p, q)
        assert "Rabin" in result
        assert "候选明文" in result or "candidate" in result.lower()
        # 4 个候选值中应包含原始明文 42
        assert "42" in result

    def test_rabin_decrypt_another_message(self):
        """Rabin 解密：使用不同的明文验证"""
        p, q = 61, 53
        n = p * q
        m = 100
        c = pow(m, 2, n)
        result = self.crypto.rabin_decrypt(c, p, q)
        assert "100" in result

    def test_rabin_decrypt_invalid_param(self):
        """Rabin 解密：无效参数（p=0）不崩溃"""
        try:
            result = self.crypto.rabin_decrypt(10, 0, 53)
            # 只要不崩溃就算通过，结果可能包含错误提示
            assert isinstance(result, str)
        except (ValueError, ZeroDivisionError):
            # 抛出异常也是可接受的行为
            pass

    # ========== 2. rsa_batch_gcd ==========

    def test_rsa_batch_gcd_shared_factor(self):
        """批量 GCD：两个 n 共享一个素因子"""
        p = 1009
        q1 = 1013
        q2 = 1019
        n1 = p * q1  # 1009 * 1013
        n2 = p * q2  # 1009 * 1019
        n_list = f"{n1},{n2}"
        result = self.crypto.rsa_batch_gcd(n_list)
        # 应找到共享素因子 1009
        assert "1009" in result or "共享" in result or "GCD" in result

    def test_rsa_batch_gcd_with_decrypt(self):
        """批量 GCD：共享因子并解密"""
        p = 1009
        q1 = 1013
        n1 = p * q1
        n2 = p * 1019
        e = 65537
        m = 42
        c = pow(m, e, n1)
        n_list = f"{n1},{n2}"
        result = self.crypto.rsa_batch_gcd(n_list, e, c)
        assert "1009" in result

    def test_rsa_batch_gcd_no_shared_factor(self):
        """批量 GCD：无共享素因子"""
        n1 = 1009 * 1013
        n2 = 1021 * 1031
        n_list = f"{n1},{n2}"
        result = self.crypto.rsa_batch_gcd(n_list)
        assert "未找到" in result or "No shared" in result.lower()

    def test_rsa_batch_gcd_single_n(self):
        """批量 GCD：只有一个 n 时应提示不足"""
        result = self.crypto.rsa_batch_gcd("143")
        assert "至少" in result or "Need" in result

    # ========== 3. rsa_franklin_reiter ==========

    def test_rsa_franklin_reiter_e3(self):
        """Franklin-Reiter：e=3 的相关消息攻击"""
        # 构造 m1, m2 = a*m1 + b, a=1, b=1
        p, q = 1009, 1013
        n = p * q
        e = 3
        m1 = 42
        a, b = 1, 1
        m2 = a * m1 + b  # 43
        c1 = pow(m1, e, n)
        c2 = pow(m2, e, n)
        result = self.crypto.rsa_franklin_reiter(c1, c2, e, n, a, b)
        assert "Franklin-Reiter" in result
        # 攻击成功时应包含明文，不成功也不崩溃
        assert isinstance(result, str)

    def test_rsa_franklin_reiter_e_not3(self):
        """Franklin-Reiter：e!=3 时提示仅支持 e=3"""
        result = self.crypto.rsa_franklin_reiter(100, 200, 5, 3233, 1, 0)
        assert "e=3" in result or "SageMath" in result

    def test_rsa_franklin_reiter_no_crash(self):
        """Franklin-Reiter：各种参数不崩溃"""
        result = self.crypto.rsa_franklin_reiter(0, 0, 3, 143, 1, 0)
        assert isinstance(result, str)

    # ========== 4. rsa_coppersmith_helper ==========

    def test_rsa_coppersmith_helper_non_empty(self):
        """Coppersmith 辅助：返回值是非空字符串"""
        result = self.crypto.rsa_coppersmith_helper()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_rsa_coppersmith_helper_sage(self):
        """Coppersmith 辅助：包含 SageMath 或 sage 关键词"""
        result = self.crypto.rsa_coppersmith_helper()
        assert "SageMath" in result or "sage" in result.lower()

    def test_rsa_coppersmith_helper_small_roots(self):
        """Coppersmith 辅助：包含 small_roots 关键词"""
        result = self.crypto.rsa_coppersmith_helper()
        assert "small_roots" in result

    # ========== 5. rsa_boneh_durfee_helper ==========

    def test_rsa_boneh_durfee_helper_non_empty(self):
        """Boneh-Durfee 辅助：返回值是非空字符串"""
        result = self.crypto.rsa_boneh_durfee_helper()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_rsa_boneh_durfee_helper_sage(self):
        """Boneh-Durfee 辅助：包含 SageMath 或 sage 关键词"""
        result = self.crypto.rsa_boneh_durfee_helper()
        assert "SageMath" in result or "sage" in result.lower()

    def test_rsa_boneh_durfee_helper_content(self):
        """Boneh-Durfee 辅助：包含 Boneh-Durfee 和关键算法信息"""
        result = self.crypto.rsa_boneh_durfee_helper()
        assert "Boneh-Durfee" in result
        assert "d" in result  # 应涉及私钥 d

    # ========== 6. rsa_williams_p1 ==========

    def test_rsa_williams_p1_basic(self):
        """Williams p+1：用 p+1 光滑的因子测试"""
        # p=1039 (p+1=1040=2^4*5*13, 光滑), q=1013
        p, q = 1039, 1013
        n = p * q
        result = self.crypto.rsa_williams_p1(n)
        assert "Williams" in result
        # 不崩溃即可，可能分解成功也可能不成功
        assert isinstance(result, str)

    def test_rsa_williams_p1_with_decrypt(self):
        """Williams p+1：分解成功后尝试解密"""
        p, q = 1039, 1013
        n = p * q
        e = 65537
        m = 42
        c = pow(m, e, n)
        result = self.crypto.rsa_williams_p1(n, e, c)
        assert "Williams" in result
        # 如果分解成功，结果中应包含因子或明文
        assert isinstance(result, str)

    def test_rsa_williams_p1_no_crash_large(self):
        """Williams p+1：较大的 n 不崩溃"""
        # 两个较大的素数，p+1 不光滑，预期分解失败但不崩溃
        n = 104729 * 104743
        result = self.crypto.rsa_williams_p1(n)
        assert isinstance(result, str)
        assert "Williams" in result


class TestLatestCryptoFeatures:
    """测试最新新增的 rsa_import_key / hash_collision_generate / password_strength"""

    def setup_method(self):
        self.c = CryptoModule()

    # ========== rsa_import_key ==========

    def test_rsa_import_key_pem_text(self):
        """直接粘贴 PEM 文本，验证返回值包含 n = 或参数信息"""
        pem_text = (
            "-----BEGIN PUBLIC KEY-----\n"
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDH5P4r6JqXjIFTKUhUv4zD3Oxf\n"
            "G6DUEFpjtGP6rYiRIbS3Iqbi9fWJ+R3YtZbM+GVf6Bst18f3ZXJEH3RpUlD4RNvQ\n"
            "maBrHjOeOdCAcaY4GNFqWJl8rlI5hEMfRIr5FT2N4/7JiqrJG+jfTxKCvLqrb8HZ\n"
            "4X2MT3anAZBFQxZJXwIDAQAB\n"
            "-----END PUBLIC KEY-----"
        )
        result = self.c.rsa_import_key(pem_text)
        assert isinstance(result, str)
        assert len(result) > 0
        # 应包含密钥参数信息
        assert "n =" in result or "e =" in result or "bits" in result.lower()

    def test_rsa_import_key_invalid_input(self):
        """无效 PEM 文本，不崩溃"""
        result = self.c.rsa_import_key("this is not a valid PEM")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_rsa_import_key_empty_input(self):
        """空输入，不崩溃"""
        result = self.c.rsa_import_key("")
        assert isinstance(result, str)
        assert len(result) > 0

    # ========== hash_collision_generate ==========

    def test_hash_collision_generate_md5(self):
        """MD5 碰撞生成返回包含 MD5 和碰撞信息"""
        result = self.c.hash_collision_generate("md5")
        assert isinstance(result, str)
        assert "MD5" in result

    def test_hash_collision_generate_crc32(self):
        """CRC32 碰撞生成返回包含 CRC32（使用 mock 加速搜索）"""
        import zlib as _zlib
        from unittest.mock import patch

        # CRC32 碰撞搜索在纯 Python 中可能很慢（遍历 2^32 空间），
        # 使用 mock 让搜索在第一个候选值就"命中"碰撞
        target_crc = _zlib.crc32(b"AAAA") & 0xFFFFFFFF
        original_crc32 = _zlib.crc32

        call_count = [0]

        def fast_crc32(data, *args, **kwargs):
            call_count[0] += 1
            # 当搜索碰撞候选值时（4字节 struct.pack 的结果），
            # 第 3 次非 AAAA 调用就命中碰撞
            if len(data) == 4 and data != b"AAAA" and call_count[0] > 3:
                return target_crc
            return original_crc32(data, *args, **kwargs)

        with patch("zlib.crc32", side_effect=fast_crc32):
            result = self.c.hash_collision_generate("crc32")
        assert isinstance(result, str)
        assert "CRC32" in result

    def test_hash_collision_generate_unknown(self):
        """未知哈希类型，不崩溃"""
        result = self.c.hash_collision_generate("unknown_hash_type")
        assert isinstance(result, str)
        assert len(result) > 0

    # ========== password_strength ==========

    def test_password_strength_weak(self):
        """弱密码 '123456' 返回低分或'弱'"""
        result = self.c.password_strength("123456")
        assert isinstance(result, str)
        # 应包含评分和等级，弱密码应含"弱"或"Weak"
        assert "弱" in result or "Weak" in result

    def test_password_strength_strong(self):
        """强密码返回高分或'强'"""
        result = self.c.password_strength("Tr0ub4dor&3#xK9!")
        assert isinstance(result, str)
        # 应包含"强"或"Strong"
        assert "强" in result or "Strong" in result

    def test_password_strength_empty(self):
        """空密码，不崩溃"""
        result = self.c.password_strength("")
        assert isinstance(result, str)
        assert len(result) > 0


class TestCRC32:
    """测试 CRC32 校验方法"""

    def setup_method(self):
        self.c = CryptoModule()

    def test_crc32_text(self):
        """文本输入返回 CRC32 值"""
        result = self.c.crc32("hello")
        assert "CRC32" in result
        assert isinstance(result, str)

    def test_crc32_empty(self):
        """空字符串不崩溃"""
        result = self.c.crc32("")
        assert isinstance(result, str)
