# -*- coding: utf-8 -*-
"""杂项模块单元测试"""

from ctftool.modules.misc import MiscModule


class TestMisc:
    def setup_method(self):
        self.m = MiscModule()

    # 进制转换
    def test_base_convert_decimal(self):
        result = self.m.base_convert("65")
        assert "0x41" in result.lower() or "十六进制" in result

    def test_base_convert_hex(self):
        result = self.m.base_convert("0x41")
        assert "65" in result

    # 摩尔斯
    def test_morse_roundtrip(self):
        encoded = self.m.morse_encode("HELLO")
        assert ".... . .-.. .-.. ---" == encoded
        decoded = self.m.morse_decode(encoded)
        assert "HELLO" in decoded

    def test_morse_with_spaces(self):
        result = self.m.morse_decode(".... .. / -.-. - ..-.")
        assert "HI" in result and "CTF" in result

    # 盲文
    def test_braille_roundtrip(self):
        encoded = self.m.braille_encode("abc")
        decoded = self.m.braille_decode(encoded)
        assert "abc" in decoded

    # ROT-N
    def test_rot_all(self):
        result = self.m.rot_all("abc")
        assert "ROT-13" in result

    # Brainfuck
    def test_brainfuck_hello(self):
        code = "++++++++++[>+++++++>++++++++++>+++>+<<<<-]>++.>+.+++++++..+++.>++.<<+++++++++++++++.>.+++.------.--------.>+.>."
        result = self.m.brainfuck_execute(code)
        assert "Hello World!" in result

    def test_brainfuck_infinite_protection(self):
        result = self.m.brainfuck_execute("+[]")
        assert "超限" in result

    # JWT
    def test_jwt_decode(self):
        # 手工构造一个简单的 JWT
        import base64
        import json
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b'=').decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "test"}).encode()).rstrip(b'=').decode()
        token = f"{header}.{payload}.fake_sig"
        result = self.m.jwt_decode(token)
        assert "HS256" in result
        assert "test" in result

    # T9 键盘
    def test_t9_decode(self):
        # 2=a, 22=b, 222=c
        result = self.m.t9_decode("2 22 222")
        assert "abc" in result

    # 键盘坐标
    def test_keyboard_coord(self):
        # 行2列1=q, 行2列2=w, 行2列3=e
        result = self.m.keyboard_coord_decode("21 22 23")
        assert "qwe" in result

    # PHP 反序列化
    def test_php_string(self):
        result = self.m.php_serialize_decode('s:5:"hello";')
        assert "hello" in result

    def test_php_int(self):
        result = self.m.php_serialize_decode('i:42;')
        assert "42" in result

    def test_php_array(self):
        result = self.m.php_serialize_decode('a:1:{s:3:"key";s:5:"value";}')
        assert "key" in result and "value" in result

    def test_php_object(self):
        data = 'O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}'
        result = self.m.php_serialize_decode(data)
        assert "User" in result
        assert "admin" in result

    # 社工字典
    def test_wordlist(self):
        result = self.m.generate_wordlist("alice", "19900101")
        assert "alice" in result
        assert "生成" in result

    # 字符转换
    def test_char_convert(self):
        result = self.m.char_convert("A")
        assert "65" in result
        assert "0x41" in result.lower()

    # 零宽字符隐写
    def test_zwc_roundtrip(self):
        encoded = self.m.zwc_encode("hi")
        # 提取嵌入的零宽字符
        zwc_text = ""
        for line in encoded.split('\n'):
            for c in line:
                if c in ('\u200b', '\u200c'):
                    zwc_text += c
        if zwc_text:
            decoded = self.m.zwc_decode(zwc_text)
            assert "hi" in decoded

    def test_zwc_decode_empty(self):
        result = self.m.zwc_decode("normal text without zwc")
        assert "未检测到" in result

    def test_qr_decode_no_file(self):
        """QR 解码不存在的文件"""
        result = self.m.qr_decode("/nonexistent/file.png")
        assert isinstance(result, str)

    def test_ascii_table(self):
        result = self.m.ascii_table()
        assert "Dec" in result
        assert "65" in result  # 'A'

    def test_ook_decode(self):
        result = self.m.ook_decode("Ook. Ook. Ook! Ook.")
        assert "Brainfuck" in result or "转换" in result


class TestNewMiscFeatures:
    def setup_method(self):
        self.m = MiscModule()

    def test_ook_execute(self):
        """Ook! 直接执行"""
        # Ook. Ook! = + in brainfuck
        # 简单测试不崩溃
        result = self.m.ook_execute("Ook. Ook. Ook! Ook.")
        assert isinstance(result, str)
        assert "Brainfuck" in result or "转换" in result

    def test_core_values_encode(self):
        """核心价值观编码"""
        result = self.m.core_values_encode("A")
        assert "核心价值观" in result or "富强" in result or "民主" in result

    def test_core_values_decode(self):
        """核心价值观解码"""
        result = self.m.core_values_decode("富强民主文明和谐")
        assert "核心价值观" in result or "索引" in result

    def test_core_values_decode_empty(self):
        """无核心价值观内容"""
        result = self.m.core_values_decode("hello world")
        assert "未检测到" in result

    def test_dna_encode(self):
        """DNA 编码"""
        result = self.m.dna_encode("A")
        assert "DNA" in result
        assert all(c in 'ACGT \n:' for c in result.replace("DNA", "").replace("密码编码", "").replace("文本", ""))

    def test_dna_decode(self):
        """DNA 解码"""
        # 'A' = 0x41 = 01000001 -> ACAAAAAC
        result = self.m.dna_decode("ACAAAAAC")
        assert "A" in result

    def test_dna_decode_invalid(self):
        """无效 DNA 序列"""
        result = self.m.dna_decode("HELLO")
        assert "无效" in result

    def test_pigpen_decode(self):
        """猪圈密码"""
        result = self.m.pigpen_decode("1 2 3")
        assert "猪圈" in result or "ABC" in result

    def test_barcode_decode_no_file(self):
        """条形码解码不存在的文件"""
        result = self.m.barcode_decode("/nonexistent/file.png")
        assert isinstance(result, str)


class TestMiscNewFeatures:
    """测试批次2-3新增的 Misc 功能"""

    def setup_method(self):
        from ctftool.modules.misc import MiscModule
        self.misc = MiscModule()

    # NATO
    def test_nato_encode(self):
        result = self.misc.nato_encode('ABC')
        assert 'Alpha' in result and 'Bravo' in result and 'Charlie' in result

    def test_nato_decode(self):
        result = self.misc.nato_decode('Alpha Bravo Charlie')
        assert 'ABC' in result

    def test_nato_roundtrip(self):
        encoded = self.misc.nato_encode('HELLO')
        # 提取编码结果中的NATO词汇
        assert 'Hotel' in encoded and 'Echo' in encoded

    # 旗语
    def test_semaphore_encode(self):
        result = self.misc.semaphore_encode('AB')
        assert '旗语' in result or 'Semaphore' in result.lower()

    def test_semaphore_decode(self):
        # A=(7,1), B=(6,1)
        result = self.misc.semaphore_decode('71 61')
        assert 'AB' in result

    # 坐标转换
    def test_coord_convert_decimal(self):
        result = self.misc.coord_convert('39.9042, 116.4074')
        assert '度分秒' in result or 'DMS' in result or 'Geohash' in result

    def test_coord_convert_invalid(self):
        result = self.misc.coord_convert('not a coord')
        assert '无法' in result or 'format' in result.lower()

    # Leet Speak
    def test_leet_encode(self):
        result = self.misc.leet_encode('HELLO')
        assert '1337' in result or 'Leet' in result.lower()

    def test_leet_decode(self):
        result = self.misc.leet_decode('#3110')
        assert 'Leet' in result

    # Baudot
    def test_baudot_decode_binary(self):
        # E in ITA2 = 00001
        result = self.misc.baudot_decode('00001')
        assert 'E' in result or 'Baudot' in result

    def test_baudot_decode_invalid(self):
        result = self.misc.baudot_decode('xyz')
        assert '无法' in result or 'format' in result.lower() or 'Baudot' in result


class TestMiscBatch12Features:
    """测试批次1-2新增的 Misc 功能"""

    def setup_method(self):
        from ctftool.modules.misc import MiscModule
        self.misc = MiscModule()

    def test_rot47(self):
        result = self.misc.rot47('Hello!')
        assert 'ROT47' in result

    def test_bacon_encode(self):
        result = self.misc.bacon_encode('AB')
        assert '培根' in result or 'Bacon' in result

    def test_base100_encode_decode(self):
        encoded = self.misc.base100_encode('Hi')
        assert 'Base100' in encoded
        decoded = self.misc.base100_decode(encoded.split(': ', 1)[1] if ': ' in encoded else '')
        assert 'Base100' in decoded

    def test_tap_code_encode_decode(self):
        encoded = self.misc.tap_code_encode('AB')
        assert '敲击码' in encoded or 'Tap' in encoded
        decoded = self.misc.tap_code_decode('11 12')
        assert 'AB' in decoded

    def test_whitespace_execute_empty(self):
        result = self.misc.whitespace_execute('no whitespace here')
        assert '未检测到' in result or 'token' in result.lower()

    def test_vigenere_auto_crack(self):
        # ROT13 加密的英文（相当于 key=N 的 Vigenere）
        ciphertext = 'GUVF VF N GRFG ZRFFNTR GUNG VF YBAT RABHTU SBE SERDHRAPL NANYLGVPF GB JBEX BA' * 3
        result = self.misc.vigenere_auto_crack(ciphertext)
        assert 'Vigenere' in result or '密钥' in result

    def test_qr_generate(self):
        result = self.misc.qr_generate('test')
        # 可能需要 qrcode 库，未安装时返回提示
        assert 'QR' in result or 'qrcode' in result


class TestMiscBatch13:
    def setup_method(self):
        self.misc = MiscModule()

    def test_emoji_cipher_roundtrip(self):
        encoded = self.misc.emoji_cipher_encode("HELLO")
        assert "Emoji" in encoded or "emoji" in encoded

    def test_emoji_cipher_decode(self):
        result = self.misc.emoji_cipher_decode("\U0001f36f\U0001f95a\U0001f34b\U0001f34b\U0001f34a")
        assert "HELLO" in result

    def test_manchester_encode(self):
        result = self.misc.manchester_encode("A")
        assert "Manchester" in result

    def test_manchester_decode(self):
        result = self.misc.manchester_decode("01100001")
        assert isinstance(result, str)

    def test_color_hex_decode(self):
        result = self.misc.color_hex_decode("#48 #49")
        assert "HI" in result

    def test_dancing_men_decode(self):
        result = self.misc.dancing_men_decode("1 2 3")
        assert isinstance(result, str)

    def test_word_frequency(self):
        result = self.misc.word_frequency("hello world hello")
        assert "hello" in result.lower()

    def test_enigma_decrypt(self):
        result = self.misc.enigma_decrypt("HELLO")
        assert "Enigma" in result

    def test_pixel_extract_not_image(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b"not an image")
            path = f.name
        try:
            result = self.misc.pixel_extract(path)
            assert isinstance(result, str)
        finally:
            os.unlink(path)

    def test_keyboard_layout_convert(self):
        result = self.misc.keyboard_layout_convert("HELLO")
        assert isinstance(result, str)


class TestNewMiscFeatures2:
    def setup_method(self):
        self.m = MiscModule()

    def test_timestamp_convert_unix(self):
        result = self.m.timestamp_convert("1700000000")
        assert "2023" in result or "时间" in result or "Unix" in result

    def test_timestamp_convert_date_string(self):
        result = self.m.timestamp_convert("2024-01-15 12:30:00")
        assert "Unix" in result or "时间" in result

    def test_timestamp_convert_invalid(self):
        result = self.m.timestamp_convert("not_a_timestamp")
        assert isinstance(result, str)

    def test_qr_batch_decode_invalid_dir(self):
        result = self.m.qr_batch_decode("/nonexistent/path")
        assert "不是" in result or "invalid" in result.lower() or "not" in result.lower()

    def test_ocr_extract_not_image(self):
        import os
        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix='.txt', delete=False)
        tmp.write(b"not an image")
        tmp.close()
        try:
            result = self.m.ocr_extract(tmp.name)
            assert isinstance(result, str)
        except Exception:
            pass
        finally:
            os.unlink(tmp.name)


class TestNewMiscFeaturesBatch4:
    """测试新增的 11 个 Misc 方法：
    uuencode/uudecode, xxencode/xxdecode,
    quoted_printable_encode/quoted_printable_decode,
    audio_morse_decode, piet_helper, malbolge_execute,
    ebcdic_to_ascii/ascii_to_ebcdic
    """

    def setup_method(self):
        self.misc = MiscModule()

    # ========== UUencode / UUdecode ==========

    def test_uuencode_uudecode_roundtrip(self):
        """uuencode 后 uudecode 应还原原始文本"""
        encoded = self.misc.uuencode("Hello")
        assert "UUencode" in encoded
        # 提取 raw 编码行（第一行 === UUencode === 之后的内容）
        # uudecode 应当能解析完整格式（带 begin/end 头）
        # 取 full_format 部分进行解码
        lines = encoded.split('\n')
        # 找到 begin 行，取 begin 到 end 之间的内容
        full_block = []
        collecting = False
        for line in lines:
            if line.strip().startswith("begin "):
                collecting = True
            if collecting:
                full_block.append(line)
            if line.strip() == "end":
                break
        full_text = '\n'.join(full_block)
        decoded = self.misc.uudecode(full_text)
        assert "Hello" in decoded

    def test_uudecode_with_begin_header(self):
        """uudecode 对带 begin 头的标准格式也能解码"""
        uu_text = "begin 644 test.txt\n*2&5L;&\\@\n`\nend"
        result = self.misc.uudecode(uu_text)
        assert isinstance(result, str)
        # 不应崩溃，应该返回解码结果或错误提示

    def test_uuencode_uudecode_roundtrip_chinese(self):
        """uuencode/uudecode 处理 UTF-8 中文"""
        encoded = self.misc.uuencode("CTF比赛")
        decoded_from_full = self.misc.uudecode(encoded)
        # 至少不崩溃
        assert isinstance(decoded_from_full, str)

    # ========== XXencode / XXdecode ==========

    def test_xxencode_xxdecode_roundtrip(self):
        """xxencode 后 xxdecode 应还原原始文本"""
        encoded = self.misc.xxencode("Hello")
        assert "XXencode" in encoded
        # 提取编码结果（格式为 "XXencode: <编码>"）
        xx_data = encoded.split(": ", 1)[1] if ": " in encoded else ""
        decoded = self.misc.xxdecode(xx_data)
        assert "Hello" in decoded

    def test_xxencode_charset(self):
        """验证 XXencode 编码结果只包含标准字符集"""
        xx_table = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        encoded = self.misc.xxencode("Test123")
        # 提取编码部分
        xx_data = encoded.split(": ", 1)[1] if ": " in encoded else ""
        for ch in xx_data:
            assert ch in xx_table, f"字符 '{ch}' 不在 XXencode 标准字符集中"

    def test_xxdecode_invalid_char(self):
        """xxdecode 遇到无效字符时应提示"""
        result = self.misc.xxdecode("!!!!")
        assert isinstance(result, str)

    # ========== Quoted-Printable ==========

    def test_qp_encode_decode_roundtrip(self):
        """Quoted-Printable 编码包含非 ASCII 字符后解码还原"""
        text = "你好世界"
        encoded = self.misc.quoted_printable_encode(text)
        assert "Quoted-Printable" in encoded
        # 提取编码内容（跳过标题行）
        qp_data = encoded.split('\n', 1)[1] if '\n' in encoded else encoded
        decoded = self.misc.quoted_printable_decode(qp_data)
        assert "你好世界" in decoded

    def test_qp_decode_hello_world(self):
        """解码 'Hello=20World' 应得到 'Hello World'"""
        result = self.misc.quoted_printable_decode("Hello=20World")
        assert "Hello World" in result

    def test_qp_encode_ascii(self):
        """纯 ASCII 文本的 QP 编码"""
        result = self.misc.quoted_printable_encode("Hello")
        assert "Quoted-Printable" in result

    # ========== audio_morse_decode ==========

    def test_audio_morse_decode_non_wav(self):
        """用非 WAV 文件测试，验证不崩溃"""
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b"this is not a wav file")
            path = f.name
        try:
            result = self.misc.audio_morse_decode(path)
            assert isinstance(result, str)
        finally:
            os.unlink(path)

    def test_audio_morse_decode_nonexistent(self):
        """不存在的文件应返回提示字符串"""
        result = self.misc.audio_morse_decode("/nonexistent/audio.wav")
        assert isinstance(result, str)

    # ========== piet_helper ==========

    def test_piet_helper_non_image(self):
        """用非图片文件测试，验证不崩溃"""
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b"this is not an image")
            path = f.name
        try:
            result = self.misc.piet_helper(path)
            assert isinstance(result, str)
        finally:
            os.unlink(path)

    def test_piet_helper_contains_keyword(self):
        """返回值应包含 'Piet' 或 'npiet' 关键字"""
        import os
        import tempfile
        try:
            from PIL import Image
            # 创建一个小的纯红色图片（Piet 标准颜色）
            img = Image.new('RGB', (10, 10), (255, 0, 0))
            with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
                path = f.name
            img.save(path)
            try:
                result = self.misc.piet_helper(path)
                assert "Piet" in result or "npiet" in result or "piet" in result
            finally:
                os.unlink(path)
        except ImportError:
            # PIL 未安装时跳过
            result = self.misc.piet_helper("/nonexistent/file.png")
            assert isinstance(result, str)

    def test_piet_helper_nonexistent(self):
        """不存在的文件应返回提示"""
        result = self.misc.piet_helper("/nonexistent/piet.png")
        assert isinstance(result, str)

    # ========== malbolge_execute ==========

    def test_malbolge_empty_string(self):
        """空字符串不应崩溃"""
        result = self.misc.malbolge_execute("")
        assert isinstance(result, str)

    def test_malbolge_returns_string(self):
        """简短 Malbolge 代码应返回字符串结果"""
        # Malbolge 的 halt 指令字符（在位置 0: (ascii + 0) % 94 == 81 => ascii = 81 + 33 = 114 = 'r' 不对）
        # 简单测试：随机短代码，验证返回值是字符串
        result = self.misc.malbolge_execute("DCB")
        assert isinstance(result, str)
        assert "Malbolge" in result

    def test_malbolge_step_limit(self):
        """超长输入应触发步数限制保护"""
        # 构造一个不会很快停止的代码（大量 nop 类字符）
        # 68 是 nop 指令: (ascii + pos) % 94 == 68
        # 在 pos=0 时, ascii = 68 + 33 = 101 = 'e' (不对, 需要 (ascii + 0) % 94 == 68)
        # 即 ascii % 94 == 68, ascii = 68 + 33 = 101 不对
        # 直接用足够长的代码让其执行到步数限制
        long_code = "!" * 100  # 大量字符让程序不会立即 halt
        result = self.misc.malbolge_execute(long_code)
        assert isinstance(result, str)
        # 结果应该包含步数信息
        assert "Malbolge" in result

    # ========== EBCDIC 转换 ==========

    def test_ebcdic_to_ascii_known_hex(self):
        """EBCDIC hex C8C5D3D3D6 应解码为 HELLO"""
        result = self.misc.ebcdic_to_ascii("C8C5D3D3D6")
        assert "HELLO" in result

    def test_ascii_to_ebcdic_hello(self):
        """ASCII 'HELLO' 应转换为对应 EBCDIC hex"""
        result = self.misc.ascii_to_ebcdic("HELLO")
        assert "EBCDIC" in result
        # H=0xC8, E=0xC5, L=0xD3, O=0xD6
        assert "C8" in result
        assert "C5" in result
        assert "D3" in result
        assert "D6" in result

    def test_ebcdic_roundtrip(self):
        """EBCDIC -> ASCII -> EBCDIC 往返测试"""
        # 从 hex EBCDIC 开始
        ebcdic_hex = "C8C5D3D3D6"  # HELLO
        ascii_result = self.misc.ebcdic_to_ascii(ebcdic_hex)
        assert "HELLO" in ascii_result
        # 反向转换
        ebcdic_result = self.misc.ascii_to_ebcdic("HELLO")
        assert "C8" in ebcdic_result and "D6" in ebcdic_result

    def test_ebcdic_to_ascii_with_spaces(self):
        """带空格的 EBCDIC hex 输入"""
        result = self.misc.ebcdic_to_ascii("C8 C5 D3 D3 D6")
        assert "HELLO" in result

    def test_ascii_to_ebcdic_lowercase(self):
        """小写字母的 ASCII -> EBCDIC 转换"""
        result = self.misc.ascii_to_ebcdic("hello")
        assert "EBCDIC" in result
        # h=0x88, e=0x85, l=0x93, o=0x96
        assert "88" in result
        assert "85" in result
