# -*- coding: utf-8 -*-
"""杂项模块

覆盖：进制转换、摩尔斯电码、盲文、QR码、社工字典等。
"""

import itertools
import re
from typing import Optional

from ctftool.core.i18n import t


class MiscModule:
    """杂项工具集"""

    # ========== 进制转换 ==========

    def base_convert(self, text: str) -> str:
        """自动检测并转换各种进制"""
        text = text.strip()
        results = []

        # 尝试作为十进制
        try:
            n = int(text)
            results.append(f"{t('misc.base.decimal')} {n}:")
            results.append(f"  {t('misc.base.hex')}: {hex(n)}")
            results.append(f"  {t('misc.base.octal')}:   {oct(n)}")
            results.append(f"  {t('misc.base.binary')}:   {bin(n)}")
            if 32 <= n < 127:
                results.append(f"  ASCII:    {chr(n)}")
        except ValueError:
            pass

        # 尝试作为十六进制
        cleaned = text.replace('0x', '').replace('0X', '').replace(' ', '')
        try:
            n = int(cleaned, 16)
            results.append(f"{t('misc.base.hex')} 0x{cleaned}:")
            results.append(f"  {t('misc.base.decimal')}:   {n}")
            results.append(f"  {t('misc.base.octal')}:   {oct(n)}")
            results.append(f"  {t('misc.base.binary')}:   {bin(n)}")
            # 转文本
            if len(cleaned) % 2 == 0:
                try:
                    text_result = bytes.fromhex(cleaned).decode('utf-8', errors='replace')
                    results.append(f"  {t('misc.base.text')}:     {text_result}")
                except Exception:
                    pass
        except ValueError:
            pass

        # 尝试作为二进制
        binary_cleaned = text.replace(' ', '')
        if all(c in '01' for c in binary_cleaned) and len(binary_cleaned) >= 8:
            n = int(binary_cleaned, 2)
            results.append(f"{t('misc.base.binary')} {text}:")
            results.append(f"  {t('misc.base.decimal')}:   {n}")
            results.append(f"  {t('misc.base.hex')}: {hex(n)}")
            # 转文本
            chars = []
            for i in range(0, len(binary_cleaned), 8):
                byte = binary_cleaned[i:i+8]
                if len(byte) == 8:
                    chars.append(chr(int(byte, 2)))
            if chars:
                results.append(f"  {t('misc.base.text')}:     {''.join(chars)}")

        # 尝试作为 ASCII 数字序列
        parts = text.split()
        if len(parts) > 1:
            try:
                nums = [int(p) for p in parts]
                if all(32 <= n < 127 for n in nums):
                    results.append(f"ASCII {t('misc.base.sequence')}:")
                    results.append(f"  {t('misc.base.text')}: {''.join(chr(n) for n in nums)}")
            except ValueError:
                pass

        if not results:
            return t("misc.base.unrecognized")
        return "\n".join(results)

    # ========== 摩尔斯电码 ==========

    MORSE_CODE = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
        'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
        'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
        'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
        'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
        'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
        '3': '...--', '4': '....-', '5': '.....', '6': '-....',
        '7': '--...', '8': '---..', '9': '----.', '.': '.-.-.-',
        ',': '--..--', '?': '..--..', '!': '-.-.--', '/': '-..-.',
        '(': '-.--.', ')': '-.--.-', '&': '.-...', ':': '---...',
        ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-',
        '_': '..--.-', '"': '.-..-.', '$': '...-..-', '@': '.--.-.',
        ' ': '/',
    }

    MORSE_DECODE = {v: k for k, v in MORSE_CODE.items()}

    def morse_encode(self, text: str) -> str:
        """文本 → 摩尔斯电码"""
        result = []
        for c in text.upper():
            if c in self.MORSE_CODE:
                result.append(self.MORSE_CODE[c])
            elif c == ' ':
                result.append('/')
        return ' '.join(result)

    def morse_decode(self, text: str) -> str:
        """摩尔斯电码 → 文本"""
        # 支持多种分隔符
        text = text.replace('|', '/').replace('  ', ' / ')
        words = text.split('/')
        result = []
        for word in words:
            chars = word.strip().split()
            decoded_word = ''
            for char in chars:
                if char in self.MORSE_DECODE:
                    decoded_word += self.MORSE_DECODE[char]
                else:
                    decoded_word += '?'
            result.append(decoded_word)
        decoded = ' '.join(result)
        if '?' not in decoded and decoded.strip():
            return f"{t('misc.morse.decoded')}: {decoded}"
        elif decoded.strip():
            return f"{t('misc.morse.partial')}: {decoded}"
        return t("misc.morse.failed")

    # ========== 盲文 ==========

    BRAILLE_MAP = {
        '⠁': 'a', '⠃': 'b', '⠉': 'c', '⠙': 'd', '⠑': 'e',
        '⠋': 'f', '⠛': 'g', '⠓': 'h', '⠊': 'i', '⠚': 'j',
        '⠅': 'k', '⠇': 'l', '⠍': 'm', '⠝': 'n', '⠕': 'o',
        '⠏': 'p', '⠟': 'q', '⠗': 'r', '⠎': 's', '⠞': 't',
        '⠥': 'u', '⠧': 'v', '⠺': 'w', '⠭': 'x', '⠽': 'y',
        '⠵': 'z', '⠼': '#', '⠀': ' ',
        '⠴': '0', '⠂': '1', '⠆': '2', '⠒': '3', '⠲': '4',
        '⠢': '5', '⠖': '6', '⠶': '7', '⠦': '8', '⠔': '9',
    }

    def braille_decode(self, text: str) -> str:
        """盲文 → 文本"""
        result = []
        for c in text:
            if c in self.BRAILLE_MAP:
                result.append(self.BRAILLE_MAP[c])
            elif c == ' ':
                result.append(' ')
        if result:
            return f"{t('misc.braille.decoded')}: {''.join(result)}"
        return t("misc.braille.failed")

    def braille_encode(self, text: str) -> str:
        """文本 → 盲文"""
        reverse_map = {v: k for k, v in self.BRAILLE_MAP.items()}
        result = []
        for c in text.lower():
            if c in reverse_map:
                result.append(reverse_map[c])
            elif c == ' ':
                result.append('⠀')
        return ''.join(result)

    # ========== 核心价值观编码 ==========

    def core_values_decode(self, text: str) -> str:
        """社会主义核心价值观编码解码"""
        values = ['富强', '民主', '文明', '和谐', '自由', '平等',
                  '公正', '法治', '爱国', '敬业', '诚信', '友善']
        # 建立解码映射
        value_to_idx = {v: i for i, v in enumerate(values)}

        # 提取文本中的核心价值观词语
        found = []
        i = 0
        while i < len(text):
            matched = False
            for v in values:
                if text[i:i+len(v)] == v:
                    found.append(value_to_idx[v])
                    i += len(v)
                    matched = True
                    break
            if not matched:
                i += 1

        if not found:
            return t("misc.core_values.not_detected")

        # 每两个值组成一个 ASCII 字符: idx1 * 12 + idx2 (12 进制)
        # 尝试方式1: 两两配对 (val1 * 12 + val2 作为 ASCII)
        result1 = ""
        if len(found) % 2 == 0:
            try:
                chars = []
                for j in range(0, len(found), 2):
                    code = found[j] * 12 + found[j+1]
                    if 32 <= code < 127:
                        chars.append(chr(code))
                result1 = ''.join(chars)
            except Exception:
                pass

        # 尝试方式2: 每个词对应一个二进制位 (0-5=0, 6-11=1)
        binary = ''.join('0' if v < 6 else '1' for v in found)
        result2 = ""
        if len(binary) >= 8:
            chars2 = []
            for j in range(0, len(binary) - 7, 8):
                byte = int(binary[j:j+8], 2)
                if 0 < byte < 128:
                    chars2.append(chr(byte))
            result2 = ''.join(chars2)

        lines = [f"=== {t('misc.core_values.title')} ==="]
        lines.append(f"{t('misc.core_values.extracted')} {len(found)} {t('misc.core_values.words')}")
        lines.append(f"{t('misc.core_values.index_seq')}: {found}")
        if result1:
            lines.append(f"\n{t('misc.core_values.method1')}: {result1}")
        if result2:
            lines.append(f"{t('misc.core_values.method2')}: {result2}")
        if not result1 and not result2:
            lines.append(f"\n{t('misc.core_values.cannot_decode')}")
        return "\n".join(lines)

    def core_values_encode(self, text: str) -> str:
        """社会主义核心价值观编码"""
        values = ['富强', '民主', '文明', '和谐', '自由', '平等',
                  '公正', '法治', '爱国', '敬业', '诚信', '友善']
        result = []
        for c in text:
            code = ord(c)
            result.append(values[code // 12])
            result.append(values[code % 12])
        return f"{t('misc.core_values.encoded')}:\n{''.join(result)}"

    # ========== 猪圈密码 ==========

    def pigpen_decode(self, text: str) -> str:
        """猪圈密码解码（基于符号描述输入）

        输入格式: 使用数字 1-26 或字母描述，空格分隔
        """
        # 猪圈密码标准映射（简化版：用数字 1-26 对应 A-Z）
        lines = [f"=== {t('misc.pigpen.title')} ==="]
        lines.append(t("misc.pigpen.description"))
        lines.append("")
        lines.append(f"{t('misc.pigpen.table')}:")
        lines.append("  ┌─┬─┐   ┌─┬─┐")
        lines.append(f"  │A│B│C  │J│K│L  ({t('misc.pigpen.no_dot')})")
        lines.append("  ├─┼─┤   ├─┼─┤")
        lines.append("  │D│E│F  │M│N│O")
        lines.append("  └─┴─┘   └─┴─┘")
        lines.append(f"   G H I   P Q R   ({t('misc.pigpen.with_dot')})")
        lines.append("")
        lines.append(f"  X {t('misc.pigpen.x_shape')}:")
        lines.append(f"  S T ({t('misc.pigpen.no_dot')})  W X ({t('misc.pigpen.with_dot')})")
        lines.append("  U V        Y Z")
        lines.append("")

        # 如果输入是数字序列，尝试直接转换
        parts = text.strip().split()
        if all(p.isdigit() for p in parts):
            try:
                result = ''.join(chr(int(p) - 1 + ord('A')) for p in parts if 1 <= int(p) <= 26)
                lines.append(f"{t('misc.pigpen.num_decode')}: {result}")
            except Exception:
                pass

        return "\n".join(lines)

    # ========== DNA 密码 ==========

    def dna_decode(self, text: str) -> str:
        """DNA 密码编解码 (ACGT -> 二进制 -> ASCII)"""
        # DNA 碱基映射为 2-bit: A=00, C=01, G=10, T=11
        dna_map = {'A': '00', 'C': '01', 'G': '10', 'T': '11'}

        cleaned = text.upper().replace(' ', '')
        if not all(c in 'ACGT' for c in cleaned):
            return t("misc.dna.invalid_sequence")

        if len(cleaned) % 4 != 0:
            return f"{t('misc.dna.length_error')} {len(cleaned)} {t('misc.dna.not_multiple_of_4')}"

        binary = ''.join(dna_map[c] for c in cleaned)
        chars = []
        for i in range(0, len(binary), 8):
            byte = int(binary[i:i+8], 2)
            if 0 < byte < 128:
                chars.append(chr(byte))

        result = ''.join(chars)
        return f"{t('misc.dna.decoded')}:\n  {t('misc.dna.base_seq')}: {cleaned[:80]}{'...' if len(cleaned) > 80 else ''}\n  {t('misc.base.binary')}: {binary[:64]}{'...' if len(binary) > 64 else ''}\n  {t('misc.base.text')}: {result}"

    def dna_encode(self, text: str) -> str:
        """文本 -> DNA 密码编码"""
        reverse_map = {'00': 'A', '01': 'C', '10': 'G', '11': 'T'}
        dna = []
        for c in text:
            binary = format(ord(c), '08b')
            for i in range(0, 8, 2):
                dna.append(reverse_map[binary[i:i+2]])
        return f"{t('misc.dna.encoded')}:\n  {t('misc.base.text')}: {text}\n  DNA: {''.join(dna)}"

    # ========== QR 码 ==========

    def qr_decode(self, filepath: str) -> str:
        """解码图片中的 QR 码"""
        try:
            from PIL import Image
            img = Image.open(filepath)

            # 尝试 pyzbar
            try:
                from pyzbar.pyzbar import decode as zbar_decode
                results = zbar_decode(img)
                if results:
                    lines = [f"{t('misc.qr.result')} ({len(results)} {t('misc.qr.count')}):"]
                    for r in results:
                        data = r.data.decode('utf-8', errors='replace')
                        lines.append(f"  {t('misc.qr.type')}: {r.type}")
                        lines.append(f"  {t('misc.qr.content')}: {data}")
                    # 分析解码内容
                    content = results[0].data.decode('utf-8', errors='replace')
                    from ctftool.core.flag_finder import flag_finder
                    flags = flag_finder.search(content)
                    if flags:
                        lines.append(f"\n[!] {t('misc.qr.flag_found')}: {', '.join(flags)}")
                    if content.startswith(('http://', 'https://')):
                        lines.append(f"\n[*] {t('misc.qr.url_detected')}")
                    return "\n".join(lines)
            except ImportError:
                pass

            # 尝试 qrcode
            try:
                import qrcode  # noqa: F401
                return t("misc.qr.install_pyzbar")
            except ImportError:
                pass

            return t("misc.qr.need_pyzbar")
        except ImportError:
            return t("misc.qr.need_pillow")
        except Exception as e:
            return f"{t('misc.qr.decode_failed')}: {e}"

    def barcode_decode(self, filepath: str) -> str:
        """解码图片中的条形码/二维码（支持多种格式）"""
        try:
            from PIL import Image
            img = Image.open(filepath)

            try:
                from pyzbar.pyzbar import decode as zbar_decode
                results = zbar_decode(img)
                if results:
                    lines = [f"{t('misc.barcode.result')} ({len(results)} {t('misc.qr.count')}):"]
                    for r in results:
                        data = r.data.decode('utf-8', errors='replace')
                        lines.append(f"  {t('misc.qr.type')}: {r.type}")
                        lines.append(f"  {t('misc.qr.content')}: {data}")
                        lines.append(f"  {t('misc.barcode.position')}: {r.rect}")
                    return "\n".join(lines)
                return t("misc.barcode.not_detected")
            except ImportError:
                return t("misc.barcode.need_pyzbar")
        except ImportError:
            return t("misc.qr.need_pillow")
        except Exception as e:
            return f"{t('misc.barcode.decode_failed')}: {e}"

    # ========== 编码工具 ==========

    def ascii_table(self, start: int = 32, end: int = 127) -> str:
        """ASCII 码表"""
        lines = [f"{t('misc.ascii.table')}:", f"{'Dec':>5} {'Hex':>5} {'Oct':>5} {'Bin':>10} {'Chr':>5}"]
        lines.append("-" * 40)
        for i in range(start, end):
            c = chr(i) if 32 <= i < 127 else '.'
            lines.append(f"{i:>5} {i:>5X} {i:>5o} {i:>10b} {c:>5}")
        return "\n".join(lines)

    def char_convert(self, text: str) -> str:
        """字符与各种编码互转"""
        lines = [f"{t('misc.char.convert')}: {text}", ""]
        for c in text:
            o = ord(c)
            lines.append(
                f"  '{c}' → Dec:{o} Hex:0x{o:02X} Oct:{o:03o} "
                f"Bin:{o:08b} HTML:&#{o};"
            )
        return "\n".join(lines)

    def rot_all(self, text: str) -> str:
        """ROT-N 全部尝试（ROT-1 到 ROT-25）"""
        lines = [f"{t('misc.rot.bruteforce')}:"]
        for n in range(1, 26):
            rotated = []
            for c in text:
                if c.isalpha():
                    base = ord('A') if c.isupper() else ord('a')
                    rotated.append(chr((ord(c) - base + n) % 26 + base))
                else:
                    rotated.append(c)
            lines.append(f"  ROT-{n:2d}: {''.join(rotated)}")
        return "\n".join(lines)

    def rot47(self, text: str) -> str:
        """ROT47 编码/解码（可打印 ASCII 范围 !-~ 旋转）"""
        result = []
        for c in text:
            n = ord(c)
            if 33 <= n <= 126:
                result.append(chr(33 + (n - 33 + 47) % 94))
            else:
                result.append(c)
        return f"ROT47: {''.join(result)}"

    # ========== 社工字典 ==========

    def generate_wordlist(self, name: str = "", birthday: str = "",
                          keywords: Optional[list[str]] = None,
                          output_file: str = "") -> str:
        """根据信息生成社工字典"""
        words = set()
        parts = []

        if name:
            parts.append(name.lower())
            parts.append(name.upper())
            parts.append(name.capitalize())

        if birthday:
            # 处理各种日期格式
            digits = re.sub(r'\D', '', birthday)
            if len(digits) >= 8:
                year = digits[:4]
                month = digits[4:6]
                day = digits[6:8]
                parts.extend([year, month + day, digits, digits[-4:], year[-2:]])

        if keywords:
            parts.extend(keywords)

        # 组合生成
        separators = ['', '_', '.', '-', '@', '#']
        import datetime
        current_year = datetime.datetime.now().year
        suffixes = ['', '!', '123', '1234', str(current_year), str(current_year - 1), '666', '888', '000']

        for p in parts:
            for sep in separators:
                for suf in suffixes:
                    words.add(f"{p}{sep}{suf}")

        # 两两组合
        for p1, p2 in itertools.combinations(parts[:5], 2):
            for sep in ['', '_', '.']:
                words.add(f"{p1}{sep}{p2}")
                words.add(f"{p2}{sep}{p1}")

        sorted_words = sorted(words)
        lines = [f"{t('misc.wordlist.generated')} {len(sorted_words)} {t('misc.wordlist.candidates')}:"]
        for w in sorted_words[:100]:
            lines.append(f"  {w}")
        if len(sorted_words) > 100:
            lines.append(f"  ... {t('misc.wordlist.remaining')} {len(sorted_words) - 100} {t('misc.wordlist.items')}")
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                for word in sorted_words:
                    f.write(word + '\n')
            lines.append(f"\n{t('misc.wordlist.exported')} {len(sorted_words)} {t('misc.wordlist.passwords_to')}: {output_file}")
        return "\n".join(lines)

    # ========== 杂项编码 ==========

    def ook_decode(self, text: str) -> str:
        """Ook! 语言解码"""
        tokens = re.findall(r'Ook[.!?]', text)
        if not tokens or len(tokens) % 2 != 0:
            return t("misc.ook.parse_failed")

        # 映射 Ook! 到 brainfuck
        ook_map = {
            'Ook.Ook.': '.', 'Ook!Ook!': '!', 'Ook.Ook?': '[',
            'Ook?Ook.': ']', 'Ook.Ook!': '+', 'Ook!Ook.': '-',
            'Ook!Ook?': '>', 'Ook?Ook!': '<',
        }

        bf = []
        for i in range(0, len(tokens), 2):
            pair = tokens[i] + tokens[i+1]
            if pair in ook_map:
                bf.append(ook_map[pair])

        return f"{t('misc.ook.to_brainfuck')}: {''.join(bf)}\n({t('misc.ook.need_interpreter')})"

    def ook_execute(self, text: str, input_data: str = "") -> str:
        """Ook! 语言直接执行（先转 Brainfuck 再执行）"""
        bf_result = self.ook_decode(text)
        # 从 ook_decode 结果中提取 Brainfuck 代码
        import re as _re
        match = _re.search(r'(?:转换为 Brainfuck|Converted to Brainfuck): (.+)', bf_result)
        if not match:
            return bf_result  # 无法解析则返回原始结果
        bf_code = match.group(1)
        exec_result = self.brainfuck_execute(bf_code, input_data)
        return f"{bf_result}\n\n{exec_result}"

    def brainfuck_execute(self, code: str, input_data: str = "") -> str:
        """Brainfuck 解释器"""
        tape = [0] * 30000
        ptr = 0
        code_ptr = 0
        output = []
        input_idx = 0
        steps = 0
        max_steps = 1000000

        # 预计算括号匹配
        brackets = {}
        stack = []
        for i, c in enumerate(code):
            if c == '[':
                stack.append(i)
            elif c == ']':
                if stack:
                    j = stack.pop()
                    brackets[j] = i
                    brackets[i] = j

        while code_ptr < len(code) and steps < max_steps:
            cmd = code[code_ptr]
            if cmd == '>':
                ptr = (ptr + 1) % 30000
            elif cmd == '<':
                ptr = (ptr - 1) % 30000
            elif cmd == '+':
                tape[ptr] = (tape[ptr] + 1) % 256
            elif cmd == '-':
                tape[ptr] = (tape[ptr] - 1) % 256
            elif cmd == '.':
                output.append(chr(tape[ptr]))
            elif cmd == ',':
                if input_idx < len(input_data):
                    tape[ptr] = ord(input_data[input_idx])
                    input_idx += 1
                else:
                    tape[ptr] = 0
            elif cmd == '[':
                if tape[ptr] == 0:
                    code_ptr = brackets.get(code_ptr, code_ptr)
            elif cmd == ']':
                if tape[ptr] != 0:
                    code_ptr = brackets.get(code_ptr, code_ptr)
            code_ptr += 1
            steps += 1

        result = ''.join(output)
        if steps >= max_steps:
            return f"{t('misc.bf.step_limit')} ({max_steps} {t('misc.bf.steps')}), {t('misc.bf.partial_output')}: {result}"
        return f"{t('misc.bf.output')}: {result}"

    def jwt_decode(self, token: str) -> str:
        """解码 JWT Token（不验证签名）"""
        import base64
        import json

        parts = token.split('.')
        if len(parts) != 3:
            return t("misc.jwt.invalid_format")

        lines = [f"=== {t('misc.jwt.title')} ==="]
        labels = ["Header", "Payload", "Signature"]
        header_data = {}

        for i, (part, label) in enumerate(zip(parts, labels)):
            if i < 2:
                # Base64URL 解码
                padded = part + '=' * (4 - len(part) % 4)
                padded = padded.replace('-', '+').replace('_', '/')
                try:
                    decoded = base64.b64decode(padded).decode('utf-8')
                    parsed = json.loads(decoded)
                    if i == 0:
                        header_data = parsed
                    lines.append(f"\n{label}:")
                    lines.append(json.dumps(parsed, indent=2, ensure_ascii=False))
                except Exception as e:
                    lines.append(f"\n{label}: {t('misc.jwt.decode_failed')} - {e}")
            else:
                lines.append(f"\n{label}: {part}")

        # 根据 alg 给出攻击建议
        alg = header_data.get('alg', 'unknown')
        lines.append(f"\n=== {t('misc.jwt.attack_tips')} ===")
        if alg.upper() == 'HS256':
            lines.append(f"  [!] HS256 — {t('misc.jwt.hs256_tip1')}")
            lines.append(f"  [!] {t('misc.jwt.hs256_tip2')}")
        elif alg.upper() == 'RS256':
            lines.append(f"  [!] RS256 — {t('misc.jwt.rs256_tip1')}")
            lines.append(f"  [!] {t('misc.jwt.rs256_tip2')}")
        elif alg.lower() == 'none':
            lines.append(f"  [!] {t('misc.jwt.none_tip')}")
        else:
            lines.append(f"  {t('misc.jwt.algorithm')}: {alg} — {t('misc.jwt.check_downgrade')}")

        return "\n".join(lines)

    # ========== 键盘密码 ==========

    T9_MAP = {
        '2': 'abc', '3': 'def', '4': 'ghi', '5': 'jkl',
        '6': 'mno', '7': 'pqrs', '8': 'tuv', '9': 'wxyz',
    }

    def t9_decode(self, text: str) -> str:
        """手机九宫格 T9 键盘密码解码

        格式: 相同数字连续表示第几个字母，如 22 33 33 -> b e e
        用空格分隔每组，如 2 33 444 -> a e i
        """
        groups = text.strip().split()
        result = []
        for group in groups:
            if not group or not group[0].isdigit():
                result.append(group)
                continue
            key = group[0]
            count = len(group)
            if key in self.T9_MAP:
                letters = self.T9_MAP[key]
                idx = (count - 1) % len(letters)
                result.append(letters[idx])
            else:
                result.append(group)
        decoded = ''.join(result)
        return f"{t('misc.t9.decoded')}: {decoded}"

    KEYBOARD_ROWS = [
        '1234567890',
        'qwertyuiop',
        'asdfghjkl',
        'zxcvbnm',
    ]

    def keyboard_coord_decode(self, text: str) -> str:
        """电脑键盘坐标密码解码 (行列格式, 如 '11 21 31' -> 1 q a)

        支持两种格式:
        - 两位数格式: '11 21 31' (第1行第1列, 第2行第1列, ...)
        - 逗号分隔格式: '2,10 1,3' (第2行第10列, 第1行第3列, ...)
        """
        pairs = text.strip().split()
        result = []
        for pair in pairs:
            pair = pair.lower().replace('r', '').replace('c', '')
            if ',' in pair:
                # 逗号分隔格式：支持两位数列号
                parts = pair.split(',')
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    row = int(parts[0]) - 1
                    col = int(parts[1]) - 1
                    if 0 <= row < len(self.KEYBOARD_ROWS):
                        keys = self.KEYBOARD_ROWS[row]
                        if 0 <= col < len(keys):
                            result.append(keys[col])
                            continue
            elif len(pair) == 2 and pair[0].isdigit() and pair[1].isdigit():
                row = int(pair[0]) - 1
                col = int(pair[1]) - 1
                if 0 <= row < len(self.KEYBOARD_ROWS):
                    keys = self.KEYBOARD_ROWS[row]
                    if 0 <= col < len(keys):
                        result.append(keys[col])
                        continue
            result.append('?')
        return f"{t('misc.keyboard.coord_decoded')}: {''.join(result)}"

    # ========== PHP 序列化 ==========

    def php_serialize_decode(self, text: str) -> str:
        """PHP 序列化格式解析"""
        text = text.strip()
        lines = [f"=== {t('misc.php.title')} ==="]
        try:
            result, _ = self._parse_php(text, 0)
            import json
            lines.append(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        except Exception as e:
            lines.append(f"{t('misc.php.parse_failed')}: {e}")
            lines.append(f"\n{t('misc.php.raw_data')}:\n{text}")
        return "\n".join(lines)

    def _parse_php(self, data: str, pos: int):
        t_char = data[pos]
        if t_char == 's':
            colon1 = data.index(':', pos + 2)
            length = int(data[pos + 2:colon1])
            start = colon1 + 2
            return data[start:start + length], start + length + 2
        elif t_char == 'i':
            semi = data.index(';', pos)
            return int(data[pos + 2:semi]), semi + 1
        elif t_char == 'd':
            semi = data.index(';', pos)
            return float(data[pos + 2:semi]), semi + 1
        elif t_char == 'b':
            return data[pos + 2] == '1', pos + 4
        elif t_char == 'N':
            return None, pos + 2
        elif t_char == 'a':
            colon1 = data.index(':', pos + 2)
            count = int(data[pos + 2:colon1])
            pos = colon1 + 2
            result = {}
            for _ in range(count):
                key, pos = self._parse_php(data, pos)
                val, pos = self._parse_php(data, pos)
                result[key] = val
            return result, pos + 1
        elif t_char == 'O':
            # O:name_len:"ClassName":prop_count:{...}
            colon1 = data.index(':', pos + 2)
            name_len = int(data[pos + 2:colon1])
            ns = colon1 + 2  # skip :"
            cls = data[ns:ns + name_len]
            rest = ns + name_len + 1  # skip closing "
            colon2 = data.index(':', rest)
            brace = data.index('{', colon2)
            pc = int(data[colon2 + 1:brace])
            pos = brace + 1
            props = {"__class__": cls}
            for _ in range(pc):
                key, pos = self._parse_php(data, pos)
                val, pos = self._parse_php(data, pos)
                props[str(key)] = val
            return props, pos + 1
        raise ValueError(f"{t('misc.php.unknown_type')} '{t_char}' at pos {pos}")

    # ========== 零宽字符隐写 ==========

    # 常见零宽字符
    ZWC_CHARS = {
        '\u200b': '0',  # ZERO WIDTH SPACE
        '\u200c': '1',  # ZERO WIDTH NON-JOINER
        '\u200d': '',   # ZERO WIDTH JOINER (分隔符)
        '\u2060': '',   # WORD JOINER
        '\ufeff': '',   # BOM / ZERO WIDTH NO-BREAK SPACE
    }

    def zwc_decode(self, text: str) -> str:
        """零宽字符隐写解码

        提取文本中的零宽字符，转为二进制后解码为 ASCII。
        """
        # 提取零宽字符
        zwc_only = []
        for c in text:
            if c in ('\u200b', '\u200c', '\u200d', '\u2060', '\ufeff'):
                zwc_only.append(c)

        if not zwc_only:
            return t("misc.zwc.not_detected")

        lines = [f"=== {t('misc.zwc.decode_title')} ==="]
        lines.append(f"{t('misc.zwc.detected')} {len(zwc_only)} {t('misc.zwc.chars')}")

        # 方式1: \u200b=0, \u200c=1, 8位一组
        binary = ''
        for c in zwc_only:
            if c == '\u200b':
                binary += '0'
            elif c == '\u200c':
                binary += '1'

        if binary:
            lines.append(f"{t('misc.base.binary')}: {binary[:80]}{'...' if len(binary) > 80 else ''}")
            chars = []
            for i in range(0, len(binary) - 7, 8):
                byte = int(binary[i:i+8], 2)
                if 0 < byte < 128:
                    chars.append(chr(byte))
            if chars:
                decoded = ''.join(chars)
                lines.append(f"{t('misc.zwc.decode_result')}: {decoded}")

        # 方式2: Unicode 码点直接转
        codes = [f"U+{ord(c):04X}" for c in zwc_only[:30]]
        lines.append(f"\n{t('misc.zwc.sequence')}: {' '.join(codes)}")

        return "\n".join(lines)

    def zwc_encode(self, text: str, carrier: str = "") -> str:
        """零宽字符隐写编码

        将文本转为零宽字符嵌入载体文本中。
        """
        binary = ''.join(format(ord(c), '08b') for c in text)
        zwc = binary.replace('0', '\u200b').replace('1', '\u200c')

        if carrier:
            # 嵌入到载体文本中间
            mid = len(carrier) // 2
            result = carrier[:mid] + zwc + carrier[mid:]
        else:
            result = zwc

        lines = [f"=== {t('misc.zwc.encode_title')} ==="]
        lines.append(f"{t('misc.zwc.hidden_text')}: {text}")
        lines.append(f"{t('misc.zwc.binary_length')}: {len(binary)} bits")
        lines.append(f"{t('misc.zwc.char_count')}: {len(zwc)}")
        if carrier:
            lines.append(f"{t('misc.zwc.carrier_text')}: {carrier}")
            lines.append(f"\n{t('misc.zwc.embedded')}:")
            lines.append(result)
        else:
            lines.append(f"\n{t('misc.zwc.pure_zwc')}:")
            lines.append(result)
        lines.append(f"\n{t('misc.zwc.verify_tip')}")
        return "\n".join(lines)

    # ========== Whitespace 语言 ==========

    def whitespace_execute(self, code: str) -> str:
        """Whitespace 语言解释器（空格/Tab/换行编程语言）"""
        # 提取空白字符: 空格=S, Tab=T, 换行=N
        tokens = []
        for c in code:
            if c == ' ':
                tokens.append('S')
            elif c == '\t':
                tokens.append('T')
            elif c == '\n':
                tokens.append('N')

        if not tokens:
            return t("misc.ws.not_detected")

        stack = []
        output = []
        heap = {}
        pos = 0
        call_stack = []
        labels = {}
        max_steps = 100000
        steps = 0

        token_str = ''.join(tokens)

        # 预扫描标签
        i = 0
        while i < len(token_str):
            if token_str[i:i+3] == 'NSS':  # 标签定义
                i += 3
                label = ''
                while i < len(token_str) and token_str[i] != 'N':
                    label += token_str[i]
                    i += 1
                labels[label] = i + 1
                i += 1
            else:
                i += 1

        def parse_number(pos):
            """解析数字: S=正/T=负, 二进制序列, N结尾"""
            if pos >= len(token_str):
                return 0, pos
            sign = 1 if token_str[pos] == 'S' else -1
            pos += 1
            num = 0
            while pos < len(token_str) and token_str[pos] != 'N':
                num = num * 2 + (0 if token_str[pos] == 'S' else 1)
                pos += 1
            return sign * num, pos + 1

        def parse_label(pos):
            label = ''
            while pos < len(token_str) and token_str[pos] != 'N':
                label += token_str[pos]
                pos += 1
            return label, pos + 1

        pos = 0
        while pos < len(token_str) and steps < max_steps:
            steps += 1

            # 栈操作 (S)
            if token_str[pos] == 'S':
                pos += 1
                if pos < len(token_str) and token_str[pos] == 'S':  # SS: push
                    pos += 1
                    num, pos = parse_number(pos)
                    stack.append(num)
                elif pos < len(token_str) and token_str[pos] == 'N':  # SN
                    pos += 1
                    if pos < len(token_str) and token_str[pos] == 'S':  # SNS: dup
                        pos += 1
                        if stack:
                            stack.append(stack[-1])
                    elif pos < len(token_str) and token_str[pos] == 'T':  # SNT: swap
                        pos += 1
                        if len(stack) >= 2:
                            stack[-1], stack[-2] = stack[-2], stack[-1]
                    elif pos < len(token_str) and token_str[pos] == 'N':  # SNN: pop
                        pos += 1
                        if stack:
                            stack.pop()
                elif pos < len(token_str) and token_str[pos] == 'T':  # ST
                    pos += 1
                    if pos < len(token_str) and token_str[pos] == 'S':  # STS: copy nth
                        pos += 1
                        num, pos = parse_number(pos)
                        if 0 <= num < len(stack):
                            stack.append(stack[-(num+1)])
                    elif pos < len(token_str) and token_str[pos] == 'N':  # STN: slide n
                        pos += 1
                        num, pos = parse_number(pos)
                        if stack:
                            top = stack[-1]
                            stack = stack[:max(0, len(stack)-1-num)] + [top]

            # 算术 (TS)
            elif token_str[pos:pos+2] == 'TS':
                pos += 2
                if pos < len(token_str):
                    op = token_str[pos:pos+2]
                    pos += 2 if len(op) == 2 else 1
                    if len(stack) >= 2:
                        b = stack.pop()
                        a = stack.pop()
                        if op == 'SS':
                            stack.append(a + b)
                        elif op == 'ST':
                            stack.append(a - b)
                        elif op == 'SN':
                            stack.append(a * b)
                        elif op == 'TS':
                            stack.append(a // b if b != 0 else 0)
                        elif op == 'TT':
                            stack.append(a % b if b != 0 else 0)

            # 堆操作 (TT)
            elif token_str[pos:pos+2] == 'TT':
                pos += 2
                if pos < len(token_str):
                    if token_str[pos] == 'S':  # TTS: store
                        pos += 1
                        if len(stack) >= 2:
                            val = stack.pop()
                            addr = stack.pop()
                            heap[addr] = val
                    elif token_str[pos] == 'T':  # TTT: retrieve
                        pos += 1
                        if stack:
                            addr = stack.pop()
                            stack.append(heap.get(addr, 0))

            # I/O (TN)
            elif token_str[pos:pos+2] == 'TN':
                pos += 2
                if pos < len(token_str):
                    if token_str[pos] == 'S':
                        pos += 1
                        if pos <= len(token_str) and token_str[pos-1:pos] == 'S':
                            if stack:
                                output.append(chr(stack.pop() & 0x7F))
                        elif token_str[pos-1:pos] == 'T':
                            if stack:
                                output.append(str(stack.pop()))
                    else:
                        pos += 1

            # 流程控制 (N)
            elif token_str[pos] == 'N':
                pos += 1
                if pos < len(token_str):
                    fc = token_str[pos]
                    pos += 1
                    if fc == 'S':  # NS: 标签/调用/跳转
                        if pos < len(token_str):
                            sub = token_str[pos]
                            pos += 1
                            label, pos = parse_label(pos)
                            if sub == 'S':  # NSS: 标签定义 (已预扫描)
                                pass
                            elif sub == 'T':  # NST: 调用子程序
                                call_stack.append(pos)
                                pos = labels.get(label, pos)
                            elif sub == 'N':  # NSN: 跳转
                                pos = labels.get(label, pos)
                    elif fc == 'T':  # NT: 条件跳转
                        if pos < len(token_str):
                            sub = token_str[pos]
                            pos += 1
                            label, pos = parse_label(pos)
                            if sub == 'S' and stack and stack.pop() == 0:  # NTS: jz
                                pos = labels.get(label, pos)
                            elif sub == 'T' and stack and stack.pop() < 0:  # NTT: jn
                                pos = labels.get(label, pos)
                    elif fc == 'N':  # NN
                        if pos < len(token_str):
                            sub = token_str[pos]
                            pos += 1
                            if sub == 'T':  # NNT: 返回
                                if call_stack:
                                    pos = call_stack.pop()
                            elif sub == 'N':  # NNN: 退出
                                break
            else:
                pos += 1

        result = ''.join(output)
        if steps >= max_steps:
            return f"{t('misc.bf.step_limit')} ({max_steps} {t('misc.bf.steps')}), {t('misc.bf.partial_output')}: {result}"
        if not result:
            return f"{t('misc.ws.done_no_output')}\n({t('misc.ws.detected_tokens')} {len(tokens)} {t('misc.ws.whitespace_tokens')})"
        return f"{t('misc.ws.output')}: {result}"

    # ========== Base100 (Emoji) ==========

    def base100_encode(self, text: str) -> str:
        """Base100 编码（Emoji 编码）"""
        result = []
        for byte in text.encode('utf-8'):
            # Base100: 每个字节映射到 U+1F600 + byte 区域的 emoji
            0xF0_9F_8E_80 + byte  # 简化映射
            # 实际 Base100 用固定偏移: emoji = chr(0x1F3A0 + byte)
            result.append(chr(0x1F600 + byte))
        return f"Base100 (Emoji): {''.join(result)}"

    def base100_decode(self, text: str) -> str:
        """Base100 解码（Emoji 解码）"""
        result = bytearray()
        for c in text:
            code = ord(c)
            if 0x1F600 <= code <= 0x1F6FF:
                result.append(code - 0x1F600)
        if not result:
            return t("misc.base100.not_detected")
        return f"{t('misc.base100.decoded')}: {bytes(result).decode('utf-8', errors='replace')}"

    # ========== 敲击码 (Tap Code) ==========

    def tap_code_decode(self, text: str) -> str:
        """敲击码解码 (Polybius 5x5 变体, K被C替代)"""
        # 敲击码: 每个字母用 (行,列) 表示, 如 A=(1,1), B=(1,2)
        grid = 'ABCDEFGHIJLMNOPQRSTUVWXYZ'  # 无 K, K=C

        # 尝试多种输入格式
        import re as _re
        # 格式1: 数字对 "11 12 13" 或 "1,1 1,2"
        pairs = _re.findall(r'(\d)[,.\s]*(\d)', text)
        if pairs:
            result = []
            for r, c in pairs:
                idx = (int(r) - 1) * 5 + (int(c) - 1)
                if 0 <= idx < 25:
                    result.append(grid[idx])
            if result:
                decoded = ''.join(result)
                return f"{t('misc.tap.decoded')}: {decoded}\n({t('misc.tap.k_replaced')})"

        # 格式2: 点/敲击 ".../.. ../..." 用 / 分隔行列
        groups = _re.findall(r'(\.+)\s*/\s*(\.+)', text)
        if groups:
            result = []
            for r_dots, c_dots in groups:
                r = len(r_dots)
                c = len(c_dots)
                idx = (r - 1) * 5 + (c - 1)
                if 0 <= idx < 25:
                    result.append(grid[idx])
            if result:
                return f"{t('misc.tap.decoded')}: {''.join(result)}"

        return f"{t('misc.tap.parse_failed')}\n{t('misc.tap.supported_formats')}"

    def tap_code_encode(self, text: str) -> str:
        """敲击码编码"""
        grid = 'ABCDEFGHIJLMNOPQRSTUVWXYZ'
        text = text.upper().replace('K', 'C')
        result_num = []
        result_dot = []
        for c in text:
            if c in grid:
                idx = grid.index(c)
                r, col = idx // 5 + 1, idx % 5 + 1
                result_num.append(f"{r}{col}")
                result_dot.append(f"{'.' * r}/{'.' * col}")
            elif c == ' ':
                result_num.append(' ')
                result_dot.append('  ')
        return f"{t('misc.tap.encoded')}:\n  {t('misc.tap.numbers')}: {' '.join(result_num)}\n  {t('misc.tap.dots')}: {' '.join(result_dot)}"

    # ========== 培根密码 ==========

    def bacon_encode(self, text: str) -> str:
        """培根密码编码 (26 字母版)"""
        # 26 字母版培根码表
        table = {}
        for i, c in enumerate('ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
            binary = format(i, '05b').replace('0', 'A').replace('1', 'B')
            table[c] = binary

        text = text.upper()
        result = []
        for c in text:
            if c in table:
                result.append(table[c])

        return f"{t('misc.bacon.encoded')}: {''.join(result)}\n{t('misc.bacon.grouped')}: {' '.join(result)}"

    # ========== Vigenere 自动破解 ==========

    def vigenere_auto_crack(self, ciphertext: str) -> str:
        """Vigenere 自动破解（密钥长度推测 + 频率分析）"""
        from ctftool.modules.crypto import CryptoModule
        crypto = CryptoModule()

        # 1. 推测密钥长度
        key_len_result = crypto.vigenere_key_length(ciphertext)

        # 提取推荐密钥长度
        import re as _re
        match = _re.search(r'推荐密钥长度[：:]\s*(\d+)', key_len_result)
        if not match:
            match = _re.search(r'Suggested.*?(\d+)', key_len_result)

        if not match:
            return f"{t('misc.vigenere.cannot_guess_length')}:\n{key_len_result}"

        key_length = int(match.group(1))
        text = ''.join(c for c in ciphertext.upper() if c.isalpha())

        # 2. 对每列进行频率分析，推断密钥字母
        english_freq = [0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020, 0.061,
                        0.070, 0.002, 0.008, 0.040, 0.024, 0.067, 0.075, 0.019,
                        0.001, 0.060, 0.063, 0.091, 0.028, 0.010, 0.023, 0.002,
                        0.020, 0.001]

        key = []
        for i in range(key_length):
            column = text[i::key_length]
            if not column:
                key.append('A')
                continue

            best_shift = 0
            best_score = -1
            for shift in range(26):
                score = 0
                for j in range(26):
                    count = column.count(chr((j + shift) % 26 + 65))
                    score += count * english_freq[j]
                if score > best_score:
                    best_score = score
                    best_shift = shift
            key.append(chr(best_shift + 65))

        key_str = ''.join(key)

        # 3. 使用推断的密钥解密
        decrypted = crypto.vigenere_decrypt(ciphertext, key_str)

        lines = [
            f"=== {t('misc.vigenere.auto_crack_title')} ===",
            f"{t('misc.vigenere.guessed_key_length')}: {key_length}",
            f"{t('misc.vigenere.guessed_key')}: {key_str}",
            "",
            decrypted,
        ]
        return '\n'.join(lines)

    # ========== QR 码生成 ==========

    def qr_generate(self, text: str) -> str:
        """生成 QR 码的 ASCII 表示"""
        # 简易 ASCII QR 码（无需第三方库）
        # 这里用文本提示，因为真正的 QR 生成需要 qrcode 库
        try:
            import qrcode
            qr = qrcode.QRCode(version=1, box_size=1, border=1)
            qr.add_data(text)
            qr.make(fit=True)
            matrix = qr.get_matrix()
            lines = [f"{t('misc.qr.generated')}:"]
            for row in matrix:
                lines.append(''.join('██' if cell else '  ' for cell in row))

            # 也保存为图片
            img = qr.make_image(fill_color="black", back_color="white")
            out_path = "qr_output.png"
            img.save(out_path)
            lines.append(f"\n{t('misc.qr.saved_to')}: {out_path}")
            return '\n'.join(lines)
        except ImportError:
            # 无 qrcode 库时，输出安装提示
            return f"{t('misc.qr.need_qrcode_lib')}\n\n{t('misc.qr.content')}: {text}"

    # ========== 旗语 (Semaphore) ==========

    def semaphore_decode(self, text: str) -> str:
        """旗语（信号旗）解码"""
        # 旗语用角度表示: 每个字母对应两面旗帜的位置
        # 用数字对表示 (左手位置, 右手位置), 1-8 代表 8 个方向
        flag_map = {
            'A': (7, 1), 'B': (6, 1), 'C': (5, 1), 'D': (4, 1),
            'E': (1, 3), 'F': (1, 2), 'G': (1, 1),
            'H': (6, 2), 'I': (5, 2), 'J': (4, 3), 'K': (7, 4),
            'L': (7, 3), 'M': (7, 2), 'N': (6, 4), 'O': (6, 3),
            'P': (5, 4), 'Q': (5, 3), 'R': (4, 5), 'S': (4, 6),
            'T': (3, 4), 'U': (3, 5), 'V': (2, 4), 'W': (2, 3),
            'X': (2, 6), 'Y': (3, 6), 'Z': (3, 2),
        }
        reverse_map = {v: k for k, v in flag_map.items()}
        # 也添加反转的对
        for (a, b), letter in list(reverse_map.items()):
            reverse_map[(b, a)] = letter

        import re as _re
        # 尝试解析数字对格式: "71 61 51" 或 "7,1 6,1 5,1"
        pairs = _re.findall(r'(\d)[,.\s]*(\d)', text)
        if pairs:
            result = []
            for a, b in pairs:
                pair = (int(a), int(b))
                if pair in reverse_map:
                    result.append(reverse_map[pair])
                else:
                    result.append('?')
            return f"{t('misc.semaphore.decoded')}: {''.join(result)}"

        return f"{t('misc.semaphore.parse_failed')}\n{t('misc.semaphore.supported_format')}\n\n{t('misc.semaphore.alphabet')}:\n" + '\n'.join(f"  {k}: {v}" for k, v in sorted(flag_map.items()))

    def semaphore_encode(self, text: str) -> str:
        """旗语（信号旗）编码"""
        flag_map = {
            'A': (7, 1), 'B': (6, 1), 'C': (5, 1), 'D': (4, 1),
            'E': (1, 3), 'F': (1, 2), 'G': (1, 1),
            'H': (6, 2), 'I': (5, 2), 'J': (4, 3), 'K': (7, 4),
            'L': (7, 3), 'M': (7, 2), 'N': (6, 4), 'O': (6, 3),
            'P': (5, 4), 'Q': (5, 3), 'R': (4, 5), 'S': (4, 6),
            'T': (3, 4), 'U': (3, 5), 'V': (2, 4), 'W': (2, 3),
            'X': (2, 6), 'Y': (3, 6), 'Z': (3, 2),
        }
        text = text.upper()
        result = []
        for c in text:
            if c in flag_map:
                r, l = flag_map[c]
                result.append(f"{r}{l}")
            elif c == ' ':
                result.append(' ')
        return f"{t('misc.semaphore.encoded')}: {' '.join(result)}"

    # ========== NATO 音标字母 ==========

    def nato_decode(self, text: str) -> str:
        """NATO 音标字母解码"""
        nato_map = {
            'ALFA': 'A', 'ALPHA': 'A', 'BRAVO': 'B', 'CHARLIE': 'C',
            'DELTA': 'D', 'ECHO': 'E', 'FOXTROT': 'F', 'GOLF': 'G',
            'HOTEL': 'H', 'INDIA': 'I', 'JULIET': 'J', 'JULIETT': 'J',
            'KILO': 'K', 'LIMA': 'L', 'MIKE': 'M', 'NOVEMBER': 'N',
            'OSCAR': 'O', 'PAPA': 'P', 'QUEBEC': 'Q', 'ROMEO': 'R',
            'SIERRA': 'S', 'TANGO': 'T', 'UNIFORM': 'U', 'VICTOR': 'V',
            'WHISKEY': 'W', 'XRAY': 'X', 'X-RAY': 'X', 'YANKEE': 'Y', 'ZULU': 'Z',
            'ZERO': '0', 'ONE': '1', 'TWO': '2', 'THREE': '3', 'FOUR': '4',
            'FIVE': '5', 'SIX': '6', 'SEVEN': '7', 'EIGHT': '8', 'NINER': '9', 'NINE': '9',
        }
        words = text.upper().replace('-', ' ').replace(',', ' ').split()
        result = [nato_map.get(w, f'[{w}]') for w in words]
        return f"{t('misc.nato.decoded')}: {''.join(result)}"

    def nato_encode(self, text: str) -> str:
        """NATO 音标字母编码"""
        char_map = {
            'A': 'Alpha', 'B': 'Bravo', 'C': 'Charlie', 'D': 'Delta',
            'E': 'Echo', 'F': 'Foxtrot', 'G': 'Golf', 'H': 'Hotel',
            'I': 'India', 'J': 'Juliet', 'K': 'Kilo', 'L': 'Lima',
            'M': 'Mike', 'N': 'November', 'O': 'Oscar', 'P': 'Papa',
            'Q': 'Quebec', 'R': 'Romeo', 'S': 'Sierra', 'T': 'Tango',
            'U': 'Uniform', 'V': 'Victor', 'W': 'Whiskey', 'X': 'X-ray',
            'Y': 'Yankee', 'Z': 'Zulu',
            '0': 'Zero', '1': 'One', '2': 'Two', '3': 'Three', '4': 'Four',
            '5': 'Five', '6': 'Six', '7': 'Seven', '8': 'Eight', '9': 'Niner',
        }
        result = [char_map.get(c.upper(), c) for c in text]
        return f"{t('misc.nato.encoded')}: {' '.join(result)}"

    # ========== 坐标系转换 ==========

    def coord_convert(self, text: str) -> str:
        """坐标系转换（十进制 / 度分秒 / Geohash）"""
        import re as _re
        lines = [f"=== {t('misc.coord.title')} ==="]

        # 尝试解析十进制坐标: "39.9042, 116.4074"
        decimal_match = _re.match(r'(-?\d+\.?\d*)[,\s]+(-?\d+\.?\d*)', text.strip())
        if decimal_match:
            lat = float(decimal_match.group(1))
            lon = float(decimal_match.group(2))

            def dd_to_dms(dd):
                d = int(abs(dd))
                m = int((abs(dd) - d) * 60)
                s = (abs(dd) - d - m/60) * 3600
                return d, m, s

            lat_d, lat_m, lat_s = dd_to_dms(lat)
            lon_d, lon_m, lon_s = dd_to_dms(lon)
            lat_dir = 'N' if lat >= 0 else 'S'
            lon_dir = 'E' if lon >= 0 else 'W'

            lines.append(f"{t('misc.base.decimal')}: {lat}, {lon}")
            lines.append(f"{t('misc.coord.dms')}: {lat_d}\u00b0{lat_m}'{lat_s:.2f}\"{lat_dir}, {lon_d}\u00b0{lon_m}'{lon_s:.2f}\"{lon_dir}")
            lines.append(f"Google Maps: https://www.google.com/maps?q={lat},{lon}")

            # 简易 Geohash 编码
            def geohash_encode(lat, lon, precision=12):
                base32 = '0123456789bcdefghjkmnpqrstuvwxyz'
                lat_range = [-90.0, 90.0]
                lon_range = [-180.0, 180.0]
                is_lon = True
                bit = 0
                ch = 0
                result = []
                while len(result) < precision:
                    if is_lon:
                        mid = (lon_range[0] + lon_range[1]) / 2
                        if lon >= mid:
                            ch |= (1 << (4 - bit))
                            lon_range[0] = mid
                        else:
                            lon_range[1] = mid
                    else:
                        mid = (lat_range[0] + lat_range[1]) / 2
                        if lat >= mid:
                            ch |= (1 << (4 - bit))
                            lat_range[0] = mid
                        else:
                            lat_range[1] = mid
                    is_lon = not is_lon
                    bit += 1
                    if bit == 5:
                        result.append(base32[ch])
                        bit = 0
                        ch = 0
                return ''.join(result)

            gh = geohash_encode(lat, lon)
            lines.append(f"Geohash: {gh}")

            return '\n'.join(lines)

        # 尝试解析度分秒: "39\u00b054'15\"N 116\u00b024'27\"E"
        dms_match = _re.findall(r'(\d+)[\u00b0d]\s*(\d+)[\'m]\s*([\d.]+)["s]?\s*([NSEWnsew])', text)
        if len(dms_match) >= 2:
            def dms_to_dd(d, m, s, direction):
                dd = int(d) + int(m)/60 + float(s)/3600
                if direction.upper() in ('S', 'W'):
                    dd = -dd
                return dd

            lat = dms_to_dd(*dms_match[0])
            lon = dms_to_dd(*dms_match[1])
            lines.append(f"{t('misc.coord.dms_input')}: {text}")
            lines.append(f"{t('misc.base.decimal')}: {lat:.6f}, {lon:.6f}")
            lines.append(f"Google Maps: https://www.google.com/maps?q={lat:.6f},{lon:.6f}")
            return '\n'.join(lines)

        return f"{t('misc.coord.parse_failed')}\n{t('misc.coord.supported_formats')}"

    # ========== Leet Speak (1337) ==========

    def leet_decode(self, text: str) -> str:
        """Leet Speak (1337) 解码"""
        # 简单映射（单字符）
        simple = {'4': 'A', '@': 'A', '8': 'B', '3': 'E', '6': 'G',
                  '9': 'G', '#': 'H', '1': 'I', '!': 'I', '0': 'O',
                  '5': 'S', '$': 'S', '7': 'T', '+': 'T', '2': 'Z'}

        result = []
        for c in text:
            if c in simple:
                result.append(simple[c])
            else:
                result.append(c.upper())

        return f"{t('misc.leet.decoded')}: {''.join(result)}"

    def leet_encode(self, text: str) -> str:
        """Leet Speak (1337) 编码"""
        leet_map = {
            'A': '4', 'B': '8', 'C': '(', 'D': '|)', 'E': '3',
            'F': '|=', 'G': '6', 'H': '#', 'I': '1', 'J': '_|',
            'K': '|<', 'L': '|_', 'M': '|v|', 'N': '|\\|', 'O': '0',
            'P': '|*', 'Q': '(,)', 'R': '|2', 'S': '5', 'T': '7',
            'U': '|_|', 'V': '\\/', 'W': '\\^/', 'X': '><', 'Y': '`/',
            'Z': '2',
        }
        result = [leet_map.get(c.upper(), c) for c in text]
        return f"1337: {''.join(result)}"

    # ========== Baudot / ITA2 码 ==========

    def baudot_decode(self, text: str) -> str:
        """Baudot / ITA2 电传打字机编码解码"""
        # ITA2 字母表 (5位编码)
        letters = '\x00E\nA SIU\rDRJNFCKTZLWHYPQOBG\x00MXV\x00'
        figures = '\x003\n- \x0787\r$4\',.:(5+)2\u00a36019?&\x00./;\x00'

        import re as _re

        # 尝试解析二进制格式: "00001 11000 10100"
        bits = _re.findall(r'[01]{5}', text.replace(' ', ''))
        if not bits:
            # 尝试十进制格式: "1 24 20"
            nums = text.strip().split()
            try:
                bits = [format(int(n), '05b') for n in nums]
            except ValueError:
                return f"{t('misc.baudot.parse_failed')}\n{t('misc.baudot.supported_formats')}"

        result = []
        shift = 'letters'  # 当前模式
        for b in bits:
            code = int(b, 2)
            if code == 31:  # 字母模式切换
                shift = 'letters'
                continue
            elif code == 27:  # 数字/符号模式切换
                shift = 'figures'
                continue

            if shift == 'letters' and code < len(letters):
                c = letters[code]
            elif shift == 'figures' and code < len(figures):
                c = figures[code]
            else:
                c = '?'

            if c not in ('\x00', '\r'):
                result.append(c)

        return f"{t('misc.baudot.decoded')}: {''.join(result)}"

    # ========== Emoji 替换密码 ==========

    def emoji_cipher_decode(self, text: str) -> str:
        """Emoji 替换密码解码（emoji → 字母）"""
        emoji_map = {
            '🍎': 'A', '🍌': 'B', '🍒': 'C', '🍩': 'D', '🥚': 'E',
            '🍟': 'F', '🍇': 'G', '🍯': 'H', '🍦': 'I', '🧃': 'J',
            '🥝': 'K', '🍋': 'L', '🍈': 'M', '🥜': 'N', '🍊': 'O',
            '🍑': 'P', '👑': 'Q', '🌹': 'R', '⭐': 'S', '🍵': 'T',
            '☂': 'U', '🌋': 'V', '🍉': 'W', '❌': 'X', '💛': 'Y',
            '⚡': 'Z',
        }
        result = []
        i = 0
        while i < len(text):
            matched = False
            # emoji 可能占 1~2 个 code point，尝试匹配最长
            for length in (2, 1):
                chunk = text[i:i + length]
                if chunk in emoji_map:
                    result.append(emoji_map[chunk])
                    i += length
                    matched = True
                    break
            if not matched:
                result.append(text[i])
                i += 1
        decoded = ''.join(result)
        return f"{t('misc.emoji.decoded')}: {decoded}"

    def emoji_cipher_encode(self, text: str) -> str:
        """Emoji 替换密码编码（字母 → emoji）"""
        letter_map = {
            'A': '🍎', 'B': '🍌', 'C': '🍒', 'D': '🍩', 'E': '🥚',
            'F': '🍟', 'G': '🍇', 'H': '🍯', 'I': '🍦', 'J': '🧃',
            'K': '🥝', 'L': '🍋', 'M': '🍈', 'N': '🥜', 'O': '🍊',
            'P': '🍑', 'Q': '👑', 'R': '🌹', 'S': '⭐', 'T': '🍵',
            'U': '☂', 'V': '🌋', 'W': '🍉', 'X': '❌', 'Y': '💛',
            'Z': '⚡',
        }
        result = []
        for ch in text.upper():
            if ch in letter_map:
                result.append(letter_map[ch])
            else:
                result.append(ch)
        encoded = ''.join(result)
        return f"{t('misc.emoji.encoded')}: {encoded}"

    # ========== Manchester 编码 ==========

    def manchester_decode(self, text: str) -> str:
        """Manchester 编码解码（支持 IEEE 802.3 和 Thomas 两种标准）"""
        raw = re.sub(r'[^01]', '', text)
        if len(raw) % 2 != 0:
            return t("misc.manchester.odd_bits")
        if not raw:
            return t("misc.manchester.no_binary")

        results = []

        # IEEE 802.3: 0→"01", 1→"10"
        ieee_bits = []
        ieee_ok = True
        for i in range(0, len(raw), 2):
            pair = raw[i:i + 2]
            if pair == '01':
                ieee_bits.append('0')
            elif pair == '10':
                ieee_bits.append('1')
            else:
                ieee_ok = False
                break

        if ieee_ok and len(ieee_bits) % 8 == 0:
            chars = []
            for i in range(0, len(ieee_bits), 8):
                byte = ''.join(ieee_bits[i:i + 8])
                chars.append(chr(int(byte, 2)))
            results.append(f"IEEE 802.3 {t('misc.manchester.standard')}: {''.join(chars)}")

        # Thomas (差分): 0→"10", 1→"01"
        thomas_bits = []
        thomas_ok = True
        for i in range(0, len(raw), 2):
            pair = raw[i:i + 2]
            if pair == '10':
                thomas_bits.append('0')
            elif pair == '01':
                thomas_bits.append('1')
            else:
                thomas_ok = False
                break

        if thomas_ok and len(thomas_bits) % 8 == 0:
            chars = []
            for i in range(0, len(thomas_bits), 8):
                byte = ''.join(thomas_bits[i:i + 8])
                chars.append(chr(int(byte, 2)))
            results.append(f"Thomas {t('misc.manchester.standard')}:     {''.join(chars)}")

        if not results:
            return t("misc.manchester.decode_failed")

        return f"{t('misc.manchester.decoded')}:\n" + '\n'.join(results)

    def manchester_encode(self, text: str, standard: str = "ieee") -> str:
        """Manchester 编码（文本 → 二进制 → Manchester）"""
        results = []
        binary = ''.join(format(ord(c), '08b') for c in text)

        # IEEE 802.3: 0→"01", 1→"10"
        ieee = ''.join('01' if b == '0' else '10' for b in binary)
        results.append(f"IEEE 802.3: {ieee}")

        # Thomas: 0→"10", 1→"01"
        thomas = ''.join('10' if b == '0' else '01' for b in binary)
        results.append(f"Thomas:     {thomas}")

        return f"{t('misc.manchester.encoded')}:\n" + '\n'.join(results)

    # ========== 颜色十六进制解码 ==========

    def color_hex_decode(self, text: str) -> str:
        """颜色十六进制解码（将颜色值的 R/G/B 分量作为 ASCII 码解码）"""
        results = []
        text = text.strip()

        # 格式1: "#52 #47 #42" — 每个 # 后跟两位十六进制
        single_hex = re.findall(r'#([0-9a-fA-F]{2})\b', text)
        if single_hex:
            chars = [chr(int(h, 16)) for h in single_hex if 32 <= int(h, 16) < 127]
            if chars:
                results.append(f"{t('misc.color.single_hex')}: {''.join(chars)}")

        # 格式2: "rgb(82,71,66)" — 取 R, G, B 各作为 ASCII
        rgb_matches = re.findall(r'rgb\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)', text, re.IGNORECASE)
        if rgb_matches:
            chars = []
            for r, g, b in rgb_matches:
                for val in (int(r), int(g), int(b)):
                    if 32 <= val < 127:
                        chars.append(chr(val))
            if chars:
                results.append(f"{t('misc.color.rgb_decode')}: {''.join(chars)}")

        # 格式3: "#524742" — 6位十六进制颜色码，拆成 R/G/B
        hex6_matches = re.findall(r'#([0-9a-fA-F]{6})\b', text)
        if hex6_matches:
            # 拼接所有 R+G+B 分量
            all_chars = []
            r_chars = []
            for h in hex6_matches:
                r_val = int(h[0:2], 16)
                g_val = int(h[2:4], 16)
                b_val = int(h[4:6], 16)
                for val in (r_val, g_val, b_val):
                    if 32 <= val < 127:
                        all_chars.append(chr(val))
                if 32 <= r_val < 127:
                    r_chars.append(chr(r_val))
            if all_chars:
                results.append(f"{t('misc.color.rgb_concat')}: {''.join(all_chars)}")
            if r_chars and r_chars != all_chars:
                results.append(f"{t('misc.color.r_only')}:    {''.join(r_chars)}")

        if not results:
            return f"{t('misc.color.decode_failed')}\n{t('misc.color.supported_formats')}"

        return f"{t('misc.color.decoded')}:\n" + '\n'.join(results)

    # ========== 跳舞小人密码 ==========

    def dancing_men_decode(self, text: str) -> str:
        """跳舞小人密码解码（福尔摩斯）"""
        # 经典跳舞小人编号到字母的映射（基于常用对照表）
        num_to_letter = {
            1: 'A', 2: 'B', 3: 'C', 4: 'D', 5: 'E',
            6: 'F', 7: 'G', 8: 'H', 9: 'I', 10: 'J',
            11: 'K', 12: 'L', 13: 'M', 14: 'N', 15: 'O',
            16: 'P', 17: 'Q', 18: 'R', 19: 'S', 20: 'T',
            21: 'U', 22: 'V', 23: 'W', 24: 'X', 25: 'Y',
            26: 'Z',
        }

        # 也接受字母描述格式如 "man_a man_b" 或 "dance_a"
        alpha_matches = re.findall(r'(?:man|dance|dancer|figure)[_\-]?([a-zA-Z])', text, re.IGNORECASE)
        if alpha_matches:
            decoded = ''.join(ch.upper() for ch in alpha_matches)
            return f"{t('misc.dancing.decoded_desc')}: {decoded}"

        # 尝试从文本中提取数字序列
        numbers = re.findall(r'\d+', text)
        if not numbers:
            return (f"{t('misc.dancing.decode_failed')}\n"
                    f"{t('misc.dancing.supported_formats')}")

        result = []
        unknown = []
        for n in numbers:
            num = int(n)
            if num in num_to_letter:
                result.append(num_to_letter[num])
            elif num == 0:
                result.append(' ')  # 0 作为空格
            else:
                result.append('?')
                unknown.append(n)

        decoded = ''.join(result)
        output = f"{t('misc.dancing.decoded')}: {decoded}"
        if unknown:
            output += f"\n{t('misc.dancing.unknown_ids')}: {', '.join(unknown)}"
        output += f"\n{t('misc.dancing.mapping')}"
        return output

    # ========== 文本字频统计 ==========

    def word_frequency(self, text: str) -> str:
        """文本字频统计与密码分析辅助"""
        if not text.strip():
            return t("misc.freq.empty_text")

        # 英文标准字母频率（%）
        english_freq = {
            'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
            'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25,
            'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
            'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29,
            'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10,
            'Z': 0.07,
        }

        results = []

        # 字符频率统计
        char_count = {}
        total_chars = 0
        alpha_count = {}
        total_alpha = 0

        for ch in text:
            char_count[ch] = char_count.get(ch, 0) + 1
            total_chars += 1
            if ch.isalpha():
                upper = ch.upper()
                alpha_count[upper] = alpha_count.get(upper, 0) + 1
                total_alpha += 1

        results.append(f"{t('misc.freq.total_chars')}: {total_chars}")
        results.append(f"{t('misc.freq.alpha_chars')}: {total_alpha}")
        results.append("")

        # 字母频率（按频率降序）
        if alpha_count:
            results.append(f"{t('misc.freq.letter_freq')}:")
            sorted_alpha = sorted(alpha_count.items(), key=lambda x: -x[1])
            for ch, count in sorted_alpha:
                pct = count / total_alpha * 100 if total_alpha else 0
                eng_pct = english_freq.get(ch, 0)
                bar = '█' * int(pct / 2)
                results.append(f"  {ch}: {count:4d} ({pct:5.2f}%) {bar:<10s}  [{t('misc.freq.english_std')}: {eng_pct:.2f}%]")

        # 重合指数 (Index of Coincidence)
        if total_alpha > 1:
            ic = sum(n * (n - 1) for n in alpha_count.values()) / (total_alpha * (total_alpha - 1))
            results.append("")
            results.append(f"{t('misc.freq.ic')}: {ic:.6f}")
            results.append(f"  {t('misc.freq.ic_reference')}")
            if ic > 0.06:
                results.append(f"  {t('misc.freq.ic_high')}")
            elif ic > 0.04:
                results.append(f"  {t('misc.freq.ic_medium')}")
            else:
                results.append(f"  {t('misc.freq.ic_low')}")

        # 单词频率统计
        words = re.findall(r'[a-zA-Z]+', text)
        if words:
            word_count = {}
            for w in words:
                w_lower = w.lower()
                word_count[w_lower] = word_count.get(w_lower, 0) + 1
            sorted_words = sorted(word_count.items(), key=lambda x: -x[1])
            results.append("")
            results.append(f"{t('misc.freq.word_stats')} ({len(words)} {t('misc.freq.words')}, {len(word_count)} {t('misc.freq.unique_words')}):")
            for w, count in sorted_words[:20]:  # 只显示前20个
                results.append(f"  {w}: {count}")
            if len(sorted_words) > 20:
                results.append(f"  ... {t('misc.wordlist.remaining')} {len(sorted_words) - 20} {t('misc.freq.different_words')}")

        return f"{t('misc.freq.title')}:\n" + '\n'.join(results)

    # ========== Enigma 密码机模拟器 ==========

    def enigma_decrypt(self, text: str, config: str = "") -> str:
        """Enigma 密码机模拟器（简化版，加密和解密为同一操作）"""
        # 转子接线定义（历史标准）
        rotor_wirings = {
            'I':   'EKMFLGDQVZNTOWYHXUSPAIBRCJ',
            'II':  'AJDKSIRUXBLHWTMCQGZNPYFVOE',
            'III': 'BDFHJLCPRTXVZNYEIWGAKMUSQO',
            'IV':  'ESOVPZJAYQUIRHXLNFTGKDCMWB',
            'V':   'VZBRGITYUPSDNHLXAWMJQOFECK',
        }
        rotor_notches = {'I': 'Q', 'II': 'E', 'III': 'V', 'IV': 'J', 'V': 'Z'}
        reflector_wirings = {
            'B': 'YRUHQSLDPXNGOKMIEBFZCWVJAT',
            'C': 'FVPJIAOYEDRZXWGCTKUQSBNMHL',
        }

        # 解析配置
        rotors_names = ['I', 'II', 'III']
        reflector_name = 'B'
        ring_settings = [0, 0, 0]
        positions = [0, 0, 0]
        plugboard_pairs = []

        if config:
            for part in config.split(';'):
                part = part.strip()
                if '=' not in part:
                    continue
                key, val = part.split('=', 1)
                key = key.strip().lower()
                val = val.strip()
                if key == 'rotors':
                    rotors_names = [r.strip().upper() for r in val.split(',')][:3]
                elif key == 'reflector':
                    reflector_name = val.upper()
                elif key == 'ring':
                    ring_settings = [ord(c.upper()) - ord('A') for c in val.upper()[:3]]
                elif key == 'pos':
                    positions = [ord(c.upper()) - ord('A') for c in val.upper()[:3]]
                elif key == 'plugboard':
                    plugboard_pairs = [p.strip().upper() for p in val.split(',') if len(p.strip()) == 2]

        # 验证配置
        for rn in rotors_names:
            if rn not in rotor_wirings:
                return f"{t('misc.enigma.unknown_rotor')} '{rn}', {t('misc.enigma.supported')}: I, II, III, IV, V"
        if reflector_name not in reflector_wirings:
            return f"{t('misc.enigma.unknown_reflector')} '{reflector_name}', {t('misc.enigma.supported')}: B, C"

        # 补齐为3个转子
        while len(rotors_names) < 3:
            rotors_names.append('I')
        while len(ring_settings) < 3:
            ring_settings.append(0)
        while len(positions) < 3:
            positions.append(0)

        # 构建接线板映射
        plugboard = {}
        for pair in plugboard_pairs:
            if len(pair) == 2 and pair[0].isalpha() and pair[1].isalpha():
                a, b = ord(pair[0]) - ord('A'), ord(pair[1]) - ord('A')
                plugboard[a] = b
                plugboard[b] = a

        # 获取转子接线
        rotors = [rotor_wirings[rn] for rn in rotors_names]
        notches = [rotor_notches.get(rn, 'A') for rn in rotors_names]
        reflector = reflector_wirings[reflector_name]

        pos = list(positions)  # 当前位置（会随加密步进）

        def step_rotors():
            """转子步进（含双步进异常）"""
            # 中间转子在缺口位置时，左转子和中间转子同时步进
            if chr(pos[1] + ord('A')) == notches[1]:
                pos[0] = (pos[0] + 1) % 26
                pos[1] = (pos[1] + 1) % 26
            elif chr(pos[2] + ord('A')) == notches[2]:
                pos[1] = (pos[1] + 1) % 26
            pos[2] = (pos[2] + 1) % 26

        def pass_through_rotor(c, rotor_wiring, rotor_pos, ring, forward=True):
            """通过一个转子"""
            if forward:
                shifted = (c + rotor_pos - ring) % 26
                out = ord(rotor_wiring[shifted]) - ord('A')
                return (out - rotor_pos + ring) % 26
            else:
                shifted = (c + rotor_pos - ring) % 26
                out = rotor_wiring.index(chr(shifted + ord('A')))
                return (out - rotor_pos + ring) % 26

        result = []
        for ch in text.upper():
            if not ch.isalpha():
                result.append(ch)
                continue

            c = ord(ch) - ord('A')

            # 步进转子
            step_rotors()

            # 接线板
            c = plugboard.get(c, c)

            # 正向通过 3 个转子（右→左: 2, 1, 0）
            for i in (2, 1, 0):
                c = pass_through_rotor(c, rotors[i], pos[i], ring_settings[i], forward=True)

            # 反射器
            c = ord(reflector[c]) - ord('A')

            # 反向通过 3 个转子（左→右: 0, 1, 2）
            for i in (0, 1, 2):
                c = pass_through_rotor(c, rotors[i], pos[i], ring_settings[i], forward=False)

            # 接线板
            c = plugboard.get(c, c)

            result.append(chr(c + ord('A')))

        pos_str = ''.join(chr(p + ord('A')) for p in positions)
        config_info = (f"{t('misc.enigma.rotors')}: {','.join(rotors_names)} | {t('misc.enigma.reflector')}: {reflector_name} | "
                       f"{t('misc.enigma.init_pos')}: {pos_str}")
        if plugboard_pairs:
            config_info += f" | {t('misc.enigma.plugboard')}: {','.join(plugboard_pairs)}"

        return f"{t('misc.enigma.result')}: {''.join(result)}\n{t('misc.enigma.config')}: {config_info}"

    # ========== 图片像素提取文本 ==========

    def pixel_extract(self, filepath: str, mode: str = "rgb") -> str:
        """图片像素提取隐藏文本"""
        try:
            from PIL import Image
        except ImportError:
            return t("misc.pixel.need_pillow")

        try:
            img = Image.open(filepath)
        except Exception as e:
            return f"{t('misc.pixel.open_failed')}: {e}"

        pixels = list(img.getdata())
        width, height = img.size

        results = []

        if mode == "lsb":
            # 提取每个像素 R 通道最低位
            bits = []
            for px in pixels:
                r = px[0] if isinstance(px, (tuple, list)) else px
                bits.append(str(r & 1))
            # 每 8 位组成一个字节
            chars = []
            for i in range(0, len(bits) - 7, 8):
                byte = ''.join(bits[i:i + 8])
                val = int(byte, 2)
                if val == 0:
                    break
                if 32 <= val < 127:
                    chars.append(chr(val))
                else:
                    break
            if chars:
                results.append(f"{t('misc.pixel.lsb_extract')} (R{t('misc.pixel.channel')}): {''.join(chars)}")
            else:
                results.append(t("misc.pixel.lsb_no_text"))

        elif mode == "r":
            # 提取每个像素的 R 值作为 ASCII
            chars = []
            for px in pixels:
                r = px[0] if isinstance(px, (tuple, list)) else px
                if r == 0:
                    break
                if 32 <= r < 127:
                    chars.append(chr(r))
                else:
                    break
            if chars:
                results.append(f"R {t('misc.pixel.channel')} ASCII: {''.join(chars)}")
            else:
                results.append(t("misc.pixel.r_no_text"))

        else:  # mode == "rgb"
            # 拼接 R+G+B 作为 ASCII
            chars = []
            for px in pixels:
                if isinstance(px, (tuple, list)):
                    channels = px[:3]
                else:
                    channels = (px,)
                for val in channels:
                    if val == 0:
                        break
                    if 32 <= val < 127:
                        chars.append(chr(val))
                    else:
                        break
                else:
                    continue
                break
            if chars:
                results.append(f"RGB {t('misc.pixel.concat_ascii')}: {''.join(chars)}")
            else:
                results.append(t("misc.pixel.rgb_no_text"))

        results.append(f"{t('misc.pixel.image_info')}: {width}x{height}, {t('misc.pixel.mode')}: {img.mode}")
        return f"{t('misc.pixel.result')}:\n" + '\n'.join(results)

    # ========== 键盘布局转换 ==========

    def keyboard_layout_convert(self, text: str, from_layout: str = "qwerty",
                                to_layout: str = "dvorak") -> str:
        """键盘布局转换（支持 QWERTY, Dvorak, Colemak）"""
        layouts = {
            'qwerty':  "qwertyuiopasdfghjkl;zxcvbnm,./"
                       'QWERTYUIOPASDFGHJKL:ZXCVBNM<>?',
            'dvorak':  "',.pyfgcrl/aoeuidhtns;qjkxbmwvz"
                       '"<>PYFGCRL?AOEUIDHTNS:QJKXBMWVZ',
            'colemak': "qwfpgjluy;arstdhneiozxcvbkm,./"
                       'QWFPGJLUY:ARSTDHNEIOZXCVBKM<>?',
        }

        from_key = from_layout.lower()
        to_key = to_layout.lower()

        if from_key not in layouts:
            return f"{t('misc.keyboard.unknown_source')} '{from_layout}', {t('misc.keyboard.supported')}: qwerty, dvorak, colemak"
        if to_key not in layouts:
            return f"{t('misc.keyboard.unknown_target')} '{to_layout}', {t('misc.keyboard.supported')}: qwerty, dvorak, colemak"

        from_chars = layouts[from_key]
        to_chars = layouts[to_key]

        # 构建映射表
        mapping = {}
        for fc, tc in zip(from_chars, to_chars):
            mapping[fc] = tc

        result = []
        for ch in text:
            result.append(mapping.get(ch, ch))

        converted = ''.join(result)
        return f"{t('misc.keyboard.layout_convert')} ({from_layout} → {to_layout}): {converted}"

    # ========== 时间与图像工具 ==========

    def timestamp_convert(self, value: str) -> str:
        """多格式时间戳转换"""
        import datetime
        value = value.strip()
        lines = ["=== 时间戳转换 ===", f"输入: {value}", ""]
        try:
            ts = float(value)
            # Unix 时间戳 (秒)
            if 0 < ts < 2e10:
                dt = datetime.datetime.fromtimestamp(ts)
                lines.append(f"  Unix 时间戳 (秒): {dt.strftime('%Y-%m-%d %H:%M:%S')}")
            # Unix 毫秒
            if ts > 1e12:
                dt = datetime.datetime.fromtimestamp(ts / 1000)
                lines.append(f"  Unix 时间戳 (毫秒): {dt.strftime('%Y-%m-%d %H:%M:%S')}")
            # Windows FILETIME (100纳秒 since 1601-01-01)
            if ts > 1e16:
                win_epoch = datetime.datetime(1601, 1, 1)
                dt = win_epoch + datetime.timedelta(microseconds=ts / 10)
                lines.append(f"  Windows FILETIME: {dt.strftime('%Y-%m-%d %H:%M:%S')}")
            # Mac timestamp (秒 since 2001-01-01)
            if 0 < ts < 1e10:
                mac_epoch = datetime.datetime(2001, 1, 1)
                dt = mac_epoch + datetime.timedelta(seconds=ts)
                lines.append(f"  Mac 时间戳: {dt.strftime('%Y-%m-%d %H:%M:%S')}")
        except (ValueError, OverflowError, OSError):
            pass
        # 尝试解析日期字符串
        for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y/%m/%d %H:%M:%S',
                    '%d/%m/%Y %H:%M:%S', '%Y-%m-%d', '%d %b %Y'):
            try:
                dt = datetime.datetime.strptime(value, fmt)
                lines.append(f"  解析为: {dt.strftime('%Y-%m-%d %H:%M:%S')}")
                lines.append(f"  Unix 时间戳: {int(dt.timestamp())}")
                break
            except ValueError:
                continue
        if len(lines) == 3:
            lines.append("  无法解析时间戳格式")
        return "\n".join(lines)

    def qr_batch_decode(self, directory: str) -> str:
        """批量扫描目录中所有图片的二维码"""
        import os
        if not os.path.isdir(directory):
            return f"不是有效的目录: {directory}"
        image_exts = {'.png', '.jpg', '.jpeg', '.bmp', '.gif', '.tiff'}
        files = [os.path.join(directory, f) for f in os.listdir(directory)
                 if os.path.splitext(f)[1].lower() in image_exts]
        if not files:
            return f"目录中未发现图片文件: {directory}"
        lines = ["=== 二维码批量扫描 ===", f"目录: {directory}", f"图片数: {len(files)}", ""]
        found = 0
        for filepath in sorted(files):
            result = self.qr_decode(filepath)
            if "内容" in result or "content" in result.lower():
                found += 1
                lines.append(f"  [+] {os.path.basename(filepath)}:")
                for line in result.split('\n'):
                    if '内容' in line or 'content' in line.lower() or 'Flag' in line:
                        lines.append(f"      {line.strip()}")
        if found == 0:
            lines.append("  [-] 未从任何图片中检测到二维码")
        else:
            lines.append(f"\n共从 {found}/{len(files)} 个图片中检测到二维码")
        return "\n".join(lines)

    def ocr_extract(self, image_path: str) -> str:
        """图片文字提取 (OCR)"""
        try:
            from PIL import Image
        except ImportError:
            return "需要安装 Pillow: pip install Pillow"
        lines = ["=== 图片 OCR 提取 ===", f"文件: {image_path}", ""]
        img = Image.open(image_path)
        lines.append(f"  尺寸: {img.size[0]}x{img.size[1]}")
        lines.append(f"  模式: {img.mode}")
        # 尝试 pytesseract
        try:
            import pytesseract
            text = pytesseract.image_to_string(img, lang='eng+chi_sim')
            if text.strip():
                lines.append("\n  OCR 识别结果:")
                lines.append(f"  {text.strip()}")
            else:
                lines.append("\n  OCR 未识别到文字")
            return "\n".join(lines)
        except ImportError:
            pass
        # 回退: 简单像素分析
        lines.append("\n  [*] pytesseract 未安装，使用简易像素分析")
        lines.append("  安装完整 OCR: pip install pytesseract")
        lines.append("  还需安装 Tesseract-OCR: https://github.com/tesseract-ocr/tesseract")
        # 提取黑白对比度高的区域
        gray = img.convert('L')
        pixels = list(gray.getdata())
        dark = sum(1 for p in pixels if p < 128)
        light = len(pixels) - dark
        lines.append(f"\n  像素分析: 暗像素 {dark} ({dark*100//len(pixels)}%), 亮像素 {light} ({light*100//len(pixels)}%)")
        if dark > 0 and light > 0:
            ratio = dark / light if light > 0 else 0
            if 0.01 < ratio < 0.5:
                lines.append("  [*] 暗/亮比例适中，可能包含文字")
            elif ratio >= 0.5:
                lines.append("  [*] 暗像素比例较高，可能是暗背景图片")
        return "\n".join(lines)

    # ========== UUencode 编解码 ==========

    def uuencode(self, text: str) -> str:
        """文本 → UUencode 编码"""
        try:
            import binascii
            data = text.encode('utf-8')
            # binascii.b2a_uu 每次最多处理 45 字节
            encoded_lines = []
            for i in range(0, len(data), 45):
                chunk = data[i:i + 45]
                encoded_lines.append(binascii.b2a_uu(chunk).decode('ascii').rstrip('\n'))
            encoded = '\n'.join(encoded_lines)
            # 带 begin/end 头的完整格式
            full = f"begin 644 data\n{encoded}\n`\nend"
            lines = ["=== UUencode ==="]
            lines.append(f"{t('misc.uuencode.raw')}: {encoded}")
            lines.append(f"\n{t('misc.uuencode.full_format')}:")
            lines.append(full)
            return "\n".join(lines)
        except Exception as e:
            return f"{t('misc.uuencode.encode_failed')}: {e}"

    def uudecode(self, text: str) -> str:
        """UUencode → 文本解码（支持带 begin 头和不带头两种格式）"""
        try:
            import binascii
            text = text.strip()
            lines_input = text.splitlines()

            # 检测是否有 begin 头
            data_lines = []
            for line in lines_input:
                stripped = line.strip()
                if stripped.lower().startswith('begin '):
                    continue
                if stripped == 'end' or stripped == '`':
                    continue
                if stripped:
                    data_lines.append(stripped)

            if not data_lines:
                return t("misc.uudecode.empty_input")

            decoded_bytes = b''
            for dl in data_lines:
                try:
                    decoded_bytes += binascii.a2b_uu(dl + '\n')
                except binascii.Error:
                    try:
                        decoded_bytes += binascii.a2b_uu(dl)
                    except binascii.Error as e2:
                        return f"{t('misc.uudecode.decode_failed')}: {e2}"

            result = decoded_bytes.decode('utf-8', errors='replace')
            return f"{t('misc.uudecode.decoded')}: {result}"
        except Exception as e:
            return f"{t('misc.uudecode.decode_failed')}: {e}"

    # ========== XXencode 编解码 ==========

    XX_TABLE = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    def xxencode(self, text: str) -> str:
        """文本 → XXencode 编码"""
        try:
            data = text.encode('utf-8')
            result = []
            for i in range(0, len(data), 3):
                chunk = data[i:i + 3]
                b0 = chunk[0] if len(chunk) > 0 else 0
                b1 = chunk[1] if len(chunk) > 1 else 0
                b2 = chunk[2] if len(chunk) > 2 else 0

                c0 = (b0 >> 2) & 0x3F
                c1 = ((b0 << 4) | (b1 >> 4)) & 0x3F
                c2 = ((b1 << 2) | (b2 >> 6)) & 0x3F
                c3 = b2 & 0x3F

                result.append(self.XX_TABLE[c0])
                result.append(self.XX_TABLE[c1])
                if len(chunk) > 1:
                    result.append(self.XX_TABLE[c2])
                else:
                    result.append(self.XX_TABLE[0])  # padding '+'
                if len(chunk) > 2:
                    result.append(self.XX_TABLE[c3])
                else:
                    result.append(self.XX_TABLE[0])  # padding '+'

            encoded = ''.join(result)
            return f"XXencode: {encoded}"
        except Exception as e:
            return f"{t('misc.xxencode.encode_failed')}: {e}"

    def xxdecode(self, text: str) -> str:
        """XXencode → 文本解码"""
        try:
            text = text.strip()
            # 去除可能的 begin/end 头
            lines_input = text.splitlines()
            data_lines = []
            for line in lines_input:
                stripped = line.strip()
                if stripped.lower().startswith('begin ') or stripped == 'end' or stripped == '+':
                    continue
                if stripped:
                    data_lines.append(stripped)

            encoded = ''.join(data_lines)

            # 构建反查表
            xx_reverse = {}
            for idx, ch in enumerate(self.XX_TABLE):
                xx_reverse[ch] = idx

            # 验证字符
            for ch in encoded:
                if ch not in xx_reverse:
                    return f"{t('misc.xxdecode.invalid_char')}: '{ch}'"

            decoded_bytes = bytearray()
            for i in range(0, len(encoded), 4):
                chunk = encoded[i:i + 4]
                if len(chunk) < 4:
                    chunk = chunk.ljust(4, self.XX_TABLE[0])

                c0 = xx_reverse[chunk[0]]
                c1 = xx_reverse[chunk[1]]
                c2 = xx_reverse[chunk[2]]
                c3 = xx_reverse[chunk[3]]

                b0 = ((c0 << 2) | (c1 >> 4)) & 0xFF
                b1 = ((c1 << 4) | (c2 >> 2)) & 0xFF
                b2 = ((c2 << 6) | c3) & 0xFF

                decoded_bytes.append(b0)
                decoded_bytes.append(b1)
                decoded_bytes.append(b2)

            # 去除尾部的零填充
            result = decoded_bytes.rstrip(b'\x00').decode('utf-8', errors='replace')
            return f"{t('misc.xxdecode.decoded')}: {result}"
        except Exception as e:
            return f"{t('misc.xxdecode.decode_failed')}: {e}"

    # ========== Quoted-Printable 编解码 ==========

    def quoted_printable_encode(self, text: str) -> str:
        """文本 → Quoted-Printable 编码"""
        try:
            import quopri
            encoded = quopri.encodestring(text.encode('utf-8')).decode('ascii')
            return f"Quoted-Printable:\n{encoded}"
        except Exception as e:
            return f"{t('misc.qp.encode_failed')}: {e}"

    def quoted_printable_decode(self, text: str) -> str:
        """Quoted-Printable → 文本解码"""
        try:
            import quopri
            decoded = quopri.decodestring(
                text.encode('ascii', errors='replace')
            ).decode('utf-8', errors='replace')
            return f"{t('misc.qp.decoded')}: {decoded}"
        except Exception as e:
            return f"{t('misc.qp.decode_failed')}: {e}"

    # ========== 音频摩尔斯解码 ==========

    def audio_morse_decode(self, filepath: str) -> str:
        """从 WAV 文件中解码摩尔斯电码音频"""
        try:
            import os
            import struct

            if not os.path.isfile(filepath):
                return f"{t('misc.audio_morse.file_not_found')}: {filepath}"

            with open(filepath, 'rb') as f:
                # 解析 WAV 头部
                riff = f.read(4)
                if riff != b'RIFF':
                    return t("misc.audio_morse.not_wav")

                f.read(4)  # file size
                wave = f.read(4)
                if wave != b'WAVE':
                    return t("misc.audio_morse.not_wav")

                # 查找 fmt 和 data 块
                num_channels = 1
                sample_rate = 44100
                bits_per_sample = 16
                audio_data = b''

                while True:
                    chunk_header = f.read(8)
                    if len(chunk_header) < 8:
                        break
                    chunk_id = chunk_header[:4]
                    chunk_size = struct.unpack('<I', chunk_header[4:8])[0]

                    if chunk_id == b'fmt ':
                        fmt_data = f.read(chunk_size)
                        num_channels = struct.unpack('<H', fmt_data[2:4])[0]
                        sample_rate = struct.unpack('<I', fmt_data[4:8])[0]
                        bits_per_sample = struct.unpack('<H', fmt_data[14:16])[0]
                    elif chunk_id == b'data':
                        audio_data = f.read(chunk_size)
                        break
                    else:
                        f.read(chunk_size)

            if not audio_data:
                return t("misc.audio_morse.no_audio_data")

            # 解析采样数据（仅取第一声道）
            if bits_per_sample == 16:
                fmt_str = '<h'
                sample_size = 2
            elif bits_per_sample == 8:
                fmt_str = '<B'
                sample_size = 1
            else:
                return f"{t('misc.audio_morse.unsupported_bits')}: {bits_per_sample}"

            samples = []
            stride = sample_size * num_channels
            for i in range(0, len(audio_data) - sample_size + 1, stride):
                val = struct.unpack(fmt_str, audio_data[i:i + sample_size])[0]
                if bits_per_sample == 8:
                    val = val - 128
                samples.append(abs(val))

            if not samples:
                return t("misc.audio_morse.no_samples")

            # 确定有声/无声阈值（峰值的 30%）
            max_amp = max(samples)
            threshold = max_amp * 0.3

            # 将采样按窗口划分为有声/无声区间
            window_size = max(1, sample_rate // 200)  # ~5ms 窗口
            intervals = []  # [(state, duration_in_samples), ...]
            current_state = 'off'
            current_start = 0

            for i in range(0, len(samples), window_size):
                window = samples[i:i + window_size]
                avg_amp = sum(window) / len(window)
                state = 'on' if avg_amp > threshold else 'off'

                if state != current_state:
                    duration = i - current_start
                    if duration > 0:
                        intervals.append((current_state, duration))
                    current_state = state
                    current_start = i

            duration = len(samples) - current_start
            if duration > 0:
                intervals.append((current_state, duration))

            # 过滤噪声（< 10ms 的区间合并到前一个）
            min_duration = sample_rate // 100
            filtered = []
            for state, dur in intervals:
                if dur >= min_duration:
                    filtered.append((state, dur))
                elif filtered:
                    prev_state, prev_dur = filtered[-1]
                    filtered[-1] = (prev_state, prev_dur + dur)

            if not filtered:
                return t("misc.audio_morse.no_morse_detected")

            # 收集有声区间时长，通过聚类区分 dot / dash
            on_durations = [dur for state, dur in filtered if state == 'on']
            if not on_durations:
                return t("misc.audio_morse.no_morse_detected")

            avg_on = sum(on_durations) / len(on_durations)
            short_durs = [d for d in on_durations if d < avg_on]
            dot_duration = (sum(short_durs) / len(short_durs)) if short_durs else (avg_on / 3)

            # 阈值：长声 > 短声的 2 倍
            dash_threshold = dot_duration * 2
            # 字符间隔 > 3 倍 dot 时长
            char_gap_threshold = dot_duration * 3
            # 单词间隔 > 7 倍 dot 时长
            word_gap_threshold = dot_duration * 7

            # 转换为摩尔斯符号
            morse_tokens = []
            for state, dur in filtered:
                if state == 'on':
                    morse_tokens.append('-' if dur >= dash_threshold else '.')
                else:
                    if dur >= word_gap_threshold:
                        morse_tokens.append(' / ')
                    elif dur >= char_gap_threshold:
                        morse_tokens.append(' ')
                    # dot 间的短间隔不添加分隔

            morse_str = ''.join(morse_tokens)

            # 用已有的 MORSE_DECODE 表解码
            words = morse_str.split(' / ')
            decoded_parts = []
            for word in words:
                chars = word.strip().split()
                decoded_word = ''
                for ch in chars:
                    if ch in self.MORSE_DECODE:
                        decoded_word += self.MORSE_DECODE[ch]
                    elif ch:
                        decoded_word += '?'
                decoded_parts.append(decoded_word)

            decoded_text = ' '.join(decoded_parts)

            lines = [f"=== {t('misc.audio_morse.title')} ==="]
            lines.append(f"{t('misc.audio_morse.file')}: {filepath}")
            lines.append(f"{t('misc.audio_morse.sample_rate')}: {sample_rate} Hz")
            lines.append(
                f"{t('misc.audio_morse.duration')}: "
                f"{len(samples) / sample_rate:.2f}s"
            )
            lines.append(f"{t('misc.audio_morse.morse_code')}: {morse_str}")
            lines.append(f"{t('misc.audio_morse.decoded')}: {decoded_text}")
            return "\n".join(lines)

        except Exception as e:
            return f"{t('misc.audio_morse.decode_failed')}: {e}"

    # ========== Piet 语言辅助 ==========

    PIET_COLORS = {
        (255, 192, 192): "light red",
        (255, 0, 0): "red",
        (192, 0, 0): "dark red",
        (255, 255, 192): "light yellow",
        (255, 255, 0): "yellow",
        (192, 192, 0): "dark yellow",
        (192, 255, 192): "light green",
        (0, 255, 0): "green",
        (0, 192, 0): "dark green",
        (192, 255, 255): "light cyan",
        (0, 255, 255): "cyan",
        (0, 192, 192): "dark cyan",
        (192, 192, 255): "light blue",
        (0, 0, 255): "blue",
        (0, 0, 192): "dark blue",
        (255, 192, 255): "light magenta",
        (255, 0, 255): "magenta",
        (192, 0, 192): "dark magenta",
        (255, 255, 255): "white",
        (0, 0, 0): "black",
    }

    def piet_helper(self, filepath: str) -> str:
        """Piet 语言辅助 -- 检测图片是否为 Piet 程序并给出建议"""
        try:
            import os
            if not os.path.isfile(filepath):
                return f"{t('misc.piet.file_not_found')}: {filepath}"

            try:
                from PIL import Image
            except ImportError:
                return t("misc.piet.need_pillow")

            img = Image.open(filepath).convert('RGB')
            width, height = img.size
            pixels = list(img.getdata())

            # 统计颜色分布
            color_count = {}
            for px in pixels:
                rgb = (px[0], px[1], px[2])
                color_count[rgb] = color_count.get(rgb, 0) + 1

            total_pixels = width * height
            piet_pixel_count = 0
            piet_colors_found = []
            non_piet_colors = []

            for rgb, count in color_count.items():
                if rgb in self.PIET_COLORS:
                    piet_pixel_count += count
                    piet_colors_found.append(
                        (self.PIET_COLORS[rgb], rgb, count)
                    )
                else:
                    non_piet_colors.append((rgb, count))

            piet_ratio = (
                piet_pixel_count / total_pixels if total_pixels > 0 else 0
            )

            lines = [f"=== {t('misc.piet.title')} ==="]
            lines.append(f"{t('misc.piet.file')}: {filepath}")
            lines.append(f"{t('misc.piet.size')}: {width}x{height}")
            lines.append(f"{t('misc.piet.total_colors')}: {len(color_count)}")
            lines.append(
                f"{t('misc.piet.piet_colors')}: {len(piet_colors_found)}/20"
            )
            lines.append(f"{t('misc.piet.piet_ratio')}: {piet_ratio:.1%}")

            if piet_ratio >= 0.95:
                lines.append(f"\n[+] {t('misc.piet.very_likely')}")
            elif piet_ratio >= 0.7:
                lines.append(f"\n[*] {t('misc.piet.possibly')}")
            else:
                lines.append(f"\n[-] {t('misc.piet.unlikely')}")

            if piet_colors_found:
                lines.append(f"\n{t('misc.piet.found_colors')}:")
                for name, rgb, count in sorted(
                    piet_colors_found, key=lambda x: -x[2]
                ):
                    lines.append(f"  {name}: RGB{rgb} x{count}")

            if non_piet_colors:
                lines.append(
                    f"\n{t('misc.piet.non_piet_colors')}: "
                    f"{len(non_piet_colors)}"
                )
                for rgb, count in sorted(
                    non_piet_colors, key=lambda x: -x[1]
                )[:5]:
                    lines.append(f"  RGB{rgb} x{count}")

            lines.append(f"\n=== {t('misc.piet.suggestions')} ===")
            lines.append(
                f"  [1] npiet ({t('misc.piet.cli_interpreter')}): "
                f"https://www.bertnase.de/npiet/"
            )
            lines.append(
                f"  [2] {t('misc.piet.online_interpreter')}: "
                f"https://www.bertnase.de/npiet/npiet-execute.php"
            )
            lines.append(
                f"  [3] PietDev ({t('misc.piet.visual_editor')}): "
                f"https://www.pietdeveloper.com/"
            )
            lines.append(
                f"  [4] {t('misc.piet.usage_tip')}: npiet {filepath}"
            )

            return "\n".join(lines)
        except Exception as e:
            return f"{t('misc.piet.analyze_failed')}: {e}"

    # ========== Malbolge 执行 ==========

    def malbolge_execute(self, code: str) -> str:
        """Malbolge 解释器（简化版，核心指令集，最大 10000 步）"""
        try:
            MEM_SIZE = 59049  # 3^10
            MAX_STEPS = 10000

            # Malbolge crazy 运算表（三进制逐位运算）
            CRAZY_OP = [
                [1, 0, 0],
                [1, 0, 2],
                [2, 2, 1],
            ]

            def crazy(a, d):
                result = 0
                power = 1
                for _ in range(10):
                    result += CRAZY_OP[d % 3][a % 3] * power
                    power *= 3
                    d //= 3
                    a //= 3
                return result % MEM_SIZE

            def rotate_r(val):
                return val // 3 + (val % 3) * (MEM_SIZE // 3)

            # 执行后的指令加密表（标准 Malbolge 规范）
            encrypt_str = (
                "5z]&gqtyfr$(9B\"?/O`>@<');#:.,"
                "bJhSADdFGjkIKcVuYWX"
                "NUPlOQRsTtEevwxLMno"
                "pHaim+Zdq1~}|{zyC"
                "4%3210/.-,+*)('&%$#\"!"
            )

            # 加载程序到内存
            mem = [0] * MEM_SIZE
            pos = 0
            for ch in code:
                if ch in (' ', '\t', '\n', '\r'):
                    continue
                ascii_val = ord(ch)
                if ascii_val < 33 or ascii_val > 126:
                    continue
                mem[pos] = ascii_val
                pos += 1

            if pos == 0:
                return t("misc.malbolge.empty_code")

            # 用 crazy 运算填充剩余内存
            for i in range(pos, MEM_SIZE):
                mem[i] = crazy(mem[i - 1], mem[i - 2])

            # 执行
            c = 0   # 代码指针
            d = 0   # 数据指针
            a = 0   # 累加器
            output = []
            steps = 0

            while steps < MAX_STEPS:
                steps += 1
                if c >= MEM_SIZE:
                    break

                val = mem[c]
                instr = (val + c) % 94

                if instr == 4:      # jmp [d]
                    c = mem[d]
                elif instr == 5:    # out a
                    output.append(chr(a % 256))
                elif instr == 23:   # in (无输入，返回 EOF)
                    a = MEM_SIZE - 1
                elif instr == 39:   # rotr [d]; mov a, [d]
                    mem[d] = rotate_r(mem[d])
                    a = mem[d]
                elif instr == 40:   # mov d, [d]
                    d = mem[d]
                elif instr == 62:   # crz [d], a; mov a, [d]
                    mem[d] = crazy(a, mem[d])
                    a = mem[d]
                elif instr == 68:   # nop
                    pass
                elif instr == 81:   # halt
                    break

                # 加密 mem[c]
                if 33 <= mem[c] <= 126:
                    idx = mem[c] - 33
                    if idx < len(encrypt_str):
                        mem[c] = ord(encrypt_str[idx])

                c = (c + 1) % MEM_SIZE
                d = (d + 1) % MEM_SIZE

            result = ''.join(output)
            lines = ["=== Malbolge ==="]
            lines.append(f"{t('misc.malbolge.steps')}: {steps}")
            if steps >= MAX_STEPS:
                lines.append(
                    f"[!] {t('misc.malbolge.step_limit')} ({MAX_STEPS})"
                )
            if result:
                lines.append(f"{t('misc.malbolge.output')}: {result}")
            else:
                lines.append(t("misc.malbolge.no_output"))
            return "\n".join(lines)
        except Exception as e:
            return f"{t('misc.malbolge.execute_failed')}: {e}"

    # ========== EBCDIC 转换 ==========

    # EBCDIC Code Page 037 (EBCDIC-CP-US) → ASCII 映射表
    EBCDIC_TO_ASCII_TABLE = {
        0x00: 0x00, 0x01: 0x01, 0x02: 0x02, 0x03: 0x03, 0x04: 0x1A,
        0x05: 0x09, 0x06: 0x1A, 0x07: 0x7F, 0x0B: 0x0B, 0x0C: 0x0C,
        0x0D: 0x0D, 0x0E: 0x0E, 0x0F: 0x0F, 0x10: 0x10, 0x11: 0x11,
        0x12: 0x12, 0x13: 0x13, 0x15: 0x0A, 0x16: 0x08, 0x18: 0x18,
        0x19: 0x19, 0x1C: 0x1C, 0x1D: 0x1D, 0x1E: 0x1E, 0x1F: 0x1F,
        0x25: 0x0A, 0x26: 0x17, 0x27: 0x1B, 0x2D: 0x05, 0x2E: 0x06,
        0x2F: 0x07, 0x32: 0x16, 0x37: 0x04, 0x3C: 0x14, 0x3D: 0x15,
        0x40: 0x20, 0x4A: 0x5B, 0x4B: 0x2E, 0x4C: 0x3C, 0x4D: 0x28,
        0x4E: 0x2B, 0x4F: 0x21, 0x50: 0x26, 0x5A: 0x5D, 0x5B: 0x24,
        0x5C: 0x2A, 0x5D: 0x29, 0x5E: 0x3B, 0x5F: 0x5E, 0x60: 0x2D,
        0x61: 0x2F, 0x6A: 0x7C, 0x6B: 0x2C, 0x6C: 0x25, 0x6D: 0x5F,
        0x6E: 0x3E, 0x6F: 0x3F, 0x79: 0x60, 0x7A: 0x3A, 0x7B: 0x23,
        0x7C: 0x40, 0x7D: 0x27, 0x7E: 0x3D, 0x7F: 0x22,
        0x81: 0x61, 0x82: 0x62, 0x83: 0x63, 0x84: 0x64, 0x85: 0x65,
        0x86: 0x66, 0x87: 0x67, 0x88: 0x68, 0x89: 0x69,
        0x91: 0x6A, 0x92: 0x6B, 0x93: 0x6C, 0x94: 0x6D, 0x95: 0x6E,
        0x96: 0x6F, 0x97: 0x70, 0x98: 0x71, 0x99: 0x72,
        0xA1: 0x7E, 0xA2: 0x73, 0xA3: 0x74, 0xA4: 0x75, 0xA5: 0x76,
        0xA6: 0x77, 0xA7: 0x78, 0xA8: 0x79, 0xA9: 0x7A,
        0xC0: 0x7B, 0xC1: 0x41, 0xC2: 0x42, 0xC3: 0x43, 0xC4: 0x44,
        0xC5: 0x45, 0xC6: 0x46, 0xC7: 0x47, 0xC8: 0x48, 0xC9: 0x49,
        0xD0: 0x7D, 0xD1: 0x4A, 0xD2: 0x4B, 0xD3: 0x4C, 0xD4: 0x4D,
        0xD5: 0x4E, 0xD6: 0x4F, 0xD7: 0x50, 0xD8: 0x51, 0xD9: 0x52,
        0xE0: 0x5C, 0xE2: 0x53, 0xE3: 0x54, 0xE4: 0x55, 0xE5: 0x56,
        0xE6: 0x57, 0xE7: 0x58, 0xE8: 0x59, 0xE9: 0x5A,
        0xF0: 0x30, 0xF1: 0x31, 0xF2: 0x32, 0xF3: 0x33, 0xF4: 0x34,
        0xF5: 0x35, 0xF6: 0x36, 0xF7: 0x37, 0xF8: 0x38, 0xF9: 0x39,
    }

    def ebcdic_to_ascii(self, text: str) -> str:
        """EBCDIC (Code Page 037) -> ASCII 转换

        输入支持 hex 字符串（如 'C1C2C3'）和原始文本。
        """
        try:
            text = text.strip()

            # 判断是否为 hex 字符串
            hex_cleaned = (
                text.replace(' ', '').replace('0x', '').replace('\\x', '')
            )
            is_hex = (
                all(c in '0123456789abcdefABCDEF' for c in hex_cleaned)
                and len(hex_cleaned) >= 2
                and len(hex_cleaned) % 2 == 0
            )

            if is_hex:
                ebcdic_bytes = bytes.fromhex(hex_cleaned)
            else:
                ebcdic_bytes = text.encode('latin-1')

            result = []
            for b in ebcdic_bytes:
                ascii_val = self.EBCDIC_TO_ASCII_TABLE.get(b, 0x1A)
                if 32 <= ascii_val < 127:
                    result.append(chr(ascii_val))
                elif ascii_val == 0x0A:
                    result.append('\n')
                elif ascii_val == 0x0D:
                    result.append('\r')
                elif ascii_val == 0x09:
                    result.append('\t')
                else:
                    result.append('.')

            decoded = ''.join(result)
            lines = ["=== EBCDIC -> ASCII ==="]
            if is_hex:
                lines.append(f"Hex {t('misc.ebcdic.input')}: {hex_cleaned}")
            else:
                lines.append(f"{t('misc.ebcdic.input')}: {text}")
            lines.append(f"ASCII: {decoded}")
            return "\n".join(lines)
        except Exception as e:
            return f"{t('misc.ebcdic.convert_failed')}: {e}"

    def ascii_to_ebcdic(self, text: str) -> str:
        """ASCII -> EBCDIC (Code Page 037) 转换

        输入支持 hex 字符串和原始文本。
        """
        try:
            text_input = text.strip()

            # 构建 ASCII -> EBCDIC 反向映射
            ascii_to_eb_table = {}
            for ebcdic_val, ascii_val in self.EBCDIC_TO_ASCII_TABLE.items():
                if ascii_val not in ascii_to_eb_table:
                    ascii_to_eb_table[ascii_val] = ebcdic_val

            # 判断是否为 hex 字符串
            hex_cleaned = (
                text_input.replace(' ', '')
                .replace('0x', '')
                .replace('\\x', '')
            )
            is_hex = (
                all(c in '0123456789abcdefABCDEF' for c in hex_cleaned)
                and len(hex_cleaned) >= 2
                and len(hex_cleaned) % 2 == 0
            )

            if is_hex:
                ascii_bytes = bytes.fromhex(hex_cleaned)
            else:
                ascii_bytes = text_input.encode('ascii', errors='replace')

            result_bytes = []
            for b in ascii_bytes:
                ebcdic_val = ascii_to_eb_table.get(b, 0x3F)  # 0x3F = '?'
                result_bytes.append(ebcdic_val)

            hex_result = ' '.join(f'{b:02X}' for b in result_bytes)

            lines = ["=== ASCII -> EBCDIC ==="]
            lines.append(f"{t('misc.ebcdic.input')}: {text_input}")
            lines.append(f"EBCDIC (hex): {hex_result}")
            return "\n".join(lines)
        except Exception as e:
            return f"{t('misc.ebcdic.convert_failed')}: {e}"
