# -*- coding: utf-8 -*-
"""Flag 智能检测引擎

支持多种 flag 格式的自动识别，包括递归解码检测。
"""

import base64
import binascii
import re
import threading
from typing import Optional
from urllib.parse import unquote

# 默认 flag 格式正则（覆盖常见 CTF 比赛前缀）
# 注意：所有模式均使用 re.IGNORECASE 编译，无需重复大小写变体
DEFAULT_FLAG_PATTERNS = [
    r'flag\{[^\}]+\}',
    r'ctf\{[^\}]+\}',
    r'f1ag\{[^\}]+\}',
    r'fl4g\{[^\}]+\}',
    r'key\{[^\}]+\}',
    # 常见 CTF 比赛前缀
    r'DASCTF\{[^\}]+\}',
    r'HGAME\{[^\}]+\}',
    r'ACTF\{[^\}]+\}',
    r'NCTF\{[^\}]+\}',
    r'SCTF\{[^\}]+\}',
    r'MRCTF\{[^\}]+\}',
    r'BUUCTF\{[^\}]+\}',
    r'ISCC\{[^\}]+\}',
    r'SWPUCTF\{[^\}]+\}',
    r'moectf\{[^\}]+\}',
    r'BaseCTF\{[^\}]+\}',
    r'picoCTF\{[^\}]+\}',
    r'HTB\{[^\}]+\}',
    r'THM\{[^\}]+\}',
    r'UNCTF\{[^\}]+\}',
    r'NewStarCTF\{[^\}]+\}',
    r'CISCN\{[^\}]+\}',
    r'geekctf\{[^\}]+\}',
    r'0xGame\{[^\}]+\}',
    r'WMCTF\{[^\}]+\}',
    r'De1CTF\{[^\}]+\}',
    r'RCTF\{[^\}]+\}',
    r'N1CTF\{[^\}]+\}',
    r'XCTF\{[^\}]+\}',
    r'GWCTF\{[^\}]+\}',
    r'HSCTF\{[^\}]+\}',
    r'justCTF\{[^\}]+\}',
    r'corctf\{[^\}]+\}',
    # 通用：任意 XXX{...} 格式（宽松匹配，排在最后）
    r'[A-Za-z0-9_]{2,20}\{[^\}]{4,200}\}',
]


class FlagFinder:
    """Flag 智能检测引擎"""

    def __init__(self, custom_patterns: Optional[list[str]] = None):
        patterns = DEFAULT_FLAG_PATTERNS.copy()
        if custom_patterns:
            patterns.extend(custom_patterns)
        self._compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
        self.found_flags: list[str] = []
        self._lock = threading.Lock()

    def add_pattern(self, pattern: str):
        """添加自定义 flag 格式"""
        self._compiled.append(re.compile(pattern, re.IGNORECASE))

    def search(self, text: str) -> list[str]:
        """在文本中搜索 flag"""
        flags = []
        for pat in self._compiled:
            flags.extend(pat.findall(text))
        # 去重并记录
        unique = list(dict.fromkeys(flags))
        with self._lock:
            for f in unique:
                if f not in self.found_flags:
                    self.found_flags.append(f)
        return unique

    def search_with_decode(self, data: str | bytes, max_depth: int = 5) -> list[str]:
        """递归解码并搜索 flag

        尝试多种解码方式（Base64、Hex、URL编码等），
        在每一层解码结果中搜索 flag。
        """
        if isinstance(data, bytes):
            try:
                data = data.decode('utf-8', errors='ignore')
            except Exception:
                data = str(data)

        all_flags = self.search(data)
        if max_depth <= 0:
            return all_flags

        # 尝试 Base64 解码
        try:
            decoded = base64.b64decode(data.strip()).decode('utf-8', errors='ignore')
            if decoded and decoded != data:
                all_flags.extend(self.search_with_decode(decoded, max_depth - 1))
        except Exception:
            pass

        # 尝试 Hex 解码
        cleaned = data.strip()
        if cleaned.startswith('0x') or cleaned.startswith('0X'):
            cleaned = cleaned[2:]
        try:
            decoded = binascii.unhexlify(cleaned).decode('utf-8', errors='ignore')
            if decoded and decoded != data:
                all_flags.extend(self.search_with_decode(decoded, max_depth - 1))
        except Exception:
            pass

        # 尝试 URL 解码
        try:
            decoded = unquote(data)
            if decoded != data:
                all_flags.extend(self.search_with_decode(decoded, max_depth - 1))
        except Exception:
            pass

        # 尝试 Base32 解码
        try:
            decoded = base64.b32decode(data.strip().upper()).decode('utf-8', errors='ignore')
            if decoded and decoded != data:
                all_flags.extend(self.search_with_decode(decoded, max_depth - 1))
        except Exception:
            pass

        # 尝试 ROT13 解码
        try:
            import codecs
            decoded = codecs.decode(data, 'rot_13')
            if decoded != data:
                found = self.search(decoded)
                if found:
                    all_flags.extend(self.search_with_decode(decoded, max_depth - 1))
        except Exception:
            pass

        return list(dict.fromkeys(all_flags))

    def clear(self):
        """清空已找到的 flag"""
        with self._lock:
            self.found_flags.clear()


# 全局单例
flag_finder = FlagFinder()
