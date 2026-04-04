# -*- coding: utf-8 -*-
"""公共工具函数"""

import os
from typing import Optional


def read_file_bytes(filepath: str, max_size: int = 50 * 1024 * 1024) -> bytes:
    """安全读取文件字节，限制最大50MB"""
    size = os.path.getsize(filepath)
    if size > max_size:
        raise ValueError(f"文件过大: {size} bytes (最大 {max_size})")
    with open(filepath, 'rb') as f:
        return f.read()


def hex_dump(data: bytes, offset: int = 0, length: int = 256) -> str:
    """生成十六进制 dump 视图"""
    lines = []
    chunk = data[offset:offset + length]
    for i in range(0, len(chunk), 16):
        row = chunk[i:i + 16]
        hex_part = ' '.join(f'{b:02x}' for b in row)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
        lines.append(f'{offset + i:08x}  {hex_part:<48s}  |{ascii_part}|')
    return '\n'.join(lines)


def bytes_to_int(data: bytes, byteorder: str = 'little') -> int:
    """字节转整数"""
    return int.from_bytes(data, byteorder=byteorder)


def int_to_bytes(value: int, length: int = 4, byteorder: str = 'little') -> bytes:
    """整数转字节"""
    return value.to_bytes(length, byteorder=byteorder)


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR 加解密"""
    return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))


def extract_printable_strings(data: bytes, min_length: int = 4) -> list[str]:
    """从二进制数据中提取可打印字符串"""
    result = []
    current = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                result.append(''.join(current))
            current = []
    if len(current) >= min_length:
        result.append(''.join(current))
    return result


def entropy(data: bytes) -> float:
    """计算数据的香农熵（0-8）"""
    import math
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    ent = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            ent -= p * math.log2(p)
    return ent


# 常见文件魔数签名
MAGIC_SIGNATURES = {
    b'\x89PNG\r\n\x1a\n': 'PNG 图片',
    b'\xff\xd8\xff': 'JPEG 图片',
    b'GIF87a': 'GIF87a 图片',
    b'GIF89a': 'GIF89a 图片',
    b'PK\x03\x04': 'ZIP 压缩包 (或 DOCX/XLSX/APK/JAR)',
    b'PK\x05\x06': 'ZIP 压缩包 (空)',
    b'\x1f\x8b': 'GZIP 压缩',
    b'BZh': 'BZIP2 压缩',
    b'\x7fELF': 'ELF 可执行文件',
    b'MZ': 'PE/EXE 可执行文件',
    b'%PDF': 'PDF 文档',
    b'\xd0\xcf\x11\xe0': 'MS Office 旧格式 (DOC/XLS/PPT)',
    b'Rar!\x1a\x07': 'RAR 压缩包',
    b'\xfd7zXZ': 'XZ 压缩',
    b'7z\xbc\xaf\x27\x1c': '7-Zip 压缩包',
    b'\x00\x00\x00\x1c\x66\x74\x79\x70': 'MP4 视频',
    b'\x00\x00\x00\x18\x66\x74\x79\x70': 'MP4 视频',
    b'RIFF': 'RIFF (WAV/AVI)',
    b'OggS': 'OGG 音频',
    b'fLaC': 'FLAC 音频',
    b'\x49\x49\x2a\x00': 'TIFF 图片 (小端)',
    b'\x4d\x4d\x00\x2a': 'TIFF 图片 (大端)',
    b'BM': 'BMP 图片',
    b'\x50\x4b\x03\x04\x14\x00\x06\x00': 'MS Office 新格式 (DOCX/XLSX)',
    b'SQLite format 3': 'SQLite 数据库',
    b'\x1f\x9d': 'LZW 压缩',
    b'\x1f\xa0': 'LZH 压缩',
    b'MSCF': 'Microsoft CAB 压缩包',
    b'\xca\xfe\xba\xbe': 'Java Class / Mach-O Fat',
    b'\xfe\xed\xfa\xce': 'Mach-O 32-bit',
    b'\xfe\xed\xfa\xcf': 'Mach-O 64-bit',
    b'\xce\xfa\xed\xfe': 'Mach-O 32-bit (LE)',
    b'\xcf\xfa\xed\xfe': 'Mach-O 64-bit (LE)',
    b'dex\n': 'Android DEX 文件',
    b'\x00asm': 'WebAssembly (WASM)',
    b'LUAC': 'Lua 字节码',
    b'#!': 'Shell 脚本',
    b'\xef\xbb\xbf': 'UTF-8 BOM 文本',
    b'\xff\xfe': 'UTF-16 LE BOM',
    b'\xfe\xff': 'UTF-16 BE BOM',
    b'\x4c\x00\x00\x00\x01\x14\x02\x00': 'Windows LNK 快捷方式',
    b'REGF': 'Windows 注册表 REGF',
    b'wOFF': 'WOFF 字体',
    b'wOF2': 'WOFF2 字体',
    b'\x00\x01\x00\x00': 'TrueType 字体',
    b'OTTO': 'OpenType 字体',
    b'\x80\x00': 'Dalvik 可执行文件',
    b'gimp xcf': 'GIMP XCF 图片',
    b'8BPS': 'Photoshop PSD',
    b'II\x2a\x00\x10': 'Samsung ARW (RAW)',
}


def identify_file_type(data: bytes) -> Optional[str]:
    """通过魔数识别文件类型"""
    for magic, desc in sorted(MAGIC_SIGNATURES.items(), key=lambda x: -len(x[0])):
        if data[:len(magic)] == magic:
            return desc
    return None
