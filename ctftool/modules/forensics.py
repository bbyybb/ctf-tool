# -*- coding: utf-8 -*-
"""取证分析模块

覆盖：文件类型识别、隐写术、元数据提取、字符串提取、文件分离、
PNG宽高修复、USB键盘解析、PCAP分析、图片通道分离等。
"""

import os
import re
import struct
import zlib
from typing import Optional

from ctftool.core.i18n import t
from ctftool.core.utils import (
    MAGIC_SIGNATURES,
    entropy,
    extract_printable_strings,
    hex_dump,
    identify_file_type,
    read_file_bytes,
)


class ForensicsModule:
    """取证分析工具集"""

    # ========== 文件分析 ==========

    def identify_file(self, filepath: str) -> str:
        """识别文件类型并进行基础分析"""
        data = read_file_bytes(filepath)
        lines = [f"{t('for.file')}: {os.path.basename(filepath)}"]
        lines.append(f"{t('for.size')}: {len(data)} bytes ({len(data)/1024:.1f} KB)")

        # 魔数识别
        file_type = identify_file_type(data)
        lines.append(f"{t('for.type')}: {file_type or t('for.unknown')}")

        # 熵值
        ent = entropy(data)
        lines.append(f"{t('for.entropy')}: {ent:.4f} / 8.0")
        if ent > 7.5:
            lines.append(f"  [!] {t('for.high_entropy')}")
        elif ent < 1.0:
            lines.append(f"  [!] {t('for.very_low_entropy')}")

        # 头部 hex dump
        lines.append(f"\n=== {t('for.file_header')} ===")
        lines.append(hex_dump(data, 0, 128))

        # 尾部 hex dump
        if len(data) > 128:
            lines.append(f"\n=== {t('for.file_tail')} ===")
            lines.append(hex_dump(data, max(0, len(data) - 64), 64))

        # 下一步分析建议
        lines.append(f"\n=== {t('for.next_steps')} ===")
        file_type_lower = file_type.lower() if file_type else ""
        if 'png' in file_type_lower or 'jpeg' in file_type_lower or 'gif' in file_type_lower or 'bmp' in file_type_lower:
            lines.append(f"  -> detect_stego <file>     # {t('for.hint_stego')}")
            lines.append(f"  -> extract_metadata <file>  # {t('for.hint_metadata')}")
            lines.append(f"  -> split_channels <file>    # {t('for.hint_channels')}")
            lines.append(f"  -> lsb_extract_advanced <file>  # {t('for.hint_adv_lsb')}")
            if 'png' in file_type_lower:
                lines.append(f"  -> png_crc_fix <file>      # {t('for.hint_png_crc')}")
                lines.append(f"  -> bit_plane_analysis <file>  # {t('for.hint_bitplane')}")
        elif 'zip' in file_type_lower:
            lines.append(f"  -> zip_crack <file>         # {t('for.hint_zip_crack')}")
            lines.append(f"  -> zip_fake_decrypt <file>  # {t('for.hint_zip_fake')}")
        elif 'rar' in file_type_lower:
            lines.append(f"  -> rar_crack <file>         # {t('for.hint_rar_crack')}")
        elif 'elf' in file_type_lower:
            lines.append(f"  -> check_elf_protections <file>  # {t('for.hint_elf_checksec')}")
            lines.append(f"  -> disassemble <file>       # {t('for.hint_disasm')}")
            lines.append(f"  -> find_rop_gadgets <file>  # {t('for.hint_rop')}")
        elif 'pe' in file_type_lower or 'exe' in file_type_lower:
            lines.append(f"  -> check_pe_protections <file>  # {t('for.hint_pe_checksec')}")
            lines.append(f"  -> detect_packer <file>     # {t('for.hint_packer')}")
        elif 'pdf' in file_type_lower:
            lines.append(f"  -> pdf_analyze <file>       # {t('for.hint_pdf')}")
        elif 'pcap' in file_type_lower:
            lines.append(f"  -> pcap_analyze <file>      # {t('for.hint_pcap')}")
            lines.append(f"  -> pcap_extract_http <file> # {t('for.hint_pcap_http')}")
        elif 'wav' in file_type_lower or 'audio' in file_type_lower:
            lines.append(f"  -> audio_spectrogram <file> # {t('for.hint_spectrogram')}")
            lines.append(f"  -> dtmf_decode <file>       # {t('for.hint_dtmf')}")
        # 通用建议
        lines.append(f"  -> extract_strings <file>   # {t('for.hint_strings')}")
        lines.append(f"  -> binwalk_scan <file>      # {t('for.hint_binwalk')}")
        if ent > 7.0:
            lines.append(f"  [!] {t('for.high_entropy_binwalk')}")

        return "\n".join(lines)

    def extract_strings(self, filepath: str, min_length: int = 4) -> str:
        """从文件中提取可打印字符串"""
        data = read_file_bytes(filepath)
        strings = extract_printable_strings(data, min_length)

        lines = [f"{t('for.extracted_strings_from')} {os.path.basename(filepath)}: {len(strings)} {t('for.strings')}"]
        for i, s in enumerate(strings[:200]):
            lines.append(f"  [{i+1:4d}] {s}")
        if len(strings) > 200:
            lines.append(f"  ... {t('for.more_strings')}: {len(strings) - 200}")
        return "\n".join(lines)

    def extract_metadata(self, filepath: str) -> str:
        """提取文件元数据"""
        data = read_file_bytes(filepath)
        file_type = identify_file_type(data)
        lines = [f"{t('for.file')}: {os.path.basename(filepath)}", f"{t('for.type')}: {file_type or t('for.unknown')}"]

        # PNG 文本块
        if data[:8] == b'\x89PNG\r\n\x1a\n':
            lines.append(f"\n=== {t('for.png_chunks')} ===")
            lines.extend(self._parse_png_chunks(data))

        # JPEG EXIF
        elif data[:2] == b'\xff\xd8':
            lines.append(f"\n=== {t('for.jpeg_segments')} ===")
            lines.extend(self._parse_jpeg_segments(data))

        # 通用 EXIF/GPS 提取 (使用 Pillow)
        try:
            import io

            from PIL import Image
            from PIL.ExifTags import GPSTAGS, TAGS
            img = Image.open(io.BytesIO(data) if isinstance(data, bytes) else filepath)
            exif = img._getexif()
            if exif:
                lines.append(f"\n=== {t('for.exif_info')} ===")
                gps_info = {}
                for tag_id, value in exif.items():
                    tag = TAGS.get(tag_id, tag_id)
                    if tag == 'GPSInfo':
                        for gps_tag_id, gps_value in value.items():
                            gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                            gps_info[gps_tag] = gps_value
                    elif isinstance(value, bytes):
                        lines.append(f"  {tag}: (binary {len(value)} bytes)")
                    else:
                        val_str = str(value)[:100]
                        lines.append(f"  {tag}: {val_str}")

                if gps_info:
                    lines.append(f"\n=== {t('for.gps_info')} ===")
                    for k, v in gps_info.items():
                        lines.append(f"  {k}: {v}")
                    # 转为十进制坐标
                    try:
                        lat = self._gps_to_decimal(
                            gps_info.get('GPSLatitude'),
                            gps_info.get('GPSLatitudeRef', 'N')
                        )
                        lon = self._gps_to_decimal(
                            gps_info.get('GPSLongitude'),
                            gps_info.get('GPSLongitudeRef', 'E')
                        )
                        if lat is not None and lon is not None:
                            lines.append(f"\n  {t('for.decimal_coords')}: {lat:.6f}, {lon:.6f}")
                            lines.append(f"  Google Maps: https://maps.google.com/?q={lat},{lon}")
                    except Exception:
                        pass
        except ImportError:
            pass
        except Exception:
            pass

        # 通用：查找嵌入的文本
        lines.append(f"\n=== {t('for.embedded_text_search')} ===")
        # 搜索常见 flag 相关关键词
        text = data.decode('utf-8', errors='ignore')
        for keyword in ['flag', 'key', 'secret', 'password', 'hidden', 'ctf']:
            positions = [m.start() for m in re.finditer(keyword, text, re.IGNORECASE)]
            if positions:
                lines.append(f"  {t('for.keyword')} '{keyword}' {t('for.at_offset')}: {positions[:10]}")
                for pos in positions[:5]:
                    context = text[max(0, pos-20):pos+50]
                    lines.append(f"    {t('for.context')}: ...{repr(context)}...")

        return "\n".join(lines)

    # ========== 隐写术 ==========

    def detect_stego(self, filepath: str) -> str:
        """隐写术检测与分析"""
        data = read_file_bytes(filepath)
        file_type = identify_file_type(data)
        lines = [f"{t('for.stego_analysis')}: {os.path.basename(filepath)} ({file_type or t('for.unknown')})"]

        # 检查文件末尾是否有额外数据
        if data[:8] == b'\x89PNG\r\n\x1a\n':
            lines.extend(self._check_png_trailing(data))
            lines.extend(self._png_lsb_extract(data))
        elif data[:2] == b'\xff\xd8':
            lines.extend(self._check_jpeg_trailing(data))
        elif data[:4] == b'PK\x03\x04':
            lines.append(f"  [i] {t('for.zip_disguise_check')}")
        elif data[:4] == b'RIFF':
            lines.extend(self._check_wav_lsb(data))

        # 通用：检查是否嵌套了其他文件
        lines.append(f"\n=== {t('for.nested_file_detection')} ===")
        for magic, desc in MAGIC_SIGNATURES.items():
            # 跳过文件自身类型的签名
            if data[:len(magic)] == magic:
                continue
            pos = data.find(magic, 1)
            if pos > 0:
                lines.append(f"  [!] {t('for.found_sig_at')} 0x{pos:X}: {desc}")
                lines.append(f"      -> dd if={filepath} bs=1 skip={pos} of=extracted_{desc.replace(' ', '_')}  # {t('for.manual_extract')}")

        lines.append(f"\n=== {t('for.extract_tips')} ===")
        lines.append(f"  -> binwalk_scan {filepath}     # {t('for.hint_binwalk')}")
        lines.append(f"  -> binwalk_extract {filepath}  # {t('for.hint_binwalk_extract')}")

        return "\n".join(lines)

    def binwalk_scan(self, filepath: str) -> str:
        """文件分离扫描（类 binwalk）"""
        data = read_file_bytes(filepath)
        lines = [f"{t('for.binwalk_scan')}: {os.path.basename(filepath)}"]
        found = []

        for magic, desc in sorted(MAGIC_SIGNATURES.items(), key=lambda x: -len(x[0])):
            offset = 0
            while True:
                pos = data.find(magic, offset)
                if pos < 0:
                    break
                found.append((pos, desc, magic))
                offset = pos + 1

        found.sort(key=lambda x: x[0])
        if found:
            lines.append(f"\n{t('for.found')} {len(found)} {t('for.embedded_sigs')}:")
            for pos, desc, magic in found:
                hex_magic = ' '.join(f'{b:02x}' for b in magic[:8])
                lines.append(f"  0x{pos:08X}  {desc:30s}  [{hex_magic}]")
            lines.append(f"\n=== {t('for.extract_tips')} ===")
            lines.append(f"  -> binwalk_extract {filepath}  # {t('for.hint_binwalk_extract')}")
            lines.append(f"  {t('for.manual_extract')}: dd if={filepath} bs=1 skip=<offset> of=output")
        else:
            lines.append(f"  {t('for.no_known_sig')}")

        return "\n".join(lines)

    def hex_view(self, filepath: str, offset: int = 0, length: int = 512) -> str:
        """十六进制查看器"""
        data = read_file_bytes(filepath)
        lines = [
            f"{t('for.file')}: {os.path.basename(filepath)}",
            f"{t('for.total_size')}: {len(data)} bytes",
            f"{t('for.display_range')}: 0x{offset:X} - 0x{min(offset+length, len(data)):X}",
            "",
        ]
        lines.append(hex_dump(data, offset, length))
        return "\n".join(lines)

    def file_diff(self, file1: str, file2: str) -> str:
        """比较两个文件的差异"""
        data1 = read_file_bytes(file1)
        data2 = read_file_bytes(file2)
        lines = [
            f"{t('for.file')}1: {os.path.basename(file1)} ({len(data1)} bytes)",
            f"{t('for.file')}2: {os.path.basename(file2)} ({len(data2)} bytes)",
        ]

        if data1 == data2:
            lines.append(t('for.files_identical'))
            return "\n".join(lines)

        # 找出不同的字节
        min_len = min(len(data1), len(data2))
        diffs = []
        for i in range(min_len):
            if data1[i] != data2[i]:
                diffs.append(i)

        lines.append(f"\n{t('for.diff_bytes')}: {len(diffs)} + {t('for.length_diff')}: {abs(len(data1) - len(data2))}")
        lines.append(f"\n{t('for.first_20_diffs')}:")
        for pos in diffs[:20]:
            lines.append(
                f"  {t('for.offset')} 0x{pos:08X}: "
                f"0x{data1[pos]:02X} ({chr(data1[pos]) if 32 <= data1[pos] < 127 else '.'}) vs "
                f"0x{data2[pos]:02X} ({chr(data2[pos]) if 32 <= data2[pos] < 127 else '.'})"
            )

        # 提取差异字节组成的文本
        diff_bytes = bytes(data1[i] ^ data2[i] for i in range(min_len) if data1[i] != data2[i])
        if diff_bytes:
            text = diff_bytes.decode('utf-8', errors='ignore')
            if text.strip():
                lines.append(f"\n{t('for.diff_xor_result')}: {text[:200]}")

        return "\n".join(lines)

    # ========== 内部方法 ==========

    def _parse_png_chunks(self, data: bytes) -> list[str]:
        """解析 PNG 块"""
        lines = []
        offset = 8  # 跳过 PNG 签名
        while offset < len(data) - 12:
            try:
                length = struct.unpack('>I', data[offset:offset+4])[0]
                chunk_type = data[offset+4:offset+8].decode('ascii', errors='replace')
                lines.append(f"  {t('for.chunk')}: {chunk_type}, {t('for.size')}: {length} bytes, {t('for.offset')}: 0x{offset:X}")

                # 提取文本块内容
                if chunk_type in ('tEXt', 'iTXt'):
                    chunk_data = data[offset+8:offset+8+length]
                    text = chunk_data.decode('utf-8', errors='ignore')
                    lines.append(f"    {t('for.content')}: {text[:200]}")
                elif chunk_type == 'zTXt':
                    chunk_data = data[offset+8:offset+8+length]
                    null_pos = chunk_data.find(b'\x00')
                    if null_pos >= 0:
                        keyword = chunk_data[:null_pos].decode('utf-8', errors='replace')
                        # 跳过 compression method 字节 (always 0 = zlib)
                        compressed = chunk_data[null_pos + 2:]
                        try:
                            text = zlib.decompress(compressed).decode('utf-8', errors='replace')
                        except Exception:
                            text = chunk_data[null_pos+1:].decode('utf-8', errors='replace')
                        lines.append(f"    zTXt: {keyword} = {text[:200]}")
                    else:
                        text = chunk_data.decode('utf-8', errors='ignore')
                        lines.append(f"    {t('for.content')}: {text[:200]}")

                offset += 12 + length
                if chunk_type == 'IEND':
                    if offset < len(data):
                        trailing = len(data) - offset
                        lines.append(f"  [!] {t('for.trailing_after_iend')}: {trailing} bytes")
                    break
            except Exception:
                break
        return lines

    def _parse_jpeg_segments(self, data: bytes) -> list[str]:
        """解析 JPEG 段"""
        lines = []
        offset = 0
        segment_names = {
            0xD8: 'SOI', 0xE0: 'APP0/JFIF', 0xE1: 'APP1/EXIF',
            0xFE: 'COM', 0xDB: 'DQT', 0xC0: 'SOF0',
            0xC4: 'DHT', 0xDA: 'SOS', 0xD9: 'EOI',
        }
        while offset < len(data) - 1:
            if data[offset] != 0xFF:
                offset += 1
                continue
            marker = data[offset + 1]
            name = segment_names.get(marker, f'{t("for.unknown")}(0x{marker:02X})')
            if marker in (0xD8, 0xD9):
                lines.append(f"  0x{offset:06X}: {name}")
                offset += 2
                if marker == 0xD9:
                    if offset < len(data):
                        lines.append(f"  [!] {t('for.trailing_after_eoi')}: {len(data) - offset} bytes")
                    break
            elif offset + 3 < len(data):
                length = struct.unpack('>H', data[offset+2:offset+4])[0]
                lines.append(f"  0x{offset:06X}: {name} ({length} bytes)")

                # 提取注释
                if marker == 0xFE:
                    comment = data[offset+4:offset+2+length].decode('utf-8', errors='ignore')
                    lines.append(f"    {t('for.comment')}: {comment[:200]}")
                # 提取 EXIF
                elif marker == 0xE1:
                    exif_data = data[offset+4:offset+2+length]
                    if exif_data[:4] == b'Exif':
                        lines.append(f"    [{t('for.exif_data_exists')}]")
                        text = exif_data.decode('utf-8', errors='ignore')
                        # 搜索可读文本
                        readable = re.findall(r'[\x20-\x7E]{8,}', text)
                        for r in readable[:10]:
                            lines.append(f"      {r}")
                offset += 2 + length
            else:
                break
        return lines

    def _check_png_trailing(self, data: bytes) -> list[str]:
        """检查 PNG 尾部多余数据"""
        lines = []
        iend = data.find(b'IEND')
        if iend > 0:
            end_pos = iend + 8  # IEND chunk length + CRC
            if end_pos < len(data):
                trailing = data[end_pos:]
                lines.append(f"\n=== {t('for.png_trailing')} ({len(trailing)} bytes) ===")
                text = trailing.decode('utf-8', errors='ignore').strip()
                if text:
                    lines.append(f"  {t('for.text_content')}: {text[:500]}")
                lines.append(f"  Hex: {trailing[:64].hex()}")
        return lines

    def _check_jpeg_trailing(self, data: bytes) -> list[str]:
        """检查 JPEG 尾部多余数据"""
        lines = []
        eoi = data.rfind(b'\xff\xd9')
        if eoi > 0 and eoi + 2 < len(data):
            trailing = data[eoi + 2:]
            lines.append(f"\n=== {t('for.jpeg_trailing')} ({len(trailing)} bytes) ===")
            text = trailing.decode('utf-8', errors='ignore').strip()
            if text:
                lines.append(f"  {t('for.text_content')}: {text[:500]}")
            lines.append(f"  Hex: {trailing[:64].hex()}")
        return lines

    def _png_lsb_extract(self, data: bytes) -> list[str]:
        """PNG LSB 隐写提取"""
        lines = []
        try:
            import io

            from PIL import Image
            img = Image.open(io.BytesIO(data))
            if img.mode not in ('RGB', 'RGBA'):
                img = img.convert('RGB')
            pixels = list(img.getdata())

            # 提取每个像素 RGB 最低位
            bits = []
            for pixel in pixels[:8192]:
                for channel in range(3):
                    bits.append(pixel[channel] & 1)

            # 转换为字节
            extracted = bytearray()
            for i in range(0, len(bits) - 7, 8):
                byte = 0
                for bit in bits[i:i+8]:
                    byte = (byte << 1) | bit
                extracted.append(byte)
                if byte == 0:
                    break

            text = bytes(extracted).decode('utf-8', errors='ignore').strip()
            if text and any(c.isalpha() for c in text):
                lines.append(f"\n=== {t('for.lsb_result')} ===")
                lines.append(f"  {text[:500]}")
        except ImportError:
            lines.append(f"\n  [i] {t('for.install_pillow_lsb')}")
        except Exception:
            pass
        return lines

    def _check_wav_lsb(self, data: bytes) -> list[str]:
        """WAV 音频 LSB 隐写检测（正确解析采样位数）"""
        lines = []
        # 解析 WAV 头获取采样位数
        bits_per_sample = 8  # 默认
        fmt_marker = data.find(b'fmt ')
        if fmt_marker > 0 and fmt_marker + 24 <= len(data):
            bits_per_sample = struct.unpack('<H', data[fmt_marker + 22:fmt_marker + 24])[0]

        data_marker = data.find(b'data')
        if data_marker > 0:
            audio_start = data_marker + 8
            audio_data = data[audio_start:]

            if bits_per_sample == 16:
                # 16-bit 采样：每 2 字节一个采样值，提取最低位
                bits = []
                for i in range(0, min(len(audio_data) - 1, 16384), 2):
                    sample = struct.unpack('<h', audio_data[i:i+2])[0]
                    bits.append(sample & 1)
            else:
                # 8-bit 采样
                bits = []
                for byte in audio_data[:8192]:
                    bits.append(byte & 1)

            extracted = bytearray()
            for i in range(0, len(bits) - 7, 8):
                byte_val = 0
                for bit in bits[i:i+8]:
                    byte_val = (byte_val << 1) | bit
                extracted.append(byte_val)
                if byte_val == 0:
                    break

            text = bytes(extracted).decode('utf-8', errors='ignore').strip()
            if text and any(c.isalpha() for c in text):
                lines.append(f"\n=== WAV LSB ({bits_per_sample}-bit) ===")
                lines.append(f"  {text[:500]}")
        return lines

    # ========== ZIP 相关 ==========

    def zip_crack(self, filepath: str, wordlist_path: Optional[str] = None) -> str:
        """ZIP 密码爆破"""
        import zipfile
        if not zipfile.is_zipfile(filepath):
            return t('for.not_valid_zip')

        # 构建字典
        passwords = self._build_zip_wordlist(wordlist_path)

        with zipfile.ZipFile(filepath) as zf:
            encrypted = any(info.flag_bits & 0x1 for info in zf.infolist())
            if not encrypted:
                return t('for.zip_not_encrypted')

            file_list = [info.filename for info in zf.infolist()]
            lines = [f"{t('for.zip_contains')}: {', '.join(file_list[:10])}"]
            lines.append(f"{t('for.trying')} {len(passwords)} {t('for.passwords')}...")

            import tempfile
            for i, pwd in enumerate(passwords):
                try:
                    with tempfile.TemporaryDirectory() as tmpdir:
                        zf.extractall(path=tmpdir, pwd=pwd.encode())
                    return (
                        f"{t('for.zip_crack_success')}!\n"
                        f"{t('for.password')}: {pwd}\n"
                        f"{t('for.attempts')}: {i + 1}\n"
                        f"{t('for.file_list')}: {', '.join(file_list)}"
                    )
                except (RuntimeError, zipfile.BadZipFile):
                    pass
                except Exception:
                    pass

        return f"{t('for.zip_crack_failed')} ({t('for.tried')} {len(passwords)} {t('for.passwords')})"

    def rar_crack(self, filepath: str, wordlist_path: str = None) -> str:
        """RAR 压缩包密码爆破"""
        try:
            import rarfile
        except ImportError:
            return t('for.install_rarfile')

        if not rarfile.is_rarfile(filepath):
            return t('for.not_valid_rar')

        passwords = self._build_zip_wordlist(wordlist_path)

        with rarfile.RarFile(filepath) as rf:
            if not rf.needs_password():
                return t('for.rar_not_encrypted')

            file_list = rf.namelist()
            lines = [f"{t('for.rar_contains')}: {', '.join(file_list[:10])}"]
            lines.append(f"{t('for.trying')} {len(passwords)} {t('for.passwords')}...")

            for i, pwd in enumerate(passwords):
                try:
                    rf.setpassword(pwd)
                    rf.testrar()
                    return (
                        f"{t('for.rar_crack_success')}!\n"
                        f"{t('for.password')}: {pwd}\n"
                        f"{t('for.attempts')}: {i + 1}\n"
                        f"{t('for.file_list')}: {', '.join(file_list)}"
                    )
                except (rarfile.BadRarFile, rarfile.RarCRCError, RuntimeError):
                    pass
                except Exception:
                    pass

        return f"{t('for.rar_crack_failed')} ({t('for.tried')} {len(passwords)} {t('for.passwords')})"

    def zip_fake_decrypt(self, filepath: str) -> str:
        """ZIP 伪加密修复（修改加密标志位）"""
        data = bytearray(read_file_bytes(filepath))
        if data[:2] != b'PK':
            return t('for.not_valid_zip')

        fixed = 0
        offset = 0
        while offset < len(data) - 4:
            # 查找 Local File Header (PK\x03\x04)
            if data[offset:offset+4] == b'PK\x03\x04':
                flag_offset = offset + 6
                flags = struct.unpack('<H', data[flag_offset:flag_offset+2])[0]
                if flags & 0x01:  # 加密标志位
                    data[flag_offset] = data[flag_offset] & 0xFE
                    fixed += 1
                offset += 30  # 跳过 header 最小长度
            # 查找 Central Directory (PK\x01\x02)
            elif data[offset:offset+4] == b'PK\x01\x02':
                flag_offset = offset + 8
                flags = struct.unpack('<H', data[flag_offset:flag_offset+2])[0]
                if flags & 0x01:
                    data[flag_offset] = data[flag_offset] & 0xFE
                    fixed += 1
                offset += 46
            else:
                offset += 1

        if fixed == 0:
            return t('for.no_encrypt_flag')

        output_path = filepath + ".fixed.zip"
        with open(output_path, 'wb') as f:
            f.write(data)
        return (
            f"{t('for.zip_fake_fixed')}!\n"
            f"{t('for.fixed_flags')}: {fixed}\n"
            f"{t('for.saved_to')}: {output_path}"
        )

    # ========== 文件分离并保存 ==========

    def binwalk_extract(self, filepath: str) -> str:
        """文件分离并保存到磁盘"""
        data = read_file_bytes(filepath)
        output_dir = filepath + "_extracted"
        os.makedirs(output_dir, exist_ok=True)

        found = []
        for magic, desc in sorted(MAGIC_SIGNATURES.items(), key=lambda x: -len(x[0])):
            offset = 0
            while True:
                pos = data.find(magic, offset)
                if pos < 0:
                    break
                found.append((pos, desc, magic))
                offset = pos + 1

        found.sort(key=lambda x: x[0])
        if not found:
            return t('for.no_embedded_sig')

        lines = [f"{t('for.found')} {len(found)} {t('for.embedded_sigs')}, {t('for.extracting')}:"]
        for i, (pos, desc, magic) in enumerate(found):
            # 确定提取范围
            if i + 1 < len(found):
                end = found[i + 1][0]
            else:
                end = len(data)
            chunk = data[pos:end]
            ext = self._guess_extension(magic)
            out_file = os.path.join(output_dir, f"{i:04d}_0x{pos:X}{ext}")
            with open(out_file, 'wb') as f:
                f.write(chunk)
            lines.append(f"  [{i}] {desc} @ 0x{pos:X} -> {out_file} ({len(chunk)} bytes)")

        lines.append(f"\n{t('for.extract_dir')}: {output_dir}")
        return "\n".join(lines)

    # ========== 文件头修复 ==========

    def fix_file_header(self, filepath: str) -> str:
        """尝试修复损坏的文件头"""
        data = bytearray(read_file_bytes(filepath))
        original_type = identify_file_type(bytes(data))

        # 常见文件头修复规则
        fixes = [
            # PNG: 前8字节必须是 89 50 4E 47 0D 0A 1A 0A
            (b'\x50\x4E\x47', 1, b'\x89PNG\r\n\x1a\n', "PNG"),
            (b'PNG', 0, b'\x89PNG\r\n\x1a\n', "PNG"),
            # JPEG: FFD8FF
            (b'\xd8\xff', 0, b'\xff\xd8\xff', "JPEG"),
            # GIF
            (b'IF89a', 0, b'GIF89a', "GIF"),
            (b'IF87a', 0, b'GIF87a', "GIF"),
            # ZIP: 50 4B 03 04
            (b'\x4B\x03\x04', 0, b'PK\x03\x04', "ZIP"),
            # RAR
            (b'ar!\x1a\x07', 0, b'Rar!\x1a\x07', "RAR"),
        ]

        for partial_sig, search_start, correct_header, desc in fixes:
            pos = data.find(partial_sig, search_start)
            if pos >= 0 and pos <= 8:
                output_path = filepath + ".fixed"
                fixed_data = bytearray(correct_header) + data[pos + len(partial_sig):]
                with open(output_path, 'wb') as f:
                    f.write(fixed_data)
                new_type = identify_file_type(bytes(fixed_data))
                return (
                    f"{t('for.header_fixed')}!\n"
                    f"{t('for.detected_partial_sig')}: {desc}\n"
                    f"{t('for.before_fix')}: {original_type or t('for.unknown')}\n"
                    f"{t('for.after_fix')}: {new_type or t('for.unknown')}\n"
                    f"{t('for.saved_to')}: {output_path}"
                )

        return (
            f"{t('for.cannot_auto_fix')}\n"
            f"{t('for.current_type')}: {original_type or t('for.unknown')}\n"
            f"{t('for.first_16_bytes')}: {data[:16].hex()}\n"
            f"{t('for.tip_hex_editor')}"
        )

    # ========== PCAP 流量分析 ==========

    def pcap_analyze(self, filepath: str) -> str:
        """PCAP 流量包分析"""
        try:
            from scapy.all import DNS, IP, TCP, UDP, Raw, rdpcap  # noqa: F401
        except ImportError:
            return t('for.install_scapy')

        packets = rdpcap(filepath)
        lines = [f"=== {t('for.pcap_analysis')}: {os.path.basename(filepath)} ==="]
        lines.append(f"{t('for.total_packets')}: {len(packets)}")

        # 统计协议分布
        protocols = {}
        src_ips = set()
        dst_ips = set()
        http_data = []
        dns_queries = []
        raw_data = []

        for pkt in packets:
            proto = pkt.lastlayer().__class__.__name__
            protocols[proto] = protocols.get(proto, 0) + 1

            if IP in pkt:
                src_ips.add(pkt[IP].src)
                dst_ips.add(pkt[IP].dst)

            # 提取 HTTP 数据
            if TCP in pkt and Raw in pkt:
                payload = pkt[Raw].load
                try:
                    text = payload.decode('utf-8', errors='ignore')
                    if text.startswith(('GET ', 'POST ', 'HTTP/')):
                        http_data.append(text[:500])
                    raw_data.append(payload)
                except Exception:
                    raw_data.append(payload)

            # 提取 DNS 查询
            if DNS in pkt and pkt[DNS].qr == 0:
                try:
                    qname = pkt[DNS].qd.qname.decode('utf-8', errors='ignore')
                    dns_queries.append(qname)
                except Exception:
                    pass

        lines.append(f"\n{t('for.protocol_dist')}:")
        for proto, count in sorted(protocols.items(), key=lambda x: -x[1]):
            lines.append(f"  {proto}: {count}")

        lines.append(f"\n{t('for.ip_addrs')}:")
        lines.append(f"  {t('for.src')}: {', '.join(sorted(src_ips)[:10])}")
        lines.append(f"  {t('for.dst')}: {', '.join(sorted(dst_ips)[:10])}")

        if dns_queries:
            lines.append(f"\n{t('for.dns_queries')} ({len(dns_queries)}):")
            for q in list(dict.fromkeys(dns_queries))[:20]:
                lines.append(f"  {q}")

        if http_data:
            lines.append(f"\n{t('for.http_data')} ({len(http_data)}):")
            for h in http_data[:10]:
                first_line = h.split('\n')[0]
                lines.append(f"  {first_line}")

        # 搜索所有 raw 数据中的可读字符串
        all_raw = b''.join(raw_data)
        if all_raw:
            strings = extract_printable_strings(all_raw, 8)
            interesting = [s for s in strings if any(
                kw in s.lower() for kw in ['flag', 'key', 'pass', 'secret', 'ctf', 'token']
            )]
            if interesting:
                lines.append(f"\n{t('for.key_strings')}:")
                for s in interesting[:20]:
                    lines.append(f"  {s}")

        lines.append(f"\n=== {t('for.further_analysis')} ===")
        lines.append(f"  -> pcap_extract_http <file>  # {t('for.hint_pcap_http')}")
        lines.append(f"  -> detect_dns_tunnel <file>  # {t('for.hint_dns_tunnel')}")

        return "\n".join(lines)

    # ========== 辅助方法 ==========

    def _build_zip_wordlist(self, wordlist_path: Optional[str]) -> list[str]:
        """构建 ZIP 爆破字典"""
        passwords = []
        if wordlist_path and os.path.isfile(wordlist_path):
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        else:
            # 内置字典
            passwords = [
                "", "123456", "password", "12345678", "qwerty", "123456789",
                "111111", "1234567", "abc123", "1234", "12345", "000000",
                "admin", "root", "test", "guest", "pass", "1q2w3e4r",
                "letmein", "welcome", "monkey", "master", "dragon",
                "flag", "ctf", "secret", "hidden",
            ]
            # 4-6位纯数字
            passwords += [str(i) for i in range(10000)]
            passwords += [f"{i:06d}" for i in range(10000)]

        return passwords

    @staticmethod
    def _gps_to_decimal(coords, ref) -> float:
        """GPS 度分秒 → 十进制度"""
        if not coords:
            return None
        d = float(coords[0])
        m = float(coords[1])
        s = float(coords[2])
        decimal = d + m / 60 + s / 3600
        if ref in ('S', 'W'):
            decimal = -decimal
        return decimal

    def _guess_extension(self, magic: bytes) -> str:
        """根据魔数猜测文件扩展名"""
        ext_map = {
            b'\x89PNG': '.png', b'\xff\xd8\xff': '.jpg',
            b'GIF87a': '.gif', b'GIF89a': '.gif',
            b'PK\x03\x04': '.zip', b'\x1f\x8b': '.gz',
            b'\x7fELF': '.elf', b'MZ': '.exe',
            b'%PDF': '.pdf', b'Rar!': '.rar',
            b'RIFF': '.wav', b'fLaC': '.flac',
            b'BM': '.bmp',
        }
        for sig, ext in ext_map.items():
            if magic[:len(sig)] == sig:
                return ext
        return '.bin'

    # ========== PNG 宽高 CRC 修复 ==========

    def png_crc_fix(self, filepath: str) -> str:
        """PNG 宽高 CRC 爆破修复

        通过遍历 width/height 组合，找到使 IHDR 块 CRC 校验通过的正确尺寸。
        """
        data = read_file_bytes(filepath)
        if data[:8] != b'\x89PNG\r\n\x1a\n':
            return t('for.not_png')

        # 解析 IHDR 块
        ihdr_length = struct.unpack('>I', data[8:12])[0]
        ihdr_type = data[12:16]  # b'IHDR'
        if ihdr_type != b'IHDR':
            return t('for.ihdr_abnormal')

        ihdr_data = data[12:12 + 4 + ihdr_length]  # type + data
        stored_crc = struct.unpack('>I', data[12 + 4 + ihdr_length:12 + 8 + ihdr_length])[0]

        orig_width = struct.unpack('>I', data[16:20])[0]
        orig_height = struct.unpack('>I', data[20:24])[0]

        # 先检查当前 CRC 是否正确
        current_crc = zlib.crc32(ihdr_data) & 0xFFFFFFFF
        if current_crc == stored_crc:
            return (
                f"{t('for.png_crc_ok')}\n"
                f"{t('for.width')}: {orig_width}\n{t('for.height')}: {orig_height}"
            )

        lines = [
            f"=== {t('for.png_crc_fix')} ===",
            f"{t('for.orig_width')}: {orig_width}",
            f"{t('for.orig_height')}: {orig_height}",
            f"{t('for.stored_crc')}: 0x{stored_crc:08X}",
            f"{t('for.calc_crc')}: 0x{current_crc:08X} ({t('for.mismatch')}!)",
            "",
            f"{t('for.bruteforcing')}...",
        ]

        # 爆破 width 和 height（通常一个被修改）
        found = False
        ihdr_base = bytearray(ihdr_data)
        # ihdr_data 结构: IHDR(4) + width(4) + height(4) + bit_depth(1) + ...
        # width 在 offset 4, height 在 offset 8

        # 先只爆破 height（更常见）
        for h in range(1, 8192):
            ihdr_base[4:8] = struct.pack('>I', orig_width)
            ihdr_base[8:12] = struct.pack('>I', h)
            if zlib.crc32(bytes(ihdr_base)) & 0xFFFFFFFF == stored_crc:
                lines.append(f"{t('for.found_correct_size')}: {orig_width} x {h}")
                found = True
                self._save_fixed_png(filepath, data, orig_width, h)
                lines.append(f"{t('for.fixed_file_saved')}: {filepath}.fixed.png")
                break

        # 如果 height 没找到，爆破 width
        if not found:
            for w in range(1, 8192):
                ihdr_base[4:8] = struct.pack('>I', w)
                ihdr_base[8:12] = struct.pack('>I', orig_height)
                if zlib.crc32(bytes(ihdr_base)) & 0xFFFFFFFF == stored_crc:
                    lines.append(f"{t('for.found_correct_size')}: {w} x {orig_height}")
                    found = True
                    self._save_fixed_png(filepath, data, w, orig_height)
                    lines.append(f"{t('for.fixed_file_saved')}: {filepath}.fixed.png")
                    break

        # 两个都爆破
        if not found:
            for w in range(1, 2048):
                for h in range(1, 2048):
                    ihdr_base[4:8] = struct.pack('>I', w)
                    ihdr_base[8:12] = struct.pack('>I', h)
                    if zlib.crc32(bytes(ihdr_base)) & 0xFFFFFFFF == stored_crc:
                        lines.append(f"{t('for.found_correct_size')}: {w} x {h}")
                        found = True
                        self._save_fixed_png(filepath, data, w, h)
                        lines.append(f"{t('for.fixed_file_saved')}: {filepath}.fixed.png")
                        break
                if found:
                    break

        if not found:
            lines.append(t('for.crc_not_found'))

        return "\n".join(lines)

    def _save_fixed_png(self, filepath: str, data: bytes, w: int, h: int):
        """保存修复后的 PNG"""
        fixed = bytearray(data)
        fixed[16:20] = struct.pack('>I', w)
        fixed[20:24] = struct.pack('>I', h)
        # 重新计算 IHDR CRC
        ihdr_length = struct.unpack('>I', fixed[8:12])[0]
        ihdr_chunk = bytes(fixed[12:12 + 4 + ihdr_length])
        new_crc = struct.pack('>I', zlib.crc32(ihdr_chunk) & 0xFFFFFFFF)
        fixed[12 + 4 + ihdr_length:12 + 8 + ihdr_length] = new_crc
        with open(filepath + ".fixed.png", 'wb') as f:
            f.write(fixed)

    # ========== USB 键盘流量解析 ==========

    USB_KEYBOARD_MAP = {
        0x04: 'a', 0x05: 'b', 0x06: 'c', 0x07: 'd', 0x08: 'e',
        0x09: 'f', 0x0A: 'g', 0x0B: 'h', 0x0C: 'i', 0x0D: 'j',
        0x0E: 'k', 0x0F: 'l', 0x10: 'm', 0x11: 'n', 0x12: 'o',
        0x13: 'p', 0x14: 'q', 0x15: 'r', 0x16: 's', 0x17: 't',
        0x18: 'u', 0x19: 'v', 0x1A: 'w', 0x1B: 'x', 0x1C: 'y',
        0x1D: 'z', 0x1E: '1', 0x1F: '2', 0x20: '3', 0x21: '4',
        0x22: '5', 0x23: '6', 0x24: '7', 0x25: '8', 0x26: '9',
        0x27: '0', 0x28: '\n', 0x29: '[ESC]', 0x2A: '[BS]',
        0x2B: '\t', 0x2C: ' ', 0x2D: '-', 0x2E: '=', 0x2F: '[',
        0x30: ']', 0x31: '\\', 0x33: ';', 0x34: "'", 0x35: '`',
        0x36: ',', 0x37: '.', 0x38: '/',
    }
    USB_KEYBOARD_SHIFT_MAP = {
        0x04: 'A', 0x05: 'B', 0x06: 'C', 0x07: 'D', 0x08: 'E',
        0x09: 'F', 0x0A: 'G', 0x0B: 'H', 0x0C: 'I', 0x0D: 'J',
        0x0E: 'K', 0x0F: 'L', 0x10: 'M', 0x11: 'N', 0x12: 'O',
        0x13: 'P', 0x14: 'Q', 0x15: 'R', 0x16: 'S', 0x17: 'T',
        0x18: 'U', 0x19: 'V', 0x1A: 'W', 0x1B: 'X', 0x1C: 'Y',
        0x1D: 'Z', 0x1E: '!', 0x1F: '@', 0x20: '#', 0x21: '$',
        0x22: '%', 0x23: '^', 0x24: '&', 0x25: '*', 0x26: '(',
        0x27: ')', 0x2D: '_', 0x2E: '+', 0x2F: '{', 0x30: '}',
        0x31: '|', 0x33: ':', 0x34: '"', 0x35: '~', 0x36: '<',
        0x37: '>', 0x38: '?',
    }

    def usb_keyboard_decode(self, filepath: str) -> str:
        """解析 USB 键盘流量（pcap 文件）"""
        try:
            from scapy.all import Raw, rdpcap
        except ImportError:
            return t('for.install_scapy')

        packets = rdpcap(filepath)
        lines = [f"=== {t('for.usb_keyboard')}: {os.path.basename(filepath)} ==="]
        result_chars = []

        for pkt in packets:
            if Raw in pkt:
                raw = pkt[Raw].load
                # USB HID 键盘数据通常是 8 字节
                if len(raw) == 8:
                    modifier = raw[0]
                    keycode = raw[2]
                    if keycode == 0:
                        continue
                    shift = modifier & 0x22  # Left/Right Shift
                    if keycode == 0x2A:  # Backspace
                        if result_chars:
                            result_chars.pop()
                    elif shift:
                        char = self.USB_KEYBOARD_SHIFT_MAP.get(keycode, f'[0x{keycode:02X}]')
                        result_chars.append(char)
                    else:
                        char = self.USB_KEYBOARD_MAP.get(keycode, f'[0x{keycode:02X}]')
                        result_chars.append(char)

        typed_text = ''.join(result_chars)
        lines.append(f"{t('for.total_packets')}: {len(packets)}")
        lines.append(f"{t('for.keys_decoded')}: {len(result_chars)}")
        lines.append(f"\n{t('for.typed_content')}:\n{typed_text}")
        return "\n".join(lines)

    # ========== USB 鼠标流量解析 ==========

    def usb_mouse_decode(self, filepath: str) -> str:
        """解析 USB 鼠标流量（pcap 文件），提取坐标轨迹"""
        try:
            from scapy.all import Raw, rdpcap
        except ImportError:
            return t('for.install_scapy')

        packets = rdpcap(filepath)
        lines = [f"=== {t('for.usb_mouse')}: {os.path.basename(filepath)} ==="]

        x, y = 0, 0
        coords = []
        clicks = []

        for pkt in packets:
            if Raw in pkt:
                raw = pkt[Raw].load
                # USB HID 鼠标数据通常是 4 字节（或更多）
                if len(raw) >= 4:
                    buttons = raw[0]
                    dx = raw[1] if raw[1] < 128 else raw[1] - 256  # 有符号
                    dy = raw[2] if raw[2] < 128 else raw[2] - 256
                    x += dx
                    y += dy
                    coords.append((x, y))
                    if buttons & 0x01:  # 左键点击
                        clicks.append((x, y))

        lines.append(f"{t('for.total_packets')}: {len(packets)}")
        lines.append(f"{t('for.valid_mouse_packets')}: {len(coords)}")
        lines.append(f"{t('for.left_clicks')}: {len(clicks)}")
        lines.append(f"{t('for.coord_range')}: X[{min(c[0] for c in coords) if coords else 0}, {max(c[0] for c in coords) if coords else 0}] "
                     f"Y[{min(c[1] for c in coords) if coords else 0}, {max(c[1] for c in coords) if coords else 0}]")

        # 尝试用 Pillow 绘制轨迹图
        try:
            from PIL import Image, ImageDraw
            if coords:
                # 归一化坐标到正值
                min_x = min(c[0] for c in coords)
                min_y = min(c[1] for c in coords)
                norm_coords = [(c[0] - min_x, c[1] - min_y) for c in coords]
                max_x = max(c[0] for c in norm_coords) + 10
                max_y = max(c[1] for c in norm_coords) + 10

                img = Image.new('RGB', (max(max_x, 100), max(max_y, 100)), 'white')
                draw = ImageDraw.Draw(img)

                # 绘制轨迹
                for i in range(1, len(norm_coords)):
                    draw.line([norm_coords[i-1], norm_coords[i]], fill='black', width=1)

                # 标记点击位置
                norm_clicks = [(c[0] - min_x, c[1] - min_y) for c in clicks]
                for cx, cy in norm_clicks:
                    draw.ellipse([cx-3, cy-3, cx+3, cy+3], fill='red')

                output_path = filepath + "_mouse_trace.png"
                img.save(output_path)
                lines.append(f"\n{t('for.mouse_trace_saved')}: {output_path}")
        except ImportError:
            lines.append(f"\n[i] {t('for.install_pillow_trace')}")
        except Exception as e:
            lines.append(f"\n{t('for.draw_failed')}: {e}")

        # 输出前 20 个坐标
        if coords:
            lines.append(f"\n{t('for.first_20_coords')}:")
            for i, (cx, cy) in enumerate(coords[:20]):
                lines.append(f"  [{i:4d}] ({cx:6d}, {cy:6d})")
            if len(coords) > 20:
                lines.append(f"  ... {t('for.total')} {len(coords)} {t('for.coord_points')}")

        return "\n".join(lines)

    # ========== 图片通道分离 ==========

    def split_channels(self, filepath: str) -> str:
        """分离图片 R/G/B/A 通道并保存"""
        try:
            from PIL import Image
        except ImportError:
            return t('for.install_pillow')

        img = Image.open(filepath)
        base_name = os.path.splitext(filepath)[0]
        lines = [f"=== {t('for.channel_split')}: {os.path.basename(filepath)} ==="]
        lines.append(f"{t('for.dimensions')}: {img.size[0]} x {img.size[1]}")
        lines.append(f"{t('for.mode')}: {img.mode}")

        if img.mode == 'RGBA':
            channels = {'R': 0, 'G': 1, 'B': 2, 'A': 3}
        elif img.mode == 'RGB':
            channels = {'R': 0, 'G': 1, 'B': 2}
        elif img.mode == 'L':
            return f"{t('for.grayscale_no_split')}\n{t('for.dimensions')}: {img.size}"
        else:
            img = img.convert('RGB')
            channels = {'R': 0, 'G': 1, 'B': 2}

        split = img.split()
        saved = []
        for name, idx in channels.items():
            out_path = f"{base_name}_{name}.png"
            split[idx].save(out_path)
            saved.append(out_path)
            lines.append(f"  {name} {t('for.channel')} -> {out_path}")

        # 额外：每个通道的 LSB 平面
        lines.append(f"\n=== {t('for.lsb_plane_extract')} ===")
        for name, idx in channels.items():
            ch = split[idx]
            pixels = list(ch.getdata())
            lsb_pixels = [((p & 1) * 255) for p in pixels]
            lsb_img = Image.new('L', img.size)
            lsb_img.putdata(lsb_pixels)
            lsb_path = f"{base_name}_{name}_LSB.png"
            lsb_img.save(lsb_path)
            saved.append(lsb_path)
            lines.append(f"  {name} LSB -> {lsb_path}")

        lines.append(f"\n{t('for.total_saved')}: {len(saved)}")
        return "\n".join(lines)

    # ========== GIF 帧分离 ==========

    def gif_frame_extract(self, filepath: str) -> str:
        """分离 GIF 动图的每一帧并保存"""
        try:
            from PIL import Image
        except ImportError:
            return t('for.install_pillow')

        img = Image.open(filepath)
        if not hasattr(img, 'n_frames') or img.n_frames <= 1:
            return f"{t('for.not_animated')}\n{t('for.dimensions')}: {img.size}"

        base_name = os.path.splitext(filepath)[0]
        output_dir = base_name + "_frames"
        os.makedirs(output_dir, exist_ok=True)

        lines = [f"=== {t('for.gif_frame_split')}: {os.path.basename(filepath)} ==="]
        lines.append(f"{t('for.total_frames')}: {img.n_frames}")
        lines.append(f"{t('for.dimensions')}: {img.size[0]} x {img.size[1]}")

        saved = []
        for i in range(img.n_frames):
            img.seek(i)
            frame = img.convert('RGBA')
            out_path = os.path.join(output_dir, f"frame_{i:04d}.png")
            frame.save(out_path)
            saved.append(out_path)
            lines.append(f"  {t('for.frame')} {i:4d} -> {out_path}")

        lines.append(f"\n{t('for.total_saved')}: {len(saved)} {t('for.frames_to')}: {output_dir}")
        return "\n".join(lines)

    # ========== 高级 LSB 提取 ==========

    def lsb_extract_advanced(self, filepath: str, bit_plane: int = 0,
                              channel_order: str = "RGB", row_first: bool = True) -> str:
        """高级 LSB 隐写提取 — 支持任意位平面、通道顺序"""
        try:
            import io

            from PIL import Image
        except ImportError:
            return t('for.install_pillow')

        data = read_file_bytes(filepath)
        img = Image.open(io.BytesIO(data))
        if img.mode not in ('RGB', 'RGBA'):
            img = img.convert('RGB')

        width, height = img.size
        pixels = list(img.getdata())

        # 通道索引映射
        ch_map = {'R': 0, 'G': 1, 'B': 2, 'A': 3}
        channels = [ch_map[c] for c in channel_order.upper() if c in ch_map]

        lines = [f"=== {t('for.adv_lsb')} ==="]
        lines.append(f"{t('for.file')}: {os.path.basename(filepath)}")
        lines.append(f"{t('for.dimensions')}: {width} x {height}")
        lines.append(f"{t('for.bit_plane')}: {bit_plane}")
        lines.append(f"{t('for.channel_order')}: {channel_order}")
        lines.append(f"{t('for.scan_order')}: {t('for.row_first') if row_first else t('for.col_first')}")

        # 按指定顺序提取 bits
        bits = []
        if row_first:
            for pixel in pixels:
                for ch in channels:
                    if ch < len(pixel):
                        bits.append((pixel[ch] >> bit_plane) & 1)
        else:
            # 列优先：按列遍历
            for x in range(width):
                for y in range(height):
                    pixel = pixels[y * width + x]
                    for ch in channels:
                        if ch < len(pixel):
                            bits.append((pixel[ch] >> bit_plane) & 1)

        # 转换为字节
        extracted = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for bit in bits[i:i+8]:
                byte = (byte << 1) | bit
            extracted.append(byte)
            if byte == 0:
                break

        text = bytes(extracted).decode('utf-8', errors='ignore').strip()
        if text and any(c.isalpha() for c in text[:50]):
            lines.append(f"\n{t('for.extract_result_text')}:")
            lines.append(f"  {text[:1000]}")
        else:
            lines.append(f"\n{t('for.extract_result_hex')}:")
            lines.append(f"  {bytes(extracted[:64]).hex()}")

        lines.append(f"\n{t('for.total_extracted')}: {len(extracted)} bytes")
        return "\n".join(lines)

    # ========== 音频频谱图分析 ==========

    def audio_spectrogram(self, filepath: str) -> str:
        """音频频谱图分析（检测隐藏信息）"""
        data = read_file_bytes(filepath)
        file_type = identify_file_type(data) or ""

        if 'RIFF' not in file_type and 'FLAC' not in file_type and not filepath.lower().endswith(('.wav', '.mp3', '.flac', '.ogg')):
            return t('for.not_audio')

        try:
            from PIL import Image
        except ImportError:
            return f"{t('for.install_pillow')}\n{t('for.use_audacity')}"

        # 解析 WAV PCM 数据
        if data[:4] == b'RIFF':
            # 查找 data 块
            pos = 12
            sample_rate = 44100
            channels = 1
            bits_per_sample = 16
            audio_data = b''
            while pos < len(data) - 8:
                chunk_id = data[pos:pos+4]
                chunk_size = struct.unpack('<I', data[pos+4:pos+8])[0]
                if chunk_id == b'fmt ':
                    channels = struct.unpack('<H', data[pos+10:pos+12])[0]
                    sample_rate = struct.unpack('<I', data[pos+12:pos+16])[0]
                    bits_per_sample = struct.unpack('<H', data[pos+22:pos+24])[0]
                elif chunk_id == b'data':
                    audio_data = data[pos+8:pos+8+chunk_size]
                    break
                pos += 8 + chunk_size
                if chunk_size % 2:
                    pos += 1

            if not audio_data:
                return t('for.cannot_parse_wav')

            # 转换为样本数组
            import array
            if bits_per_sample == 16:
                samples = array.array('h', audio_data[:len(audio_data)//2*2])
            elif bits_per_sample == 8:
                samples = array.array('b', audio_data)
            else:
                return f"{t('for.unsupported_bit_depth')}: {bits_per_sample}"

            # 如果是多声道，取第一声道
            if channels > 1:
                samples = samples[::channels]

            # 简易频谱图（短时傅里叶变换）
            import math
            window_size = 1024
            hop = window_size // 2
            n_windows = min((len(samples) - window_size) // hop, 800)
            if n_windows < 1:
                return t('for.audio_too_short')

            n_freq = window_size // 2
            spectrogram = []

            for i in range(n_windows):
                start = i * hop
                window = samples[start:start + window_size]
                # Hanning 窗
                windowed = [window[j] * (0.5 - 0.5 * math.cos(2 * math.pi * j / window_size)) for j in range(len(window))]
                # DFT（取前半频率）
                magnitudes = []
                for k in range(n_freq):
                    real = sum(windowed[n] * math.cos(2 * math.pi * k * n / window_size) for n in range(window_size))
                    imag = sum(windowed[n] * math.sin(2 * math.pi * k * n / window_size) for n in range(window_size))
                    mag = math.sqrt(real*real + imag*imag)
                    magnitudes.append(mag)
                spectrogram.append(magnitudes)

            # 生成图片
            width = len(spectrogram)
            height = min(n_freq, 256)
            img = Image.new('L', (width, height))

            # 归一化
            max_mag = max(max(col) for col in spectrogram) or 1
            for x, col in enumerate(spectrogram):
                for y in range(height):
                    freq_idx = int(y * n_freq / height)
                    val = col[freq_idx]
                    # 对数刻度
                    db = 20 * math.log10(val / max_mag + 1e-10)
                    pixel = max(0, min(255, int((db + 80) * 255 / 80)))
                    img.putpixel((x, height - 1 - y), pixel)

            out_path = filepath + '_spectrogram.png'
            img.save(out_path)

            lines = [
                f"{t('for.spectrogram_generated')}: {out_path}",
                f"{t('for.sample_rate')}: {sample_rate} Hz",
                f"{t('for.channels')}: {channels}",
                f"{t('for.bit_depth')}: {bits_per_sample}",
                f"{t('for.sample_count')}: {len(samples)}",
                f"{t('for.window_count')}: {n_windows}",
                "",
                t('for.spectrogram_tip'),
                t('for.use_audacity_detail'),
            ]
            return '\n'.join(lines)

        return f"{t('for.wav_only_spectrogram')}\n{t('for.use_audacity')}"

    # ========== PDF 分析 ==========

    def pdf_analyze(self, filepath: str) -> str:
        """PDF 文件分析 -- 提取文本、链接、嵌入对象、JavaScript"""
        data = read_file_bytes(filepath)
        if not data.startswith(b'%PDF'):
            return t('for.not_valid_pdf')

        lines = [f"=== {t('for.pdf_analysis')} ==="]

        # 提取 PDF 版本
        version = data[:20].split(b'\n')[0].decode('ascii', errors='ignore')
        lines.append(f"{t('for.version')}: {version}")
        lines.append(f"{t('for.file_size')}: {len(data)} bytes")

        # 统计对象数量
        import re as _re
        objects = _re.findall(rb'\d+\s+\d+\s+obj', data)
        lines.append(f"{t('for.object_count')}: {len(objects)}")

        # 检测 JavaScript
        js_refs = _re.findall(rb'/JavaScript|/JS\s', data)
        if js_refs:
            lines.append(f"\n[!] {t('for.js_found')}: {len(js_refs)}")
            for match in _re.finditer(rb'/JS\s*\((.*?)\)', data[:50000]):
                lines.append(f"  JS: {match.group(1).decode('latin-1', errors='replace')[:200]}")

        # 检测嵌入文件
        embedded = _re.findall(rb'/EmbeddedFile', data)
        if embedded:
            lines.append(f"\n[!] {t('for.embedded_files_found')}: {len(embedded)}")

        # 检测自动动作
        auto_actions = _re.findall(rb'/OpenAction|/AA\s', data)
        if auto_actions:
            lines.append(f"\n[!] {t('for.auto_actions_found')}: {len(auto_actions)}")

        # 检测链接/URI
        uris = _re.findall(rb'/URI\s*\((.*?)\)', data)
        if uris:
            lines.append(f"\n{t('for.links')} ({len(uris)}):")
            for uri in uris[:20]:
                lines.append(f"  {uri.decode('latin-1', errors='replace')}")

        # 检测流对象
        streams = _re.findall(rb'stream\r?\n', data)
        lines.append(f"\n{t('for.stream_objects')}: {len(streams)}")

        # 提取可打印字符串中的 flag
        strings = extract_printable_strings(data, 6)
        interesting = [s for s in strings if any(k in s.lower() for k in ('flag', 'key', 'secret', 'password', 'ctf', 'hidden'))]
        if interesting:
            lines.append(f"\n{t('for.sensitive_strings')} ({len(interesting)}):")
            for s in interesting[:30]:
                lines.append(f"  {s[:200]}")

        # 检测加密
        if b'/Encrypt' in data:
            lines.append(f"\n[!] {t('for.pdf_encrypted')}")

        return '\n'.join(lines)

    # ========== PCAP HTTP 流提取 ==========

    def pcap_extract_http(self, filepath: str) -> str:
        """从 PCAP 中提取 HTTP 请求和响应"""
        try:
            from scapy.all import TCP, Raw, rdpcap
        except ImportError:
            return t('for.install_scapy')

        try:
            packets = rdpcap(filepath)
        except Exception as e:
            return f"{t('for.pcap_read_failed')}: {e}"

        # 按 TCP 流分组
        streams = {}
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                key = tuple(sorted([(pkt[TCP].sport, pkt[TCP].dport)]))
                if key not in streams:
                    streams[key] = []
                streams[key].append(bytes(pkt[Raw].load))

        lines = [f"=== {t('for.http_stream_extract')} ===", f"{t('for.tcp_streams')}: {len(streams)}", ""]

        http_count = 0
        for key, payloads in streams.items():
            combined = b''.join(payloads)
            if b'HTTP/' not in combined[:20] and b'GET ' not in combined[:10] and b'POST ' not in combined[:10]:
                continue
            http_count += 1
            lines.append(f"--- {t('for.stream')} {key[0]}:{key[1]} ---")

            # 提取请求
            for payload in payloads:
                text = payload.decode('utf-8', errors='replace')
                if text.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')):
                    first_line = text.split('\r\n')[0]
                    lines.append(f"  {t('for.request')}: {first_line[:200]}")
                elif text.startswith('HTTP/'):
                    first_line = text.split('\r\n')[0]
                    lines.append(f"  {t('for.response')}: {first_line[:200]}")
                    # 检查是否有文件内容
                    if b'\r\n\r\n' in payload:
                        body = payload.split(b'\r\n\r\n', 1)[1]
                        if body[:4] in (b'\x89PNG', b'\xff\xd8\xff', b'GIF8', b'PK\x03\x04', b'%PDF'):
                            file_type = identify_file_type(body) or t('for.unknown')
                            lines.append(f"    [!] {t('for.response_contains_file')}: {file_type} ({len(body)} bytes)")
            lines.append("")

        if http_count == 0:
            lines.append(t('for.no_http'))
        else:
            lines.append(f"{t('for.found')} {http_count} {t('for.http_streams')}")

        return '\n'.join(lines)

    # ========== 位平面全分析 ==========

    def bit_plane_analysis(self, filepath: str) -> str:
        """位平面全分析（0-7 位全部可视化，类似 Stegsolve）"""
        try:
            from PIL import Image
        except ImportError:
            return t('for.install_pillow')

        try:
            img = Image.open(filepath)
        except Exception as e:
            return f"{t('for.cannot_open_image')}: {e}"

        if img.mode not in ('RGB', 'RGBA'):
            img = img.convert('RGB')

        pixels = list(img.getdata())
        width, height = img.size
        output_dir = filepath + '_bitplanes'
        os.makedirs(output_dir, exist_ok=True)

        channels = ['R', 'G', 'B']
        saved = []

        for ch_idx, ch_name in enumerate(channels):
            for bit in range(8):
                plane = Image.new('L', (width, height))
                plane_pixels = []
                for pixel in pixels:
                    val = (pixel[ch_idx] >> bit) & 1
                    plane_pixels.append(val * 255)
                plane.putdata(plane_pixels)
                out_file = os.path.join(output_dir, f'{ch_name}_bit{bit}.png')
                plane.save(out_file)
                saved.append(f'{ch_name}_bit{bit}.png')

        lines = [
            f"{t('for.bitplane_done')}! {t('for.generated')} {len(saved)} {t('for.images')}",
            f"{t('for.output_dir')}: {output_dir}",
            "",
            f"{t('for.file_list')}:",
        ]
        for f in saved:
            lines.append(f"  {f}")
        lines.append(f"\n{t('for.bitplane_tip')}")

        return '\n'.join(lines)

    # ========== DTMF 音频解码 ==========

    def dtmf_decode(self, filepath: str) -> str:
        """DTMF 拨号音解码（从 WAV 文件中提取电话号码）"""
        data = read_file_bytes(filepath)
        if data[:4] != b'RIFF':
            return t('for.need_wav')

        import math

        # 解析 WAV header
        pos = 12
        sample_rate = 44100
        channels = 1
        bits = 16
        audio_data = b''
        while pos < len(data) - 8:
            chunk_id = data[pos:pos+4]
            chunk_size = struct.unpack('<I', data[pos+4:pos+8])[0]
            if chunk_id == b'fmt ':
                channels = struct.unpack('<H', data[pos+10:pos+12])[0]
                sample_rate = struct.unpack('<I', data[pos+12:pos+16])[0]
                bits = struct.unpack('<H', data[pos+22:pos+24])[0]
            elif chunk_id == b'data':
                audio_data = data[pos+8:pos+8+chunk_size]
                break
            pos += 8 + chunk_size + (chunk_size % 2)

        if not audio_data:
            return t('for.cannot_parse_wav')

        # 转换为样本
        import array
        if bits == 16:
            samples = array.array('h', audio_data[:len(audio_data)//2*2])
        elif bits == 8:
            samples = array.array('b', audio_data)
        else:
            return f"{t('for.unsupported_audio_bits')}: {bits}"

        if channels > 1:
            samples = samples[::channels]

        # DTMF 频率表
        dtmf_freqs = {
            (697, 1209): '1', (697, 1336): '2', (697, 1477): '3', (697, 1633): 'A',
            (770, 1209): '4', (770, 1336): '5', (770, 1477): '6', (770, 1633): 'B',
            (852, 1209): '7', (852, 1336): '8', (852, 1477): '9', (852, 1633): 'C',
            (941, 1209): '*', (941, 1336): '0', (941, 1477): '#', (941, 1633): 'D',
        }
        low_freqs = [697, 770, 852, 941]
        high_freqs = [1209, 1336, 1477, 1633]

        # Goertzel 算法检测频率
        def goertzel_mag(samples_chunk, target_freq, sample_rate):
            N = len(samples_chunk)
            k = int(0.5 + N * target_freq / sample_rate)
            w = 2 * math.pi * k / N
            coeff = 2 * math.cos(w)
            s0 = s1 = s2 = 0
            for sample in samples_chunk:
                s0 = sample + coeff * s1 - s2
                s2 = s1
                s1 = s0
            return math.sqrt(s1*s1 + s2*s2 - coeff*s1*s2)

        # 按窗口扫描
        window_size = int(sample_rate * 0.04)  # 40ms 窗口
        hop = window_size // 2

        result_chars = []
        prev_char = ''
        silence_count = 0

        for i in range(0, len(samples) - window_size, hop):
            chunk = samples[i:i + window_size]

            # 检测每个 DTMF 频率的能量
            low_mags = [(f, goertzel_mag(chunk, f, sample_rate)) for f in low_freqs]
            high_mags = [(f, goertzel_mag(chunk, f, sample_rate)) for f in high_freqs]

            best_low = max(low_mags, key=lambda x: x[1])
            best_high = max(high_mags, key=lambda x: x[1])

            # 判断是否有有效 DTMF 信号（能量阈值）
            threshold = max(s * s for s in chunk) * 0.01 if any(chunk) else 0

            if best_low[1] > threshold and best_high[1] > threshold:
                char = dtmf_freqs.get((best_low[0], best_high[0]), '?')
                if char != prev_char:
                    if char != '?':
                        result_chars.append(char)
                    prev_char = char
                    silence_count = 0
            else:
                silence_count += 1
                if silence_count > 3:
                    prev_char = ''

        if not result_chars:
            return f"{t('for.no_dtmf')}\n{t('for.dtmf_tip')}"

        decoded = ''.join(result_chars)
        lines = [
            f"{t('for.dtmf_result')}: {decoded}",
            f"{t('for.sample_rate')}: {sample_rate} Hz",
            f"{t('for.detected_keys')}: {len(result_chars)}",
            "",
            f"{t('for.dtmf_table')}:",
            "       1209Hz  1336Hz  1477Hz  1633Hz",
            "697Hz    1       2       3       A",
            "770Hz    4       5       6       B",
            "852Hz    7       8       9       C",
            "941Hz    *       0       #       D",
        ]
        return '\n'.join(lines)

    # ========== Office 文档分析 ==========

    def office_analyze(self, filepath: str) -> str:
        """Office 文档分析（OLE/OOXML） -- 提取宏、嵌入对象、隐藏内容"""
        data = read_file_bytes(filepath)
        identify_file_type(data) or ""

        lines = [f"=== {t('for.office_analysis')} ==="]

        # OLE 格式 (DOC/XLS/PPT)
        if data[:4] == b'\xd0\xcf\x11\xe0':
            lines.append(f"{t('for.format')}: OLE Compound")

            # 检查 VBA 宏
            if b'VBA' in data or b'_VBA_PROJECT' in data:
                lines.append(f"\n[!] {t('for.vba_found')}!")
                # 提取可能的宏字符串
                import re as _re
                vba_strings = _re.findall(rb'(?:Sub |Function |Dim |Set |CreateObject|Shell|WScript|Powershell|cmd)[^\x00]{5,200}', data)
                if vba_strings:
                    lines.append(f"  {t('for.suspicious_vba')}:")
                    for s in vba_strings[:20]:
                        lines.append(f"    {s.decode('latin-1', errors='replace')}")

            # 检查嵌入对象
            if b'\x01Ole' in data or b'Package' in data:
                lines.append(f"\n[!] {t('for.embedded_ole')}")

            # 提取可打印字符串中的敏感信息
            strings = extract_printable_strings(data, 8)
            urls = [s for s in strings if s.startswith(('http://', 'https://', 'ftp://'))]
            if urls:
                lines.append(f"\nURL ({len(urls)}):")
                for u in urls[:20]:
                    lines.append(f"  {u}")

        # OOXML 格式 (DOCX/XLSX/PPTX)
        elif data[:4] == b'PK\x03\x04':
            import zipfile
            lines.append(f"{t('for.format')}: OOXML (ZIP-based Office)")

            try:
                with zipfile.ZipFile(filepath) as zf:
                    names = zf.namelist()
                    lines.append(f"{t('for.contained_files')}: {len(names)}")

                    # 检查 VBA 宏
                    vba_files = [n for n in names if 'vbaProject' in n or 'macro' in n.lower()]
                    if vba_files:
                        lines.append(f"\n[!] {t('for.vba_files_found')}: {', '.join(vba_files)}")

                    # 检查隐藏内容
                    hidden_sheets = []
                    for name in names:
                        if name.endswith('.xml'):
                            try:
                                content = zf.read(name).decode('utf-8', errors='ignore')
                                if 'hidden' in content.lower() and 'sheet' in name.lower():
                                    hidden_sheets.append(name)
                                # 检查外部链接
                                import re as _re
                                ext_links = _re.findall(r'https?://[^\s"<>]+', content)
                                if ext_links:
                                    for link in ext_links[:5]:
                                        lines.append(f"  {t('for.external_link')}: {link[:200]}")
                            except Exception:
                                pass

                    if hidden_sheets:
                        lines.append(f"\n[!] {t('for.hidden_sheets')}: {', '.join(hidden_sheets)}")

                    # 列出关键文件
                    interesting = [n for n in names if any(k in n.lower() for k in ('media', 'image', 'embed', 'ole', 'active'))]
                    if interesting:
                        lines.append(f"\n{t('for.embedded_resources')}:")
                        for n in interesting[:20]:
                            lines.append(f"  {n} ({zf.getinfo(n).file_size} bytes)")

            except zipfile.BadZipFile:
                lines.append(t('for.zip_corrupted'))
        else:
            lines.append(t('for.not_office'))

        return '\n'.join(lines)

    # ========== 内存 dump 基础分析 ==========

    def memory_dump_analyze(self, filepath: str) -> str:
        """内存 dump 基础分析 -- 字符串/进程/URL 提取"""
        data = read_file_bytes(filepath)

        lines = [f"=== {t('for.memory_dump')} ===", f"{t('for.file_size')}: {len(data):,} bytes"]

        # 提取可打印字符串
        strings = extract_printable_strings(data, 6)
        lines.append(f"{t('for.printable_strings')}: {len(strings)}")

        # 搜索 URL
        import re as _re
        urls = list(set(_re.findall(rb'https?://[\w./\-?&=%#@:]+', data)))
        if urls:
            lines.append(f"\nURL ({len(urls)}):")
            for u in sorted(urls)[:30]:
                lines.append(f"  {u.decode('ascii', errors='ignore')}")

        # 搜索 IP 地址
        ips = list(set(_re.findall(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b', data)))
        # 过滤常见无意义 IP
        real_ips = [ip for ip in ips if not ip.startswith((b'0.0', b'255.255', b'127.0'))]
        if real_ips:
            lines.append(f"\n{t('for.ip_addrs')} ({len(real_ips)}):")
            for ip in sorted(real_ips)[:20]:
                lines.append(f"  {ip.decode()}")

        # 搜索邮箱
        emails = list(set(_re.findall(rb'[\w.+-]+@[\w-]+\.[\w.]+', data)))
        if emails:
            lines.append(f"\n{t('for.emails')} ({len(emails)}):")
            for e in sorted(emails)[:20]:
                lines.append(f"  {e.decode('ascii', errors='ignore')}")

        # 搜索 flag
        flags = list(set(_re.findall(rb'[A-Za-z0-9_]{2,20}\{[^\}]{4,100}\}', data)))
        if flags:
            lines.append(f"\n{t('for.suspected_flags')} ({len(flags)}):")
            for f in flags[:20]:
                lines.append(f"  {f.decode('ascii', errors='ignore')}")

        # 搜索文件路径 (Windows)
        win_paths = list(set(_re.findall(rb'[A-Z]:\\[\w\\. -]{5,200}', data)))
        if win_paths:
            lines.append(f"\n{t('for.win_paths')} ({len(win_paths)}):")
            for p in sorted(win_paths)[:20]:
                lines.append(f"  {p.decode('ascii', errors='ignore')}")

        # 搜索 Linux 路径
        lin_paths = list(set(_re.findall(rb'/(?:home|root|etc|var|tmp|usr|opt)/[\w/.-]{3,200}', data)))
        if lin_paths:
            lines.append(f"\n{t('for.linux_paths')} ({len(lin_paths)}):")
            for p in sorted(lin_paths)[:20]:
                lines.append(f"  {p.decode('ascii', errors='ignore')}")

        # 检测嵌入文件
        embedded_count = 0
        for magic, desc in MAGIC_SIGNATURES.items():
            if len(magic) >= 4:
                found_pos = data.find(magic, 1)
                if found_pos > 0:
                    if embedded_count == 0:
                        lines.append(f"\n{t('for.embedded_file_sigs')}:")
                    lines.append(f"  {desc} @ offset 0x{found_pos:X}")
                    embedded_count += 1
                    if embedded_count >= 15:
                        break

        lines.append(f"\n{t('for.tip_volatility')}")
        lines.append("  volatility -f dump.raw imageinfo")
        lines.append("  volatility -f dump.raw --profile=... pslist")

        return '\n'.join(lines)

    # ========== NTFS ADS 检测 ==========

    def detect_ntfs_ads(self, filepath: str) -> str:
        """NTFS ADS（备用数据流）检测"""
        data = read_file_bytes(filepath)
        lines = [f"=== {t('for.ntfs_ads')} ===", f"{t('for.file')}: {os.path.basename(filepath)}"]

        # 检测文件内容中的 ADS 相关特征
        lines.append(f"\n--- {t('for.ads_content_features')} ---")
        ads_indicators = []

        # 搜索 $DATA 属性标记（NTFS MFT 中的属性类型 0x80）
        data_attr_marker = b'\x80\x00\x00\x00'
        offsets = []
        pos = 0
        while True:
            idx = data.find(data_attr_marker, pos)
            if idx == -1 or len(offsets) >= 20:
                break
            offsets.append(idx)
            pos = idx + 1
        if offsets:
            lines.append(f"  [*] {t('for.data_attr_found')}: {len(offsets)}")
            for off in offsets[:10]:
                lines.append(f"      {t('for.offset')} 0x{off:X}")
            ads_indicators.append("$DATA 属性标记")

        # 搜索 Zone.Identifier 流（常见的 ADS）
        zone_id = data.find(b'Zone.Identifier')
        if zone_id != -1:
            lines.append(f"  [!] {t('for.zone_id_found')} @ {t('for.offset')} 0x{zone_id:X}")
            ads_indicators.append("Zone.Identifier")

        # 搜索 $FILE_NAME 属性（0x30）
        filename_attr = b'\x30\x00\x00\x00'
        fn_offsets = []
        pos = 0
        while True:
            idx = data.find(filename_attr, pos)
            if idx == -1 or len(fn_offsets) >= 20:
                break
            fn_offsets.append(idx)
            pos = idx + 1
        if fn_offsets:
            lines.append(f"  [*] {t('for.filename_attr_found')}: {len(fn_offsets)}")

        # 搜索文件名中包含冒号的引用（ADS 语法: filename:streamname）
        ads_pattern = re.findall(rb'[\w.-]{1,50}:[\w.-]{1,50}:\$DATA', data)
        if ads_pattern:
            lines.append(f"  [!] {t('for.ads_ref_found')}:")
            for match in ads_pattern[:10]:
                lines.append(f"      {match.decode('ascii', errors='ignore')}")
            ads_indicators.append("ADS 引用")

        # 搜索常见的隐藏数据流名称
        hidden_stream_names = [b'hidden', b'secret', b'flag', b'payload', b'shell', b'backdoor']
        for name in hidden_stream_names:
            idx = data.find(name)
            if idx != -1:
                context = data[max(0, idx - 10):idx + len(name) + 10]
                if b':' in context:
                    lines.append(f"  [?] {t('for.possible_hidden_stream')} '{name.decode()}' @ {t('for.offset')} 0x{idx:X}")

        # 如果是 NTFS 镜像文件，搜索 "NTFS" 标志
        if data[:4] == b'\xeb\x52\x90N' or b'NTFS    ' in data[:512]:
            lines.append(f"\n  [*] {t('for.ntfs_image')}")
            ads_indicators.append("NTFS 镜像")

        if not ads_indicators:
            lines.append(f"  [-] {t('for.no_ads_features')}")

        # Windows 平台尝试列出备用数据流
        lines.append(f"\n--- {t('for.system_ads_detect')} ---")
        if os.name == 'nt':
            try:
                import subprocess
                # 校验路径合法性，防止 cmd /c 二次解析特殊字符
                abs_path = os.path.abspath(filepath)
                if not os.path.exists(abs_path):
                    lines.append(f"  [-] {t('for.file_not_exist')}: {abs_path}")
                    return "\n".join(lines)
                # 使用目录和文件名分离的方式避免路径中的特殊字符被 cmd 解析
                dir_path = os.path.dirname(abs_path)
                result = subprocess.run(
                    ['cmd', '/c', 'dir', '/r', abs_path],
                    capture_output=True, text=True, timeout=10,
                    cwd=dir_path
                )
                output = result.stdout
                # 搜索 ADS 条目（格式: 大小 filename:streamname:$DATA）
                ads_lines = [l.strip() for l in output.split('\n')
                             if ':$DATA' in l and l.strip()]
                if ads_lines:
                    lines.append(f"  [!] {t('for.ads_found')}:")
                    for al in ads_lines:
                        lines.append(f"      {al}")
                else:
                    lines.append(f"  [-] {t('for.no_extra_streams')}")
            except Exception as e:
                lines.append(f"  [-] {t('for.system_detect_failed')}: {e}")
        else:
            lines.append(f"  [*] {t('for.not_windows')}")

        # 提供手动检查命令
        lines.append(f"\n--- {t('for.manual_check')} ---")
        lines.append("  Windows:")
        lines.append(f"    dir /r \"{filepath}\"")
        lines.append(f"    powershell Get-Item \"{filepath}\" -Stream *")
        lines.append(f"    powershell Get-Content \"{filepath}\" -Stream <streamname>")
        lines.append("  Linux (NTFS mount):")
        lines.append("    getfattr -d <file>")
        lines.append(f"  {t('for.tools')}:")
        lines.append("    streams.exe (Sysinternals)")
        lines.append("    AlternateStreamView (NirSoft)")

        return '\n'.join(lines)

    # ========== EXIF 篡改检测 ==========

    def detect_exif_tampering(self, filepath: str) -> str:
        """EXIF 篡改检测 -- 检查图片元数据是否被修改"""
        lines = [f"=== {t('for.exif_tampering')} ===", f"{t('for.file')}: {os.path.basename(filepath)}"]

        try:
            from PIL import Image
            from PIL.ExifTags import GPSTAGS, TAGS
        except ImportError:
            lines.append(f"[!] {t('for.install_pillow')}")
            lines.append(t('for.trying_raw_exif'))
            data = read_file_bytes(filepath)
            # 搜索 EXIF 编辑器特征
            editors = [b'Photoshop', b'GIMP', b'ExifTool', b'Adobe',
                       b'Lightroom', b'Paint.NET', b'Snapseed']
            for editor in editors:
                if editor in data:
                    lines.append(f"  [!] {t('for.editor_found')}: {editor.decode()}")
            return '\n'.join(lines)

        try:
            img = Image.open(filepath)
        except Exception as e:
            lines.append(f"[!] {t('for.cannot_open_image')}: {e}")
            return '\n'.join(lines)

        exif_data = img.getexif()
        if not exif_data:
            lines.append(f"  [-] {t('for.no_exif')}")
            lines.append(f"  [?] {t('for.no_exif_suspicious')}")
            return '\n'.join(lines)

        # 解析 EXIF 标签
        exif_dict = {}
        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, tag_id)
            exif_dict[tag] = value

        lines.append(f"\n--- {t('for.exif_basic')} ---")
        basic_tags = ['Make', 'Model', 'Software', 'DateTime',
                      'DateTimeOriginal', 'DateTimeDigitized',
                      'ImageWidth', 'ImageLength']
        for tag in basic_tags:
            if tag in exif_dict:
                lines.append(f"  {tag}: {exif_dict[tag]}")

        tampering_signs = []

        # 检查 1: Software 标签是否包含编辑器名称
        lines.append(f"\n--- {t('for.tampering_check')} ---")
        software = str(exif_dict.get('Software', ''))
        editor_keywords = ['Photoshop', 'GIMP', 'ExifTool', 'Adobe', 'Lightroom',
                           'Paint.NET', 'Snapseed', 'ACDSee', 'PhotoScape',
                           'Pixlr', 'Capture One']
        for editor in editor_keywords:
            if editor.lower() in software.lower():
                lines.append(f"  [!] {t('for.editor_in_software')}: {software}")
                tampering_signs.append(f"{t('for.editor')}: {software}")
                break
        else:
            if software:
                lines.append(f"  [*] Software: {software}")

        # 检查 2: 修改时间是否晚于创建时间
        dt_original = str(exif_dict.get('DateTimeOriginal', ''))
        dt_modified = str(exif_dict.get('DateTime', ''))
        dt_digitized = str(exif_dict.get('DateTimeDigitized', ''))

        if dt_original and dt_modified:
            if dt_modified > dt_original:
                lines.append(f"  [!] {t('for.modified_later')} ({dt_modified}) > ({dt_original})")
                tampering_signs.append(t('for.mod_time_later'))
            elif dt_modified == dt_original:
                lines.append(f"  [+] {t('for.mod_time_match')}")
        if dt_original and dt_digitized and dt_original != dt_digitized:
            lines.append(f"  [?] {t('for.time_mismatch')} ({dt_original}) vs ({dt_digitized})")
            tampering_signs.append(t('for.time_inconsistent'))

        # 检查 3: 缩略图是否与主图不匹配
        try:
            thumb_data = exif_data.get(0x0201)  # JPEGInterchangeFormat (缩略图偏移)
            if thumb_data is not None:
                # 获取主图尺寸和缩略图尺寸
                main_w, main_h = img.size
                main_ratio = main_w / main_h if main_h else 0

                # 尝试从 EXIF 获取缩略图
                thumb_len = exif_data.get(0x0202)  # JPEGInterchangeFormatLength
                if thumb_len:
                    lines.append(f"  [*] {t('for.thumbnail_exists')} ({thumb_len} bytes)")
                    # 简单比例检查
                    thumb_w = exif_dict.get('ThumbnailImageWidth',
                                            exif_dict.get('ImageWidth', 0))
                    thumb_h = exif_dict.get('ThumbnailImageLength',
                                            exif_dict.get('ImageLength', 0))
                    if isinstance(thumb_w, int) and isinstance(thumb_h, int) and thumb_h > 0:
                        thumb_ratio = thumb_w / thumb_h
                        if main_ratio > 0 and abs(thumb_ratio - main_ratio) > 0.1:
                            lines.append(
                                f"  [!] {t('for.thumbnail_ratio_mismatch')} ({thumb_ratio:.2f}) "
                                f"vs ({main_ratio:.2f})")
                            tampering_signs.append(t('for.thumbnail_mismatch'))
        except Exception:
            pass

        # 检查 4: GPS 坐标合理性
        gps_info = exif_dict.get('GPSInfo')
        if gps_info:
            lines.append(f"\n--- {t('for.gps_info')} ---")
            try:
                gps_dict = {}
                for key in gps_info:
                    decode = GPSTAGS.get(key, key)
                    gps_dict[decode] = gps_info[key]

                lat = gps_dict.get('GPSLatitude')
                lat_ref = gps_dict.get('GPSLatitudeRef', 'N')
                lon = gps_dict.get('GPSLongitude')
                lon_ref = gps_dict.get('GPSLongitudeRef', 'E')

                if lat and lon:
                    def dms_to_decimal(dms, ref):
                        d = float(dms[0])
                        m = float(dms[1])
                        s = float(dms[2])
                        decimal = d + m / 60 + s / 3600
                        if ref in ('S', 'W'):
                            decimal = -decimal
                        return decimal

                    lat_dec = dms_to_decimal(lat, lat_ref)
                    lon_dec = dms_to_decimal(lon, lon_ref)
                    lines.append(f"  GPS: {lat_dec:.6f}, {lon_dec:.6f}")

                    # 检查坐标合理性
                    if abs(lat_dec) > 90:
                        lines.append(f"  [!] {t('for.lat_out_of_range')} ({lat_dec})")
                        tampering_signs.append(t('for.gps_lat_range'))
                    if abs(lon_dec) > 180:
                        lines.append(f"  [!] {t('for.lon_out_of_range')} ({lon_dec})")
                        tampering_signs.append(t('for.gps_lon_range'))
                    if lat_dec == 0.0 and lon_dec == 0.0:
                        lines.append(f"  [?] {t('for.gps_zero')}")
                        tampering_signs.append(t('for.gps_zero_point'))
            except Exception:
                lines.append(f"  [-] {t('for.gps_parse_failed')}")
        else:
            lines.append(f"\n  [-] {t('for.no_gps')}")

        # 检查 5: 相机型号与 EXIF 一致性
        make = str(exif_dict.get('Make', ''))
        model = str(exif_dict.get('Model', ''))
        if make and model:
            # 检查 Make 是否出现在 Model 中（正常情况）或完全不相关
            make_lower = make.lower().strip()
            model_lower = model.lower().strip()
            known_makes = {
                'canon': ['eos', 'powershot', 'ixus', 'canon'],
                'nikon': ['nikon', 'coolpix', 'd3', 'd5', 'd7', 'd8', 'z'],
                'sony': ['ilce', 'dsc', 'alpha', 'sony', 'a6', 'a7', 'a9'],
                'apple': ['iphone', 'ipad'],
                'samsung': ['galaxy', 'sm-'],
                'huawei': ['huawei', 'p10', 'p20', 'p30', 'p40', 'mate', 'nova'],
                'xiaomi': ['mi ', 'redmi', 'poco'],
                'google': ['pixel'],
            }
            for brand, keywords in known_makes.items():
                if brand in make_lower:
                    if not any(kw in model_lower for kw in keywords):
                        lines.append(
                            f"  [?] {t('for.brand_model_mismatch')} ({make}) / ({model})")
                        tampering_signs.append(t('for.brand_mismatch'))
                    break

        # 汇总
        lines.append(f"\n--- {t('for.summary')} ---")
        if tampering_signs:
            lines.append(f"{t('for.found')} {len(tampering_signs)} {t('for.suspicious_signs')}:")
            for sign in tampering_signs:
                lines.append(f"  [!] {sign}")
        else:
            lines.append(f"  [-] {t('for.no_tampering')}")

        return '\n'.join(lines)

    # ========== 磁盘镜像基础分析 ==========

    def analyze_disk_image(self, filepath: str) -> str:
        """磁盘镜像基础分析 -- 分区表、文件系统识别"""
        data = read_file_bytes(filepath)
        lines = [f"=== {t('for.disk_image')} ===",
                 f"{t('for.file')}: {os.path.basename(filepath)}",
                 f"{t('for.size')}: {len(data):,} bytes ({len(data) / 1024 / 1024:.1f} MB)"]

        if len(data) < 512:
            lines.append(f"[!] {t('for.file_too_small')}")
            return '\n'.join(lines)

        # 检测分区表类型
        lines.append(f"\n--- {t('for.partition_table')} ---")
        is_mbr = False
        is_gpt = False

        # MBR 检测: 偏移 510-511 为 0x55 0xAA
        if len(data) >= 512:
            boot_sig = struct.unpack('<H', data[510:512])[0]
            if boot_sig == 0xAA55:
                is_mbr = True
                lines.append(f"  [+] {t('for.mbr_found')}")

        # GPT 检测: 偏移 512 处为 "EFI PART"
        if len(data) >= 520:
            gpt_sig = data[512:520]
            if gpt_sig == b'EFI PART':
                is_gpt = True
                lines.append(f"  [+] {t('for.gpt_found')}")

        if not is_mbr and not is_gpt:
            lines.append(f"  [-] {t('for.no_partition_table')}")

        # MBR 分区表解析
        if is_mbr:
            lines.append(f"\n--- {t('for.mbr_partitions')} ---")
            partition_types = {
                0x00: t('for.pt_empty'),
                0x01: "FAT12",
                0x04: "FAT16 (<32MB)",
                0x05: t('for.pt_extended'),
                0x06: "FAT16 (>32MB)",
                0x07: "NTFS/exFAT/HPFS",
                0x0B: "FAT32 (CHS)",
                0x0C: "FAT32 (LBA)",
                0x0E: "FAT16 (LBA)",
                0x0F: t('for.pt_extended') + " (LBA)",
                0x11: t('for.pt_hidden') + " FAT12",
                0x14: t('for.pt_hidden') + " FAT16",
                0x17: t('for.pt_hidden') + " NTFS",
                0x1B: t('for.pt_hidden') + " FAT32",
                0x82: "Linux swap",
                0x83: "Linux",
                0x85: "Linux " + t('for.pt_extended'),
                0x8E: "Linux LVM",
                0xA5: "FreeBSD",
                0xEE: t('for.pt_gpt_protect'),
                0xEF: t('for.pt_efi'),
                0xFD: "Linux RAID",
            }

            for i in range(4):
                offset = 446 + i * 16
                entry = data[offset:offset + 16]
                if len(entry) < 16:
                    break

                status = entry[0]
                part_type = entry[4]
                lba_start = struct.unpack('<I', entry[8:12])[0]
                num_sectors = struct.unpack('<I', entry[12:16])[0]
                size_mb = num_sectors * 512 / (1024 * 1024)

                type_name = partition_types.get(part_type, f"{t('for.unknown')}(0x{part_type:02X})")
                active = f" [{t('for.active')}]" if status == 0x80 else ""

                if part_type == 0x00 and lba_start == 0 and num_sectors == 0:
                    lines.append(f"  {t('for.partition')} {i + 1}: {t('for.pt_empty')}")
                else:
                    lines.append(
                        f"  {t('for.partition')} {i + 1}: {type_name}{active}")
                    lines.append(
                        f"    {t('for.start_sector')}: {lba_start}, {t('for.sector_count')}: {num_sectors}, "
                        f"{t('for.size')}: {size_mb:.1f} MB")

        # GPT 分区表解析
        if is_gpt and len(data) >= 592:
            lines.append(f"\n--- {t('for.gpt_header')} ---")
            gpt_revision = struct.unpack('<I', data[520:524])[0]
            gpt_header_size = struct.unpack('<I', data[524:528])[0]
            gpt_first_lba = struct.unpack('<Q', data[552:560])[0]
            gpt_last_lba = struct.unpack('<Q', data[560:568])[0]
            struct.unpack('<Q', data[584:592])[0]
            gpt_num_parts = struct.unpack('<I', data[592:596])[0] if len(data) >= 596 else 0

            lines.append(f"  {t('for.revision')}: {gpt_revision >> 16}.{gpt_revision & 0xFFFF}")
            lines.append(f"  {t('for.header_size')}: {gpt_header_size} bytes")
            lines.append(f"  {t('for.usable_sectors')}: {gpt_first_lba} - {gpt_last_lba}")
            lines.append(f"  {t('for.partition_entries')}: {gpt_num_parts}")

        # 搜索文件系统签名
        lines.append(f"\n--- {t('for.fs_sig_search')} ---")

        # FAT 文件系统
        fat_signatures = [
            (b'FAT12   ', "FAT12"),
            (b'FAT16   ', "FAT16"),
            (b'FAT32   ', "FAT32"),
        ]
        for sig, name in fat_signatures:
            idx = data.find(sig, 0, min(len(data), 1024 * 1024))
            if idx != -1:
                lines.append(f"  [+] {name} @ offset 0x{idx:X}")

        # NTFS 文件系统
        ntfs_idx = data.find(b'NTFS    ', 0, min(len(data), 1024 * 1024))
        if ntfs_idx != -1:
            lines.append(f"  [+] NTFS @ offset 0x{ntfs_idx:X}")

        # ext2/3/4 文件系统 (超级块 magic number 0xEF53 at offset 1080)
        if len(data) >= 1082:
            ext_magic = struct.unpack('<H', data[1080:1082])[0]
            if ext_magic == 0xEF53:
                lines.append("  [+] ext2/3/4 (0xEF53) @ offset 0x438")
        # 也搜索非标准偏移（多分区情况）
        search_limit = min(len(data), 100 * 1024 * 1024)
        for offset in range(0, search_limit, 512):
            if offset + 1082 <= len(data):
                magic = struct.unpack('<H', data[offset + 1080:offset + 1082])[0]
                if magic == 0xEF53 and offset != 0:
                    lines.append(
                        f"  [+] ext2/3/4 签名 @ offset 0x{offset + 1080:X} "
                        f"(分区起始 @ 0x{offset:X})")
                    break

        # 引导代码检测
        if is_mbr:
            lines.append(f"\n--- {t('for.boot_code')} ---")
            boot_code = data[:446]
            if boot_code == b'\x00' * 446:
                lines.append(f"  [-] {t('for.boot_code_empty')}")
            else:
                # 搜索常见引导加载程序特征
                if b'GRUB' in boot_code:
                    lines.append(f"  [+] {t('for.detected_grub')}")
                elif b'NTLDR' in boot_code or b'BOOTMGR' in boot_code:
                    lines.append(f"  [+] {t('for.detected_windows_boot')}")
                elif b'LILO' in boot_code:
                    lines.append(f"  [+] {t('for.detected_lilo')}")
                else:
                    lines.append(f"  [*] {t('for.boot_code_unknown')}")

        lines.append(f"\n{t('for.tips')}:")
        lines.append(f"  - {t('for.tip_fdisk')}")
        lines.append(f"  - {t('for.tip_mmls')}")
        lines.append(f"  - {t('for.tip_mount')}")

        return '\n'.join(lines)

    # ========== Email 头分析 ==========

    def analyze_email(self, filepath: str) -> str:
        """Email 头分析 -- 解析 .eml 文件提取关键信息"""
        import email
        from email import policy

        data = read_file_bytes(filepath)
        lines = [f"=== {t('for.email_analysis')} ===", f"{t('for.file')}: {os.path.basename(filepath)}"]

        try:
            msg = email.message_from_bytes(data, policy=policy.default)
        except Exception as e:
            lines.append(f"[!] {t('for.parse_failed')}: {e}")
            return '\n'.join(lines)

        # 基本头信息
        lines.append(f"\n--- {t('for.basic_info')} ---")
        basic_headers = ['From', 'To', 'Cc', 'Bcc', 'Subject', 'Date', 'Message-ID',
                         'Reply-To', 'Return-Path']
        for header in basic_headers:
            value = msg.get(header)
            if value:
                lines.append(f"  {header}: {value}")

        # Received 头解析（路由追踪）
        lines.append(f"\n--- {t('for.email_route')} ---")
        received_headers = msg.get_all('Received') or []
        if received_headers:
            for i, recv in enumerate(reversed(received_headers), 1):
                recv_clean = ' '.join(recv.split())
                lines.append(f"  {t('for.hop')} {i}: {recv_clean[:200]}")
                # 提取 IP 地址
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', recv)
                if ips:
                    lines.append(f"       IP: {', '.join(ips)}")
        else:
            lines.append(f"  [-] {t('for.no_received')}")

        # SPF/DKIM/DMARC 检查
        lines.append(f"\n--- {t('for.auth_info')} ---")
        auth_headers = {
            'Authentication-Results': t('for.auth_results'),
            'DKIM-Signature': t('for.dkim_sig'),
            'Received-SPF': t('for.spf_result'),
            'ARC-Authentication-Results': t('for.arc_auth'),
        }
        auth_found = False
        for header, desc in auth_headers.items():
            value = msg.get(header)
            if value:
                auth_found = True
                value_clean = ' '.join(value.split())
                lines.append(f"  {desc}: {value_clean[:200]}")
                # 检查 SPF/DKIM 状态
                if 'fail' in value.lower():
                    lines.append(f"    [!] {t('for.auth_fail')}")
                elif 'pass' in value.lower():
                    lines.append(f"    [+] {t('for.auth_pass')}")
        if not auth_found:
            lines.append(f"  [-] {t('for.no_auth_headers')}")

        # 附件信息
        lines.append(f"\n--- {t('for.attachment_info')} ---")
        attachments = []
        for part in msg.walk():
            content_disposition = part.get_content_disposition()
            if content_disposition == 'attachment' or (
                    content_disposition and 'attachment' in content_disposition):
                filename = part.get_filename() or t('for.unknown_filename')
                size = len(part.get_payload(decode=True) or b'')
                content_type = part.get_content_type()
                attachments.append((filename, content_type, size))
        if attachments:
            for fname, ctype, size in attachments:
                lines.append(f"  [{ctype}] {fname} ({size:,} bytes)")
                # 检查可疑附件类型
                suspicious_ext = ['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js',
                                  '.wsf', '.scr', '.pif', '.hta', '.dll']
                if any(fname.lower().endswith(ext) for ext in suspicious_ext):
                    lines.append(f"    [!] {t('for.suspicious_attachment')}!")
        else:
            lines.append(f"  [-] {t('for.no_attachments')}")

        # 搜索可疑内容
        lines.append(f"\n--- {t('for.suspicious_content')} ---")
        body_text = str(data)
        # 搜索 URL
        urls = list(set(re.findall(r'https?://[\w./\-?&=%#@:]+', body_text)))
        if urls:
            lines.append(f"  URL ({len(urls)}):")
            for u in sorted(urls)[:15]:
                lines.append(f"    {u}")
        # 搜索 IP
        ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', body_text)))
        if ips:
            lines.append(f"  {t('for.ip_addrs')} ({len(ips)}):")
            for ip in sorted(ips)[:10]:
                lines.append(f"    {ip}")

        return '\n'.join(lines)

    # ========== Windows 注册表分析 ==========

    def analyze_registry(self, filepath: str) -> str:
        """Windows 注册表分析 -- 解析 regf 文件结构"""
        data = read_file_bytes(filepath)
        lines = [f"=== {t('for.registry_analysis')} ===",
                 f"{t('for.file')}: {os.path.basename(filepath)}",
                 f"{t('for.size')}: {len(data):,} bytes"]

        # 检测 regf 签名
        lines.append(f"\n--- {t('for.header_detection')} ---")
        if len(data) < 4 or data[:4] != b'regf':
            lines.append(f"[!] {t('for.not_regf')}")
            lines.append(f"    {t('for.actual_header')}: {data[:4].hex() if len(data) >= 4 else t('for.file_too_small')}")
        else:
            lines.append(f"  [+] {t('for.valid_regf')}")

        # 解析 regf header
        if len(data) >= 96 and data[:4] == b'regf':
            lines.append(f"\n--- {t('for.regf_header')} ---")
            # 序列号
            seq1 = struct.unpack('<I', data[4:8])[0]
            seq2 = struct.unpack('<I', data[8:12])[0]
            lines.append(f"  {t('for.seq_num')} 1: {seq1}")
            lines.append(f"  {t('for.seq_num')} 2: {seq2}")
            if seq1 != seq2:
                lines.append(f"  [!] {t('for.seq_mismatch')}")

            # 最后修改时间 (Windows FILETIME at offset 12)
            try:
                filetime = struct.unpack('<Q', data[12:20])[0]
                if filetime > 0:
                    # 将 Windows FILETIME 转换为 Unix 时间戳
                    import datetime
                    epoch_diff = 116444736000000000
                    timestamp = (filetime - epoch_diff) / 10000000
                    dt = datetime.datetime.utcfromtimestamp(timestamp)
                    lines.append(f"  {t('for.last_modified')}: {dt.strftime('%Y-%m-%d %H:%M:%S')} UTC")
            except (ValueError, OSError, OverflowError):
                lines.append(f"  {t('for.last_modified')}: {t('for.cannot_parse')}")

            # 文件名 (在偏移 48 处，UTF-16LE)
            try:
                hive_name_raw = data[48:96]
                hive_name = hive_name_raw.decode('utf-16le', errors='ignore').rstrip('\x00')
                if hive_name:
                    lines.append(f"  Hive: {hive_name}")
            except Exception:
                pass

        # 搜索常见注册表键值特征字符串
        lines.append(f"\n--- {t('for.keyword_search')} ---")
        key_patterns = {
            'RunOnce': t('for.reg_autorun_once'),
            'Run\\\\': t('for.reg_autorun'),
            'RunServices': t('for.reg_service_autorun'),
            'UserAssist': t('for.reg_user_assist'),
            'MRUList': t('for.reg_mru'),
            'RecentDocs': t('for.reg_recent_docs'),
            'TypedURLs': t('for.reg_typed_urls'),
            'TypedPaths': t('for.reg_typed_paths'),
            'OpenSaveMRU': t('for.reg_open_save'),
            'ComDlg32': t('for.reg_comdlg'),
            'ShellBags': t('for.reg_shellbags'),
            'AppCompatCache': t('for.reg_appcompat'),
            'Uninstall': t('for.reg_uninstall'),
            'NetworkList': t('for.reg_network'),
            'MountedDevices': t('for.reg_mounted'),
        }

        for pattern, desc in key_patterns.items():
            # 搜索 ASCII 和 UTF-16LE 版本
            ascii_count = data.count(pattern.encode('ascii'))
            utf16_count = data.count(pattern.encode('utf-16le'))
            total = ascii_count + utf16_count
            if total > 0:
                lines.append(f"  [+] {desc} ({pattern}): {total}")

        # 提取可打印字符串中的有用信息
        lines.append(f"\n--- {t('for.printable_string_analysis')} ---")
        strings = extract_printable_strings(data, 8)

        # 提取路径
        paths = [s for s in strings if re.match(r'^[A-Z]:\\', s)]
        if paths:
            lines.append(f"  {t('for.file_paths')} ({len(paths)}):")
            for p in sorted(set(paths))[:20]:
                lines.append(f"    {p}")

        # 提取 URL
        urls = [s for s in strings if re.match(r'^https?://', s)]
        if urls:
            lines.append(f"  URL ({len(urls)}):")
            for u in sorted(set(urls))[:15]:
                lines.append(f"    {u}")

        # 提取可能的用户名（搜索 Users\ 或 home\ 路径中的用户名）
        usernames = set()
        for s in strings:
            m = re.search(r'[Uu]sers\\([A-Za-z0-9._-]{2,30})(?:\\|$)', s)
            if m:
                usernames.add(m.group(1))
        if usernames:
            lines.append(f"  {t('for.usernames')}:")
            for u in sorted(usernames):
                lines.append(f"    {u}")

        # 搜索可疑字符串
        suspicious_keywords = [b'password', b'passwd', b'secret', b'token',
                               b'credential', b'private', b'hack', b'exploit']
        found_suspicious = []
        for kw in suspicious_keywords:
            if kw in data.lower():
                found_suspicious.append(kw.decode())
        if found_suspicious:
            lines.append(f"  [!] {t('for.suspicious_keywords')}: {', '.join(found_suspicious)}")

        lines.append(f"\n{t('for.tips')}:")
        lines.append(f"  - {t('for.tip_reg_explorer')}")
        lines.append(f"  - {t('for.tip_regripper')}")
        lines.append(f"  - {t('for.tip_python_registry')}")

        return '\n'.join(lines)

    # ========== 文件时间线分析 ==========

    def file_timeline(self, filepath: str) -> str:
        """文件时间线分析 -- 提取和展示文件时间信息"""
        import datetime
        lines = [f"=== {t('for.file_timeline')} ==="]

        timeline_entries = []

        if os.path.isfile(filepath):
            # 单个文件分析
            stat = os.stat(filepath)
            fname = os.path.basename(filepath)
            lines.append(f"{t('for.file')}: {fname}")

            ctime = datetime.datetime.fromtimestamp(stat.st_ctime)
            mtime = datetime.datetime.fromtimestamp(stat.st_mtime)
            atime = datetime.datetime.fromtimestamp(stat.st_atime)

            lines.append(f"\n--- {t('for.fs_timestamps')} ---")
            lines.append(f"  {t('for.create_time')} (ctime): {ctime.strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append(f"  {t('for.modify_time')} (mtime): {mtime.strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append(f"  {t('for.access_time')} (atime): {atime.strftime('%Y-%m-%d %H:%M:%S')}")

            timeline_entries.append((ctime, t('for.tl_create'), fname))
            timeline_entries.append((mtime, t('for.tl_modify'), fname))
            timeline_entries.append((atime, t('for.tl_access'), fname))

            # 检查时间异常
            if mtime < ctime:
                lines.append(f"  [!] {t('for.mtime_before_ctime')}")
            if atime < mtime:
                lines.append(f"  [?] {t('for.atime_before_mtime')}")

            # 尝试提取压缩包内的时间
            data = read_file_bytes(filepath)

            # ZIP 文件
            if data[:2] == b'PK':
                lines.append(f"\n--- {t('for.zip_internal_timeline')} ---")
                try:
                    import io
                    import zipfile
                    zf = zipfile.ZipFile(io.BytesIO(data))
                    for info in zf.infolist():
                        try:
                            dt = datetime.datetime(*info.date_time)
                            timeline_entries.append((dt, t('for.tl_zip_file'), info.filename))
                        except (ValueError, TypeError):
                            pass
                    zf.close()
                except Exception as e:
                    lines.append(f"  [!] {t('for.zip_parse_failed')}: {e}")

            # TAR 文件
            elif (data[:5] == b'\x1f\x8b\x08' or  # gzip
                  data[257:262] == b'ustar' or  # tar
                  filepath.endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2'))):
                lines.append(f"\n--- {t('for.tar_internal_timeline')} ---")
                try:
                    import io
                    import tarfile
                    tf = tarfile.open(fileobj=io.BytesIO(data))
                    for member in tf.getmembers():
                        dt = datetime.datetime.fromtimestamp(member.mtime)
                        timeline_entries.append((dt, t('for.tl_tar_file'), member.name))
                    tf.close()
                except Exception as e:
                    lines.append(f"  [!] {t('for.tar_parse_failed')}: {e}")

        elif os.path.isdir(filepath):
            # 目录分析
            lines.append(f"{t('for.directory')}: {filepath}")
            lines.append(f"\n--- {t('for.dir_timeline')} ---")
            try:
                for entry in os.scandir(filepath):
                    try:
                        stat = entry.stat()
                        ctime = datetime.datetime.fromtimestamp(stat.st_ctime)
                        mtime = datetime.datetime.fromtimestamp(stat.st_mtime)
                        atime = datetime.datetime.fromtimestamp(stat.st_atime)
                        timeline_entries.append((ctime, t('for.tl_create'), entry.name))
                        timeline_entries.append((mtime, t('for.tl_modify'), entry.name))
                        timeline_entries.append((atime, t('for.tl_access'), entry.name))
                    except OSError:
                        pass
            except PermissionError:
                lines.append(f"  [!] {t('for.permission_denied')}")
        else:
            lines.append(f"[!] {t('for.path_not_exist')}: {filepath}")
            return '\n'.join(lines)

        # 按时间排序并显示时间线
        if timeline_entries:
            timeline_entries.sort(key=lambda x: x[0])
            lines.append(f"\n--- {t('for.full_timeline')} ({len(timeline_entries)}) ---")

            # 限制显示数量
            display_entries = timeline_entries[:100]
            for dt, action, name in display_entries:
                lines.append(f"  {dt.strftime('%Y-%m-%d %H:%M:%S')} [{action}] {name}")
            if len(timeline_entries) > 100:
                lines.append(f"  ... {t('for.more_records')}: {len(timeline_entries) - 100}")

            # 时间跨度统计
            if len(timeline_entries) >= 2:
                earliest = timeline_entries[0][0]
                latest = timeline_entries[-1][0]
                span = latest - earliest
                lines.append(f"\n{t('for.time_span')}: {earliest.strftime('%Y-%m-%d')} ~ "
                             f"{latest.strftime('%Y-%m-%d')} ({span.days} {t('for.days')})")

        return '\n'.join(lines)

    # ========== DNS 隧道检测 ==========

    def detect_dns_tunnel(self, filepath: str) -> str:
        """DNS 隧道检测 -- 从 PCAP 文件中检测 DNS 隧道"""
        lines = [f"=== {t('for.dns_tunnel')} ===", f"{t('for.file')}: {os.path.basename(filepath)}"]

        try:
            from scapy.all import DNS, DNSQR, DNSRR, rdpcap
        except ImportError:
            lines.append(f"[!] {t('for.install_scapy')}")
            lines.append(t('for.trying_raw_dns'))
            data = read_file_bytes(filepath)
            # 简单搜索 DNS 查询特征
            dns_queries = re.findall(rb'[\x03-\x3f][\w-]{3,63}(?:\.\w{2,10})+', data)
            if dns_queries:
                lines.append(f"  {t('for.found')} {len(dns_queries)} {t('for.dns_fragments')}")
                for q in dns_queries[:20]:
                    lines.append(f"    {q.decode('ascii', errors='ignore')}")
            return '\n'.join(lines)

        try:
            packets = rdpcap(filepath)
        except Exception as e:
            lines.append(f"[!] {t('for.pcap_parse_failed')}: {e}")
            return '\n'.join(lines)

        # 提取 DNS 查询
        dns_queries = []
        dns_responses = []
        txt_records = []

        for pkt in packets:
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                # 查询
                if dns.qr == 0 and dns.haslayer(DNSQR):
                    qname = dns[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                    qtype = dns[DNSQR].qtype
                    dns_queries.append((qname, qtype))
                # 响应
                elif dns.qr == 1:
                    if dns.haslayer(DNSRR):
                        for i in range(dns.ancount):
                            try:
                                rr = dns.an[i] if hasattr(dns.an, '__getitem__') else dns.an
                                rdata = rr.rdata
                                if rr.type == 16:  # TXT 记录
                                    if isinstance(rdata, bytes):
                                        txt_records.append(rdata)
                                    elif isinstance(rdata, list):
                                        for r in rdata:
                                            txt_records.append(
                                                r if isinstance(r, bytes) else r.encode())
                                dns_responses.append((rr.rrname, rr.type, rdata))
                            except Exception:
                                pass

        lines.append(f"\n{t('for.dns_query_total')}: {len(dns_queries)}")
        lines.append(f"{t('for.dns_response_total')}: {len(dns_responses)}")
        lines.append(f"{t('for.txt_records')}: {len(txt_records)}")

        if not dns_queries:
            lines.append(f"  [-] {t('for.no_dns_queries')}")
            return '\n'.join(lines)

        # 统计查询域名
        domain_count = {}
        for qname, _ in dns_queries:
            parts = qname.split('.')
            if len(parts) >= 2:
                base_domain = '.'.join(parts[-2:])
                domain_count[base_domain] = domain_count.get(base_domain, 0) + 1

        lines.append(f"\n--- {t('for.domain_freq')} ---")
        sorted_domains = sorted(domain_count.items(), key=lambda x: -x[1])
        for domain, count in sorted_domains[:15]:
            marker = " [!]" if count > 20 else ""
            lines.append(f"  {domain}: {count}{marker}")

        # 检测异常长的子域名
        lines.append(f"\n--- {t('for.abnormal_subdomain')} ---")
        long_subdomains = []
        for qname, qtype in dns_queries:
            parts = qname.split('.')
            if len(parts) >= 3:
                subdomain = '.'.join(parts[:-2])
                if len(subdomain) > 30:
                    long_subdomains.append((qname, len(subdomain)))

        if long_subdomains:
            lines.append(f"  [!] {t('for.found')} {len(long_subdomains)} {t('for.long_subdomains')}:")
            for qname, length in long_subdomains[:20]:
                lines.append(f"    [{length}{t('for.chars')}] {qname[:100]}")

            # 尝试拼接并解码子域名数据
            lines.append(f"\n--- {t('for.subdomain_decode')} ---")
            # 按基础域名分组
            subdomain_data = {}
            for qname, _ in dns_queries:
                parts = qname.split('.')
                if len(parts) >= 3:
                    base = '.'.join(parts[-2:])
                    sub = '.'.join(parts[:-2]).replace('.', '')
                    if base not in subdomain_data:
                        subdomain_data[base] = []
                    subdomain_data[base].append(sub)

            for base, subs in subdomain_data.items():
                concatenated = ''.join(subs)
                if len(concatenated) > 50:
                    lines.append(f"\n  {t('for.domain')} {base} {t('for.concat_data')} ({len(concatenated)} {t('for.chars')}):")
                    lines.append(f"    {t('for.first_100')}: {concatenated[:100]}")

                    # 尝试 Base64 解码
                    import base64
                    try:
                        # 补齐 padding
                        padded = concatenated + '=' * (4 - len(concatenated) % 4)
                        decoded = base64.b64decode(padded, validate=False)
                        printable = decoded.decode('utf-8', errors='ignore')
                        if len(printable.strip()) > 10:
                            lines.append(f"    [!] Base64 {t('for.decode_success')}:")
                            lines.append(f"        {printable[:200]}")
                    except Exception:
                        pass

                    # 尝试 Base32 解码
                    try:
                        padded = concatenated.upper() + '=' * (8 - len(concatenated) % 8)
                        decoded = base64.b32decode(padded)
                        printable = decoded.decode('utf-8', errors='ignore')
                        if len(printable.strip()) > 10:
                            lines.append(f"    [!] Base32 {t('for.decode_success')}:")
                            lines.append(f"        {printable[:200]}")
                    except Exception:
                        pass

                    # 尝试十六进制解码
                    try:
                        decoded = bytes.fromhex(concatenated)
                        printable = decoded.decode('utf-8', errors='ignore')
                        if len(printable.strip()) > 10:
                            lines.append(f"    [!] Hex {t('for.decode_success')}:")
                            lines.append(f"        {printable[:200]}")
                    except Exception:
                        pass
        else:
            lines.append(f"  [-] {t('for.no_long_subdomains')}")

        # 检测 TXT 记录中的 Base64 数据
        if txt_records:
            lines.append(f"\n--- {t('for.txt_record_analysis')} ---")
            import base64
            for i, record in enumerate(txt_records[:20]):
                record_str = record.decode('ascii', errors='ignore').strip()
                lines.append(f"  TXT [{i}]: {record_str[:100]}")
                # 检查是否是 Base64
                if re.match(r'^[A-Za-z0-9+/=]{20,}$', record_str):
                    try:
                        decoded = base64.b64decode(record_str)
                        printable = decoded.decode('utf-8', errors='ignore')
                        if printable.strip():
                            lines.append(f"    [!] Base64: {printable[:200]}")
                    except Exception:
                        pass

        # 汇总
        lines.append(f"\n--- {t('for.summary')} ---")
        tunnel_indicators = []
        if long_subdomains:
            tunnel_indicators.append(f"{t('for.long_subdomains')} ({len(long_subdomains)})")
        if any(count > 50 for _, count in domain_count.items()):
            tunnel_indicators.append(t('for.high_freq_dns'))
        if txt_records:
            tunnel_indicators.append(f"{t('for.txt_records')} ({len(txt_records)})")

        if tunnel_indicators:
            lines.append(f"[!] {t('for.dns_tunnel_indicators')}: {', '.join(tunnel_indicators)}")
            lines.append(f"{t('for.suggestions')}:")
        else:
            lines.append(f"[-] {t('for.no_dns_tunnel')}")

        return '\n'.join(lines)

    # ========== 高级提取 ==========

    def pcap_extract_files(self, filepath: str, output_dir: str = "") -> str:
        """从 PCAP 流量中自动导出传输的文件"""
        try:
            from scapy.all import TCP, Raw, rdpcap
        except ImportError:
            return "需要安装 scapy: pip install scapy"
        data = read_file_bytes(filepath)
        if not data or data[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x0a\x0d\x0d\x0a'):
            return "不是有效的 PCAP/PCAPNG 文件"
        packets = rdpcap(filepath)
        if not output_dir:
            output_dir = os.path.splitext(filepath)[0] + "_extracted"
        os.makedirs(output_dir, exist_ok=True)
        # 按 TCP 流重组
        streams = {}
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                key = tuple(sorted([(pkt[TCP].sport,), (pkt[TCP].dport,)]))
                if key not in streams:
                    streams[key] = b""
                streams[key] += bytes(pkt[Raw].load)
        lines = ["=== PCAP 文件提取 ===", f"TCP 流数: {len(streams)}", ""]
        extracted = 0
        for stream_id, stream_data in streams.items():
            for magic, desc in sorted(MAGIC_SIGNATURES.items(), key=lambda x: -len(x[0])):
                idx = stream_data.find(magic)
                while idx != -1:
                    ext = desc.split()[0].lower()
                    ext_map = {'png': '.png', 'jpeg': '.jpg', 'gif87a': '.gif', 'gif89a': '.gif',
                              'zip': '.zip', 'pdf': '.pdf', 'rar': '.rar', 'elf': '.elf', 'pe/exe': '.exe'}
                    file_ext = ext_map.get(ext, '.bin')
                    out_file = os.path.join(output_dir, f"file_{extracted:03d}{file_ext}")
                    # 简单提取：从 magic 开始取最多 10MB
                    chunk = stream_data[idx:idx+10*1024*1024]
                    with open(out_file, 'wb') as f:
                        f.write(chunk)
                    lines.append(f"  [+] 提取 {desc} -> {out_file} ({len(chunk)} bytes)")
                    extracted += 1
                    idx = stream_data.find(magic, idx + len(magic))
        if extracted == 0:
            lines.append("  [-] 未发现可提取的文件")
        else:
            lines.append(f"\n共提取 {extracted} 个文件到: {output_dir}")
        return "\n".join(lines)

    def lsb_encode(self, image_path: str, secret_text: str, output_path: str = "") -> str:
        """LSB 隐写写入 — 将文本隐藏到图片最低有效位"""
        try:
            from PIL import Image
        except ImportError:
            return "需要安装 Pillow: pip install Pillow"
        img = Image.open(image_path)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        pixels = list(img.getdata())
        # 文本转二进制 + 终止符
        binary = ''.join(format(ord(c), '08b') for c in secret_text) + '00000000'
        if len(binary) > len(pixels) * 3:
            return f"图片容量不足: 需要 {len(binary)} 位，可用 {len(pixels) * 3} 位"
        new_pixels = []
        bit_idx = 0
        for r, g, b in pixels:
            if bit_idx < len(binary):
                r = (r & 0xFE) | int(binary[bit_idx]); bit_idx += 1
            if bit_idx < len(binary):
                g = (g & 0xFE) | int(binary[bit_idx]); bit_idx += 1
            if bit_idx < len(binary):
                b = (b & 0xFE) | int(binary[bit_idx]); bit_idx += 1
            new_pixels.append((r, g, b))
        img_out = Image.new('RGB', img.size)
        img_out.putdata(new_pixels)
        if not output_path:
            base, ext = os.path.splitext(image_path)
            output_path = f"{base}_stego.png"
        img_out.save(output_path, 'PNG')
        return f"=== LSB 隐写写入 ===\n  原图: {image_path}\n  写入: {len(secret_text)} 字符\n  输出: {output_path}\n  使用 lsb_extract_advanced 可提取"

    def file_carve(self, filepath: str, output_dir: str = "") -> str:
        """基于 magic bytes 的智能文件切割"""
        data = read_file_bytes(filepath)
        if not data:
            return "无法读取文件"
        if not output_dir:
            output_dir = os.path.splitext(filepath)[0] + "_carved"
        os.makedirs(output_dir, exist_ok=True)
        # 在文件中搜索所有 magic bytes
        found = []
        for magic, desc in sorted(MAGIC_SIGNATURES.items(), key=lambda x: -len(x[0])):
            offset = 0
            while True:
                idx = data.find(magic, offset)
                if idx == -1:
                    break
                found.append((idx, magic, desc))
                offset = idx + len(magic)
        found.sort(key=lambda x: x[0])
        lines = ["=== 文件切割 ===", f"文件大小: {len(data)} bytes", f"发现 {len(found)} 个签名", ""]
        carved = 0
        for i, (offset, magic, desc) in enumerate(found):
            # 确定切割范围: 从当前签名到下一个签名（或文件末尾）
            end = found[i + 1][0] if i + 1 < len(found) else len(data)
            chunk = data[offset:end]
            if len(chunk) < 16:
                continue
            ext_map = {'PNG': '.png', 'JPEG': '.jpg', 'GIF': '.gif', 'ZIP': '.zip',
                      'PDF': '.pdf', 'RAR': '.rar', 'ELF': '.elf', 'PE/EXE': '.exe',
                      'GZIP': '.gz', '7-Zip': '.7z', 'SQLite': '.db'}
            file_ext = '.bin'
            for key, ext in ext_map.items():
                if key in desc.upper():
                    file_ext = ext
                    break
            out_file = os.path.join(output_dir, f"carved_{carved:03d}_0x{offset:08X}{file_ext}")
            with open(out_file, 'wb') as f:
                f.write(chunk)
            lines.append(f"  [+] 0x{offset:08X}: {desc} ({len(chunk)} bytes) -> {os.path.basename(out_file)}")
            carved += 1
        if carved == 0:
            lines.append("  [-] 未发现可切割的文件")
        else:
            lines.append(f"\n共切割 {carved} 个文件到: {output_dir}")
        return "\n".join(lines)

    # ========== 隐写术高级功能 ==========

    def steghide_extract(self, filepath: str, password: str = "") -> str:
        """使用 steghide 提取隐藏数据，支持密码爆破

        Args:
            filepath: 目标文件路径
            password: 密码字符串；若为空则先尝试空密码再尝试内置字典；
                      若为已存在文件路径则读取为字典逐行尝试
        """
        import shutil
        import subprocess

        lines = [f"=== {t('for.steghide_extract')} ==="]

        # 检查 steghide 是否可用
        if not shutil.which("steghide"):
            lines.append(f"[!] {t('for.steghide_not_installed')}")
            lines.append("  -> Windows: 从 http://steghide.sourceforge.net/ 下载安装")
            lines.append("  -> Linux:   sudo apt install steghide")
            lines.append("  -> macOS:   brew install steghide")
            return "\n".join(lines)

        if not os.path.isfile(filepath):
            return f"[!] {t('for.file_not_found')}: {filepath}"

        def _try_steghide(pw: str) -> tuple[bool, str]:
            """尝试用指定密码调用 steghide，返回 (是否成功, 输出内容)"""
            try:
                result = subprocess.run(
                    ["steghide", "extract", "-sf", filepath, "-p", pw, "-f"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    return True, result.stdout
                return False, result.stderr
            except subprocess.TimeoutExpired:
                return False, "timeout"
            except Exception as e:
                return False, str(e)

        # 构建密码列表
        passwords_to_try: list[str] = []

        if password == "":
            # 空密码先试一次
            passwords_to_try.append("")
        elif os.path.isfile(password):
            # password 参数是字典文件
            lines.append(f"[*] {t('for.steghide_dict_file')}: {password}")
            try:
                with open(password, 'r', encoding='utf-8', errors='ignore') as f:
                    passwords_to_try = [line.strip() for line in f if line.strip()]
            except Exception as e:
                lines.append(f"[!] {t('for.steghide_dict_read_error')}: {e}")
                return "\n".join(lines)
        else:
            # 直接使用给定密码
            ok, output = _try_steghide(password)
            if ok:
                lines.append(f"[+] {t('for.steghide_success')}: password={password!r}")
                lines.append(output)
            else:
                lines.append(f"[-] {t('for.steghide_fail')}: password={password!r}")
                lines.append(f"    {output}")
            return "\n".join(lines)

        # 如果空密码列表后追加内置常见密码
        if not passwords_to_try or passwords_to_try == [""]:
            builtin_passwords = [
                "", "password", "123456", "12345678", "admin", "flag", "ctf",
                "secret", "hidden", "stego", "steghide", "pass", "passwd",
                "1234", "123", "root", "test", "guest", "hello", "love",
                "qwerty", "abc123", "letmein", "welcome", "monkey", "master",
                "dragon", "login", "princess", "football", "shadow", "sunshine",
                "trustno1", "iloveyou", "batman", "access", "superman", "michael",
                "ninja", "mustang", "password1", "123456789", "1234567", "12345",
                "111111", "1234567890", "000000", "qwerty123", "1q2w3e4r",
                "654321", "555555", "lovely", "7777777", "888888", "123123",
                "password123", "p@ssw0rd", "admin123", "root123", "toor",
                "changeme", "default", "hack", "hacker", "security", "secure",
                "server", "computer", "internet", "network", "system",
                "flag{", "CTF", "ctf2024", "ctf2025", "ctf2026", "P@ssw0rd",
                "key", "encrypt", "decrypt", "stegano", "forensics",
                "challenge", "capture", "theflag", "s3cr3t", "h1dd3n",
                "passw0rd", "p@ss", "qwer1234", "asdf1234", "zxcv1234",
                "abc", "aaa", "god", "sex", "money", "power", "magic",
                "1", "a", "x", "0", "info", "data", "file", "image",
                "picture", "photo", "text", "message", "msg", "hide",
                "open", "unlock", "extract", "reveal",
            ]
            passwords_to_try = builtin_passwords

        lines.append(f"[*] {t('for.steghide_bruteforce')}: {len(passwords_to_try)} {t('for.steghide_passwords')}")

        for i, pw in enumerate(passwords_to_try):
            ok, output = _try_steghide(pw)
            if ok:
                lines.append(f"[+] {t('for.steghide_success')}: password={pw!r}")
                lines.append(output)
                return "\n".join(lines)
            # 进度提示
            if (i + 1) % 20 == 0:
                lines.append(f"  ... {t('for.steghide_tried')} {i + 1}/{len(passwords_to_try)}")

        lines.append(f"[-] {t('for.steghide_all_fail')}")
        lines.append(f"  -> {t('for.steghide_try_custom_dict')}")
        return "\n".join(lines)

    def zsteg_scan(self, filepath: str) -> str:
        """纯 Python 实现 zsteg 式 LSB/MSB 自动扫描（PNG/BMP）

        自动遍历位平面、通道、扫描顺序、LSB/MSB 组合，
        检查提取数据中是否包含可读文本或已知文件魔数。
        """
        try:
            from PIL import Image
        except ImportError:
            return (
                f"[!] {t('for.pillow_not_installed')}\n"
                "  -> pip install Pillow"
            )

        if not os.path.isfile(filepath):
            return f"[!] {t('for.file_not_found')}: {filepath}"

        lines = [f"=== {t('for.zsteg_scan')} ==="]
        lines.append(f"{t('for.file')}: {os.path.basename(filepath)}")

        try:
            img = Image.open(filepath)
        except Exception as e:
            lines.append(f"[!] {t('for.zsteg_open_error')}: {e}")
            return "\n".join(lines)

        width, height = img.size
        lines.append(f"{t('for.zsteg_size')}: {width}x{height}, {t('for.zsteg_mode')}: {img.mode}")

        # 确定可用通道
        mode = img.mode
        if mode == "RGBA":
            channel_names = ["R", "G", "B", "A"]
        elif mode == "RGB":
            channel_names = ["R", "G", "B"]
        elif mode == "L":
            channel_names = ["L"]
        elif mode == "P":
            img = img.convert("RGBA")
            channel_names = ["R", "G", "B", "A"]
        else:
            img = img.convert("RGB")
            channel_names = ["R", "G", "B"]

        pixels = list(img.getdata())
        found_results = []

        # 通道组合定义
        single_channels = list(range(len(channel_names)))
        multi_channels = []
        if len(channel_names) >= 3:
            multi_channels.append(("RGB", [0, 1, 2]))
            multi_channels.append(("BGR", [2, 1, 0]))

        def _extract_bits(channel_indices: list[int], bit: int, msb: bool,
                          col_first: bool) -> bytes:
            """从指定通道/位平面提取数据，返回前256字节"""
            bits_collected = []
            max_bits = 256 * 8

            if col_first:
                order = [(x, y) for x in range(width) for y in range(height)]
            else:
                order = [(x, y) for y in range(height) for x in range(width)]

            for x, y in order:
                if len(bits_collected) >= max_bits:
                    break
                idx = y * width + x
                if idx >= len(pixels):
                    break
                pixel = pixels[idx]
                if isinstance(pixel, int):
                    pixel = (pixel,)
                for ch in channel_indices:
                    if ch >= len(pixel):
                        continue
                    val = pixel[ch]
                    if msb:
                        b = (val >> (7 - bit)) & 1
                    else:
                        b = (val >> bit) & 1
                    bits_collected.append(b)
                    if len(bits_collected) >= max_bits:
                        break

            # 转字节
            result = bytearray()
            for i in range(0, len(bits_collected) - 7, 8):
                byte_val = 0
                for j in range(8):
                    byte_val = (byte_val << 1) | bits_collected[i + j]
                result.append(byte_val)
            return bytes(result)

        def _check_data(data: bytes) -> tuple[bool, str]:
            """检查提取的数据是否有意义"""
            if not data:
                return False, ""
            # 检查文件魔数
            file_type = identify_file_type(data)
            if file_type:
                return True, f"[FILE] {file_type}"
            # 检查可打印字符比例
            printable = sum(1 for b in data[:128] if 32 <= b < 127 or b in (9, 10, 13))
            total = min(len(data), 128)
            if total > 0 and printable / total > 0.7:
                text = data[:128].decode('ascii', errors='replace')
                text = ''.join(c if 32 <= ord(c) < 127 else '.' for c in text)
                return True, f"[TEXT] {text}"
            return False, ""

        # 遍历所有组合
        for bit in range(8):
            for msb in [False, True]:
                for col_first in [False, True]:
                    # 单通道
                    for ch_idx in single_channels:
                        data = _extract_bits([ch_idx], bit, msb, col_first)
                        found, desc = _check_data(data)
                        if found:
                            order_str = "col" if col_first else "row"
                            bit_str = "MSB" if msb else "LSB"
                            ch_name = channel_names[ch_idx]
                            label = f"b{bit},{ch_name},{order_str},{bit_str}"
                            found_results.append((label, desc))
                    # 多通道组合
                    for ch_label, ch_indices in multi_channels:
                        data = _extract_bits(ch_indices, bit, msb, col_first)
                        found, desc = _check_data(data)
                        if found:
                            order_str = "col" if col_first else "row"
                            bit_str = "MSB" if msb else "LSB"
                            label = f"b{bit},{ch_label},{order_str},{bit_str}"
                            found_results.append((label, desc))

        if found_results:
            lines.append(f"\n[+] {t('for.zsteg_found')}: {len(found_results)} {t('for.zsteg_results')}")
            seen = set()
            for label, desc in found_results:
                key = (label, desc)
                if key not in seen:
                    seen.add(key)
                    lines.append(f"  [{label}] {desc}")
        else:
            lines.append(f"\n[-] {t('for.zsteg_nothing_found')}")
            lines.append(f"  -> {t('for.zsteg_try_other_tools')}")

        return "\n".join(lines)

    def blind_watermark_extract(self, filepath: str) -> str:
        """频域盲水印提取：FFT 变换后保存幅值谱图片

        水印通常在频域中可见。输出幅值谱图片到同目录。
        """
        try:
            import numpy as np
        except ImportError:
            return (
                f"[!] {t('for.numpy_not_installed')}\n"
                "  -> pip install numpy"
            )
        try:
            from PIL import Image
        except ImportError:
            return (
                f"[!] {t('for.pillow_not_installed')}\n"
                "  -> pip install Pillow"
            )

        if not os.path.isfile(filepath):
            return f"[!] {t('for.file_not_found')}: {filepath}"

        lines = [f"=== {t('for.blind_watermark')} ==="]

        try:
            img = Image.open(filepath).convert("L")
        except Exception as e:
            lines.append(f"[!] {t('for.blind_wm_open_error')}: {e}")
            return "\n".join(lines)

        width, height = img.size
        lines.append(f"{t('for.file')}: {os.path.basename(filepath)}")
        lines.append(f"{t('for.zsteg_size')}: {width}x{height}")

        try:
            img_array = np.array(img, dtype=np.float64)

            # FFT
            f_transform = np.fft.fft2(img_array)
            f_shift = np.fft.fftshift(f_transform)

            # 幅值谱，取 log 增强对比度
            magnitude = np.abs(f_shift)
            magnitude = np.log1p(magnitude)

            # 归一化到 0-255
            mag_min = magnitude.min()
            mag_max = magnitude.max()
            if mag_max > mag_min:
                magnitude = (magnitude - mag_min) / (mag_max - mag_min) * 255
            else:
                magnitude = np.zeros_like(magnitude)

            magnitude = magnitude.astype(np.uint8)

            # 保存
            base, ext = os.path.splitext(filepath)
            output_path = f"{base}_fft_spectrum.png"
            result_img = Image.fromarray(magnitude, mode="L")
            result_img.save(output_path)

            lines.append(f"[+] {t('for.blind_wm_saved')}: {output_path}")
            lines.append(f"  -> {t('for.blind_wm_hint')}")

        except Exception as e:
            lines.append(f"[!] {t('for.blind_wm_error')}: {e}")

        return "\n".join(lines)

    def apng_extract(self, filepath: str) -> str:
        """提取 APNG 动图的每一帧为独立 PNG 文件

        纯 Python 解析 PNG 块结构（acTL/fcTL/fdAT），
        将每帧数据重建为标准 PNG 并保存。
        """
        if not os.path.isfile(filepath):
            return f"[!] {t('for.file_not_found')}: {filepath}"

        lines = [f"=== {t('for.apng_extract')} ==="]
        lines.append(f"{t('for.file')}: {os.path.basename(filepath)}")

        try:
            data = read_file_bytes(filepath)
        except Exception as e:
            lines.append(f"[!] {t('for.apng_read_error')}: {e}")
            return "\n".join(lines)

        # 校验 PNG 签名
        png_sig = b'\x89PNG\r\n\x1a\n'
        if data[:8] != png_sig:
            lines.append(f"[!] {t('for.apng_not_png')}")
            return "\n".join(lines)

        # 解析所有 PNG 块
        chunks = []
        pos = 8
        while pos < len(data):
            if pos + 8 > len(data):
                break
            length = struct.unpack(">I", data[pos:pos+4])[0]
            chunk_type = data[pos+4:pos+8]
            if pos + 12 + length > len(data):
                break
            chunk_data = data[pos+8:pos+8+length]
            crc = data[pos+8+length:pos+12+length]
            chunks.append((chunk_type, chunk_data, crc))
            pos += 12 + length

        # 查找 acTL（动画控制块）
        actl_found = False
        num_frames = 0
        for ctype, cdata, _ in chunks:
            if ctype == b'acTL':
                actl_found = True
                num_frames = struct.unpack(">I", cdata[:4])[0]
                break

        if not actl_found:
            lines.append(f"[-] {t('for.apng_no_actl')}")
            lines.append(f"  -> {t('for.apng_not_animated')}")
            return "\n".join(lines)

        lines.append(f"[+] {t('for.apng_frames')}: {num_frames}")

        # 收集 IHDR, PLTE, tRNS 等需要复制到每帧的块
        ihdr_chunk = None
        palette_chunks = []
        for ctype, cdata, ccrc in chunks:
            if ctype == b'IHDR':
                ihdr_chunk = (ctype, cdata, ccrc)
            elif ctype in (b'PLTE', b'tRNS', b'cHRM', b'gAMA', b'iCCP',
                           b'sBIT', b'sRGB'):
                palette_chunks.append((ctype, cdata, ccrc))

        if ihdr_chunk is None:
            lines.append(f"[!] {t('for.apng_no_ihdr')}")
            return "\n".join(lines)

        ihdr_data = ihdr_chunk[1]
        default_width = struct.unpack(">I", ihdr_data[:4])[0]
        default_height = struct.unpack(">I", ihdr_data[4:8])[0]

        # 输出目录
        base = os.path.splitext(filepath)[0]
        output_dir = f"{base}_apng_frames"
        os.makedirs(output_dir, exist_ok=True)

        def _make_chunk(ctype: bytes, cdata: bytes) -> bytes:
            """构建一个 PNG 块（含长度和 CRC）"""
            raw = ctype + cdata
            c = zlib.crc32(raw) & 0xFFFFFFFF
            return struct.pack(">I", len(cdata)) + raw + struct.pack(">I", c)

        def _build_png(frame_width: int, frame_height: int, idat_data: bytes) -> bytes:
            """用给定 IDAT 数据构建完整 PNG"""
            # 可能需要调整 IHDR 的宽高
            new_ihdr = struct.pack(">II", frame_width, frame_height) + ihdr_data[8:]
            parts = [png_sig]
            parts.append(_make_chunk(b'IHDR', new_ihdr))
            for pctype, pcdata, _ in palette_chunks:
                parts.append(_make_chunk(pctype, pcdata))
            parts.append(_make_chunk(b'IDAT', idat_data))
            parts.append(_make_chunk(b'IEND', b''))
            return b''.join(parts)

        # 提取帧
        saved_count = 0
        # 第一帧可能用默认 IDAT
        default_idat_parts = []
        fcTL_seen = False

        frame_configs = []  # (width, height, [idat_data_parts])
        current_fctl = None

        for ctype, cdata, ccrc in chunks:
            if ctype == b'fcTL':
                # 如果之前有默认 IDAT 数据且还没遇到 fcTL，先存为帧0
                if not fcTL_seen and default_idat_parts:
                    frame_configs.append((default_width, default_height,
                                         b''.join(default_idat_parts)))
                elif current_fctl is not None:
                    pass  # fdAT 帧已在 fdAT 中处理

                fcTL_seen = True
                # 解析 fcTL
                fw = struct.unpack(">I", cdata[4:8])[0]
                fh = struct.unpack(">I", cdata[8:12])[0]
                current_fctl = (fw, fh)
                # 准备收集 fdAT

            elif ctype == b'IDAT':
                if not fcTL_seen:
                    default_idat_parts.append(cdata)
                else:
                    # 第一帧如果在 fcTL 后用 IDAT
                    if current_fctl is not None:
                        frame_configs.append((current_fctl[0], current_fctl[1], cdata))
                        current_fctl = None

            elif ctype == b'fdAT':
                if current_fctl is not None:
                    # fdAT 前4字节是序列号，后面才是压缩数据
                    frame_data = cdata[4:]
                    if not hasattr(self, '_apng_fdat_buf'):
                        self._apng_fdat_buf = []
                    self._apng_fdat_buf.append(frame_data)

        # 处理剩余的 fdAT 缓冲——需要重新扫描以正确分组
        # 重新用更稳定的方法：按 fcTL 分组
        frame_configs = []
        current_frame_data = []
        current_fctl = None

        for ctype, cdata, ccrc in chunks:
            if ctype == b'fcTL':
                # 保存前一帧
                if current_fctl is not None and current_frame_data:
                    frame_configs.append((current_fctl[0], current_fctl[1],
                                         b''.join(current_frame_data)))
                elif current_fctl is None and current_frame_data:
                    # 默认 IDAT（无 fcTL 在前）
                    pass

                fw = struct.unpack(">I", cdata[4:8])[0]
                fh = struct.unpack(">I", cdata[8:12])[0]
                current_fctl = type('FCTLInfo', (), {'w': fw, 'h': fh})()
                current_frame_data = []

            elif ctype == b'IDAT':
                if current_fctl is not None and not current_frame_data:
                    # 第一帧用 IDAT
                    current_frame_data.append(cdata)
                elif current_fctl is None:
                    # 没有 fcTL 的默认帧
                    current_frame_data.append(cdata)

            elif ctype == b'fdAT':
                # fdAT: 前4字节为序列号
                current_frame_data.append(cdata[4:])

        # 保存最后一帧
        if current_fctl is not None and current_frame_data:
            frame_configs.append((current_fctl.w, current_fctl.h,
                                  b''.join(current_frame_data)))

        # 如果没找到任何帧但有默认 IDAT
        if not frame_configs and default_idat_parts:
            frame_configs.append((default_width, default_height,
                                  b''.join(default_idat_parts)))

        for i, (fw, fh, idat_data) in enumerate(frame_configs):
            try:
                png_bytes = _build_png(fw, fh, idat_data)
                out_path = os.path.join(output_dir, f"frame_{i:04d}.png")
                with open(out_path, 'wb') as f:
                    f.write(png_bytes)
                saved_count += 1
            except Exception as e:
                lines.append(f"  [!] {t('for.apng_frame_error')} {i}: {e}")

        lines.append(f"[+] {t('for.apng_saved')}: {saved_count} {t('for.apng_frames_to')} {output_dir}")
        return "\n".join(lines)

    def sstv_decode_helper(self, filepath: str) -> str:
        """SSTV 解码辅助：检测音频中是否包含 SSTV 校准头并给出工具建议

        检测 1900Hz 校准音（约 300ms），若检测到则提供解码工具使用说明。
        """
        if not os.path.isfile(filepath):
            return f"[!] {t('for.file_not_found')}: {filepath}"

        lines = [f"=== {t('for.sstv_helper')} ==="]
        lines.append(f"{t('for.file')}: {os.path.basename(filepath)}")

        # 尝试读取音频
        try:
            import wave
            has_wave = True
        except ImportError:
            has_wave = False

        raw_samples = None
        sample_rate = None

        if has_wave:
            try:
                with wave.open(filepath, 'rb') as wf:
                    sample_rate = wf.getframerate()
                    n_channels = wf.getnchannels()
                    sampwidth = wf.getsampwidth()
                    n_frames = wf.getnframes()
                    raw = wf.readframes(n_frames)

                    lines.append(f"  {t('for.sstv_sample_rate')}: {sample_rate} Hz")
                    lines.append(f"  {t('for.sstv_channels')}: {n_channels}")
                    lines.append(f"  {t('for.sstv_duration')}: {n_frames / sample_rate:.2f}s")

                    # 转换为单通道样本列表
                    if sampwidth == 2:
                        import array
                        samples = array.array('h', raw)
                    elif sampwidth == 1:
                        samples = [b - 128 for b in raw]
                    else:
                        samples = None

                    if samples is not None and n_channels > 1:
                        # 取第一通道
                        samples = samples[::n_channels]
                    raw_samples = samples
            except Exception as e:
                lines.append(f"[*] {t('for.sstv_wave_error')}: {e}")

        # 简易频率检测：用过零率估算主频
        sstv_detected = False
        if raw_samples is not None and sample_rate is not None:
            try:
                # 滑动窗口检测 1900Hz（过零率法）
                # 1900Hz 对应每秒 3800 次过零
                # 300ms 窗口 = sample_rate * 0.3 个采样点
                window_size = int(sample_rate * 0.3)
                step = int(sample_rate * 0.05)  # 50ms 步进
                target_freq = 1900
                tolerance = 150  # Hz

                for start in range(0, len(raw_samples) - window_size, step):
                    window = raw_samples[start:start + window_size]
                    # 计算过零次数
                    zero_crossings = 0
                    for i in range(1, len(window)):
                        if (window[i] >= 0) != (window[i-1] >= 0):
                            zero_crossings += 1

                    # 过零率 -> 频率估算
                    duration = window_size / sample_rate
                    estimated_freq = zero_crossings / (2 * duration)

                    if abs(estimated_freq - target_freq) < tolerance:
                        sstv_detected = True
                        time_pos = start / sample_rate
                        lines.append(
                            f"\n[+] {t('for.sstv_detected')} @ {time_pos:.2f}s "
                            f"(~{estimated_freq:.0f} Hz)"
                        )
                        break
            except Exception as e:
                lines.append(f"[*] {t('for.sstv_detect_error')}: {e}")

        if sstv_detected:
            lines.append(f"\n[+] {t('for.sstv_likely')}")
        else:
            lines.append(f"\n[?] {t('for.sstv_uncertain')}")

        # 工具建议
        lines.append(f"\n=== {t('for.sstv_tools')} ===")
        lines.append("  1. RX-SSTV (Windows GUI):")
        lines.append("     https://www.qsl.net/on6mu/rxsstv.htm")
        lines.append("  2. QSSTV (Linux GUI):")
        lines.append("     sudo apt install qsstv")
        lines.append("  3. Python sstv 库:")
        lines.append("     pip install sstv")
        lines.append(f"     sstv -d {os.path.basename(filepath)} -o output.png")
        lines.append("  4. 命令行工具:")
        lines.append(f"     python -m sstv -d {os.path.basename(filepath)} -o output.png")
        lines.append("")
        lines.append(f"  {t('for.sstv_manual_hint')}")

        return "\n".join(lines)

    # ========== 自动隐写全扫描 / 精确文件切割 / 内存取证增强 ==========

    def stego_full_scan(self, filepath: str) -> str:
        """一键运行所有隐写检测，汇总结果"""
        from ctftool.core.flag_finder import FlagFinder

        data = read_file_bytes(filepath)
        file_type = identify_file_type(data)
        ft_lower = (file_type or "").lower()
        is_image = any(k in ft_lower for k in ("png", "jpeg", "gif", "bmp", "tiff"))
        is_png = "png" in ft_lower
        is_jpeg = "jpeg" in ft_lower
        is_wav = "wav" in ft_lower or "riff" in ft_lower

        lines = [
            f"{'=' * 60}",
            f"  {t('for.sfs_title')}: {os.path.basename(filepath)}",
            f"  {t('for.type')}: {file_type or t('for.unknown')}",
            f"{'=' * 60}",
        ]

        all_results: dict[str, str] = {}

        # ---- 1. 基础隐写检测 ----
        try:
            result = self.detect_stego(filepath)
            all_results[t('for.sfs_detect_stego')] = result
            lines.append(f"\n{'─' * 40}")
            lines.append(f"[1/8] {t('for.sfs_detect_stego')}")
            lines.append(f"{'─' * 40}")
            lines.append(result)
        except Exception as e:
            lines.append(f"\n[1/8] {t('for.sfs_detect_stego')} - {t('for.sfs_failed')}: {e}")

        # ---- 2. LSB 高级提取（仅图片） ----
        if is_image:
            try:
                result = self.lsb_extract_advanced(filepath)
                all_results[t('for.sfs_lsb_extract')] = result
                lines.append(f"\n{'─' * 40}")
                lines.append(f"[2/8] {t('for.sfs_lsb_extract')}")
                lines.append(f"{'─' * 40}")
                lines.append(result)
            except Exception as e:
                lines.append(f"\n[2/8] {t('for.sfs_lsb_extract')} - {t('for.sfs_failed')}: {e}")
        else:
            lines.append(f"\n[2/8] {t('for.sfs_lsb_extract')} - {t('for.sfs_skipped_not_image')}")

        # ---- 3. zsteg 自动扫描（仅 PNG/BMP，不适用于 JPEG） ----
        if is_png or "bmp" in ft_lower:
            try:
                result = self.zsteg_scan(filepath)
                all_results[t('for.sfs_zsteg_scan')] = result
                lines.append(f"\n{'─' * 40}")
                lines.append(f"[3/8] {t('for.sfs_zsteg_scan')}")
                lines.append(f"{'─' * 40}")
                lines.append(result)
            except Exception as e:
                lines.append(f"\n[3/8] {t('for.sfs_zsteg_scan')} - {t('for.sfs_failed')}: {e}")
        else:
            lines.append(f"\n[3/8] {t('for.sfs_zsteg_scan')} - {t('for.sfs_skipped_not_png_bmp')}")

        # ---- 4. steghide 提取（仅 JPEG/WAV/BMP/AU） ----
        if is_jpeg or is_wav or "bmp" in ft_lower:
            try:
                result = self.steghide_extract(filepath)
                all_results[t('for.sfs_steghide')] = result
                lines.append(f"\n{'─' * 40}")
                lines.append(f"[4/8] {t('for.sfs_steghide')}")
                lines.append(f"{'─' * 40}")
                lines.append(result)
            except Exception as e:
                lines.append(f"\n[4/8] {t('for.sfs_steghide')} - {t('for.sfs_failed')}: {e}")
        else:
            lines.append(f"\n[4/8] {t('for.sfs_steghide')} - {t('for.sfs_skipped_unsupported')}")

        # ---- 5. 盲水印提取（仅图片） ----
        if is_image:
            try:
                result = self.blind_watermark_extract(filepath)
                all_results[t('for.sfs_blind_watermark')] = result
                lines.append(f"\n{'─' * 40}")
                lines.append(f"[5/8] {t('for.sfs_blind_watermark')}")
                lines.append(f"{'─' * 40}")
                lines.append(result)
            except Exception as e:
                lines.append(f"\n[5/8] {t('for.sfs_blind_watermark')} - {t('for.sfs_failed')}: {e}")
        else:
            lines.append(f"\n[5/8] {t('for.sfs_blind_watermark')} - {t('for.sfs_skipped_not_image')}")

        # ---- 6. 位平面分析（仅 PNG） ----
        if is_png:
            try:
                result = self.bit_plane_analysis(filepath)
                all_results[t('for.sfs_bit_plane')] = result
                lines.append(f"\n{'─' * 40}")
                lines.append(f"[6/8] {t('for.sfs_bit_plane')}")
                lines.append(f"{'─' * 40}")
                lines.append(result)
            except Exception as e:
                lines.append(f"\n[6/8] {t('for.sfs_bit_plane')} - {t('for.sfs_failed')}: {e}")
        else:
            lines.append(f"\n[6/8] {t('for.sfs_bit_plane')} - {t('for.sfs_skipped_not_png')}")

        # ---- 7. binwalk 扫描 ----
        try:
            result = self.binwalk_scan(filepath)
            all_results[t('for.sfs_binwalk')] = result
            lines.append(f"\n{'─' * 40}")
            lines.append(f"[7/8] {t('for.sfs_binwalk')}")
            lines.append(f"{'─' * 40}")
            lines.append(result)
        except Exception as e:
            lines.append(f"\n[7/8] {t('for.sfs_binwalk')} - {t('for.sfs_failed')}: {e}")

        # ---- 8. 文件类型识别 ----
        try:
            result = self.identify_file(filepath)
            all_results[t('for.sfs_identify')] = result
            lines.append(f"\n{'─' * 40}")
            lines.append(f"[8/8] {t('for.sfs_identify')}")
            lines.append(f"{'─' * 40}")
            lines.append(result)
        except Exception as e:
            lines.append(f"\n[8/8] {t('for.sfs_identify')} - {t('for.sfs_failed')}: {e}")

        # ---- 汇总可疑内容 ----
        lines.append(f"\n{'=' * 60}")
        lines.append(f"  {t('for.sfs_summary')}")
        lines.append(f"{'=' * 60}")

        suspicious: list[str] = []
        for source, text in all_results.items():
            for marker in ("[!]", "[+]", "flag", "FLAG", "ctf", "CTF", "hidden", "secret"):
                for line in text.splitlines():
                    if marker.lower() in line.lower() and line.strip() not in suspicious:
                        suspicious.append(f"  [{source}] {line.strip()}")

        if suspicious:
            lines.append(f"\n{t('for.sfs_suspicious_found')} ({len(suspicious)}):")
            lines.extend(suspicious[:50])
        else:
            lines.append(f"\n{t('for.sfs_no_suspicious')}")

        # ---- 自动搜索 flag ----
        lines.append(f"\n{'─' * 40}")
        lines.append(f"  {t('for.sfs_flag_search')}")
        lines.append(f"{'─' * 40}")

        flag_finder = FlagFinder()
        combined_text = "\n".join(all_results.values())
        flags = flag_finder.search(combined_text)
        if flags:
            lines.append(f"\n[!!!] {t('for.sfs_flags_found')}:")
            for f in flags:
                lines.append(f"  >>> {f}")
        else:
            lines.append(f"\n{t('for.sfs_no_flags')}")

        return "\n".join(lines)

    def file_carve_precise(self, filepath: str) -> str:
        """基于文件头部和尾部标记的精确切割"""
        data = read_file_bytes(filepath)
        basename = os.path.splitext(os.path.basename(filepath))[0]
        out_dir = os.path.join(os.path.dirname(filepath), f"{basename}_carved")

        # 定义支持的格式：(名称, 头部字节, 尾部字节, 尾部额外长度)
        # 尾部额外长度表示在匹配到尾部标记后还需要再包含多少字节
        FILE_SIGNATURES: list[tuple[str, bytes, bytes | None, int]] = [
            ("PNG",  b'\x89PNG\r\n\x1a\n', b'\x00\x00\x00\x00IEND\xaeB`\x82', 0),
            ("JPEG", b'\xff\xd8\xff',       b'\xff\xd9',                        0),
            ("GIF",  b'GIF',                b'\x00;',                           0),
            ("PDF",  b'%PDF-',              b'%%EOF',                           0),
            ("ZIP",  b'PK\x03\x04',         b'PK\x05\x06',                     18),
            ("RAR",  b'Rar!\x1a\x07',       None,                              0),
        ]

        # 收集所有已知文件头的位置（用于 RAR 的尾部推断）
        all_known_headers: list[bytes] = [sig[1] for sig in FILE_SIGNATURES]

        carved_files: list[dict] = []
        lines = [
            f"{t('for.fcp_title')}: {os.path.basename(filepath)}",
            f"{t('for.size')}: {len(data)} bytes",
            "",
        ]

        for sig_name, header, footer, extra_after_footer in FILE_SIGNATURES:
            offset = 0
            while offset < len(data):
                pos = data.find(header, offset)
                if pos < 0:
                    break

                end_pos = -1
                if footer is not None:
                    # 从文件头之后搜索尾部标记
                    tail_search_start = pos + len(header)
                    tail_pos = data.find(footer, tail_search_start)
                    if tail_pos >= 0:
                        end_pos = tail_pos + len(footer) + extra_after_footer
                    else:
                        # 没有找到尾部，跳过这个头
                        offset = pos + 1
                        continue
                else:
                    # RAR：没有明确尾部标记，扫描到下一个已知文件头或文件末尾
                    search_start = pos + len(header)
                    next_header_pos = len(data)  # 默认到文件末尾
                    for known_header in all_known_headers:
                        np = data.find(known_header, search_start)
                        if 0 < np < next_header_pos:
                            next_header_pos = np
                    end_pos = next_header_pos

                # 确保不越界
                end_pos = min(end_pos, len(data))
                carved_data = data[pos:end_pos]

                if len(carved_data) < len(header) + 1:
                    offset = pos + 1
                    continue

                carved_files.append({
                    "type": sig_name,
                    "offset": pos,
                    "size": len(carved_data),
                    "data": carved_data,
                })
                offset = pos + 1

        # 保存切割结果
        if carved_files:
            os.makedirs(out_dir, exist_ok=True)
            lines.append(f"{t('for.fcp_found')} {len(carved_files)} {t('for.fcp_files')}:")
            lines.append(f"{t('for.fcp_output_dir')}: {out_dir}")
            lines.append("")
            lines.append(f"  {'#':<4s} {t('for.type'):<8s} {t('for.fcp_offset'):<14s} {t('for.size'):<14s} {t('for.file')}")
            lines.append(f"  {'─' * 60}")

            type_count: dict[str, int] = {}
            for i, cf in enumerate(carved_files):
                ext = cf["type"].lower()
                type_count[ext] = type_count.get(ext, 0) + 1
                out_name = f"{i:03d}_{cf['type'].lower()}_{cf['offset']:08X}.{ext}"
                out_path = os.path.join(out_dir, out_name)
                with open(out_path, 'wb') as f:
                    f.write(cf["data"])
                lines.append(
                    f"  {i:<4d} {cf['type']:<8s} 0x{cf['offset']:08X}    "
                    f"{cf['size']:<14d} {out_name}"
                )

            lines.append("")
            lines.append(f"{t('for.fcp_type_summary')}:")
            for ftype, count in sorted(type_count.items()):
                lines.append(f"  {ftype.upper()}: {count}")
        else:
            lines.append(f"{t('for.fcp_no_files')}")

        return "\n".join(lines)

    def memory_forensics_enhanced(self, filepath: str) -> str:
        """纯 Python 内存取证增强 -- 从内存转储中提取关键信息"""
        file_size = os.path.getsize(filepath)
        CHUNK_SIZE = 4 * 1024 * 1024  # 4MB 分块
        OVERLAP = 4096  # 块间重叠，避免跨块遗漏

        # 结果容器（使用 set 去重）
        processes: set[str] = set()
        network_conns: set[str] = set()
        cmd_history: set[str] = set()
        env_vars: set[str] = set()
        urls: set[str] = set()
        domains: set[str] = set()
        reg_keys: set[str] = set()
        file_paths: set[str] = set()
        emails: set[str] = set()
        secrets: set[str] = set()

        # 正则表达式预编译
        re_process = re.compile(
            rb'[\x20-\x7e]{1,64}\.exe', re.IGNORECASE
        )
        re_ip_port = re.compile(
            rb'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:\s](\d{1,5})'
        )
        re_cmd = re.compile(
            rb'(?:cmd\.exe|powershell|bash|sh|zsh|fish)[\x00-\x20]+(.{4,200})',
            re.IGNORECASE
        )
        re_cmd_strings = re.compile(
            rb'(?:C:\\Windows\\System32\\cmd\.exe|'
            rb'PS [A-Z]:\\[^\x00]{2,120}> .{2,200}|'
            rb'\$ [a-z][\x20-\x7e]{2,200})',
            re.IGNORECASE
        )
        re_env = re.compile(
            rb'(?:PATH|HOME|USERNAME|USER|COMPUTERNAME|HOSTNAME|'
            rb'USERPROFILE|APPDATA|TEMP|TMP|LANG|SHELL|LOGNAME|'
            rb'HOMEDRIVE|HOMEPATH|SYSTEMROOT|WINDIR|PROGRAMFILES)='
            rb'[\x20-\x7e]{1,500}',
            re.IGNORECASE
        )
        re_url = re.compile(
            rb'https?://[\x21-\x7e]{4,500}', re.IGNORECASE
        )
        re_domain = re.compile(
            rb'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
            rb'{1,5}(?:com|net|org|edu|gov|mil|io|cn|ru|uk|de|fr|jp|kr|'
            rb'info|biz|xyz|top|cc|me|tv)\b'
        )
        re_reg_key = re.compile(
            rb'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|'
            rb'HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU)'
            rb'[\\/][\x20-\x7e]{2,300}',
            re.IGNORECASE
        )
        re_win_path = re.compile(
            rb'[A-Z]:\\(?:[\x20-\x7e]{1,60}\\){1,15}[\x20-\x7e]{1,60}',
        )
        re_unix_path = re.compile(
            rb'(?:/home/|/etc/|/usr/|/var/|/tmp/|/opt/|/root/|/bin/|/sbin/)'
            rb'[\x21-\x7e]{1,300}'
        )
        re_email = re.compile(
            rb'[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,255}\.'
            rb'[a-zA-Z]{2,10}'
        )
        re_secret = re.compile(
            rb'(?:password|passwd|pwd|key|secret|token|api_key|apikey|'
            rb'access_token|auth_token|private_key)[\s=:]+[\x21-\x7e]{1,200}',
            re.IGNORECASE
        )

        lines = [
            f"{'=' * 60}",
            f"  {t('for.mfe_title')}: {os.path.basename(filepath)}",
            f"  {t('for.size')}: {file_size} bytes ({file_size / (1024*1024):.1f} MB)",
            f"  {t('for.mfe_chunk_size')}: {CHUNK_SIZE // (1024*1024)} MB",
            f"{'=' * 60}",
            "",
        ]

        with open(filepath, 'rb') as f:
            offset = 0
            chunk_num = 0
            while offset < file_size:
                read_size = min(CHUNK_SIZE + OVERLAP, file_size - offset)
                chunk = f.read(read_size)
                if not chunk:
                    break

                # 1. 进程名
                for m in re_process.finditer(chunk):
                    proc = m.group(0).decode('ascii', errors='ignore').strip()
                    if len(proc) > 4 and not proc.startswith('.'):
                        processes.add(proc)

                # 2. 网络连接 (IP:PORT)
                for m in re_ip_port.finditer(chunk):
                    ip_raw = m.group(1).decode('ascii', errors='ignore')
                    port_raw = m.group(2).decode('ascii', errors='ignore')
                    try:
                        parts = ip_raw.split('.')
                        if all(0 <= int(p) <= 255 for p in parts):
                            port = int(port_raw)
                            if 0 < port <= 65535:
                                network_conns.add(f"{ip_raw}:{port_raw}")
                    except (ValueError, IndexError):
                        pass

                # 3. 命令行历史
                for m in re_cmd.finditer(chunk):
                    cmd_str = m.group(0).decode('ascii', errors='ignore').strip()
                    if len(cmd_str) > 5:
                        cmd_history.add(cmd_str[:200])
                for m in re_cmd_strings.finditer(chunk):
                    cmd_str = m.group(0).decode('ascii', errors='ignore').strip()
                    if len(cmd_str) > 5:
                        cmd_history.add(cmd_str[:200])

                # 4. 环境变量
                for m in re_env.finditer(chunk):
                    env_str = m.group(0).decode('ascii', errors='ignore').strip()
                    env_vars.add(env_str[:300])

                # 5. URL
                for m in re_url.finditer(chunk):
                    url_str = m.group(0).decode('ascii', errors='ignore').strip()
                    url_str = re.split(r'[\s<>"\'\\]', url_str)[0]
                    if len(url_str) > 10:
                        urls.add(url_str[:300])

                # 6. 域名
                for m in re_domain.finditer(chunk):
                    domain_str = m.group(0).decode('ascii', errors='ignore').strip()
                    if len(domain_str) > 4:
                        domains.add(domain_str)

                # 7. 注册表键
                for m in re_reg_key.finditer(chunk):
                    reg_str = m.group(0).decode('ascii', errors='ignore').strip()
                    reg_keys.add(reg_str[:200])

                # 8. 文件路径
                for m in re_win_path.finditer(chunk):
                    p = m.group(0).decode('ascii', errors='ignore').strip()
                    if len(p) > 5:
                        file_paths.add(p[:200])
                for m in re_unix_path.finditer(chunk):
                    p = m.group(0).decode('ascii', errors='ignore').strip()
                    if len(p) > 5:
                        file_paths.add(p[:200])

                # 9. Email
                for m in re_email.finditer(chunk):
                    email_str = m.group(0).decode('ascii', errors='ignore').strip()
                    if len(email_str) > 5:
                        emails.add(email_str)

                # 10. 密码/密钥
                for m in re_secret.finditer(chunk):
                    secret_str = m.group(0).decode('ascii', errors='ignore').strip()
                    secrets.add(secret_str[:200])

                chunk_num += 1
                # 回退 OVERLAP 字节以覆盖跨块边界
                offset += CHUNK_SIZE
                f.seek(offset)

        # ---- 输出汇总 ----
        def _format_section(title: str, items: set[str], limit: int = 50) -> list[str]:
            section = [f"\n{'─' * 40}", f"  {title} ({len(items)})", f"{'─' * 40}"]
            sorted_items = sorted(items)
            for item in sorted_items[:limit]:
                section.append(f"    {item}")
            if len(sorted_items) > limit:
                section.append(f"    ... {t('for.mfe_and_more')} {len(sorted_items) - limit}")
            return section

        lines.append(f"{t('for.mfe_scan_complete')} ({chunk_num} {t('for.mfe_chunks_processed')})")

        lines.extend(_format_section(
            t('for.mfe_processes'), processes))
        lines.extend(_format_section(
            t('for.mfe_network'), network_conns))
        lines.extend(_format_section(
            t('for.mfe_cmd_history'), cmd_history, 30))
        lines.extend(_format_section(
            t('for.mfe_env_vars'), env_vars, 30))
        lines.extend(_format_section(
            t('for.mfe_urls'), urls, 30))
        lines.extend(_format_section(
            t('for.mfe_domains'), domains, 50))
        lines.extend(_format_section(
            t('for.mfe_reg_keys'), reg_keys, 30))
        lines.extend(_format_section(
            t('for.mfe_file_paths'), file_paths, 50))
        lines.extend(_format_section(
            t('for.mfe_emails'), emails, 30))
        lines.extend(_format_section(
            t('for.mfe_secrets'), secrets, 20))

        # ---- 统计总览 ----
        lines.append(f"\n{'=' * 60}")
        lines.append(f"  {t('for.mfe_overview')}")
        lines.append(f"{'=' * 60}")
        stats = [
            (t('for.mfe_processes'), len(processes)),
            (t('for.mfe_network'), len(network_conns)),
            (t('for.mfe_cmd_history'), len(cmd_history)),
            (t('for.mfe_env_vars'), len(env_vars)),
            (t('for.mfe_urls'), len(urls)),
            (t('for.mfe_domains'), len(domains)),
            (t('for.mfe_reg_keys'), len(reg_keys)),
            (t('for.mfe_file_paths'), len(file_paths)),
            (t('for.mfe_emails'), len(emails)),
            (t('for.mfe_secrets'), len(secrets)),
        ]
        for label, count in stats:
            indicator = "[!]" if count > 0 else "[ ]"
            lines.append(f"  {indicator} {label}: {count}")

        return "\n".join(lines)

    def tool_cheatsheet(self, input: str = "") -> str:
        """取证/隐写工具命令速查表"""
        lines = [f"=== {t('for.tool_cheatsheet')} ===", ""]

        lines.append("[1] Steghide (JPEG/BMP steganography)")
        lines.append("  steghide info image.jpg                    # Check for embedded data")
        lines.append("  steghide extract -sf image.jpg             # Extract (no password)")
        lines.append("  steghide extract -sf image.jpg -p ''       # Extract with empty password")
        lines.append("  steghide extract -sf image.jpg -p secret   # Extract with password")
        lines.append("  steghide embed -cf cover.jpg -ef secret.txt -p pass  # Embed data")

        lines.append("\n[2] Binwalk (embedded file extraction)")
        lines.append("  binwalk file.bin                           # Scan for signatures")
        lines.append("  binwalk -e file.bin                        # Extract embedded files")
        lines.append("  binwalk -Me file.bin                       # Recursive extraction")
        lines.append("  binwalk --dd='.*' file.bin                 # Extract all types")

        lines.append("\n[3] Foremost (file carving)")
        lines.append("  foremost -i disk.img                       # Auto carve all types")
        lines.append("  foremost -t jpg,png,pdf -i disk.img        # Specific types only")

        lines.append("\n[4] Volatility (memory forensics)")
        lines.append("  vol.py -f mem.raw imageinfo                # Detect OS profile")
        lines.append("  vol.py -f mem.raw --profile=X pslist       # Process list")
        lines.append("  vol.py -f mem.raw --profile=X pstree       # Process tree")
        lines.append("  vol.py -f mem.raw --profile=X filescan     # Scan for files")
        lines.append("  vol.py -f mem.raw --profile=X dumpfiles -D out/  # Dump files")
        lines.append("  vol.py -f mem.raw --profile=X hashdump     # Password hashes")
        lines.append("  vol.py -f mem.raw --profile=X cmdscan      # CMD history")
        lines.append("  vol.py -f mem.raw --profile=X netscan      # Network connections")
        lines.append("  vol.py -f mem.raw --profile=X clipboard    # Clipboard content")
        lines.append("  vol.py -f mem.raw --profile=X screenshot   # Screenshots")

        lines.append("\n[5] Exiftool (metadata)")
        lines.append("  exiftool image.jpg                         # View all metadata")
        lines.append("  exiftool -Comment image.jpg                # View comment field")
        lines.append("  exiftool -all= image.jpg                   # Remove all metadata")
        lines.append("  exiftool -Comment='hidden' image.jpg       # Inject comment")

        lines.append("\n[6] Stegsolve (image analysis)")
        lines.append("  java -jar stegsolve.jar                    # GUI tool")
        lines.append("  # Analyse -> Channel: R/G/B bit planes 0-7")
        lines.append("  # Analyse -> Data Extract -> LSB/MSB")
        lines.append("  # Analyse -> Frame Browser (GIF/APNG)")

        lines.append("\n[7] Zsteg (PNG/BMP LSB)")
        lines.append("  zsteg image.png                            # Auto scan all channels")
        lines.append("  zsteg -a image.png                         # All combinations")
        lines.append("  zsteg image.png -b 1                       # Bit 1 only")

        lines.append("\n[8] Strings / xxd / hexdump")
        lines.append("  strings file.bin                           # ASCII strings")
        lines.append("  strings -e l file.bin                      # UTF-16LE strings")
        lines.append("  xxd file.bin | head -50                    # Hex dump")
        lines.append("  xxd -r hex.txt > file.bin                  # Hex to binary")

        lines.append("\n[9] Wireshark / tshark (PCAP)")
        lines.append("  tshark -r capture.pcap                     # Read PCAP")
        lines.append("  tshark -r capture.pcap -Y 'http'           # Filter HTTP")
        lines.append("  tshark -r capture.pcap -Y 'tcp.port==80'   # Filter port")
        lines.append("  tshark -r capture.pcap -T fields -e http.file_data  # Extract data")
        lines.append("  tshark -r capture.pcap --export-objects http,out/    # Export files")

        lines.append("\n[10] File repair")
        lines.append("  # PNG: fix header -> 89 50 4E 47 0D 0A 1A 0A")
        lines.append("  # JPEG: fix header -> FF D8 FF E0")
        lines.append("  # ZIP: fix header -> 50 4B 03 04")
        lines.append("  # GIF: fix header -> 47 49 46 38 39 61")
        lines.append("  # PDF: fix header -> 25 50 44 46")
        lines.append("  pngcheck -v image.png                      # Validate PNG structure")

        lines.append("\n[11] Audio steganography")
        lines.append("  sox audio.wav -n spectrogram -o spec.png   # Spectrogram")
        lines.append("  audacity -> Analyze -> Plot Spectrum        # Frequency analysis")
        lines.append("  # SSTV: qsstv / RX-SSTV (decode slow-scan TV)")
        lines.append("  # DTMF: multimon-ng -a DTMF -t wav audio.wav")
        lines.append("  # Morse: decode by spectrogram pattern")

        lines.append("\n[12] Disk forensics")
        lines.append("  fdisk -l disk.img                          # Partition table")
        lines.append("  mmls disk.img                              # Partition layout (sleuthkit)")
        lines.append("  fls -r -o <offset> disk.img                # List files")
        lines.append("  icat -o <offset> disk.img <inode> > out    # Extract file by inode")
        lines.append("  autopsy                                     # GUI forensics suite")

        return "\n".join(lines)
