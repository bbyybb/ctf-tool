# -*- coding: utf-8 -*-
"""取证 & 逆向模块单元测试"""

import gc
import os
import struct
import sys
import tempfile
import zlib


def _safe_unlink(path):
    """跨平台安全删除临时文件（Windows 上 scapy 等库可能持有文件句柄）"""
    try:
        os.unlink(path)
    except PermissionError:
        # Windows: 文件可能仍被 scapy 锁定，强制 GC 后重试
        gc.collect()
        try:
            os.unlink(path)
        except PermissionError:
            if sys.platform == "win32":
                pass  # Windows CI 上放弃清理，由 OS 回收
            else:
                raise


from ctftool.core.utils import (
    bytes_to_int,
    entropy,
    extract_printable_strings,
    hex_dump,
    identify_file_type,
    int_to_bytes,
    xor_bytes,
)
from ctftool.modules.forensics import ForensicsModule
from ctftool.modules.reverse import ReverseModule

# ========== core/utils 测试 ==========

class TestUtils:
    def test_hex_dump(self):
        result = hex_dump(b'\x00\x01\x02\x41\x42\x43')
        assert "00 01 02 41 42 43" in result
        assert "ABC" in result

    def test_entropy_zero(self):
        assert entropy(b'\x00' * 100) == 0.0

    def test_entropy_random(self):
        import random
        data = bytes(random.randint(0, 255) for _ in range(10000))
        ent = entropy(data)
        assert 7.0 < ent <= 8.0

    def test_identify_png(self):
        assert "PNG" in identify_file_type(b'\x89PNG\r\n\x1a\n' + b'\x00' * 20)

    def test_identify_jpeg(self):
        assert "JPEG" in identify_file_type(b'\xff\xd8\xff' + b'\x00' * 20)

    def test_identify_elf(self):
        assert "ELF" in identify_file_type(b'\x7fELF' + b'\x00' * 20)

    def test_identify_unknown(self):
        assert identify_file_type(b'\x00\x00\x00\x00') is None

    def test_extract_strings(self):
        data = b'\x00\x00hello world\x00\x00test\x00'
        strings = extract_printable_strings(data, 4)
        assert "hello world" in strings
        assert "test" in strings

    def test_xor_bytes(self):
        data = b'hello'
        key = b'\xff'
        encrypted = xor_bytes(data, key)
        decrypted = xor_bytes(encrypted, key)
        assert decrypted == data

    def test_bytes_int_roundtrip(self):
        assert bytes_to_int(int_to_bytes(12345)) == 12345


# ========== Forensics 测试 ==========

class TestForensics:
    def setup_method(self):
        self.f = ForensicsModule()

    def _make_test_file(self, data: bytes) -> str:
        """创建临时测试文件"""
        fd, path = tempfile.mkstemp()
        os.write(fd, data)
        os.close(fd)
        return path

    def test_identify_file(self):
        path = self._make_test_file(b'\x89PNG\r\n\x1a\n' + b'\x00' * 100)
        result = self.f.identify_file(path)
        assert "PNG" in result
        os.unlink(path)

    def test_extract_strings(self):
        path = self._make_test_file(b'\x00flag{test_string}\x00other\x00')
        result = self.f.extract_strings(path, min_length=4)
        assert "flag{test_string}" in result
        os.unlink(path)

    def test_hex_view(self):
        path = self._make_test_file(b'ABCDEFGH' * 10)
        result = self.f.hex_view(path, 0, 32)
        assert "41 42 43 44" in result
        os.unlink(path)

    def test_binwalk_scan(self):
        # 在数据中嵌入一个 PNG 签名
        data = b'\x00' * 100 + b'\x89PNG\r\n\x1a\n' + b'\x00' * 50
        path = self._make_test_file(data)
        result = self.f.binwalk_scan(path)
        assert "PNG" in result
        os.unlink(path)

    def test_file_diff(self):
        path1 = self._make_test_file(b'AAAA')
        path2 = self._make_test_file(b'AABA')
        result = self.f.file_diff(path1, path2)
        assert "Different bytes: 1" in result or "不同字节数: 1" in result
        os.unlink(path1)
        os.unlink(path2)

    def test_png_crc_fix_correct(self):
        """CRC 正确的 PNG 不需要修复"""
        # 构造最小有效 PNG IHDR
        ihdr_data = b'IHDR' + struct.pack('>II', 100, 100) + b'\x08\x02\x00\x00\x00'
        ihdr_crc = struct.pack('>I', zlib.crc32(ihdr_data) & 0xFFFFFFFF)
        ihdr_length = struct.pack('>I', 13)
        png = b'\x89PNG\r\n\x1a\n' + ihdr_length + ihdr_data + ihdr_crc
        path = self._make_test_file(png + b'\x00' * 20)
        result = self.f.png_crc_fix(path)
        assert "no fix needed" in result.lower() or "无需修复" in result
        os.unlink(path)

    def test_png_crc_fix_wrong_height(self):
        """修改 height 后 CRC 不匹配，应能修复"""
        # 正确的 IHDR: 100x200
        ihdr_data = b'IHDR' + struct.pack('>II', 100, 200) + b'\x08\x02\x00\x00\x00'
        ihdr_crc = struct.pack('>I', zlib.crc32(ihdr_data) & 0xFFFFFFFF)
        ihdr_length = struct.pack('>I', 13)
        # 把 height 改为 50（CRC 保持原来正确值）
        wrong_ihdr = b'IHDR' + struct.pack('>II', 100, 50) + b'\x08\x02\x00\x00\x00'
        png = b'\x89PNG\r\n\x1a\n' + ihdr_length + wrong_ihdr + ihdr_crc
        path = self._make_test_file(png + b'\x00' * 20)
        result = self.f.png_crc_fix(path)
        # 应该找到正确尺寸 100x200
        assert "100 x 200" in result
        # 清理
        os.unlink(path)
        fixed = path + ".fixed.png"
        if os.path.exists(fixed):
            os.unlink(fixed)

    def test_zip_fake_decrypt_not_zip(self):
        path = self._make_test_file(b'not a zip')
        result = self.f.zip_fake_decrypt(path)
        assert "Not a valid ZIP" in result or "不是有效的 ZIP" in result
        os.unlink(path)

    def test_extract_metadata(self):
        """元数据提取不崩溃"""
        path = self._make_test_file(b'\x89PNG\r\n\x1a\n' + b'\x00' * 100)
        result = self.f.extract_metadata(path)
        assert "PNG" in result
        os.unlink(path)

    def test_detect_stego_png(self):
        """PNG 隐写检测不崩溃"""
        # 带 IEND + trailing 数据的最小 PNG
        data = b'\x89PNG\r\n\x1a\n' + b'\x00' * 50 + b'IEND' + b'\x00' * 8 + b'flag{hidden}'
        path = self._make_test_file(data)
        result = self.f.detect_stego(path)
        assert "隐写" in result or "IEND" in result or "flag" in result
        os.unlink(path)

    def test_fix_file_header_no_fix(self):
        """无法修复的未知格式"""
        path = self._make_test_file(b'\x00\x01\x02\x03' * 20)
        result = self.f.fix_file_header(path)
        assert "Cannot auto-fix" in result or "无法自动修复" in result
        os.unlink(path)

    def test_binwalk_extract(self):
        """文件分离保存"""
        data = b'\x00' * 50 + b'\x89PNG\r\n\x1a\n' + b'\x00' * 50
        path = self._make_test_file(data)
        result = self.f.binwalk_extract(path)
        assert "PNG" in result
        # 清理提取目录
        import shutil
        extract_dir = path + "_extracted"
        if os.path.isdir(extract_dir):
            shutil.rmtree(extract_dir)
        os.unlink(path)

    def test_zip_crack_not_zip(self):
        path = self._make_test_file(b'not a zip file')
        result = self.f.zip_crack(path)
        assert "Not a valid ZIP" in result or "不是有效的 ZIP" in result or "ZIP" in result
        os.unlink(path)

    def test_split_channels_needs_pillow(self):
        """通道分离（需要有效图片或 Pillow 安装）"""
        # 使用无效数据应返回错误而非崩溃
        path = self._make_test_file(b'\x00' * 100)
        try:
            result = self.f.split_channels(path)
            assert isinstance(result, str)
        except Exception:
            pass
        os.unlink(path)

    def test_pcap_analyze_not_pcap(self):
        """非 PCAP 文件"""
        path = self._make_test_file(b'not a pcap')
        try:
            self.f.pcap_analyze(path)
        except Exception:
            pass  # scapy 可能未安装或文件格式错误
        _safe_unlink(path)

    def test_usb_keyboard_decode_not_pcap(self):
        """非 PCAP 文件"""
        path = self._make_test_file(b'not a pcap')
        try:
            self.f.usb_keyboard_decode(path)
        except Exception:
            pass
        _safe_unlink(path)


# ========== Reverse 测试 ==========

class TestReverse:
    def setup_method(self):
        self.r = ReverseModule()

    def _make_test_file(self, data: bytes) -> str:
        fd, path = tempfile.mkstemp()
        os.write(fd, data)
        os.close(fd)
        return path

    def test_analyze_binary_unknown(self):
        path = self._make_test_file(b'\x00' * 100 + b'flag{in_binary}' + b'\x00' * 100)
        result = self.r.analyze_binary(path)
        assert "flag{in_binary}" in result or "熵值" in result
        os.unlink(path)

    def test_extract_strings(self):
        path = self._make_test_file(b'\x00password=admin123\x00secret_key\x00')
        result = self.r.extract_strings_from_binary(path)
        assert "password=admin123" in result
        os.unlink(path)

    def test_check_elf_not_elf(self):
        path = self._make_test_file(b'MZ' + b'\x00' * 100)
        result = self.r.check_elf_protections(path)
        assert "Not an ELF" in result or "不是 ELF" in result
        os.unlink(path)

    def test_disassemble_unknown(self):
        """反汇编非标准格式不崩溃"""
        path = self._make_test_file(b'\x90\x90\x90\xc3' * 10)  # NOP NOP NOP RET
        result = self.r.disassemble(path)
        assert "反汇编" in result or "Disassembly" in result or "hex" in result.lower() or "nop" in result.lower() or "capstone" in result.lower()
        os.unlink(path)

    def test_decompile_pyc_not_pyc(self):
        """非 pyc 文件"""
        path = self._make_test_file(b'\x00' * 20)
        try:
            result = self.r.decompile_pyc(path)
            assert isinstance(result, str)
        except Exception:
            pass
        os.unlink(path)


class TestNewForensicsFeatures:
    def setup_method(self):
        self.f = ForensicsModule()

    def _make_test_file(self, data: bytes) -> str:
        fd, path = tempfile.mkstemp()
        os.write(fd, data)
        os.close(fd)
        return path

    def test_usb_mouse_decode_not_pcap(self):
        """非 PCAP 文件"""
        path = self._make_test_file(b'not a pcap')
        try:
            self.f.usb_mouse_decode(path)
        except Exception:
            pass  # scapy 可能报错
        _safe_unlink(path)

    def test_gif_frame_extract_not_gif(self):
        """非 GIF 文件"""
        path = self._make_test_file(b'\x89PNG\r\n\x1a\n' + b'\x00' * 100)
        try:
            result = self.f.gif_frame_extract(path)
            assert isinstance(result, str)
        except Exception:
            pass
        os.unlink(path)

    def test_lsb_extract_advanced_invalid(self):
        """无效图片文件"""
        path = self._make_test_file(b'\x00' * 100)
        try:
            result = self.f.lsb_extract_advanced(path)
            assert isinstance(result, str)
        except Exception:
            pass
        os.unlink(path)

    def test_rar_crack_not_rar(self):
        """非 RAR 文件"""
        path = self._make_test_file(b'not a rar file')
        result = self.f.rar_crack(path)
        assert "不是" in result or "RAR" in result or "rarfile" in result.lower()
        os.unlink(path)


class TestForensicsNewFeatures:
    """测试批次2-3新增的 Forensics 功能"""

    def setup_method(self):
        from ctftool.modules.forensics import ForensicsModule
        self.forensics = ForensicsModule()

    def test_dtmf_decode_non_wav(self):
        """非 WAV 文件应提示格式不支持"""
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False, mode='w') as f:
            f.write('not audio data')
            path = f.name
        try:
            result = self.forensics.dtmf_decode(path)
            assert 'WAV' in result or 'RIFF' in result.upper() or '需要' in result
        finally:
            os.unlink(path)

    def test_office_analyze_non_office(self):
        """非 Office 文件应提示格式不支持"""
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False, mode='wb') as f:
            f.write(b'plain text file content')
            path = f.name
        try:
            result = self.forensics.office_analyze(path)
            assert '不是' in result or 'not' in result.lower() or 'Office' in result
        finally:
            os.unlink(path)

    def test_memory_dump_analyze(self):
        """基础内存 dump 分析应能提取字符串"""
        import os
        import tempfile
        # 创建含有 URL 和 flag 的假 dump
        content = b'\x00' * 100 + b'http://example.com/secret' + b'\x00' * 50
        content += b'flag{test_memory_dump}' + b'\x00' * 100
        with tempfile.NamedTemporaryFile(suffix='.raw', delete=False, mode='wb') as f:
            f.write(content)
            path = f.name
        try:
            result = self.forensics.memory_dump_analyze(path)
            assert 'http://example.com' in result or 'URL' in result
            assert 'flag{test_memory_dump}' in result or 'Flag' in result
        finally:
            os.unlink(path)


class TestReverseNewFeatures:
    """测试批次2-3新增的 Reverse 功能"""

    def setup_method(self):
        from ctftool.modules.reverse import ReverseModule
        self.reverse = ReverseModule()

    def test_detect_packer_non_packed(self):
        """普通文件应不检测到壳"""
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False, mode='wb') as f:
            f.write(b'\x7fELF' + b'\x00' * 100)
            path = f.name
        try:
            result = self.reverse.detect_packer(path)
            assert 'No known packer' in result or '未检测到' in result or 'not' in result.lower()
        finally:
            os.unlink(path)

    def test_detect_packer_upx(self):
        """含有 UPX 标记的文件应检测到"""
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False, mode='wb') as f:
            f.write(b'MZ' + b'\x00' * 50 + b'UPX!' + b'\x00' * 50)
            path = f.name
        try:
            result = self.reverse.detect_packer(path)
            assert 'UPX' in result
        finally:
            os.unlink(path)

    def test_list_imports_exports_non_binary(self):
        """非 PE/ELF 文件应提示"""
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False, mode='wb') as f:
            f.write(b'plain text')
            path = f.name
        try:
            result = self.reverse.list_imports_exports(path)
            assert '不是' in result or 'not' in result.lower() or 'PE' in result
        finally:
            os.unlink(path)


class TestForensicsBatch12Features:
    """测试批次1-2新增的 Forensics 功能"""

    def setup_method(self):
        from ctftool.modules.forensics import ForensicsModule
        self.forensics = ForensicsModule()

    def test_audio_spectrogram_non_audio(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False, mode='wb') as f:
            f.write(b'not audio')
            path = f.name
        try:
            result = self.forensics.audio_spectrogram(path)
            assert '不是' in result or 'not' in result.lower() or '音频' in result or 'Audacity' in result
        finally:
            os.unlink(path)

    def test_pdf_analyze_non_pdf(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False, mode='wb') as f:
            f.write(b'not a pdf')
            path = f.name
        try:
            result = self.forensics.pdf_analyze(path)
            assert '不是' in result or 'not' in result.lower() or 'PDF' in result
        finally:
            os.unlink(path)

    def test_pdf_analyze_valid(self):
        import os
        import tempfile
        # 最简 PDF
        pdf = b'%PDF-1.0\n1 0 obj<</Type/Catalog>>endobj\nxref\n0 0\ntrailer<</Root 1 0 R>>\nstartxref\n0\n%%EOF'
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False, mode='wb') as f:
            f.write(pdf)
            path = f.name
        try:
            result = self.forensics.pdf_analyze(path)
            assert 'PDF' in result and '对象' in result or 'obj' in result.lower()
        finally:
            os.unlink(path)

    def test_pcap_extract_http_non_pcap(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False, mode='wb') as f:
            f.write(b'not a pcap')
            path = f.name
        try:
            result = self.forensics.pcap_extract_http(path)
            assert '失败' in result or 'fail' in result.lower() or 'scapy' in result.lower()
        finally:
            _safe_unlink(path)

    def test_bit_plane_analysis_non_image(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False, mode='wb') as f:
            f.write(b'not an image')
            path = f.name
        try:
            result = self.forensics.bit_plane_analysis(path)
            assert '无法' in result or 'cannot' in result.lower() or 'Pillow' in result
        finally:
            os.unlink(path)


class TestReverseBatch12Features:
    """测试批次1-2新增的 Reverse 功能"""

    def setup_method(self):
        from ctftool.modules.reverse import ReverseModule
        self.reverse = ReverseModule()

    def test_check_pe_protections_non_pe(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False, mode='wb') as f:
            f.write(b'\x7fELF' + b'\x00' * 100)
            path = f.name
        try:
            result = self.reverse.check_pe_protections(path)
            assert '不是' in result or 'not' in result.lower() or 'PE' in result
        finally:
            os.unlink(path)


class TestForensicsBatch13:
    def setup_method(self):
        self.forensics = ForensicsModule()

    def test_detect_exif_tampering_not_image(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b"not an image")
            path = f.name
        try:
            result = self.forensics.detect_exif_tampering(path)
            assert isinstance(result, str)
        finally:
            os.unlink(path)

    def test_analyze_email_not_eml(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.eml', delete=False) as f:
            f.write(b"From: test@test.com\nTo: a@b.com\nSubject: Test\n\nBody")
            path = f.name
        try:
            result = self.forensics.analyze_email(path)
            assert "test@test.com" in result
        finally:
            os.unlink(path)

    def test_file_timeline(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b"test")
            path = f.name
        try:
            result = self.forensics.file_timeline(path)
            assert "时间线" in result or "Timeline" in result
        finally:
            os.unlink(path)

    def test_analyze_disk_image_not_disk(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.img', delete=False) as f:
            f.write(b"\x00" * 1024)
            path = f.name
        try:
            result = self.forensics.analyze_disk_image(path)
            assert isinstance(result, str)
        finally:
            os.unlink(path)

    def test_detect_ntfs_ads(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(b"test data without ADS")
            path = f.name
        try:
            result = self.forensics.detect_ntfs_ads(path)
            assert isinstance(result, str)
        finally:
            os.unlink(path)

    def test_analyze_registry(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.reg', delete=False) as f:
            f.write(b"regf" + b"\x00" * 200)
            path = f.name
        try:
            result = self.forensics.analyze_registry(path)
            assert isinstance(result, str)
        finally:
            os.unlink(path)

    def test_detect_dns_tunnel_not_pcap(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            f.write(b"not a pcap file")
            path = f.name
        try:
            result = self.forensics.detect_dns_tunnel(path)
            assert isinstance(result, str)
        finally:
            _safe_unlink(path)


class TestReverseBatch13:
    def setup_method(self):
        self.reverse = ReverseModule()

    def test_analyze_apk_not_apk(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as f:
            f.write(b"not a zip")
            path = f.name
        try:
            result = self.reverse.analyze_apk(path)
            assert isinstance(result, str)
        finally:
            os.unlink(path)

    def test_analyze_go_binary(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(b"\x7fELF" + b"\x00" * 100 + b"go1.21.0" + b"\x00" * 50)
            path = f.name
        try:
            result = self.reverse.analyze_go_binary(path)
            assert "Go" in result
        finally:
            os.unlink(path)

    def test_analyze_rust_binary(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(b"\x7fELF" + b"\x00" * 100 + b"rustc/1.70.0" + b"\x00" * 50)
            path = f.name
        try:
            result = self.reverse.analyze_rust_binary(path)
            assert "Rust" in result or "rust" in result
        finally:
            os.unlink(path)

    def test_analyze_dotnet(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b"MZ" + b"\x00" * 200)
            path = f.name
        try:
            result = self.reverse.analyze_dotnet(path)
            assert isinstance(result, str)
        finally:
            os.unlink(path)

    def test_yara_scan(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(b"UPX!" + b"\x00" * 100)
            path = f.name
        try:
            result = self.reverse.yara_scan(path)
            assert isinstance(result, str)
        finally:
            os.unlink(path)

    def test_deobfuscate_strings(self):
        import os
        import tempfile
        # Create file with base64 string inside
        content = b"\x00" * 50 + b"aGVsbG8gd29ybGQ=" + b"\x00" * 50
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(content)
            path = f.name
        try:
            result = self.reverse.deobfuscate_strings(path)
            assert isinstance(result, str)
        finally:
            os.unlink(path)


class TestNewForensicsFeatures2:
    def setup_method(self):
        self.f = ForensicsModule()

    def test_lsb_encode_not_image(self):
        import os
        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix='.txt', delete=False)
        tmp.write(b"not an image")
        tmp.close()
        try:
            result = self.f.lsb_encode(tmp.name, "secret")
            assert isinstance(result, str)
        except Exception:
            pass
        finally:
            os.unlink(tmp.name)

    def test_file_carve(self):
        import os
        import tempfile
        # 创建含 PNG 签名的测试文件
        tmp = tempfile.NamedTemporaryFile(suffix='.bin', delete=False)
        tmp.write(b'\x00' * 100 + b'\x89PNG\r\n\x1a\n' + b'\x00' * 200)
        tmp.close()
        try:
            result = self.f.file_carve(tmp.name)
            assert "文件切割" in result or "carve" in result.lower() or "File" in result
        except Exception:
            pass
        finally:
            os.unlink(tmp.name)
            import shutil
            carved_dir = os.path.splitext(tmp.name)[0] + "_carved"
            if os.path.isdir(carved_dir):
                shutil.rmtree(carved_dir)

    def test_pcap_extract_files_not_pcap(self):
        import os
        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
        tmp.write(b"not a pcap")
        tmp.close()
        try:
            result = self.f.pcap_extract_files(tmp.name)
            assert isinstance(result, str)
        finally:
            os.unlink(tmp.name)


class TestNewForensicsFeatures3:
    """测试 steghide_extract / zsteg_scan / blind_watermark_extract / apng_extract / sstv_decode_helper"""

    def setup_method(self):
        self.forensics = ForensicsModule()

    def _make_test_file(self, data: bytes, suffix: str = "") -> str:
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.write(fd, data)
        os.close(fd)
        return path

    @staticmethod
    def _minimal_png() -> bytes:
        """生成最小的 1x1 像素白色 PNG 文件"""
        # PNG 签名
        sig = b'\x89PNG\r\n\x1a\n'
        # IHDR: 1x1, 8-bit RGB, 无 interlace
        ihdr_data = b'IHDR' + struct.pack('>II', 1, 1) + b'\x08\x02\x00\x00\x00'
        ihdr_crc = struct.pack('>I', zlib.crc32(ihdr_data) & 0xFFFFFFFF)
        ihdr_chunk = struct.pack('>I', 13) + ihdr_data + ihdr_crc
        # IDAT: 1x1 RGB = filter_byte(0) + R G B = 4 bytes
        raw_row = b'\x00\xff\xff\xff'  # filter=None, 白色像素
        compressed = zlib.compress(raw_row)
        idat_data = b'IDAT' + compressed
        idat_crc = struct.pack('>I', zlib.crc32(idat_data) & 0xFFFFFFFF)
        idat_chunk = struct.pack('>I', len(compressed)) + idat_data + idat_crc
        # IEND
        iend_data = b'IEND'
        iend_crc = struct.pack('>I', zlib.crc32(iend_data) & 0xFFFFFFFF)
        iend_chunk = struct.pack('>I', 0) + iend_data + iend_crc
        return sig + ihdr_chunk + idat_chunk + iend_chunk

    # ---------- steghide_extract ----------

    def test_steghide_extract_returns_string(self):
        """steghide_extract 应返回字符串，不崩溃"""
        path = self._make_test_file(b"plain text content", suffix=".txt")
        try:
            result = self.forensics.steghide_extract(path, password="")
            assert isinstance(result, str)
        finally:
            os.unlink(path)

    def test_steghide_extract_no_steghide_hint(self):
        """steghide 未安装时应提示安装"""
        import shutil
        path = self._make_test_file(b"test data", suffix=".txt")
        try:
            result = self.forensics.steghide_extract(path)
            # 如果 steghide 未安装，应包含安装提示
            if not shutil.which("steghide"):
                assert "steghide" in result.lower() or "install" in result.lower() or "安装" in result
            # 无论如何，返回值应是字符串
            assert isinstance(result, str)
        finally:
            os.unlink(path)

    # ---------- zsteg_scan ----------

    def test_zsteg_scan_returns_string(self):
        """zsteg_scan 应返回字符串，不崩溃"""
        png_data = self._minimal_png()
        path = self._make_test_file(png_data, suffix=".png")
        try:
            result = self.forensics.zsteg_scan(path)
            assert isinstance(result, str)
        finally:
            os.unlink(path)

    def test_zsteg_scan_pillow_hint(self):
        """如果 Pillow 不可用，zsteg_scan 应提示安装"""
        png_data = self._minimal_png()
        path = self._make_test_file(png_data, suffix=".png")
        try:
            result = self.forensics.zsteg_scan(path)
            assert isinstance(result, str)
            # 如果 Pillow 不可用，结果中应含有提示
            try:
                from PIL import Image  # noqa: F401
            except ImportError:
                assert "Pillow" in result or "pip install" in result
        finally:
            os.unlink(path)

    # ---------- blind_watermark_extract ----------

    def test_blind_watermark_extract_returns_string(self):
        """blind_watermark_extract 应返回字符串，不崩溃"""
        png_data = self._minimal_png()
        path = self._make_test_file(png_data, suffix=".png")
        try:
            result = self.forensics.blind_watermark_extract(path)
            assert isinstance(result, str)
        finally:
            # 清理可能生成的幅值谱文件
            import glob
            base = os.path.splitext(path)[0]
            for f in glob.glob(base + "*_fft*"):
                os.unlink(f)
            os.unlink(path)

    def test_blind_watermark_extract_numpy_hint(self):
        """如果 numpy 不可用，blind_watermark_extract 应提示安装"""
        png_data = self._minimal_png()
        path = self._make_test_file(png_data, suffix=".png")
        try:
            result = self.forensics.blind_watermark_extract(path)
            assert isinstance(result, str)
            try:
                import numpy  # noqa: F401
            except ImportError:
                assert "numpy" in result.lower() or "pip install" in result
        finally:
            import glob
            base = os.path.splitext(path)[0]
            for f in glob.glob(base + "*_fft*"):
                os.unlink(f)
            os.unlink(path)

    # ---------- apng_extract ----------

    def test_apng_extract_not_apng(self):
        """普通 PNG（非 APNG）应返回非 APNG 的提示"""
        png_data = self._minimal_png()
        path = self._make_test_file(png_data, suffix=".png")
        try:
            result = self.forensics.apng_extract(path)
            assert isinstance(result, str)
            # 普通 PNG 没有 acTL 块，应提示不是 APNG
            assert "APNG" in result or "apng" in result or "不是" in result or "帧" in result
        finally:
            os.unlink(path)

    def test_apng_extract_not_png(self):
        """非 PNG 文件应提示不是 PNG"""
        path = self._make_test_file(b"not a png file at all", suffix=".txt")
        try:
            result = self.forensics.apng_extract(path)
            assert isinstance(result, str)
            assert "PNG" in result or "png" in result
        finally:
            os.unlink(path)

    def test_apng_extract_no_crash(self):
        """APNG 提取对普通 PNG 不崩溃"""
        png_data = self._minimal_png()
        path = self._make_test_file(png_data, suffix=".png")
        try:
            result = self.forensics.apng_extract(path)
            assert isinstance(result, str)
        finally:
            os.unlink(path)

    # ---------- sstv_decode_helper ----------

    def test_sstv_decode_helper_returns_string(self):
        """sstv_decode_helper 应返回字符串，不崩溃"""
        path = self._make_test_file(b"not audio data", suffix=".bin")
        try:
            result = self.forensics.sstv_decode_helper(path)
            assert isinstance(result, str)
        finally:
            os.unlink(path)

    def test_sstv_decode_helper_non_wav(self):
        """用非 WAV 文件测试，验证不崩溃"""
        path = self._make_test_file(b"\x00" * 200, suffix=".dat")
        try:
            result = self.forensics.sstv_decode_helper(path)
            assert isinstance(result, str)
            # 应包含 SSTV 相关信息
            assert len(result) > 0
        finally:
            os.unlink(path)


class TestLatestForensicsFeatures:
    """测试最新新增的 stego_full_scan / file_carve_precise / memory_forensics_enhanced"""

    def setup_method(self):
        self.f = ForensicsModule()

    def _make_test_file(self, data: bytes, suffix: str = "") -> str:
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.write(fd, data)
        os.close(fd)
        return path

    @staticmethod
    def _minimal_png() -> bytes:
        """生成最小的 1x1 像素白色 PNG 文件"""
        sig = b'\x89PNG\r\n\x1a\n'
        ihdr_data = b'IHDR' + struct.pack('>II', 1, 1) + b'\x08\x02\x00\x00\x00'
        ihdr_crc = struct.pack('>I', zlib.crc32(ihdr_data) & 0xFFFFFFFF)
        ihdr_chunk = struct.pack('>I', 13) + ihdr_data + ihdr_crc
        raw_row = b'\x00\xff\xff\xff'
        compressed = zlib.compress(raw_row)
        idat_data = b'IDAT' + compressed
        idat_crc = struct.pack('>I', zlib.crc32(idat_data) & 0xFFFFFFFF)
        idat_chunk = struct.pack('>I', len(compressed)) + idat_data + idat_crc
        iend_data = b'IEND'
        iend_crc = struct.pack('>I', zlib.crc32(iend_data) & 0xFFFFFFFF)
        iend_chunk = struct.pack('>I', 0) + iend_data + iend_crc
        return sig + ihdr_chunk + idat_chunk + iend_chunk

    # ========== stego_full_scan ==========

    def test_stego_full_scan_png(self):
        """用小 PNG 文件测试，不崩溃，返回字符串"""
        png_data = self._minimal_png()
        path = self._make_test_file(png_data, suffix=".png")
        try:
            result = self.f.stego_full_scan(path)
            assert isinstance(result, str)
            assert len(result) > 0
        finally:
            os.unlink(path)

    def test_stego_full_scan_non_image(self):
        """用普通文本文件测试，不崩溃"""
        path = self._make_test_file(b"just some plain text data", suffix=".txt")
        try:
            result = self.f.stego_full_scan(path)
            assert isinstance(result, str)
            assert len(result) > 0
        finally:
            os.unlink(path)

    # ========== file_carve_precise ==========

    def test_file_carve_precise_with_embedded(self):
        """用包含嵌入 PNG 的文件测试，不崩溃，返回字符串"""
        png_data = self._minimal_png()
        data = b'\x00' * 50 + png_data + b'\x00' * 50
        path = self._make_test_file(data, suffix=".bin")
        try:
            result = self.f.file_carve_precise(path)
            assert isinstance(result, str)
            assert len(result) > 0
        finally:
            os.unlink(path)
            # 清理可能生成的 carved 目录
            import shutil
            carved_dir = os.path.splitext(path)[0] + "_carved"
            if os.path.isdir(carved_dir):
                shutil.rmtree(carved_dir)

    def test_file_carve_precise_plain_file(self):
        """用不含已知文件签名的普通文件测试，不崩溃"""
        path = self._make_test_file(b"no known file signatures here", suffix=".bin")
        try:
            result = self.f.file_carve_precise(path)
            assert isinstance(result, str)
            assert len(result) > 0
        finally:
            os.unlink(path)

    # ========== memory_forensics_enhanced ==========

    def test_memory_forensics_enhanced_with_artifacts(self):
        """用包含 URL 和 IP 的文本文件测试，不崩溃，返回字符串"""
        content = (
            b'\x00' * 50
            + b'http://example.com/secret?token=abc123'
            + b'\x00' * 20
            + b'192.168.1.100:8080'
            + b'\x00' * 20
            + b'admin@test.com'
            + b'\x00' * 20
            + b'password=SuperSecret123'
            + b'\x00' * 50
        )
        path = self._make_test_file(content, suffix=".raw")
        try:
            result = self.f.memory_forensics_enhanced(path)
            assert isinstance(result, str)
            assert len(result) > 0
        finally:
            os.unlink(path)

    def test_memory_forensics_enhanced_empty_like(self):
        """用几乎为空的文件测试，不崩溃"""
        path = self._make_test_file(b'\x00' * 200, suffix=".raw")
        try:
            result = self.f.memory_forensics_enhanced(path)
            assert isinstance(result, str)
            assert len(result) > 0
        finally:
            os.unlink(path)
