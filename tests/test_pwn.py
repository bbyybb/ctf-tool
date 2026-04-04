# -*- coding: utf-8 -*-
"""Pwn 模块单元测试"""

from ctftool.modules.pwn import PwnModule


class TestPwn:
    def setup_method(self):
        self.p = PwnModule()

    def test_pattern_generation(self):
        result = self.p.generate_pattern(100)
        assert "100" in result

    def test_pattern_offset(self):
        # 生成 pattern 后查找已知偏移
        result = self.p.find_pattern_offset("Aa0A")
        assert "偏移" in result or "未找到" in result

    def test_padding_x86(self):
        result = self.p.generate_padding(64, "0xdeadbeef", "x86")
        assert "deadbeef" in result.lower()
        assert "64" in result

    def test_padding_x64(self):
        result = self.p.generate_padding(72, "0x401234", "x64")
        assert "401234" in result

    def test_format_string_read(self):
        result = self.p.format_string_read(7, "0x08048000", "x86")
        assert "格式化字符串" in result

    def test_format_string_write(self):
        result = self.p.format_string_write(7, "0x08048000", 0x42424242, "x86")
        assert "格式化字符串" in result

    def test_find_format_offset(self):
        result = self.p.find_format_offset()
        assert "AAAA" in result

    def test_shellcode_linux_x86(self):
        result = self.p.shellcode_template("linux", "x86")
        assert "execve" in result or "/bin/sh" in result

    def test_shellcode_linux_x64(self):
        result = self.p.shellcode_template("linux", "x64")
        assert "syscall" in result or "/bin/sh" in result

    def test_addr_convert(self):
        result = self.p.addr_convert("0xdeadbeef")
        assert "小端" in result
        assert "大端" in result
        assert "十进制" in result

    def test_pwntools_template(self):
        result = self.p.pwntools_template("vuln", "x64")
        assert "from pwn import" in result
        assert "amd64" in result

    def test_ret2libc_x86(self):
        result = self.p.ret2libc_template("x86")
        assert "system" in result
        assert "bin/sh" in result

    def test_ret2libc_x64(self):
        result = self.p.ret2libc_template("x64")
        assert "pop_rdi" in result

    def test_find_rop_gadgets(self):
        """ROP gadget 搜索（使用含 ret 的测试数据）"""
        import os
        import tempfile
        # \xc3 = ret, \x5b\xc3 = pop ebx; ret
        data = b'\x90' * 50 + b'\xc3' + b'\x90' * 10 + b'\x5b\xc3' + b'\x90' * 50
        fd, path = tempfile.mkstemp()
        os.write(fd, data)
        os.close(fd)
        result = self.p.find_rop_gadgets(path)
        assert "ret" in result
        os.unlink(path)


class TestNewPwnFeatures:
    def setup_method(self):
        self.p = PwnModule()

    def test_ret2syscall_x86(self):
        result = self.p.ret2syscall_template("x86")
        assert "execve" in result
        assert "int 0x80" in result.lower() or "int_80" in result

    def test_ret2syscall_x64(self):
        result = self.p.ret2syscall_template("x64")
        assert "syscall" in result
        assert "rax" in result

    def test_srop_template(self):
        result = self.p.srop_template("x64")
        assert "SigreturnFrame" in result or "SROP" in result
        assert "sigreturn" in result.lower()

    def test_check_bad_chars_with_null(self):
        """含 null 字节的 shellcode"""
        result = self.p.check_bad_chars("90 00 90 c3")
        assert "NULL" in result or "\\x00" in result

    def test_check_bad_chars_clean(self):
        """无坏字符的 shellcode"""
        result = self.p.check_bad_chars("90 90 c3")
        assert "未发现" in result or "null-free" in result.lower()

    def test_got_overwrite_x86(self):
        result = self.p.got_overwrite_template("x86")
        assert "GOT" in result
        assert "system" in result

    def test_got_overwrite_x64(self):
        result = self.p.got_overwrite_template("x64")
        assert "GOT" in result
        assert "amd64" in result


class TestPwnNewFeatures:
    """测试批次2-3新增的 Pwn 功能"""

    def setup_method(self):
        from ctftool.modules.pwn import PwnModule
        self.pwn = PwnModule()

    def test_heap_exploit_template_tcache(self):
        result = self.pwn.heap_exploit_template('tcache')
        assert 'Tcache' in result or 'tcache' in result

    def test_heap_exploit_template_list(self):
        result = self.pwn.heap_exploit_template('unknown')
        assert 'tcache' in result and 'fastbin' in result

    def test_one_gadget_helper(self):
        result = self.pwn.one_gadget_helper()
        assert 'one_gadget' in result and 'gem install' in result


class TestPwnBatch13:
    def setup_method(self):
        self.pwn = PwnModule()

    def test_ret2csu_template(self):
        result = self.pwn.ret2csu_template("x64")
        assert "csu" in result.lower() or "CSU" in result

    def test_stack_pivot_template(self):
        result = self.pwn.stack_pivot_template("x64")
        assert "pivot" in result.lower() or "leave" in result.lower()

    def test_seccomp_helper(self):
        result = self.pwn.seccomp_helper()
        assert "seccomp" in result.lower()

    def test_io_file_template(self):
        result = self.pwn.io_file_template()
        assert "IO_FILE" in result or "_IO_FILE" in result

    def test_house_of_orange_template(self):
        result = self.pwn.house_of_orange_template()
        assert "orange" in result.lower() or "Orange" in result


class TestPwnAutoAnalysis:
    """测试 Pwn 自动化分析方法（使用最小 ELF 文件）"""

    def setup_method(self):
        import os
        import tempfile
        self.pwn = PwnModule()
        # 创建最小 ELF 文件
        elf = b'\x7fELF' + b'\x01' * 12 + b'\x02\x00\x03\x00\x01\x00\x00\x00'
        elf += b'\x00' * 32 + b'\x90' * 100
        self.tmp = tempfile.NamedTemporaryFile(suffix='.elf', delete=False)
        self.tmp.write(elf)
        self.tmp.close()

    def teardown_method(self):
        import os
        if os.path.exists(self.tmp.name):
            os.unlink(self.tmp.name)

    def test_auto_ret2text(self):
        """auto_ret2text 对最小 ELF 不崩溃"""
        result = self.pwn.auto_ret2text(self.tmp.name)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_auto_ret2shellcode(self):
        """auto_ret2shellcode 对最小 ELF 不崩溃"""
        result = self.pwn.auto_ret2shellcode(self.tmp.name)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_auto_pwn_analyze(self):
        """auto_pwn_analyze 对最小 ELF 不崩溃"""
        result = self.pwn.auto_pwn_analyze(self.tmp.name)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_auto_ret2text_nonexistent(self):
        """不存在的文件抛出 FileNotFoundError"""
        import pytest
        with pytest.raises(FileNotFoundError):
            self.pwn.auto_ret2text("/nonexistent/file.elf")
