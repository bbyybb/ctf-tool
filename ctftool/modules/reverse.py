# -*- coding: utf-8 -*-
"""逆向工程模块

覆盖：PE/ELF 分析、字符串提取、基础反汇编、熵值分析等。
"""

import os
import re
import struct
from typing import Optional

from ctftool.core.i18n import t
from ctftool.core.utils import (
    entropy,
    extract_printable_strings,
    hex_dump,
    read_file_bytes,
)


class ReverseModule:
    """逆向工程工具集"""

    def analyze_binary(self, filepath: str) -> str:
        """综合二进制分析"""
        data = read_file_bytes(filepath)
        lines = [f"=== {t('rev.binary_analysis')}: {os.path.basename(filepath)} ==="]
        lines.append(f"{t('rev.file_size')}: {len(data)} bytes")

        # 判断文件类型并分析
        if data[:4] == b'\x7fELF':
            lines.extend(self._analyze_elf(data))
        elif data[:2] == b'MZ':
            lines.extend(self._analyze_pe(data))
        else:
            lines.append(f"{t('rev.file_type')}: {t('rev.unknown_binary')}")

        # 熵值分析
        ent = entropy(data)
        lines.append(f"\n{t('rev.entropy')}: {ent:.4f}")
        if ent > 7.0:
            lines.append(f"  [!] {t('rev.high_entropy')}")
        elif ent > 6.0:
            lines.append(f"  [i] {t('rev.medium_entropy')}")

        # 分段熵值
        lines.append(f"\n=== {t('rev.segment_entropy')} ===")
        block_size = max(len(data) // 16, 256)
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]
            block_ent = entropy(block)
            bar = '█' * int(block_ent * 3)
            lines.append(f"  0x{i:08X}: {block_ent:.2f} {bar}")

        # 可打印字符串
        strings = extract_printable_strings(data, 6)
        interesting = self._filter_interesting_strings(strings)
        if interesting:
            lines.append(f"\n=== {t('rev.interesting_strings')} ({len(interesting)} {t('rev.count_unit')}) ===")
            for s in interesting[:50]:
                lines.append(f"  {s}")

        # 建议下一步
        lines.append(f"\n=== {t('rev.next_steps')} ===")
        is_elf = data[:4] == b'\x7fELF'
        is_pe = data[:2] == b'MZ'
        if is_elf:
            lines.append(f"  → check_elf_protections <file>  # {t('rev.hint_checksec')}")
            lines.append(f"  → disassemble <file>            # {t('rev.hint_disasm')}")
            lines.append(f"  → list_imports_exports <file>   # {t('rev.hint_imports')}")
            lines.append(f"  → find_rop_gadgets <file>       # {t('rev.hint_rop')}")
        elif is_pe:
            lines.append(f"  → check_pe_protections <file>   # {t('rev.hint_pe_checksec')}")
            lines.append(f"  → detect_packer <file>          # {t('rev.hint_packer')}")
            lines.append(f"  → list_imports_exports <file>   # {t('rev.hint_imports')}")
        if ent > 7.0:
            lines.append(f"  [!] {t('rev.high_entropy_packer')}")
        lines.append(f"  → extract_strings_from_binary <file>  # {t('rev.hint_strings')}")

        return "\n".join(lines)

    def extract_strings_from_binary(self, filepath: str, min_len: int = 4,
                                     encoding: str = "ascii") -> str:
        """从二进制文件提取字符串"""
        data = read_file_bytes(filepath)
        if encoding == "ascii":
            strings = extract_printable_strings(data, min_len)
        elif encoding == "utf16":
            strings = self._extract_utf16_strings(data, min_len)
        else:
            strings = extract_printable_strings(data, min_len)

        lines = [f"{t('rev.extracted_strings')} {len(strings)} {t('rev.count_unit')} ({t('rev.min_length')}: {min_len}):"]
        for i, s in enumerate(strings[:300]):
            lines.append(f"  [{i+1:4d}] {s}")
        if len(strings) > 300:
            lines.append(f"  ... {t('rev.more_items')} {len(strings) - 300} {t('rev.count_unit')}")
        return "\n".join(lines)

    def disassemble(self, filepath: str, offset: int = 0, count: int = 50) -> str:
        """基础反汇编"""
        data = read_file_bytes(filepath)
        lines = [f"=== {t('rev.disassembly')}: {os.path.basename(filepath)} ==="]

        try:
            from capstone import (
                CS_ARCH_ARM,
                CS_ARCH_ARM64,
                CS_ARCH_MIPS,
                CS_ARCH_X86,
                CS_MODE_32,
                CS_MODE_64,
                CS_MODE_ARM,
                CS_MODE_BIG_ENDIAN,
                CS_MODE_LITTLE_ENDIAN,
                CS_MODE_MIPS32,
                Cs,
            )

            # 自动检测架构
            arch = CS_ARCH_X86
            mode = CS_MODE_64
            if data[:4] == b'\x7fELF':
                data[4]
                ei_data = data[5]  # 1=LE, 2=BE
                e_machine = struct.unpack('<H' if ei_data == 1 else '>H', data[18:20])[0]

                endian = CS_MODE_LITTLE_ENDIAN if ei_data == 1 else CS_MODE_BIG_ENDIAN

                if e_machine == 0x03:  # EM_386
                    arch, mode = CS_ARCH_X86, CS_MODE_32
                elif e_machine == 0x3E:  # EM_X86_64
                    arch, mode = CS_ARCH_X86, CS_MODE_64
                elif e_machine == 0x28:  # EM_ARM
                    arch, mode = CS_ARCH_ARM, CS_MODE_ARM | endian
                elif e_machine == 0xB7:  # EM_AARCH64
                    arch, mode = CS_ARCH_ARM64, endian
                elif e_machine == 0x08:  # EM_MIPS
                    arch, mode = CS_ARCH_MIPS, CS_MODE_MIPS32 | endian
                else:
                    arch, mode = CS_ARCH_X86, CS_MODE_64

                if offset == 0:
                    offset = self._find_elf_entry(data)
            elif data[:2] == b'MZ':
                pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
                if data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                    machine = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
                    if machine == 0x8664:
                        arch, mode = CS_ARCH_X86, CS_MODE_64
                    else:
                        arch, mode = CS_ARCH_X86, CS_MODE_32
                else:
                    arch, mode = CS_ARCH_X86, CS_MODE_32
                if offset == 0:
                    offset = self._find_pe_entry(data)

            md = Cs(arch, mode)
            code = data[offset:offset + count * 15]
            arch_names = {CS_ARCH_X86: "x86", CS_ARCH_ARM: "ARM", CS_ARCH_ARM64: "AArch64", CS_ARCH_MIPS: "MIPS"}
            mode_names = {CS_MODE_32: "32", CS_MODE_64: "64"}
            arch_name = arch_names.get(arch, "unknown")
            mode_name = mode_names.get(mode & (CS_MODE_32 | CS_MODE_64), "")
            lines.append(f"{t('rev.arch')}: {arch_name}{'-' + mode_name if mode_name else ''}")
            lines.append(f"{t('rev.start_offset')}: 0x{offset:X}\n")

            dangerous_funcs = ['gets', 'scanf', 'strcpy', 'strcat', 'sprintf', 'system', 'execve', 'popen']
            for i, insn in enumerate(md.disasm(code, offset)):
                if i >= count:
                    break
                hex_bytes = ' '.join(f'{b:02x}' for b in insn.bytes)
                line = f"  0x{insn.address:08X}: {hex_bytes:<24s} {insn.mnemonic} {insn.op_str}"
                if insn.mnemonic in ('call', 'bl', 'blx'):
                    for func in dangerous_funcs:
                        if func in insn.op_str:
                            line += f"  <- [!] {t('rev.dangerous_func')}: {func}"
                            break
                if insn.mnemonic in ('syscall', 'int') and '0x80' in insn.op_str:
                    line += f"  <- [!] {t('rev.syscall')}"
                lines.append(line)
        except ImportError:
            lines.append(f"[!] {t('rev.install_capstone')}")
            lines.append(f"\n=== {t('rev.raw_bytes')} (hex) ===")
            lines.append(hex_dump(data, offset, min(count * 8, 256)))

        return "\n".join(lines)

    # ========== ELF 分析 ==========

    def _analyze_elf(self, data: bytes) -> list[str]:
        """分析 ELF 文件"""
        lines = [f"{t('rev.file_type')}: {t('rev.elf_executable')}"]

        # ELF Header
        ei_class = data[4]  # 1=32位, 2=64位
        ei_data = data[5]   # 1=小端, 2=大端
        ei_osabi = data[7]

        arch = "64-bit" if ei_class == 2 else "32-bit"
        endian = t('rev.little_endian') if ei_data == 1 else t('rev.big_endian')
        lines.append(f"{t('rev.arch')}: {arch} ({endian})")

        osabi_map = {0: "UNIX System V", 3: "Linux", 6: "Solaris"}
        _unknown = t('rev.unknown')
        lines.append(f"OS/ABI: {osabi_map.get(ei_osabi, f'{_unknown}({ei_osabi})')}")

        if ei_class == 2 and ei_data == 1:
            e_type = struct.unpack('<H', data[16:18])[0]
            e_entry = struct.unpack('<Q', data[24:32])[0]
            type_map = {1: t('rev.relocatable'), 2: t('rev.executable'), 3: t('rev.shared_lib'), 4: t('rev.core_dump')}
            _unknown = t('rev.unknown')
            lines.append(f"{t('rev.type')}: {type_map.get(e_type, f'{_unknown}({e_type})')}")
            lines.append(f"{t('rev.entry_point')}: 0x{e_entry:X}")
        elif ei_class == 1 and ei_data == 1:
            e_type = struct.unpack('<H', data[16:18])[0]
            e_entry = struct.unpack('<I', data[24:28])[0]
            type_map = {1: t('rev.relocatable'), 2: t('rev.executable'), 3: t('rev.shared_lib'), 4: t('rev.core_dump')}
            _unknown = t('rev.unknown')
            lines.append(f"{t('rev.type')}: {type_map.get(e_type, f'{_unknown}({e_type})')}")
            lines.append(f"{t('rev.entry_point')}: 0x{e_entry:X}")

        return lines

    def _find_elf_entry(self, data: bytes) -> int:
        """查找 ELF 入口点对应的文件偏移（非虚拟地址）"""
        ei_class = data[4]
        ei_data = data[5]
        fmt = '<' if ei_data == 1 else '>'

        if ei_class == 2:  # 64-bit
            e_entry = struct.unpack(f'{fmt}Q', data[24:32])[0]
            e_phoff = struct.unpack(f'{fmt}Q', data[32:40])[0]
            e_phentsize = struct.unpack(f'{fmt}H', data[54:56])[0]
            e_phnum = struct.unpack(f'{fmt}H', data[56:58])[0]
            for i in range(e_phnum):
                off = e_phoff + i * e_phentsize
                p_type = struct.unpack(f'{fmt}I', data[off:off+4])[0]
                if p_type == 1:  # PT_LOAD
                    p_offset = struct.unpack(f'{fmt}Q', data[off+8:off+16])[0]
                    p_vaddr = struct.unpack(f'{fmt}Q', data[off+16:off+24])[0]
                    p_filesz = struct.unpack(f'{fmt}Q', data[off+32:off+40])[0]
                    if p_vaddr <= e_entry < p_vaddr + p_filesz:
                        return p_offset + (e_entry - p_vaddr)
        else:  # 32-bit
            e_entry = struct.unpack(f'{fmt}I', data[24:28])[0]
            e_phoff = struct.unpack(f'{fmt}I', data[28:32])[0]
            e_phentsize = struct.unpack(f'{fmt}H', data[42:44])[0]
            e_phnum = struct.unpack(f'{fmt}H', data[44:46])[0]
            for i in range(e_phnum):
                off = e_phoff + i * e_phentsize
                p_type = struct.unpack(f'{fmt}I', data[off:off+4])[0]
                if p_type == 1:  # PT_LOAD
                    p_offset = struct.unpack(f'{fmt}I', data[off+4:off+8])[0]
                    p_vaddr = struct.unpack(f'{fmt}I', data[off+8:off+12])[0]
                    p_filesz = struct.unpack(f'{fmt}I', data[off+16:off+20])[0]
                    if p_vaddr <= e_entry < p_vaddr + p_filesz:
                        return p_offset + (e_entry - p_vaddr)
        return 0  # 回退到文件开头

    # ========== PE 分析 ==========

    def _analyze_pe(self, data: bytes) -> list[str]:
        """分析 PE 文件"""
        lines = [f"{t('rev.file_type')}: {t('rev.pe_executable')}"]

        try:
            import pefile
            pe = pefile.PE(data=data)

            lines.append(f"{t('rev.machine_type')}: {hex(pe.FILE_HEADER.Machine)}")
            machine_map = {0x14c: 'i386', 0x8664: 'AMD64', 0x1c0: 'ARM'}
            lines.append(f"{t('rev.arch')}: {machine_map.get(pe.FILE_HEADER.Machine, t('rev.unknown'))}")
            lines.append(f"{t('rev.num_sections')}: {pe.FILE_HEADER.NumberOfSections}")
            lines.append(f"{t('rev.timestamp')}: {pe.FILE_HEADER.TimeDateStamp}")

            if hasattr(pe, 'OPTIONAL_HEADER'):
                lines.append(f"{t('rev.entry_point')} RVA: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}")
                lines.append(f"{t('rev.image_base')}: 0x{pe.OPTIONAL_HEADER.ImageBase:X}")

            # 节区信息
            lines.append(f"\n=== {t('rev.sections')} ===")
            for section in pe.sections:
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                ent = section.get_entropy()
                lines.append(
                    f"  {name:8s}  VA: 0x{section.VirtualAddress:08X}  "
                    f"{t('rev.size')}: {section.SizeOfRawData:8d}  {t('rev.entropy')}: {ent:.2f}"
                )
                if ent > 7.0:
                    lines.append(f"    [!] {t('rev.high_entropy_packed')}")

            # 导入表
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                lines.append(f"\n=== {t('rev.import_table')} ===")
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    funcs = [imp.name.decode('utf-8', errors='ignore')
                             for imp in entry.imports if imp.name]
                    lines.append(f"  {dll_name}: {len(funcs)} {t('rev.functions')}")
                    for f in funcs[:10]:
                        lines.append(f"    - {f}")
                    if len(funcs) > 10:
                        lines.append(f"    ... {t('rev.more_items')} {len(funcs) - 10} {t('rev.count_unit')}")
        except ImportError:
            lines.append(f"[!] {t('rev.install_pefile')}")
            # 基础分析
            pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
            if data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                lines.append(f"{t('rev.pe_sig_at')}: 0x{pe_offset:X}")
        except Exception as e:
            lines.append(f"{t('rev.pe_parse_error')}: {e}")

        return lines

    def _find_pe_entry(self, data: bytes) -> int:
        """查找 PE 入口点对应的文件偏移（RVA→文件偏移转换）"""
        try:
            pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
            entry_rva = struct.unpack('<I', data[pe_offset + 0x28:pe_offset + 0x2C])[0]
            num_sections = struct.unpack('<H', data[pe_offset + 0x06:pe_offset + 0x08])[0]
            opt_header_size = struct.unpack('<H', data[pe_offset + 0x14:pe_offset + 0x16])[0]
            section_table = pe_offset + 0x18 + opt_header_size
            for i in range(num_sections):
                s_off = section_table + i * 40
                virt_size = struct.unpack('<I', data[s_off + 8:s_off + 12])[0]
                virt_addr = struct.unpack('<I', data[s_off + 12:s_off + 16])[0]
                raw_offset = struct.unpack('<I', data[s_off + 20:s_off + 24])[0]
                if virt_addr <= entry_rva < virt_addr + virt_size:
                    return raw_offset + (entry_rva - virt_addr)
            return entry_rva
        except Exception:
            return 0

    # ========== ELF 保护检测 ==========

    def check_elf_protections(self, filepath: str) -> str:
        """检测 ELF 二进制文件的安全保护机制（类似 checksec）"""
        data = read_file_bytes(filepath)
        if data[:4] != b'\x7fELF':
            return t('rev.not_elf')

        ei_class = data[4]
        ei_data = data[5]
        fmt = '<' if ei_data == 1 else '>'
        lines = [f"=== {t('rev.elf_checksec')}: {os.path.basename(filepath)} ===\n"]

        # 解析 Program Headers
        if ei_class == 2:
            e_phoff = struct.unpack(f'{fmt}Q', data[32:40])[0]
            e_phentsize = struct.unpack(f'{fmt}H', data[54:56])[0]
            e_phnum = struct.unpack(f'{fmt}H', data[56:58])[0]
        else:
            e_phoff = struct.unpack(f'{fmt}I', data[28:32])[0]
            e_phentsize = struct.unpack(f'{fmt}H', data[42:44])[0]
            e_phnum = struct.unpack(f'{fmt}H', data[44:46])[0]

        has_stack_nx = False
        has_gnu_relro = False

        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type = struct.unpack(f'{fmt}I', data[off:off+4])[0]

            # PT_GNU_STACK (0x6474e551)
            if p_type == 0x6474e551:
                if ei_class == 2:
                    p_flags = struct.unpack(f'{fmt}I', data[off+4:off+8])[0]
                else:
                    p_flags = struct.unpack(f'{fmt}I', data[off+24:off+28])[0]
                # PF_X = 1
                has_stack_nx = not (p_flags & 0x1)

            # PT_GNU_RELRO (0x6474e552)
            if p_type == 0x6474e552:
                has_gnu_relro = True

        # NX (No Execute)
        nx_status = "NX enabled" if has_stack_nx else "NX disabled"
        lines.append(f"  NX ({t('rev.nx_desc')}):      {'[OK]' if has_stack_nx else '[--]'} {nx_status}")
        if has_stack_nx:
            lines.append(f"    -> {t('rev.nx_hint_rop')}")
        else:
            lines.append(f"    -> {t('rev.nx_hint_shellcode')}")

        # RELRO
        if has_gnu_relro:
            # 正确检测 Full RELRO：解析 .dynamic 段查找 DT_BIND_NOW
            bind_now = False
            for i in range(e_phnum):
                off = e_phoff + i * e_phentsize
                p_type = struct.unpack(f'{fmt}I', data[off:off+4])[0]
                if p_type == 2:  # PT_DYNAMIC
                    if ei_class == 2:
                        dyn_off = struct.unpack(f'{fmt}Q', data[off+8:off+16])[0]
                        dyn_size = struct.unpack(f'{fmt}Q', data[off+32:off+40])[0]
                    else:
                        dyn_off = struct.unpack(f'{fmt}I', data[off+4:off+8])[0]
                        dyn_size = struct.unpack(f'{fmt}I', data[off+16:off+20])[0]
                    # 遍历 dynamic entries
                    entry_size = 16 if ei_class == 2 else 8
                    for j in range(0, min(dyn_size, 4096), entry_size):
                        pos = dyn_off + j
                        if pos + entry_size > len(data):
                            break
                        if ei_class == 2:
                            d_tag = struct.unpack(f'{fmt}Q', data[pos:pos+8])[0]
                        else:
                            d_tag = struct.unpack(f'{fmt}I', data[pos:pos+4])[0]
                        if d_tag == 24:  # DT_BIND_NOW
                            bind_now = True
                            break
                        if d_tag == 30:  # DT_FLAGS
                            if ei_class == 2:
                                d_val = struct.unpack(f'{fmt}Q', data[pos+8:pos+16])[0]
                            else:
                                d_val = struct.unpack(f'{fmt}I', data[pos+4:pos+8])[0]
                            if d_val & 0x8:  # DF_BIND_NOW
                                bind_now = True
                                break
                        if d_tag == 0:  # DT_NULL
                            break
                    break
            if bind_now:
                full_relro = True
                lines.append("  RELRO:                [OK] Full RELRO")
                lines.append("    -> {0}".format(t('rev.relro_full_hint')))
            else:
                full_relro = False
                lines.append("  RELRO:                [~~] Partial RELRO")
                lines.append("    -> {0}".format(t('rev.relro_partial_hint')))
        else:
            full_relro = False
            lines.append("  RELRO:                [--] No RELRO")
            lines.append("    -> {0}".format(t('rev.relro_partial_hint')))

        # PIE (Position Independent Executable)
        if ei_class == 2:
            e_type = struct.unpack(f'{fmt}H', data[16:18])[0]
        else:
            e_type = struct.unpack(f'{fmt}H', data[16:18])[0]
        is_pie = (e_type == 3)  # ET_DYN
        lines.append(f"  PIE ({t('rev.pie_desc')}):     {'[OK]' if is_pie else '[--]'} {'PIE enabled' if is_pie else 'No PIE'}")
        if is_pie:
            lines.append(f"    -> {t('rev.pie_hint_leak')}")
        else:
            lines.append(f"    -> {t('rev.pie_hint_fixed')}")

        # Stack Canary（搜索 __stack_chk_fail）
        has_canary = b'__stack_chk_fail' in data
        lines.append(f"  Canary ({t('rev.canary_desc')}):      {'[OK]' if has_canary else '[--]'} {'Canary found' if has_canary else 'No Canary'}")
        if has_canary:
            lines.append(f"    -> {t('rev.canary_hint_leak')}")
        else:
            lines.append(f"    -> {t('rev.canary_hint_none')}")

        # FORTIFY_SOURCE
        has_fortify = any(s in data for s in [b'__printf_chk', b'__memcpy_chk', b'__strcpy_chk'])
        lines.append(f"  FORTIFY_SOURCE:       {'[OK]' if has_fortify else '[--]'} {'FORTIFY enabled' if has_fortify else 'No FORTIFY'}")

        # 总结
        protections = sum([has_stack_nx, has_gnu_relro, is_pie, has_canary])
        lines.append(f"\n  {t('rev.security_score')}: {protections}/4 {t('rev.protections_enabled')}")
        if protections <= 1:
            lines.append(f"  [!] {t('rev.security_weak')}")
        elif protections <= 2:
            lines.append(f"  [i] {t('rev.security_partial')}")
        else:
            lines.append(f"  [i] {t('rev.security_strong')}")

        # 推荐利用路线
        lines.append(f"\n=== {t('rev.exploit_routes')} ===")
        if not has_stack_nx and not has_canary:
            lines.append(f"  {t('rev.route')} 1: {t('rev.route_shellcode')}")
            lines.append(f"  {t('rev.steps')}: generate_pattern -> find_pattern_offset -> shellcode_template")
        elif not has_canary:
            lines.append(f"  {t('rev.route')} 1: {t('rev.route_rop')}")
            lines.append(f"  {t('rev.steps')}: generate_pattern -> find_pattern_offset -> ret2libc_template")
        if not full_relro:
            lines.append(f"  {t('rev.route')} 2: {t('rev.route_got')}")
        lines.append(f"  {t('rev.route')} 3: {t('rev.route_fmt')}")

        return "\n".join(lines)

    # ========== .pyc 反编译 ==========

    def decompile_pyc(self, filepath: str) -> str:
        """反编译 Python .pyc 文件"""
        data = read_file_bytes(filepath)
        lines = [f"=== {t('rev.pyc_analysis')}: {os.path.basename(filepath)} ==="]

        # 检测 Python 版本（magic number）
        magic = struct.unpack('<H', data[:2])[0]
        pyc_versions = {
            3394: "3.8", 3401: "3.8", 3413: "3.9", 3425: "3.10",
            3430: "3.10", 3439: "3.11", 3495: "3.12", 3531: "3.13",
        }
        version = pyc_versions.get(magic, f"{t('rev.unknown')} (magic={magic})")
        lines.append(f"Python {t('rev.version')}: {version}")

        # 尝试使用 uncompyle6 或 decompile3
        decompiled = False
        for decompiler_name, decompiler_func in [
            ("uncompyle6", self._try_uncompyle6),
            ("decompile3", self._try_decompile3),
        ]:
            try:
                result = decompiler_func(filepath)
                if result:
                    lines.append(f"{t('rev.decompiler')}: {decompiler_name}")
                    lines.append(f"\n{result}")
                    decompiled = True
                    break
            except Exception:
                pass

        if not decompiled:
            # 回退：使用 dis 模块反汇编字节码
            lines.append(f"\n{t('rev.no_decompiler')}")
            lines.append(f"  pip install uncompyle6  # {t('rev.install_decompiler')}")
            try:
                import dis
                import marshal
                # 跳过 pyc header（16字节 for 3.8+, 12 for 3.7-, 8 for older）
                header_size = 16 if magic >= 3394 else 12
                code = marshal.loads(data[header_size:])
                import io
                buf = io.StringIO()
                dis.dis(code, file=buf)
                disasm = buf.getvalue()
                lines.append(disasm[:3000])
                if len(disasm) > 3000:
                    lines.append(f"... ({t('rev.output_truncated')})")
            except Exception as e:
                lines.append(f"  {t('rev.disasm_failed')}: {e}")
            # 提取字符串常量
            strings = extract_printable_strings(data, 6)
            interesting = [s for s in strings if not s.startswith(('__', 'builtins'))]
            if interesting:
                lines.append(f"\n{t('rev.string_constants')} ({len(interesting)} {t('rev.count_unit')}):")
                for s in interesting[:50]:
                    lines.append(f"  {s}")

        return "\n".join(lines)

    def _try_uncompyle6(self, filepath: str) -> Optional[str]:
        import io

        import uncompyle6
        buf = io.StringIO()
        uncompyle6.decompile_file(filepath, buf)
        return buf.getvalue()

    def _try_decompile3(self, filepath: str) -> Optional[str]:
        import io

        import decompile3
        buf = io.StringIO()
        decompile3.decompile_file(filepath, buf)
        return buf.getvalue()

    # ========== 辅助方法 ==========

    def _filter_interesting_strings(self, strings: list[str]) -> list[str]:
        """过滤出可能有趣的字符串"""
        interesting = []
        keywords = [
            'flag', 'key', 'pass', 'secret', 'admin', 'root', 'login',
            'http', 'ftp', '/bin/', 'base64', 'encrypt', 'decrypt',
            'license', 'serial', 'correct', 'wrong', 'success', 'fail',
            'debug', 'error', 'warning', '.php', '.html', '.txt',
            'username', 'password', 'token', 'auth', 'hash',
        ]
        for s in strings:
            lower = s.lower()
            if any(kw in lower for kw in keywords):
                interesting.append(s)
            elif re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', s):
                interesting.append(f"[Base64?] {s}")
            elif re.match(r'^[0-9a-fA-F]{32,}$', s):
                interesting.append(f"[Hash?] {s}")
        return interesting

    def _extract_utf16_strings(self, data: bytes, min_len: int = 4) -> list[str]:
        """提取 UTF-16 LE 字符串"""
        result = []
        current = []
        for i in range(0, len(data) - 1, 2):
            char_code = struct.unpack('<H', data[i:i+2])[0]
            if 32 <= char_code < 127:
                current.append(chr(char_code))
            else:
                if len(current) >= min_len:
                    result.append(''.join(current))
                current = []
        if len(current) >= min_len:
            result.append(''.join(current))
        return result

    # ========== PE 安全保护检测 ==========

    def check_pe_protections(self, filepath: str) -> str:
        """检测 PE 文件的安全保护机制"""
        data = read_file_bytes(filepath)
        if data[:2] != b'MZ':
            return t('rev.not_pe')

        pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
        if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return t('rev.pe_sig_invalid')

        # COFF header
        machine = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
        is_64 = machine == 0x8664
        struct.unpack('<H', data[pe_offset+22:pe_offset+24])[0]

        # Optional header
        opt_offset = pe_offset + 24
        magic = struct.unpack('<H', data[opt_offset:opt_offset+2])[0]

        if magic == 0x20b:  # PE32+
            dll_chars_offset = opt_offset + 70
        else:  # PE32
            dll_chars_offset = opt_offset + 46

        dll_characteristics = struct.unpack('<H', data[dll_chars_offset:dll_chars_offset+2])[0]

        lines = [f"=== {t('rev.pe_checksec')} ==="]
        lines.append(f"{t('rev.arch')}: {'x64 (PE32+)' if is_64 else 'x86 (PE32)'}")
        lines.append(f"Machine: 0x{machine:04X}")
        lines.append("")

        score = 0
        total = 5

        # DEP / NX
        nx = bool(dll_characteristics & 0x0100)  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        lines.append(f"{'[+]' if nx else '[-]'} DEP/NX: {t('rev.enabled') if nx else t('rev.disabled')}")
        if nx: score += 1

        # ASLR
        aslr = bool(dll_characteristics & 0x0040)  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        lines.append(f"{'[+]' if aslr else '[-]'} ASLR: {t('rev.enabled') if aslr else t('rev.disabled')}")
        if aslr: score += 1

        # High Entropy ASLR
        high_entropy = bool(dll_characteristics & 0x0020)  # IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
        lines.append(f"{'[+]' if high_entropy else '[-]'} High Entropy ASLR: {t('rev.enabled') if high_entropy else t('rev.disabled')}")
        if high_entropy: score += 1

        # SafeSEH (仅 32 位)
        if not is_64:
            no_seh = bool(dll_characteristics & 0x0400)  # IMAGE_DLLCHARACTERISTICS_NO_SEH
            lines.append(f"{'[+]' if no_seh else '[-]'} SafeSEH/NO_SEH: {t('rev.safeseh_enabled') if no_seh else t('rev.disabled')}")
            if no_seh: score += 1
        else:
            lines.append(f"[*] SafeSEH: N/A ({t('rev.x86_only')})")
            score += 1  # x64 不需要

        # CFG (Control Flow Guard)
        cfg = bool(dll_characteristics & 0x4000)  # IMAGE_DLLCHARACTERISTICS_GUARD_CF
        lines.append(f"{'[+]' if cfg else '[-]'} CFG (Control Flow Guard): {t('rev.enabled') if cfg else t('rev.disabled')}")
        if cfg: score += 1

        # GS (Stack Cookie) - 通过搜索 __security_cookie 和 __GSHandlerCheck
        gs = b'__security_cookie' in data or b'__GSHandlerCheck' in data
        lines.append(f"{'[+]' if gs else '[-]'} GS (Stack Cookie): {t('rev.detected') if gs else t('rev.not_detected')}")

        lines.append(f"\n{t('rev.security_score')}: {score}/{total}")

        return '\n'.join(lines)

    # ========== 加壳检测 ==========

    def detect_packer(self, filepath: str) -> str:
        """检测加壳/保护工具"""
        data = read_file_bytes(filepath)

        lines = [f"=== {t('rev.packer_detection')} ==="]
        detected = []

        # UPX
        if b'UPX!' in data or b'UPX0' in data or b'UPX1' in data:
            detected.append("UPX")
            lines.append(f"[!] {t('rev.detected_upx')}")
            lines.append(f"    {t('rev.unpack')}: upx -d <file>")

        # ASPack
        if b'.aspack' in data or b'ASPack' in data:
            detected.append("ASPack")
            lines.append(f"[!] {t('rev.detected_aspack')}")

        # Themida
        if b'Themida' in data or b'.themida' in data:
            detected.append("Themida")
            lines.append(f"[!] {t('rev.detected_themida')}")

        # VMProtect
        if b'.vmp0' in data or b'.vmp1' in data or b'VMProtect' in data:
            detected.append("VMProtect")
            lines.append(f"[!] {t('rev.detected_vmprotect')}")

        # PyInstaller
        if b'MEIPASS' in data or b'pyiboot' in data or b'PYZ-00.pyz' in data:
            detected.append("PyInstaller")
            lines.append(f"[!] {t('rev.detected_pyinstaller')}")
            lines.append(f"    {t('rev.extract')}: pyinstxtractor <file>")

        # Electron / Node.js
        if b'electron.asar' in data or b'app.asar' in data:
            detected.append("Electron")
            lines.append(f"[!] {t('rev.detected_electron')}")
            lines.append(f"    {t('rev.extract')}: npx asar extract app.asar ./output")

        # .NET
        if b'mscoree.dll' in data or b'_CorExeMain' in data:
            detected.append(".NET")
            lines.append(f"[*] {t('rev.detected_dotnet')}")
            lines.append(f"    {t('rev.decompile')}: dnSpy, ILSpy, dotPeek")

        # Go
        if b'runtime.main' in data and b'go.buildid' in data:
            detected.append("Go")
            lines.append(f"[*] {t('rev.detected_go')}")
            lines.append(f"    {t('rev.analysis')}: IDA + GoReSym {t('rev.plugin')}")

        # Rust
        if b'rust_begin_unwind' in data or b'rust_panic' in data:
            detected.append("Rust")
            lines.append(f"[*] {t('rev.detected_rust')}")

        if not detected:
            # 检查段名/节名特征
            if data[:2] == b'MZ':
                sections = re.findall(rb'\.[\w]{1,8}\x00', data[:2048])
                section_names = [s.decode('ascii', errors='ignore').strip('\x00') for s in sections]
                lines.append(f"{t('rev.pe_sections')}: {', '.join(section_names)}")
                unusual = [s for s in section_names if s not in ('.text', '.data', '.rdata', '.bss', '.rsrc', '.reloc', '.idata', '.edata', '.pdata', '.tls')]
                if unusual:
                    lines.append(f"[?] {t('rev.unusual_sections')}: {', '.join(unusual)} ({t('rev.may_packed')})")
                else:
                    lines.append(f"[-] {t('rev.no_packer')}")
            elif data[:4] == b'\x7fELF':
                lines.append(f"[-] {t('rev.no_packer')} (ELF)")
            else:
                lines.append(f"[-] {t('rev.no_packer')}")

        return '\n'.join(lines)

    # ========== 导入/导出表 ==========

    def list_imports_exports(self, filepath: str) -> str:
        """列出 PE/ELF 的导入和导出函数"""
        data = read_file_bytes(filepath)
        lines = [f"=== {t('rev.imports_exports')} ==="]

        if data[:2] == b'MZ':
            # PE 文件 - 使用 pefile
            try:
                import pefile
                pe = pefile.PE(filepath)

                # 导入表
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    lines.append(f"\n{t('rev.import_table')} ({len(pe.DIRECTORY_ENTRY_IMPORT)} {t('rev.count_unit')} DLL):")
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode('utf-8', errors='replace')
                        funcs = [imp.name.decode('utf-8', errors='replace') if imp.name else f"ord({imp.ordinal})" for imp in entry.imports[:10]]
                        lines.append(f"  {dll_name}: {', '.join(funcs)}")
                        if len(entry.imports) > 10:
                            lines.append(f"    ... {t('rev.total')} {len(entry.imports)} {t('rev.functions')}")

                # 导出表
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    exports = pe.DIRECTORY_ENTRY_EXPORT.symbols
                    lines.append(f"\n{t('rev.export_table')} ({len(exports)} {t('rev.count_unit')}):")
                    for exp in exports[:30]:
                        name = exp.name.decode('utf-8', errors='replace') if exp.name else f"ord({exp.ordinal})"
                        lines.append(f"  {name} @ 0x{exp.address:X}")

                pe.close()
            except ImportError:
                lines.append(f"{t('rev.need_pefile')}")
            except Exception as e:
                lines.append(f"{t('rev.pe_parse_failed')}: {e}")

        elif data[:4] == b'\x7fELF':
            # ELF - 手动解析动态符号
            data[4] == 2
            data[5] == 1

            # 提取字符串中的函数名
            strings = extract_printable_strings(data, 4)
            libc_funcs = ['printf', 'scanf', 'malloc', 'free', 'system', 'execve',
                           'read', 'write', 'open', 'close', 'puts', 'gets', 'strcpy',
                           'strcmp', 'strlen', 'memcpy', 'mmap', 'fork', 'socket',
                           'connect', 'bind', 'listen', 'accept', 'send', 'recv']

            found_imports = [s for s in strings if s in libc_funcs or s.startswith('__')]
            interesting = [s for s in found_imports if not s.startswith('__pyx')][:50]

            if interesting:
                lines.append(f"\n{t('rev.detected_lib_funcs')} ({len(interesting)} {t('rev.count_unit')}):")
                for func in sorted(set(interesting)):
                    flag = ""
                    if func in ('system', 'execve', 'gets', 'strcpy'):
                        flag = f" [!] {t('rev.dangerous_func')}"
                    lines.append(f"  {func}{flag}")
            else:
                lines.append(t('rev.no_lib_funcs'))
        else:
            lines.append(t('rev.not_pe_or_elf'))

        return '\n'.join(lines)

    # ========== APK 分析 ==========

    def analyze_apk(self, filepath: str) -> str:
        """Android APK 基础分析"""
        import zipfile

        data = read_file_bytes(filepath)
        lines = [f"=== {t('rev.apk_analysis')}: {os.path.basename(filepath)} ==="]
        lines.append(f"{t('rev.file_size')}: {len(data)} bytes")

        # APK 本质上是 ZIP 文件
        try:
            import io
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            return t('rev.not_apk')

        all_files = zf.namelist()
        lines.append(f"{t('rev.total_files')}: {len(all_files)}")

        # 重点文件检测
        key_files = ['AndroidManifest.xml', 'classes.dex', 'resources.arsc']
        lines.append(f"\n=== {t('rev.key_files')} ===")
        for kf in key_files:
            if kf in all_files:
                info = zf.getinfo(kf)
                lines.append(f"  [+] {kf} ({info.file_size} bytes)")
            else:
                lines.append(f"  [-] {kf} {t('rev.not_found')}")

        # 检查多个 dex 文件（multidex）
        dex_files = [f for f in all_files if f.endswith('.dex')]
        if len(dex_files) > 1:
            lines.append(f"\n[*] Multidex {t('rev.detected')}: {t('rev.total')} {len(dex_files)} {t('rev.count_unit')} dex {t('rev.files')}")
            for df in dex_files:
                info = zf.getinfo(df)
                lines.append(f"  {df} ({info.file_size} bytes)")

        # 解析 classes.dex 头部
        if 'classes.dex' in all_files:
            dex_data = zf.read('classes.dex')
            lines.append(f"\n=== classes.dex {t('rev.header_info')} ===")
            magic = dex_data[:8]
            lines.append(f"  Magic: {repr(magic)}")
            if dex_data[:4] == b'dex\n' and len(dex_data) >= 112:
                # DEX header 解析
                checksum = struct.unpack('<I', dex_data[8:12])[0]
                file_size = struct.unpack('<I', dex_data[32:36])[0]
                string_ids_size = struct.unpack('<I', dex_data[56:60])[0]
                type_ids_size = struct.unpack('<I', dex_data[64:68])[0]
                method_ids_size = struct.unpack('<I', dex_data[88:92])[0]
                class_defs_size = struct.unpack('<I', dex_data[96:100])[0]
                lines.append(f"  Checksum: 0x{checksum:08X}")
                lines.append(f"  {t('rev.file_size')}: {file_size} bytes")
                lines.append(f"  {t('rev.string_count')}: {string_ids_size}")
                lines.append(f"  {t('rev.type_count')}: {type_ids_size}")
                lines.append(f"  {t('rev.method_count')}: {method_ids_size}")
                lines.append(f"  {t('rev.class_count')}: {class_defs_size}")

        # META-INF 签名信息
        meta_files = [f for f in all_files if f.startswith('META-INF/')]
        if meta_files:
            lines.append(f"\n=== {t('rev.signature_info')} (META-INF/) ===")
            for mf in meta_files:
                info = zf.getinfo(mf)
                lines.append(f"  {mf} ({info.file_size} bytes)")
                if mf.endswith('.RSA') or mf.endswith('.DSA') or mf.endswith('.EC'):
                    lines.append(f"    [*] {t('rev.cert_file')}")
                elif mf.endswith('.SF'):
                    lines.append(f"    [*] {t('rev.sig_file')}")

        # lib/ 目录 - CPU 架构
        lib_files = [f for f in all_files if f.startswith('lib/')]
        if lib_files:
            archs = set()
            for lf in lib_files:
                parts = lf.split('/')
                if len(parts) >= 2:
                    archs.add(parts[1])
            lines.append(f"\n=== Native {t('rev.libs')} (lib/) ===")
            lines.append(f"  {t('rev.supported_archs')}: {', '.join(sorted(archs))}")
            for arch in sorted(archs):
                arch_libs = [f for f in lib_files if f.startswith(f'lib/{arch}/')]
                lines.append(f"  {arch}/ ({len(arch_libs)} {t('rev.count_unit')} {t('rev.files')}):")
                for al in arch_libs[:10]:
                    lines.append(f"    {al}")
                if len(arch_libs) > 10:
                    lines.append(f"    ... {t('rev.more_items')} {len(arch_libs) - 10} {t('rev.count_unit')}")

        # assets/ 目录
        asset_files = [f for f in all_files if f.startswith('assets/')]
        if asset_files:
            lines.append(f"\n=== Assets {t('rev.directory')} ({len(asset_files)} {t('rev.count_unit')} {t('rev.files')}) ===")
            for af in asset_files[:20]:
                info = zf.getinfo(af)
                lines.append(f"  {af} ({info.file_size} bytes)")
            if len(asset_files) > 20:
                lines.append(f"  ... {t('rev.more_items')} {len(asset_files) - 20} {t('rev.count_unit')}")

        zf.close()
        return '\n'.join(lines)

    # ========== .NET 程序集分析 ==========

    def analyze_dotnet(self, filepath: str) -> str:
        """.NET 程序集分析"""
        data = read_file_bytes(filepath)
        lines = [f"=== {t('rev.dotnet_analysis')}: {os.path.basename(filepath)} ==="]

        if data[:2] != b'MZ':
            return t('rev.not_pe')

        pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
        if pe_offset + 4 > len(data) or data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return t('rev.pe_sig_invalid')

        # 检查 Optional Header magic
        opt_offset = pe_offset + 24
        magic = struct.unpack('<H', data[opt_offset:opt_offset+2])[0]
        is_pe32_plus = (magic == 0x20b)

        # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 是第 15 个目录项 (index 14)
        # 在 Optional Header 中，数据目录从固定偏移开始
        if is_pe32_plus:
            # PE32+: 数据目录起始偏移 = opt_offset + 112
            dd_offset = opt_offset + 112
        else:
            # PE32: 数据目录起始偏移 = opt_offset + 96
            dd_offset = opt_offset + 96

        # 每个目录项 8 字节 (VA + Size)，COM_DESCRIPTOR 是第 15 项
        com_desc_offset = dd_offset + 14 * 8
        if com_desc_offset + 8 > len(data):
            return t('rev.not_dotnet_no_com')

        com_rva = struct.unpack('<I', data[com_desc_offset:com_desc_offset+4])[0]
        com_size = struct.unpack('<I', data[com_desc_offset+4:com_desc_offset+8])[0]

        if com_rva == 0 or com_size == 0:
            return t('rev.not_dotnet_empty_com')

        lines.append(f"[+] {t('rev.dotnet_detected')}")
        lines.append(f"  COM Descriptor RVA: 0x{com_rva:08X}")
        lines.append(f"  COM Descriptor Size: {com_size}")

        # 搜索 .NET metadata 根签名 "BSJB"
        bsjb_pos = data.find(b'BSJB')
        if bsjb_pos >= 0:
            lines.append(f"\n=== CLI Metadata {t('rev.root')} ({t('rev.offset')} 0x{bsjb_pos:X}) ===")
            # 读取版本字符串
            if bsjb_pos + 16 <= len(data):
                version_len = struct.unpack('<I', data[bsjb_pos+12:bsjb_pos+16])[0]
                if bsjb_pos + 16 + version_len <= len(data):
                    version_str = data[bsjb_pos+16:bsjb_pos+16+version_len].decode('utf-8', errors='ignore').strip('\x00')
                    lines.append(f"  {t('rev.runtime_version')}: {version_str}")

            # 解析 stream headers
            # 跳过 metadata root 头部
            padded_len = (version_len + 3) & ~3  # 4 字节对齐
            streams_offset = bsjb_pos + 16 + padded_len
            if streams_offset + 4 <= len(data):
                struct.unpack('<H', data[streams_offset:streams_offset+2])[0]
                num_streams = struct.unpack('<H', data[streams_offset+2:streams_offset+4])[0]
                lines.append(f"  {t('rev.stream_count')}: {num_streams}")

                # 解析每个流
                pos = streams_offset + 4
                for _ in range(num_streams):
                    if pos + 8 > len(data):
                        break
                    s_offset = struct.unpack('<I', data[pos:pos+4])[0]
                    s_size = struct.unpack('<I', data[pos+4:pos+8])[0]
                    pos += 8
                    # 读取流名称（null 结尾，4 字节对齐）
                    name_start = pos
                    while pos < len(data) and data[pos] != 0:
                        pos += 1
                    s_name = data[name_start:pos].decode('ascii', errors='ignore')
                    pos = ((pos + 1) + 3) & ~3  # 跳过 null 并对齐
                    lines.append(f"  {t('rev.stream')}: {s_name} ({t('rev.offset')}: 0x{s_offset:X}, {t('rev.size')}: {s_size})")

                    # 从 #Strings heap 提取字符串
                    if s_name == '#Strings' and s_size > 0:
                        heap_start = bsjb_pos + s_offset
                        heap_end = heap_start + s_size
                        if heap_end <= len(data):
                            heap_data = data[heap_start:heap_end]
                            str_list = [s for s in heap_data.split(b'\x00') if len(s) >= 2]
                            str_list = [s.decode('utf-8', errors='ignore') for s in str_list]

                            # 提取类名和方法名
                            class_names = [s for s in str_list if '.' not in s and s[0:1].isupper() and len(s) > 2]
                            method_names = [s for s in str_list if s[0:1].islower() or s.startswith('get_') or s.startswith('set_') or s.startswith('.')]
                            namespaces = [s for s in str_list if '.' in s]

                            if namespaces:
                                lines.append(f"\n=== {t('rev.namespaces')} ({len(namespaces)} {t('rev.count_unit')}) ===")
                                for ns in namespaces[:30]:
                                    lines.append(f"  {ns}")
                                if len(namespaces) > 30:
                                    lines.append(f"  ... {t('rev.more_items')} {len(namespaces) - 30} {t('rev.count_unit')}")

                            if class_names:
                                lines.append(f"\n=== {t('rev.class_names')} ({len(class_names)} {t('rev.count_unit')}) ===")
                                for cn in class_names[:50]:
                                    lines.append(f"  {cn}")
                                if len(class_names) > 50:
                                    lines.append(f"  ... {t('rev.more_items')} {len(class_names) - 50} {t('rev.count_unit')}")

                            if method_names:
                                lines.append(f"\n=== {t('rev.method_names')} ({len(method_names)} {t('rev.count_unit')}) ===")
                                for mn in method_names[:50]:
                                    lines.append(f"  {mn}")
                                if len(method_names) > 50:
                                    lines.append(f"  ... {t('rev.more_items')} {len(method_names) - 50} {t('rev.count_unit')}")

        # 搜索常见 .NET 特征
        dotnet_markers = []
        if b'mscorlib' in data:
            dotnet_markers.append("mscorlib")
        if b'System.Runtime' in data:
            dotnet_markers.append("System.Runtime")
        if b'System.Reflection' in data:
            dotnet_markers.append("System.Reflection")
        if dotnet_markers:
            lines.append(f"\n=== {t('rev.dotnet_features')} ===")
            for m in dotnet_markers:
                lines.append(f"  [+] {m}")

        lines.append(f"\n=== {t('rev.recommended_tools')} ===")
        lines.append(f"  dnSpy / ILSpy / dotPeek - .NET {t('rev.decompiler')}")
        lines.append(f"  de4dot - .NET {t('rev.deobfuscation_tool')}")

        return '\n'.join(lines)

    # ========== Go 二进制分析 ==========

    def analyze_go_binary(self, filepath: str) -> str:
        """Go 二进制分析辅助"""
        data = read_file_bytes(filepath)
        lines = [f"=== Go {t('rev.binary_analysis')}: {os.path.basename(filepath)} ==="]
        lines.append(f"{t('rev.file_size')}: {len(data)} bytes")

        is_go = False

        # 搜索 go.buildid
        buildid_pos = data.find(b'go.buildid')
        if buildid_pos >= 0:
            is_go = True
            lines.append(f"\n[+] {t('rev.found')} go.buildid ({t('rev.offset')} 0x{buildid_pos:X})")
            # 尝试提取 buildid 值
            buildid_marker = data.find(b'\xff Go build ID: "', buildid_pos - 64)
            if buildid_marker >= 0:
                start = buildid_marker + len(b'\xff Go build ID: "')
                end = data.find(b'"', start)
                if end > start and end - start < 200:
                    bid = data[start:end].decode('ascii', errors='ignore')
                    lines.append(f"  Build ID: {bid}")

        # 搜索 gopclntab (Go PC-line table)
        gopclntab_pos = data.find(b'\xfb\xff\xff\xff\x00\x00')  # Go 1.16+ magic
        if gopclntab_pos < 0:
            gopclntab_pos = data.find(b'\xfa\xff\xff\xff\x00\x00')  # Go 1.18+ magic
        if gopclntab_pos < 0:
            gopclntab_pos = data.find(b'\xf1\xff\xff\xff\x00\x00')  # Go 1.20+ magic
        if gopclntab_pos < 0:
            if b'gopclntab' in data:
                is_go = True
                lines.append(f"[+] {t('rev.found')} gopclntab {t('rev.section_mark')}")
        else:
            is_go = True
            lines.append(f"[+] {t('rev.found')} pclntab ({t('rev.offset')} 0x{gopclntab_pos:X})")

        if not is_go:
            if b'runtime.main' in data:
                is_go = True
            else:
                return t('rev.no_go_features')

        # 搜索 Go 版本字符串
        go_version_pattern = re.compile(rb'go1\.\d+(\.\d+)?')
        versions = set()
        for m in go_version_pattern.finditer(data):
            ver = m.group().decode('ascii')
            versions.add(ver)
        if versions:
            lines.append(f"\n=== Go {t('rev.version')} ===")
            for v in sorted(versions):
                lines.append(f"  {v}")

        # 提取 Go 风格函数名
        func_pattern = re.compile(rb'(?:main|runtime|fmt|os|net|io|sync|crypto|encoding|strings|bytes|math|reflect|syscall|internal)\.[A-Za-z_][\w.*/()]*')
        func_names = set()
        for m in func_pattern.finditer(data):
            name = m.group().decode('ascii', errors='ignore')
            if len(name) < 120:
                func_names.add(name)

        # 分类显示
        main_funcs = sorted([f for f in func_names if f.startswith('main.')])
        runtime_funcs = sorted([f for f in func_names if f.startswith('runtime.')])
        other_funcs = sorted([f for f in func_names if not f.startswith('main.') and not f.startswith('runtime.')])

        if main_funcs:
            lines.append(f"\n=== main {t('rev.pkg_funcs')} ({len(main_funcs)} {t('rev.count_unit')}) ===")
            for f in main_funcs[:30]:
                lines.append(f"  {f}")
            if len(main_funcs) > 30:
                lines.append(f"  ... {t('rev.more_items')} {len(main_funcs) - 30} {t('rev.count_unit')}")

        if other_funcs:
            lines.append(f"\n=== {t('rev.imported_pkg_funcs')} ({len(other_funcs)} {t('rev.count_unit')}) ===")
            packages = set()
            for f in other_funcs:
                pkg = f.split('.')[0]
                packages.add(pkg)
            lines.append(f"  {t('rev.imported_pkgs')}: {', '.join(sorted(packages))}")
            for f in other_funcs[:40]:
                lines.append(f"  {f}")
            if len(other_funcs) > 40:
                lines.append(f"  ... {t('rev.more_items')} {len(other_funcs) - 40} {t('rev.count_unit')}")

        if runtime_funcs:
            lines.append(f"\n=== runtime {t('rev.functions')} ({len(runtime_funcs)} {t('rev.count_unit')}, {t('rev.show_first')} 20) ===")
            for f in runtime_funcs[:20]:
                lines.append(f"  {f}")

        lines.append(f"\n=== {t('rev.recommended_tools')} ===")
        lines.append(f"  GoReSym - {t('rev.go_restore_symbols')}")
        lines.append(f"  go_parser (IDA {t('rev.plugin')}) - Go {t('rev.binary_ida_helper')}")
        lines.append(f"  redress - Go {t('rev.binary_analysis_tool')}")

        return '\n'.join(lines)

    # ========== YARA 规则匹配 ==========

    def yara_scan(self, filepath: str, rules_text: str = "") -> str:
        """YARA 规则匹配"""
        data = read_file_bytes(filepath)
        lines = [f"=== YARA {t('rev.scan')}: {os.path.basename(filepath)} ==="]

        # 内置规则集（当 rules_text 为空时使用）
        builtin_patterns = {
            "UPX_packed": {
                "patterns": [b'UPX!', b'UPX0', b'UPX1'],
                "desc": t('rev.yara_upx'),
            },
            "Base64_string": {
                "regex": rb'[A-Za-z0-9+/]{40,}={0,2}',
                "desc": t('rev.yara_base64'),
            },
            "Shellcode_NOP_sled": {
                "patterns": [b'\x90' * 16],
                "desc": t('rev.yara_nop'),
            },
            "XOR_loop": {
                "patterns": [
                    b'\x80\x30',  # xor byte ptr [eax], imm8
                    b'\x80\x31',  # xor byte ptr [ecx], imm8
                    b'\x80\x32',  # xor byte ptr [edx], imm8
                    b'\x80\x33',  # xor byte ptr [ebx], imm8
                    b'\x80\x34\x24',  # xor byte ptr [esp], imm8
                ],
                "desc": t('rev.yara_xor'),
            },
            "Crypto_AES_SBox": {
                "patterns": [b'\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5'],
                "desc": t('rev.yara_aes_sbox'),
            },
            "Crypto_AES_InvSBox": {
                "patterns": [b'\x52\x09\x6a\xd5\x30\x36\xa5\x38'],
                "desc": t('rev.yara_aes_inv_sbox'),
            },
            "Crypto_RC4_KSA": {
                "regex": rb'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15',
                "desc": t('rev.yara_rc4'),
            },
            "Suspicious_API_strings": {
                "patterns": [
                    b'VirtualAlloc', b'VirtualProtect', b'CreateRemoteThread',
                    b'WriteProcessMemory', b'NtUnmapViewOfSection',
                ],
                "desc": t('rev.yara_suspicious_api'),
            },
            "ELF_shellcode_execve": {
                "patterns": [
                    b'/bin/sh', b'/bin/bash',
                    b'\x0f\x05',  # syscall
                    b'\xcd\x80',  # int 0x80
                ],
                "desc": t('rev.yara_shellcode'),
            },
            "PE_MZ_embedded": {
                "regex": rb'(?<=.{16})MZ',
                "desc": t('rev.yara_embedded_pe'),
            },
        }

        # 尝试使用 yara-python 库
        if rules_text:
            try:
                import yara
                rules = yara.compile(source=rules_text)
                matches = rules.match(data=data)
                if matches:
                    lines.append(f"\n{t('rev.found')} {len(matches)} {t('rev.matches')}:")
                    for match in matches:
                        lines.append(f"\n{t('rev.rule')}: {match.rule}")
                        if match.tags:
                            lines.append(f"  {t('rev.tags')}: {', '.join(match.tags)}")
                        for s_offset, s_id, s_data in match.strings:
                            lines.append(f"  {t('rev.offset')} 0x{s_offset:08X}: {s_id} = {repr(s_data[:64])}")
                else:
                    lines.append(t('rev.no_yara_match'))
                return '\n'.join(lines)
            except ImportError:
                lines.append(f"[!] yara-python {t('rev.not_installed_builtin')}")
                lines.append(f"    {t('rev.install')}: pip install yara-python")
            except Exception as e:
                lines.append(f"[!] YARA {t('rev.compile_match_error')}: {e}")
                lines.append(f"    {t('rev.fallback_builtin')}")

        # 内置模式匹配
        lines.append(f"\n{t('rev.using_builtin') if not rules_text else t('rev.fallback_to_builtin')}{t('rev.pattern_matching')}:")
        total_matches = 0

        for rule_name, rule_def in builtin_patterns.items():
            match_offsets = []

            if 'patterns' in rule_def:
                for pattern in rule_def['patterns']:
                    offset = 0
                    while True:
                        pos = data.find(pattern, offset)
                        if pos < 0:
                            break
                        match_offsets.append((pos, pattern))
                        offset = pos + 1
                        if len(match_offsets) >= 20:
                            break

            if 'regex' in rule_def:
                for m in re.finditer(rule_def['regex'], data):
                    match_offsets.append((m.start(), m.group()[:32]))
                    if len(match_offsets) >= 20:
                        break

            if match_offsets:
                total_matches += len(match_offsets)
                lines.append(f"\n[+] {rule_name}: {rule_def['desc']}")
                for pos, matched in match_offsets[:5]:
                    if isinstance(matched, bytes):
                        lines.append(f"    {t('rev.offset')} 0x{pos:08X}: {matched[:16].hex()}")
                    else:
                        lines.append(f"    {t('rev.offset')} 0x{pos:08X}: {repr(matched)}")
                if len(match_offsets) > 5:
                    lines.append(f"    ... {t('rev.more_items')} {len(match_offsets) - 5} {t('rev.matches')}")

        if total_matches == 0:
            lines.append(f"\n[-] {t('rev.no_builtin_match')}")
        else:
            lines.append(f"\n{t('rev.total_matches')}: {total_matches} {t('rev.locations')}")

        return '\n'.join(lines)

    # ========== 反混淆辅助 - 字符串解密 ==========

    def deobfuscate_strings(self, filepath: str) -> str:
        """反混淆辅助 - 字符串解密"""
        data = read_file_bytes(filepath)
        lines = [f"=== {t('rev.deobfuscate_analysis')}: {os.path.basename(filepath)} ==="]
        lines.append(f"{t('rev.file_size')}: {len(data)} bytes")

        results = []

        # 1. 检测 Base64 编码
        lines.append(f"\n=== Base64 {t('rev.encoding_detection')} ===")
        import base64
        b64_pattern = re.compile(rb'[A-Za-z0-9+/]{16,}={0,2}')
        b64_count = 0
        for m in b64_pattern.finditer(data):
            candidate = m.group()
            try:
                decoded = base64.b64decode(candidate)
                # 检查解码结果是否为可打印字符串
                printable = sum(1 for b in decoded if 32 <= b < 127)
                if len(decoded) > 4 and printable / len(decoded) > 0.7:
                    decoded_str = decoded.decode('utf-8', errors='replace')
                    lines.append(f"  {t('rev.offset')} 0x{m.start():08X}: {decoded_str[:80]}")
                    results.append(('base64', m.start(), decoded_str))
                    b64_count += 1
                    if b64_count >= 30:
                        break
            except Exception:
                pass
        if b64_count == 0:
            lines.append(f"  {t('rev.no_base64_found')}")

        # 2. 单字节 XOR 暴力破解
        lines.append(f"\n=== {t('rev.xor_single_byte')} ===")
        xor_results = []
        # 搜索高熵区段来尝试 XOR 解密
        block_size = 256
        interesting_blocks = []
        for i in range(0, min(len(data), 65536), block_size):
            block = data[i:i+block_size]
            ent = entropy(block)
            if 3.5 < ent < 5.5:  # 加密字符串的典型熵值范围
                interesting_blocks.append(i)

        for key in range(1, 256):
            for block_start in interesting_blocks[:10]:
                block = data[block_start:block_start+block_size]
                decrypted = bytes(b ^ key for b in block)
                # 搜索解密后的可打印字符串
                strings_found = re.findall(rb'[\x20-\x7e]{6,}', decrypted)
                for s in strings_found:
                    decoded = s.decode('ascii', errors='ignore')
                    # 过滤有意义的字符串
                    if any(kw in decoded.lower() for kw in ['flag', 'http', 'key', 'pass', 'admin',
                                                             'secret', 'file', 'path', 'system',
                                                             'bin/sh', '.exe', '.dll', '.php']):
                        xor_results.append((key, block_start, decoded))

        if xor_results:
            seen = set()
            for key, offset, text in xor_results[:20]:
                if text not in seen:
                    lines.append(f"  XOR key=0x{key:02X}, {t('rev.offset')} 0x{offset:08X}: {text[:80]}")
                    seen.add(text)
                    results.append(('xor', offset, text))
        else:
            lines.append(f"  {t('rev.no_xor_found')}")

        # 3. 栈字符串构造检测 (mov byte ptr [rbp-xx], 'c')
        lines.append(f"\n=== {t('rev.stack_string_detection')} ===")
        # 检测模式: C6 45 xx yy (mov byte ptr [rbp+disp8], imm8)
        stack_str_pattern = re.compile(rb'\xc6\x45[\x80-\xff][\x20-\x7e]')
        stack_chars = []
        for m in stack_str_pattern.finditer(data):
            disp = struct.unpack('b', data[m.start()+2:m.start()+3])[0]
            char = chr(data[m.start()+3])
            stack_chars.append((m.start(), disp, char))

        if stack_chars:
            # 按偏移分组连续的构造
            groups = []
            current_group = [stack_chars[0]]
            for i in range(1, len(stack_chars)):
                if stack_chars[i][0] - stack_chars[i-1][0] <= 8:
                    current_group.append(stack_chars[i])
                else:
                    if len(current_group) >= 3:
                        groups.append(current_group)
                    current_group = [stack_chars[i]]
            if len(current_group) >= 3:
                groups.append(current_group)

            for group in groups[:10]:
                sorted_chars = sorted(group, key=lambda x: x[1])
                reconstructed = ''.join(c for _, _, c in sorted_chars)
                offset = group[0][0]
                lines.append(f"  {t('rev.offset')} 0x{offset:08X}: \"{reconstructed}\"")
                results.append(('stack_str', offset, reconstructed))

            if not groups:
                lines.append(f"  {t('rev.no_stack_string')}")
        else:
            lines.append(f"  {t('rev.no_stack_string')}")

        # 总结
        lines.append(f"\n=== {t('rev.summary')} ===")
        lines.append(f"{t('rev.found')} {len(results)} {t('rev.deobfuscate_results')}")

        return '\n'.join(lines)

    # ========== Rust 二进制分析 ==========

    def analyze_rust_binary(self, filepath: str) -> str:
        """Rust 二进制分析辅助"""
        data = read_file_bytes(filepath)
        lines = [f"=== Rust {t('rev.binary_analysis')}: {os.path.basename(filepath)} ==="]
        lines.append(f"{t('rev.file_size')}: {len(data)} bytes")

        is_rust = False

        # 搜索 Rust 特征字符串
        rust_markers = {
            b'rustc': 'Rust compiler marker',
            b'rust_begin_unwind': 'Rust panic unwind',
            b'rust_panic': 'Rust panic handler',
            b'.rustc': '.rustc section',
            b'rust_eh_personality': 'Rust EH personality',
            b'core::panicking': 'core panic module',
            b'std::panicking': 'std panic module',
            b'core::fmt': 'core fmt module',
            b'alloc::': 'alloc crate',
        }

        lines.append(f"\n=== Rust {t('rev.feature_detection')} ===")
        for marker, desc in rust_markers.items():
            pos = data.find(marker)
            if pos >= 0:
                is_rust = True
                lines.append(f"  [+] {desc} ({t('rev.offset')} 0x{pos:X})")

        if not is_rust:
            return t('rev.no_rust_features')

        # 提取 Rust 版本信息
        lines.append(f"\n=== Rust {t('rev.version_info')} ===")
        rustc_pattern = re.compile(rb'rustc\s+\d+\.\d+\.\d+[\w\-. ]*')
        versions = set()
        for m in rustc_pattern.finditer(data):
            ver = m.group().decode('ascii', errors='ignore').strip()
            versions.add(ver)
        if versions:
            for v in sorted(versions):
                lines.append(f"  {v}")
        else:
            ver_pattern = re.compile(rb'rust[/-](\d+\.\d+\.\d+)')
            for m in ver_pattern.finditer(data):
                versions.add(m.group().decode('ascii', errors='ignore'))
            if versions:
                for v in sorted(versions):
                    lines.append(f"  {v}")
            else:
                lines.append(f"  {t('rev.cannot_extract_version')}")

        # 搜索 demangle 过的函数名
        lines.append(f"\n=== {t('rev.func_extraction')} ===")

        # Legacy mangling: _ZN 前缀; v0 mangling: _R 前缀
        rust_func_pattern = re.compile(
            rb'(?:_ZN|_R)'
            rb'[\w$]{4,120}'
        )
        mangled_names = set()
        for m in rust_func_pattern.finditer(data):
            name = m.group().decode('ascii', errors='ignore')
            if len(name) < 120:
                mangled_names.add(name)

        # 搜索已 demangle 的名称（调试信息中可能存在）
        demangled_pattern = re.compile(
            rb'(?:[\w]+::){2,}[\w<>]+(?:::[\w<>]+)*'
        )
        demangled_names = set()
        for m in demangled_pattern.finditer(data):
            name = m.group().decode('ascii', errors='ignore')
            if len(name) < 200 and '::' in name:
                demangled_names.add(name)

        # 提取 crate 名称
        crate_names = set()
        for name in demangled_names:
            parts = name.split('::')
            if parts[0] not in ('core', 'std', 'alloc', 'compiler_builtins', ''):
                crate_names.add(parts[0])

        # 显示用户代码函数（排除标准库）
        std_prefixes = ('core::', 'std::', 'alloc::', 'compiler_builtins::',
                        '<core::', '<std::', '<alloc::', '<&', '<()')
        user_funcs = sorted([n for n in demangled_names
                             if not any(n.startswith(p) for p in std_prefixes)])
        std_funcs = sorted([n for n in demangled_names
                            if any(n.startswith(p) for p in std_prefixes)])

        if user_funcs:
            lines.append(f"\n{t('rev.user_code_funcs')} ({len(user_funcs)} {t('rev.count_unit')}):")
            for f in user_funcs[:40]:
                lines.append(f"  {f}")
            if len(user_funcs) > 40:
                lines.append(f"  ... {t('rev.more_items')} {len(user_funcs) - 40} {t('rev.count_unit')}")

        if std_funcs:
            lines.append(f"\n{t('rev.stdlib_funcs')} ({len(std_funcs)} {t('rev.count_unit')}, {t('rev.show_first')} 20):")
            for f in std_funcs[:20]:
                lines.append(f"  {f}")

        if mangled_names:
            lines.append(f"\nMangled {t('rev.names')} ({len(mangled_names)} {t('rev.count_unit')}, {t('rev.show_first')} 15):")
            for n in sorted(mangled_names)[:15]:
                lines.append(f"  {n}")

        # Crate 列表
        if crate_names:
            lines.append(f"\n=== {t('rev.detected_crates')} ({len(crate_names)} {t('rev.count_unit')}) ===")
            for c in sorted(crate_names):
                lines.append(f"  {c}")

        lines.append(f"\n=== {t('rev.recommended_tools')} ===")
        lines.append(f"  rust-demangler - Rust {t('rev.symbol_demangle')}")
        lines.append(f"  cargo-bloat - {t('rev.rust_size_analysis')}")
        lines.append(f"  IDA + Rust {t('rev.plugin')} - {t('rev.reverse_analysis')}")

        return '\n'.join(lines)

    def analyze_ipa(self, filepath: str) -> str:
        """iOS IPA 文件分析"""
        import plistlib
        import zipfile

        basename = os.path.basename(filepath)
        lines = [f"=== iOS IPA {t('rev.analysis')}: {basename} ===", ""]

        # IPA 是 ZIP 格式
        if not zipfile.is_zipfile(filepath):
            return f"[-] {basename} {t('rev.ipa.not_ipa')}"

        with zipfile.ZipFile(filepath, 'r') as zf:
            entries = zf.namelist()
            lines.append(f"[*] {t('rev.ipa.total_files')}: {len(entries)}")

            # 查找 .app 目录
            app_dirs = [e for e in entries if e.startswith('Payload/') and e.endswith('.app/')]
            if not app_dirs:
                app_dirs = [e for e in entries if '.app/' in e]
            app_prefix = app_dirs[0] if app_dirs else "Payload/App.app/"
            app_name = app_prefix.split('/')[-2] if '/' in app_prefix else "Unknown"
            lines.append(f"[*] App: {app_name}")

            # Info.plist 解析
            plist_path = f"{app_prefix}Info.plist"
            lines.append("\n=== Info.plist ===")
            if plist_path in entries:
                try:
                    plist_data = zf.read(plist_path)
                    info = plistlib.loads(plist_data)
                    key_fields = [
                        ('CFBundleIdentifier', 'Bundle ID'),
                        ('CFBundleName', 'App Name'),
                        ('CFBundleShortVersionString', 'Version'),
                        ('CFBundleVersion', 'Build'),
                        ('MinimumOSVersion', 'Min iOS'),
                        ('CFBundleExecutable', 'Executable'),
                        ('DTSDKName', 'SDK'),
                        ('DTPlatformName', 'Platform'),
                    ]
                    for key, label in key_fields:
                        if key in info:
                            lines.append(f"  {label}: {info[key]}")

                    # URL Schemes
                    url_types = info.get('CFBundleURLTypes', [])
                    if url_types:
                        lines.append("\n  URL Schemes:")
                        for ut in url_types:
                            schemes = ut.get('CFBundleURLSchemes', [])
                            for s in schemes:
                                lines.append(f"    - {s}://")

                    # App Transport Security
                    ats = info.get('NSAppTransportSecurity', {})
                    if ats:
                        lines.append("\n  App Transport Security:")
                        if ats.get('NSAllowsArbitraryLoads'):
                            lines.append(f"    [!] NSAllowsArbitraryLoads = YES ({t('rev.ipa.ats_disabled')})")
                        else:
                            lines.append(f"    [+] ATS {t('rev.ipa.ats_enabled')}")

                    # 权限 (Privacy keys)
                    lines.append(f"\n  {t('rev.ipa.permissions')}:")
                    permission_count = 0
                    for key, val in info.items():
                        if key.startswith('NS') and 'UsageDescription' in key:
                            perm_name = key.replace('NS', '').replace('UsageDescription', '')
                            lines.append(f"    - {perm_name}: {val}")
                            permission_count += 1
                    if permission_count == 0:
                        lines.append(f"    ({t('rev.ipa.no_permissions')})")

                except Exception as e:
                    lines.append(f"  [{t('rev.ipa.parse_fail')}]: {e}")
            else:
                lines.append(f"  [-] Info.plist {t('rev.not_found')}")

            # Mach-O 二进制检测
            lines.append(f"\n=== Mach-O {t('rev.analysis')} ===")
            exe_name = app_name
            try:
                if plist_path in entries:
                    plist_data = zf.read(plist_path)
                    info = plistlib.loads(plist_data)
                    exe_name = info.get('CFBundleExecutable', app_name)
            except Exception:
                pass

            exe_path = f"{app_prefix}{exe_name}"
            if exe_path in entries:
                exe_data = zf.read(exe_path)
                # Mach-O magic numbers
                if len(exe_data) >= 4:
                    magic = int.from_bytes(exe_data[:4], 'little')
                    magic_map = {
                        0xfeedface: "Mach-O 32-bit",
                        0xfeedfacf: "Mach-O 64-bit",
                        0xcafebabe: "Universal (FAT) Binary",
                        0xbebafeca: "Universal (FAT) Binary (swapped)",
                    }
                    mtype = magic_map.get(magic, f"Unknown (0x{magic:08x})")
                    lines.append(f"  {t('rev.ipa.binary_type')}: {mtype}")
                    lines.append(f"  {t('rev.ipa.binary_size')}: {len(exe_data):,} bytes")

                    # 检查加密标记 (LC_ENCRYPTION_INFO)
                    if b'cryptid' in exe_data or b'\x21\x00\x00\x00' in exe_data[:1024]:
                        lines.append(f"  [!] {t('rev.ipa.encrypted')}")
                    else:
                        lines.append(f"  [+] {t('rev.ipa.not_encrypted')}")
            else:
                lines.append(f"  [-] {exe_name} {t('rev.not_found')}")

            # 框架依赖
            frameworks = [e for e in entries if '.framework/' in e and e.endswith('/')]
            fw_names = list(set(e.split('.framework/')[0].split('/')[-1] for e in frameworks if '.framework/' in e))
            if fw_names:
                lines.append(f"\n=== Frameworks ({len(fw_names)}) ===")
                for fw in sorted(fw_names)[:30]:
                    lines.append(f"  - {fw}.framework")

            # 字符串提取（搜索 URL/API/密钥）
            lines.append(f"\n=== {t('rev.ipa.sensitive_strings')} ===")
            if exe_path in entries:
                exe_data = zf.read(exe_path)
                text = extract_printable_strings(exe_data, min_length=8)
                sensitive = []
                for line_str in text.split('\n'):
                    s = line_str.strip()
                    if any(kw in s.lower() for kw in ['http://', 'https://', 'api.', '/api/',
                                                       'secret', 'password', 'token', 'key=',
                                                       'firebase', 'amazonaws']):
                        sensitive.append(s)
                if sensitive:
                    for s in sensitive[:20]:
                        lines.append(f"  {s}")
                    if len(sensitive) > 20:
                        lines.append(f"  ... (+{len(sensitive) - 20} more)")
                else:
                    lines.append(f"  ({t('rev.ipa.no_sensitive')})")

            # Entitlements
            ent_path = f"{app_prefix}embedded.mobileprovision"
            if ent_path in entries:
                lines.append("\n=== Entitlements ===")
                try:
                    prov_data = zf.read(ent_path)
                    # 提取 plist 部分
                    start = prov_data.find(b'<?xml')
                    end = prov_data.find(b'</plist>') + len(b'</plist>')
                    if start >= 0 and end > start:
                        plist_xml = prov_data[start:end]
                        prov = plistlib.loads(plist_xml)
                        ents = prov.get('Entitlements', {})
                        for key, val in ents.items():
                            lines.append(f"  {key}: {val}")
                except Exception:
                    lines.append(f"  ({t('rev.ipa.parse_fail')})")

        # 推荐工具
        lines.append(f"\n=== {t('rev.recommended_tools')} ===")
        lines.append(f"  class-dump — {t('rev.ipa.tool_classdump')}")
        lines.append(f"  Hopper/IDA — {t('rev.ipa.tool_disasm')}")
        lines.append(f"  Frida — {t('rev.ipa.tool_frida')}")
        lines.append(f"  objection — {t('rev.ipa.tool_objection')}")
        lines.append(f"  MachOView — {t('rev.ipa.tool_machoview')}")

        return '\n'.join(lines)
