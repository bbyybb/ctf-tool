# -*- coding: utf-8 -*-
"""区块链模块单元测试"""

from ctftool.modules.blockchain import BlockchainModule


class TestBlockchainVulnDetection:
    """漏洞检测测试"""

    def setup_method(self):
        self.bc = BlockchainModule()

    def test_analyze_contract_basic(self):
        source = """
        pragma solidity ^0.7.0;
        contract Vulnerable {
            mapping(address => uint) balances;
            function withdraw() public {
                msg.sender.call{value: balances[msg.sender]}("");
                balances[msg.sender] = 0;
            }
        }
        """
        result = self.bc.analyze_contract(source)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_analyze_contract_empty(self):
        result = self.bc.analyze_contract("")
        assert isinstance(result, str)

    def test_detect_reentrancy_vulnerable(self):
        source = """
        function withdraw() public {
            msg.sender.call{value: balances[msg.sender]}("");
            balances[msg.sender] = 0;
        }
        """
        result = self.bc.detect_reentrancy(source)
        assert isinstance(result, str)
        assert "call" in result.lower() or "!" in result

    def test_detect_reentrancy_safe(self):
        source = """
        function withdraw() public nonReentrant {
            uint amount = balances[msg.sender];
            balances[msg.sender] = 0;
            msg.sender.call{value: amount}("");
        }
        """
        result = self.bc.detect_reentrancy(source)
        assert isinstance(result, str)

    def test_detect_integer_overflow(self):
        source = """
        pragma solidity ^0.7.0;
        function add(uint a, uint b) public returns (uint) {
            return a + b;
        }
        """
        result = self.bc.detect_integer_overflow(source)
        assert isinstance(result, str)

    def test_detect_tx_origin(self):
        source = """
        function onlyOwner() public {
            require(tx.origin == owner);
        }
        """
        result = self.bc.detect_tx_origin(source)
        assert isinstance(result, str)
        assert "tx.origin" in result

    def test_detect_selfdestruct(self):
        source = """
        function destroy() public {
            selfdestruct(payable(msg.sender));
        }
        """
        result = self.bc.detect_selfdestruct(source)
        assert isinstance(result, str)

    def test_detect_unchecked_call(self):
        source = """
        function send(address to) public {
            to.call{value: 1 ether}("");
        }
        """
        result = self.bc.detect_unchecked_call(source)
        assert isinstance(result, str)

    def test_detect_no_source(self):
        result = self.bc.detect_reentrancy("")
        assert isinstance(result, str)


class TestBlockchainABI:
    """ABI 工具测试"""

    def setup_method(self):
        self.bc = BlockchainModule()

    def test_abi_decode_transfer(self):
        # transfer(address,uint256) selector = a9059cbb
        data = "a9059cbb000000000000000000000000" + "ab" * 16 + "0" * 63 + "1"
        result = self.bc.abi_decode(data)
        assert isinstance(result, str)
        assert "a9059cbb" in result

    def test_abi_decode_short(self):
        result = self.bc.abi_decode("ab")
        assert isinstance(result, str)

    def test_abi_decode_empty(self):
        result = self.bc.abi_decode("")
        assert isinstance(result, str)

    def test_abi_encode_transfer(self):
        result = self.bc.abi_encode("transfer(address,uint256)")
        assert isinstance(result, str)
        assert "a9059cbb" in result

    def test_abi_encode_empty(self):
        result = self.bc.abi_encode("")
        assert isinstance(result, str)

    def test_selector_lookup_known(self):
        result = self.bc.selector_lookup("transfer(address,uint256)")
        assert isinstance(result, str)
        assert "a9059cbb" in result

    def test_selector_lookup_hex(self):
        result = self.bc.selector_lookup("0xa9059cbb")
        assert isinstance(result, str)
        assert "transfer" in result

    def test_selector_lookup_unknown(self):
        result = self.bc.selector_lookup("0xdeadbeef")
        assert isinstance(result, str)


class TestBlockchainBytecode:
    """字节码分析测试"""

    def setup_method(self):
        self.bc = BlockchainModule()

    def test_disasm_basic(self):
        # PUSH1 0x60 PUSH1 0x40 MSTORE
        result = self.bc.disasm_bytecode("6060604052")
        assert isinstance(result, str)
        assert "PUSH1" in result

    def test_disasm_empty(self):
        result = self.bc.disasm_bytecode("")
        assert isinstance(result, str)

    def test_disasm_invalid(self):
        result = self.bc.disasm_bytecode("xyz")
        assert isinstance(result, str)

    def test_storage_layout(self):
        result = self.bc.storage_layout_helper("uint256 balance;\naddress owner;")
        assert isinstance(result, str)
        assert "slot" in result.lower()

    def test_storage_layout_empty(self):
        result = self.bc.storage_layout_helper("")
        assert isinstance(result, str)


class TestBlockchainTemplates:
    """攻击模板测试"""

    def setup_method(self):
        self.bc = BlockchainModule()

    def test_flashloan_template(self):
        result = self.bc.flashloan_template()
        assert isinstance(result, str)
        assert "flash" in result.lower() or "IFlash" in result

    def test_reentrancy_exploit_template(self):
        result = self.bc.reentrancy_exploit_template()
        assert isinstance(result, str)
        assert "attack" in result.lower() or "Attack" in result

    def test_evm_puzzle_helper(self):
        result = self.bc.evm_puzzle_helper()
        assert isinstance(result, str)
        assert "PUSH" in result or "JUMP" in result

    def test_common_patterns(self):
        result = self.bc.common_patterns()
        assert isinstance(result, str)
        assert len(result) > 100
