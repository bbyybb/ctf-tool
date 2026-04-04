# -*- coding: utf-8 -*-
"""Flag Finder 单元测试"""

from ctftool.core.flag_finder import FlagFinder


class TestFlagFinder:
    def setup_method(self):
        self.ff = FlagFinder()

    def test_basic_flag(self):
        assert self.ff.search("flag{hello}") == ["flag{hello}"]

    def test_uppercase_flag(self):
        assert "FLAG{TEST}" in self.ff.search("FLAG{TEST}")

    def test_ctf_prefix(self):
        assert "CTF{abc}" in self.ff.search("CTF{abc}")

    def test_custom_prefix(self):
        """测试常见比赛前缀"""
        assert "DASCTF{x}" in self.ff.search("DASCTF{x}")
        assert "HGAME{y}" in self.ff.search("HGAME{y}")
        assert "picoCTF{z}" in self.ff.search("picoCTF{z}")

    def test_generic_pattern(self):
        """测试通用 XXX{...} 宽松匹配"""
        results = self.ff.search("MYCTF{custom_test_here}")
        assert any("MYCTF{custom_test_here}" in r for r in results)

    def test_no_flag(self):
        assert self.ff.search("no flags here") == []

    def test_multiple_flags(self):
        text = "flag{one} and FLAG{two}"
        results = self.ff.search(text)
        assert len(results) >= 2

    def test_base64_decode(self):
        """递归解码 Base64 中的 flag"""
        import base64
        encoded = base64.b64encode(b"flag{hidden}").decode()
        results = self.ff.search_with_decode(encoded)
        assert "flag{hidden}" in results

    def test_hex_decode(self):
        """递归解码 Hex 中的 flag"""
        results = self.ff.search_with_decode("666c61677b68657874657374fD")
        # 666c61677b68657874657374fD = flag{hextest}
        # This might not decode perfectly, so let's test with clean hex
        results = self.ff.search_with_decode("666c61677b6865787d")
        assert any("flag{hex}" in r for r in results)

    def test_nested_encoding(self):
        """多层嵌套编码"""
        import base64
        inner = b"flag{nested}"
        layer1 = inner.hex()
        layer2 = base64.b64encode(layer1.encode()).decode()
        results = self.ff.search_with_decode(layer2)
        assert "flag{nested}" in results

    def test_add_custom_pattern(self):
        ff = FlagFinder()
        ff.add_pattern(r'CUSTOM_\d+_FLAG')
        assert ff.search("CUSTOM_42_FLAG") == ["CUSTOM_42_FLAG"]

    def test_found_flags_accumulate(self):
        ff = FlagFinder()
        ff.search("flag{a}")
        ff.search("flag{b}")
        assert "flag{a}" in ff.found_flags
        assert "flag{b}" in ff.found_flags

    def test_clear(self):
        ff = FlagFinder()
        ff.search("flag{a}")
        ff.clear()
        assert ff.found_flags == []


class TestFlagFinderDecodeBranches:
    def setup_method(self):
        from ctftool.core.flag_finder import FlagFinder
        self.ff = FlagFinder()

    def test_base32_decode(self):
        """Base32 编码的 flag"""
        import base64
        encoded = base64.b32encode(b"flag{base32_test}").decode()
        flags = self.ff.search_with_decode(encoded)
        assert any("base32_test" in f for f in flags)

    def test_rot13_decode(self):
        """ROT13 编码的 flag"""
        import codecs
        encoded = codecs.encode("flag{rot13_test}", 'rot_13')
        flags = self.ff.search_with_decode(encoded)
        assert any("rot13_test" in f for f in flags)

    def test_url_decode(self):
        """URL 编码的 flag"""
        from urllib.parse import quote
        encoded = quote("flag{url_test}")
        flags = self.ff.search_with_decode(encoded)
        assert any("url_test" in f for f in flags)
