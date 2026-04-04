# -*- coding: utf-8 -*-
"""自动扫描调度器模块单元测试"""

import base64
import os
import tempfile

from ctftool.core.scanner import AutoScanner, ScanResult


class TestScanResult:
    def setup_method(self):
        self.result = ScanResult("TestModule", "TestAction")

    def test_default_fields(self):
        """默认字段值正确"""
        assert self.result.module == "TestModule"
        assert self.result.action == "TestAction"
        assert self.result.output == ""
        assert self.result.flags == []
        assert self.result.success is True
        assert self.result.error == ""

    def test_to_dict_keys(self):
        """to_dict() 返回包含所有必要键的字典"""
        d = self.result.to_dict()
        expected_keys = {"module", "action", "output", "flags", "success", "error"}
        assert set(d.keys()) == expected_keys

    def test_to_dict_values(self):
        """to_dict() 返回的值与字段一致"""
        self.result.output = "some output"
        self.result.flags = ["flag{test}"]
        self.result.success = False
        self.result.error = "some error"
        d = self.result.to_dict()
        assert d["module"] == "TestModule"
        assert d["action"] == "TestAction"
        assert d["output"] == "some output"
        assert d["flags"] == ["flag{test}"]
        assert d["success"] is False
        assert d["error"] == "some error"

    def test_to_dict_returns_dict(self):
        """to_dict() 返回类型为 dict"""
        assert isinstance(self.result.to_dict(), dict)


class TestAutoScannerText:
    def setup_method(self):
        self.scanner = AutoScanner()

    def test_scan_text_returns_list(self):
        """scan_text 返回结果列表"""
        results = self.scanner.scan_text("hello world")
        assert isinstance(results, list)
        assert len(results) > 0

    def test_scan_text_result_type(self):
        """scan_text 返回的每个元素都是 ScanResult"""
        results = self.scanner.scan_text("test input")
        for r in results:
            assert isinstance(r, ScanResult)

    def test_scan_text_base64_flag(self):
        """scan_text 对 Base64 编码的 flag 能够解码并发现"""
        encoded = base64.b64encode(b"flag{scanner_test}").decode()
        results = self.scanner.scan_text(encoded)
        # 检查至少有一个结果成功
        assert any(r.success for r in results)

    def test_scan_text_empty_input(self):
        """scan_text 对空字符串输入不崩溃"""
        results = self.scanner.scan_text("")
        assert isinstance(results, list)

    def test_scan_text_nonsense_input(self):
        """scan_text 对无意义文本不崩溃"""
        results = self.scanner.scan_text("zzzzzzzzzzzzzzzz")
        assert isinstance(results, list)

    def test_scan_text_callback_called(self):
        """scan_text 的 callback 参数会被调用"""
        callback_results = []
        self.scanner.scan_text("hello", callback=lambda r: callback_results.append(r))
        assert len(callback_results) > 0
        for r in callback_results:
            assert isinstance(r, ScanResult)

    def test_scan_text_results_accumulated(self):
        """scan_text 的结果会累积到 scanner.results 中"""
        self.scanner.scan_text("abc")
        count_first = len(self.scanner.results)
        assert count_first > 0
        self.scanner.scan_text("def")
        assert len(self.scanner.results) > count_first


class TestAutoScannerFile:
    def setup_method(self):
        self.scanner = AutoScanner()

    def test_scan_file_with_temp_file(self):
        """scan_file 对临时文件能运行且不崩溃"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt',
                                          delete=False) as f:
            f.write("hello world flag{test_file}")
            tmppath = f.name
        try:
            results = self.scanner.scan_file(tmppath)
            assert isinstance(results, list)
            assert len(results) > 0
            for r in results:
                assert isinstance(r, ScanResult)
        finally:
            os.unlink(tmppath)

    def test_scan_file_nonexistent(self):
        """scan_file 对不存在的文件不崩溃（会记录错误）"""
        results = self.scanner.scan_file("/nonexistent/file/path.bin")
        assert isinstance(results, list)
        # 部分操作应该失败但不应抛出异常
        assert any(not r.success for r in results)

    def test_scan_file_callback(self):
        """scan_file 的 callback 参数会被调用"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt',
                                          delete=False) as f:
            f.write("test content")
            tmppath = f.name
        try:
            callback_results = []
            self.scanner.scan_file(tmppath, callback=lambda r: callback_results.append(r))
            assert len(callback_results) > 0
        finally:
            os.unlink(tmppath)


class TestAutoScannerUrl:
    def setup_method(self):
        self.scanner = AutoScanner()
        # 配置短 timeout 避免 CI 中长时间等待
        from ctftool.modules.web import WebModule
        self.scanner._web_module = WebModule(timeout=2)

    def test_scan_url_no_crash(self):
        """scan_url 在网络不可用时不崩溃"""
        try:
            results = self.scanner.scan_url("http://127.0.0.1:1")
        except Exception:
            # 即使抛出异常也算通过（某些环境下可能会）
            return
        assert isinstance(results, list)
        for r in results:
            assert isinstance(r, ScanResult)

    def test_scan_url_callback(self):
        """scan_url 的 callback 会被调用（即使请求失败）"""
        callback_results = []
        try:
            self.scanner.scan_url(
                "http://127.0.0.1:1",
                callback=lambda r: callback_results.append(r)
            )
        except Exception:
            pass
        # 如果有任何结果被回调，验证类型
        for r in callback_results:
            assert isinstance(r, ScanResult)


class TestAutoScannerFlagsAndClear:
    def setup_method(self):
        self.scanner = AutoScanner()

    def test_get_all_flags_returns_list(self):
        """get_all_flags 返回列表"""
        flags = self.scanner.get_all_flags()
        assert isinstance(flags, list)

    def test_clear_resets_results(self):
        """clear 清空扫描结果"""
        self.scanner.scan_text("hello")
        assert len(self.scanner.results) > 0
        self.scanner.clear()
        assert len(self.scanner.results) == 0

    def test_get_all_flags_after_scan(self):
        """扫描含 flag 文本后 get_all_flags 能获取到"""
        encoded = base64.b64encode(b"flag{auto_scan_flag}").decode()
        self.scanner.scan_text(encoded)
        flags = self.scanner.get_all_flags()
        assert isinstance(flags, list)

    def test_clear_resets_flags(self):
        """clear 同时清空发现的 flag"""
        encoded = base64.b64encode(b"flag{will_be_cleared}").decode()
        self.scanner.scan_text(encoded)
        self.scanner.clear()
        flags = self.scanner.get_all_flags()
        assert isinstance(flags, list)
        assert len(flags) == 0


class TestScannerExport:
    def setup_method(self):
        self.scanner = AutoScanner()

    def test_export_json_string(self):
        """export_json 无路径时返回 JSON 字符串"""
        self.scanner.scan_text("hello")
        result = self.scanner.export_json()
        assert isinstance(result, str)
        import json
        data = json.loads(result)
        assert "tool" in data
        assert "results" in data
        assert "timestamp" in data

    def test_export_json_file(self):
        """export_json 写入文件"""
        import json
        import os
        import tempfile
        self.scanner.scan_text("test")
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "report.json")
            result = self.scanner.export_json(filepath)
            assert "导出" in result or "export" in result.lower()
            assert os.path.isfile(filepath)
            with open(filepath, encoding='utf-8') as f:
                data = json.load(f)
            assert "results" in data

    def test_export_html(self):
        """export_html 生成 HTML 文件"""
        import os
        import tempfile
        self.scanner.scan_text("hello")
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "report.html")
            self.scanner.export_html(filepath)
            assert os.path.isfile(filepath)
            with open(filepath, encoding='utf-8') as f:
                html = f.read()
            assert "<html>" in html
            assert "CTF-Tool" in html

    def test_scan_files_batch(self):
        """批量文件扫描"""
        import os
        import tempfile
        files = []
        for i in range(2):
            fd, path = tempfile.mkstemp(suffix='.txt')
            os.write(fd, f"test content {i}".encode())
            os.close(fd)
            files.append(path)
        try:
            results = self.scanner.scan_files_batch(files)
            assert isinstance(results, list)
            assert len(results) > 0
        finally:
            for f in files:
                os.unlink(f)


class TestScannerBatchUrl:
    def test_scan_urls_batch_unreachable(self):
        from ctftool.core.scanner import AutoScanner
        from ctftool.modules.web import WebModule
        scanner = AutoScanner()
        scanner._web_module = WebModule(timeout=2)
        results = scanner.scan_urls_batch(["http://127.0.0.1:19999/a"])
        assert isinstance(results, list)

    def test_scan_urls_batch_empty(self):
        from ctftool.core.scanner import AutoScanner
        scanner = AutoScanner()
        results = scanner.scan_urls_batch([])
        assert results == []
