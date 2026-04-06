# -*- coding: utf-8 -*-
"""Web 模块单元测试（非网络部分）"""

from ctftool.modules.web import WebModule


class TestWebPayloads:
    def setup_method(self):
        self.w = WebModule()

    def test_gen_sqli_payload(self):
        result = self.w.generate_payload("sqli")
        assert "UNION" in result
        assert "OR" in result

    def test_gen_xss_payload(self):
        result = self.w.generate_payload("xss")
        assert "script" in result
        assert "alert" in result

    def test_gen_ssti_payload(self):
        result = self.w.generate_payload("ssti")
        assert "{{7*7}}" in result

    def test_gen_lfi_payload(self):
        result = self.w.generate_payload("lfi")
        assert "etc/passwd" in result

    def test_gen_cmdi_payload(self):
        result = self.w.generate_payload("cmdi")
        assert "id" in result

    def test_gen_unknown_type(self):
        result = self.w.generate_payload("unknown")
        assert "支持的类型" in result or "Supported types" in result


class TestJWT:
    def setup_method(self):
        self.w = WebModule()

    def _make_jwt(self, alg="HS256"):
        import base64
        import json
        h = base64.urlsafe_b64encode(json.dumps({"alg": alg, "typ": "JWT"}).encode()).rstrip(b'=').decode()
        p = base64.urlsafe_b64encode(json.dumps({"sub": "1", "name": "test"}).encode()).rstrip(b'=').decode()
        return f"{h}.{p}.fakesig"

    def test_jwt_forge_none(self):
        token = self._make_jwt("HS256")
        result = self.w.jwt_forge_none(token)
        assert "HS256" in result  # 原始算法
        assert "none" in result    # 伪造算法

    def test_jwt_forge_invalid(self):
        result = self.w.jwt_forge_none("not.a.valid")
        # 应该不会崩溃
        assert isinstance(result, str)

    def test_jwt_crack_no_match(self):
        token = self._make_jwt()
        result = self.w.jwt_crack(token)
        assert "失败" in result or "成功" in result or "failed" in result.lower() or "success" in result.lower()


class TestWebDetection:
    """Web 检测方法测试（无需真实网络，测试参数解析和错误处理）"""

    def setup_method(self):
        self.w = WebModule(timeout=2)

    def test_analyze_headers_no_url(self):
        """无网络时应抛出异常或返回错误"""
        try:
            self.w.analyze_headers("http://127.0.0.1:1")
        except Exception:
            pass  # 连接拒绝是预期行为

    def test_detect_sqli_no_params(self):
        result = self.w.detect_sqli("http://example.com/")
        assert "无参数" in result or "no param" in result.lower()

    def test_detect_xss_no_params(self):
        result = self.w.detect_xss("http://example.com/")
        assert "无参数" in result or "no param" in result.lower()

    def test_detect_lfi_no_params(self):
        result = self.w.detect_lfi("http://example.com/")
        assert "无参数" in result or "no param" in result.lower()

    def test_detect_cmdi_no_params(self):
        result = self.w.detect_cmdi("http://example.com/")
        assert "无参数" in result or "no param" in result.lower()

    def test_detect_ssrf_no_params(self):
        result = self.w.detect_ssrf("http://example.com/")
        assert "未发现" in result or "无参数" in result or "no param" in result.lower()

    def test_detect_ssti_no_params(self):
        result = self.w.detect_ssti("http://example.com/")
        assert "无参数" in result or "no param" in result.lower()

    def test_check_robots_unreachable(self):
        try:
            self.w.check_robots("http://127.0.0.1:1")
        except Exception:
            pass

    def test_check_git_leak_unreachable(self):
        try:
            self.w.check_git_leak("http://127.0.0.1:1")
        except Exception:
            pass

    def test_dir_scan_unreachable(self):
        try:
            self.w.dir_scan("http://127.0.0.1:1")
        except Exception:
            pass


class TestWebNewFeatures:
    """测试批次2-3新增的 Web 功能"""

    def setup_method(self):
        from ctftool.modules.web import WebModule
        self.web = WebModule(timeout=2)

    def test_detect_open_redirect_no_params(self):
        result = self.web.detect_open_redirect('http://example.com/')
        assert '无参数' in result or 'no param' in result.lower() or 'Redirect' in result

    def test_detect_crlf_unreachable(self):
        result = self.web.detect_crlf('http://192.0.2.1/')
        assert 'CRLF' in result

    def test_deserialize_helper(self):
        result = self.web.deserialize_helper()
        assert 'PHP' in result and 'Java' in result and 'Python' in result


class TestWebBatch12Features:
    """测试批次1-2新增的 Web 功能"""

    def setup_method(self):
        from ctftool.modules.web import WebModule
        self.web = WebModule(timeout=2)

    def test_detect_xxe_unreachable(self):
        result = self.web.detect_xxe('http://192.0.2.1/')
        assert 'XXE' in result

    def test_detect_cors_unreachable(self):
        result = self.web.detect_cors('http://192.0.2.1/')
        assert 'CORS' in result


class TestWebBatch13:
    def setup_method(self):
        self.web = WebModule(timeout=2)

    def test_detect_path_traversal_no_params(self):
        result = self.web.detect_path_traversal("http://example.com/")
        assert isinstance(result, str)

    def test_prototype_pollution_helper(self):
        result = self.web.prototype_pollution_helper()
        assert "__proto__" in result

    def test_race_condition_helper(self):
        result = self.web.race_condition_helper()
        assert "threading" in result.lower() or "并发" in result

    def test_detect_http_smuggling_unreachable(self):
        result = self.web.detect_http_smuggling("http://192.0.2.1:1/test")
        assert isinstance(result, str)

    def test_detect_waf_unreachable(self):
        result = self.web.detect_waf("http://192.0.2.1:1/test")
        assert isinstance(result, str)


class TestNewWebFeatures:
    def setup_method(self):
        self.web = WebModule(timeout=2)

    def test_subdomain_enum(self):
        import socket
        from unittest.mock import patch
        with patch("socket.gethostbyname", side_effect=socket.gaierror("mocked")):
            result = self.web.subdomain_enum("example.com")
        assert "子域名" in result or "subdomain" in result.lower()
        assert isinstance(result, str)

    def test_fingerprint_unreachable(self):
        try:
            result = self.web.fingerprint("http://192.0.2.1:1/test")
        except Exception:
            result = "error"
        assert isinstance(result, str)

    def test_info_gather_unreachable(self):
        try:
            result = self.web.info_gather("http://192.0.2.1:1/test")
        except Exception:
            result = "error"
        assert isinstance(result, str)


class TestNewWebDetections:
    """测试新增的 7 个 Web 检测方法（不崩溃 + 不可达 URL 模式）"""

    UNREACHABLE_URL = "http://127.0.0.1:19999/test"

    def setup_method(self):
        self.web = WebModule(timeout=2)

    def test_detect_svn_leak_unreachable(self):
        result = self.web.detect_svn_leak(self.UNREACHABLE_URL)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_detect_ds_store_unreachable(self):
        result = self.web.detect_ds_store(self.UNREACHABLE_URL)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_detect_backup_files_unreachable(self):
        result = self.web.detect_backup_files(self.UNREACHABLE_URL)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_detect_env_leak_unreachable(self):
        result = self.web.detect_env_leak(self.UNREACHABLE_URL)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_detect_graphql_unreachable(self):
        result = self.web.detect_graphql(self.UNREACHABLE_URL)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_detect_host_injection_unreachable(self):
        result = self.web.detect_host_injection(self.UNREACHABLE_URL)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_detect_jsonp_unreachable(self):
        result = self.web.detect_jsonp(self.UNREACHABLE_URL)
        assert isinstance(result, str)
        assert len(result) > 0


class TestLatestWebFeatures:
    """测试最新新增的 detect_swagger / sqli_auto_exploit"""

    UNREACHABLE_URL = "http://127.0.0.1:19999/test"

    def setup_method(self):
        self.web = WebModule(timeout=2)

    def test_detect_swagger_unreachable(self):
        """不可达 URL 不崩溃，返回非空字符串"""
        result = self.web.detect_swagger(self.UNREACHABLE_URL)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_sqli_auto_exploit_unreachable(self):
        """不可达 URL 不崩溃，返回非空字符串"""
        result = self.web.sqli_auto_exploit(self.UNREACHABLE_URL)
        assert isinstance(result, str)
        assert len(result) > 0


class TestWebUtilities:
    def setup_method(self):
        from ctftool.modules.web import WebModule
        self.web = WebModule(timeout=2)

    def test_parse_curl_basic(self):
        result = self.web.parse_curl("curl 'https://example.com' -H 'Auth: token'")
        assert "example.com" in result
        assert "Auth" in result

    def test_parse_curl_with_data(self):
        result = self.web.parse_curl("curl 'https://example.com' -d 'test=123'")
        assert "POST" in result

    def test_parse_curl_invalid(self):
        result = self.web.parse_curl("")
        assert isinstance(result, str)

    def test_close_no_crash(self):
        self.web.close()  # 不崩溃

    def test_close_twice(self):
        self.web.close()
        self.web.close()  # 再次调用不崩溃

    def test_dir_listing_crawl_unreachable(self):
        result = self.web.dir_listing_crawl("http://127.0.0.1:19999/test")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_dir_listing_crawl_no_listing(self):
        """非目录列表页面不崩溃"""
        result = self.web.dir_listing_crawl("http://127.0.0.1:19999/")
        assert isinstance(result, str)


class TestWebConfigure:
    """测试 WebModule.configure 方法"""

    def setup_method(self):
        self.web = WebModule(timeout=2)

    def test_configure_headers(self):
        """配置自定义 headers"""
        self.web.configure(headers={"X-Custom": "test"})
        assert self.web.session.headers.get("X-Custom") == "test"

    def test_configure_cookies(self):
        """配置自定义 cookies"""
        self.web.configure(cookies={"session": "abc123"})
        assert self.web.session.cookies.get("session") == "abc123"

    def test_configure_no_crash_empty(self):
        """空参数调用不崩溃"""
        self.web.configure()


class TestCSRFDetection:
    """测试 CSRF 检测"""

    def setup_method(self):
        self.web = WebModule(timeout=2)

    def test_detect_csrf_unreachable(self):
        result = self.web.detect_csrf("http://127.0.0.1:1/")
        assert isinstance(result, str)
        assert "CSRF" in result or "connect" in result.lower()

    def test_detect_csrf_no_crash(self):
        result = self.web.detect_csrf("http://127.0.0.1:19999/")
        assert isinstance(result, str)


class TestFileUploadHelper:
    """测试文件上传绕过辅助"""

    def setup_method(self):
        self.web = WebModule(timeout=2)

    def test_file_upload_helper_basic(self):
        result = self.web.file_upload_helper()
        assert isinstance(result, str)
        assert "Content-Type" in result
        assert ".php" in result
        assert ".htaccess" in result
        assert "GIF89a" in result

    def test_file_upload_helper_with_url(self):
        result = self.web.file_upload_helper("http://example.com/upload")
        assert isinstance(result, str)
        assert "Content-Type" in result


class TestCodeAudit:
    """测试源码审计"""

    def setup_method(self):
        self.web = WebModule(timeout=2)

    def test_code_audit_php_lfi(self):
        php = '<?php include $_GET["file"]; ?>'
        result = self.web.code_audit(php)
        assert "LFI" in result or "File Inclusion" in result

    def test_code_audit_php_strpos(self):
        php = '<?php if(!strpos($_GET["x"],"flag")) include $_GET["x"]; ?>'
        result = self.web.code_audit(php)
        assert "strpos" in result

    def test_code_audit_python_ssti(self):
        py = 'from flask import *\nrender_template_string(request.args.get("t"))'
        result = self.web.code_audit(py)
        assert "SSTI" in result or "Template" in result

    def test_code_audit_empty(self):
        result = self.web.code_audit("")
        assert isinstance(result, str)

    def test_xxe_payload_helper(self):
        result = self.web.xxe_payload_helper()
        assert "XXE" in result and "file://" in result

    def test_ssrf_payload_helper(self):
        result = self.web.ssrf_payload_helper()
        assert "SSRF" in result and "127.0.0.1" in result

    def test_waf_bypass_helper(self):
        result = self.web.waf_bypass_helper()
        assert "WAF" in result and "SQL" in result


class TestForensicsCheatsheet:
    def test_tool_cheatsheet(self):
        from ctftool.modules.forensics import ForensicsModule
        f = ForensicsModule()
        result = f.tool_cheatsheet()
        assert "steghide" in result.lower()
        assert "binwalk" in result.lower()
        assert "volatility" in result.lower()


class TestReverseCheatsheet:
    def test_tool_cheatsheet(self):
        from ctftool.modules.reverse import ReverseModule
        r = ReverseModule()
        result = r.tool_cheatsheet()
        assert "gdb" in result.lower()
        assert "objdump" in result.lower()
        assert "ROPgadget" in result


class TestSqliTimeBlind:
    """测试 sqli_time_blind（不可达 URL 模式）"""

    def setup_method(self):
        self.web = WebModule(timeout=2)

    def test_sqli_time_blind_unreachable(self):
        """不可达 URL 不崩溃"""
        result = self.web.sqli_time_blind("http://127.0.0.1:1/?id=1")
        assert isinstance(result, str)

    def test_sqli_time_blind_no_params(self):
        """无参数 URL"""
        result = self.web.sqli_time_blind("http://example.com/")
        assert isinstance(result, str)
