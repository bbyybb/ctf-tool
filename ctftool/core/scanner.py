# -*- coding: utf-8 -*-
"""自动扫描调度器

根据目标类型（URL/文件/文本）自动选择并运行相关模块。
"""

import html
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from ctftool.core.flag_finder import flag_finder


class ScanResult:
    """单次扫描结果"""

    def __init__(self, module: str, action: str):
        self.module = module
        self.action = action
        self.output: str = ""
        self.flags: list[str] = []
        self.success: bool = True
        self.error: str = ""

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "action": self.action,
            "output": self.output,
            "flags": self.flags,
            "success": self.success,
            "error": self.error,
        }


class AutoScanner:
    """自动扫描调度器"""

    def __init__(self):
        self.results: list[ScanResult] = []
        self._web_module = None

    def configure_web(self, headers: dict = None, cookies: dict = None,
                      proxies: dict = None, auth: tuple = None,
                      curl_cmd: str = None):
        """配置 Web 扫描的 HTTP 请求上下文

        Args:
            headers: 自定义请求头
            cookies: 自定义 cookies
            proxies: 代理设置 {"http": "...", "https": "..."}
            auth: 认证信息 (user, password)
            curl_cmd: curl 命令字符串，自动解析并配置
        """
        from ctftool.modules.web import WebModule
        self._web_module = WebModule()
        if curl_cmd:
            self._web_module.parse_curl(curl_cmd)
        if headers or cookies or proxies or auth:
            self._web_module.configure(headers, cookies, proxies, auth)

    def scan_url(self, url: str, callback=None) -> list[ScanResult]:
        """对 URL 目标并行运行所有 Web 相关扫描"""
        from ctftool.modules.web import WebModule

        # 使用已配置的 WebModule 实例或创建新实例
        web = self._web_module if self._web_module else WebModule()
        results = []

        actions = [
            ("HTTP 头分析", lambda: web.analyze_headers(url)),
            ("robots.txt 检测", lambda: web.check_robots(url)),
            ("敏感路径扫描", lambda: web.dir_scan(url)),
            ("Git 泄露检测", lambda: web.check_git_leak(url)),
            ("SQL 注入检测", lambda: web.detect_sqli(url)),
            ("XSS 检测", lambda: web.detect_xss(url)),
            ("LFI 检测", lambda: web.detect_lfi(url)),
            ("命令注入检测", lambda: web.detect_cmdi(url)),
            ("SSRF 检测", lambda: web.detect_ssrf(url)),
            ("SSTI 检测", lambda: web.detect_ssti(url)),
            ("XXE 检测", lambda: web.detect_xxe(url)),
            ("CORS 检测", lambda: web.detect_cors(url)),
            ("Open Redirect 检测", lambda: web.detect_open_redirect(url)),
            ("CRLF 注入检测", lambda: web.detect_crlf(url)),
            ("目录遍历检测", lambda: web.detect_path_traversal(url)),
            ("WAF 检测", lambda: web.detect_waf(url)),
            ("HTTP 走私检测", lambda: web.detect_http_smuggling(url)),
            ("子域名枚举", lambda: web.subdomain_enum(url)),
            ("Web 指纹识别", lambda: web.fingerprint(url)),
            ("敏感信息收集", lambda: web.info_gather(url)),
            ("SVN 泄露检测", lambda: web.detect_svn_leak(url)),
            (".DS_Store 泄露检测", lambda: web.detect_ds_store(url)),
            ("备份文件检测", lambda: web.detect_backup_files(url)),
            (".env 文件泄露", lambda: web.detect_env_leak(url)),
            ("GraphQL 自省检测", lambda: web.detect_graphql(url)),
            ("Host 头注入检测", lambda: web.detect_host_injection(url)),
            ("JSONP 劫持检测", lambda: web.detect_jsonp(url)),
            ("Swagger/OpenAPI 探测", lambda: web.detect_swagger(url)),
            ("目录列表递归爬取", lambda: web.dir_listing_crawl(url)),
            ("SQL 时间盲注", lambda: web.sqli_time_blind(url)),
            ("CSRF 检测", lambda: web.detect_csrf(url)),
        ]

        def _run_one(name, action):
            result = ScanResult("Web", name)
            try:
                output = action()
                result.output = output
                result.flags = flag_finder.search_with_decode(output)
            except Exception as e:
                result.success = False
                result.error = str(e)
            if callback:
                callback(result)
            return result

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(_run_one, name, action): name for name, action in actions}
            for future in as_completed(futures):
                results.append(future.result())

        self.results.extend(results)
        return results

    def scan_file(self, filepath: str, callback=None) -> list[ScanResult]:
        """对文件目标运行所有相关扫描（根据文件类型智能调度）"""
        from ctftool.core.utils import identify_file_type, read_file_bytes
        from ctftool.modules.forensics import ForensicsModule
        from ctftool.modules.misc import MiscModule
        from ctftool.modules.reverse import ReverseModule

        forensics = ForensicsModule()
        reverse = ReverseModule()
        misc = MiscModule()
        results = []

        # 尝试识别文件类型以智能调度扫描项
        data = b""
        try:
            data = read_file_bytes(filepath)
            file_type = identify_file_type(data) or ""
        except Exception:
            file_type = ""

        ft = file_type.upper()
        ext = os.path.splitext(filepath)[1].lower()

        # ========== 通用扫描（所有文件都跑） ==========
        actions = [
            ("Forensics", "文件类型识别", lambda: forensics.identify_file(filepath)),
            ("Forensics", "元数据/EXIF提取", lambda: forensics.extract_metadata(filepath)),
            ("Forensics", "字符串提取", lambda: forensics.extract_strings(filepath)),
            ("Forensics", "隐藏文件扫描", lambda: forensics.binwalk_scan(filepath)),
            ("Forensics", "文件头修复检测", lambda: forensics.fix_file_header(filepath)),
            ("Forensics", "NTFS ADS 检测", lambda: forensics.detect_ntfs_ads(filepath)),
            ("Forensics", "文件时间线", lambda: forensics.file_timeline(filepath)),
            ("Reverse", "二进制分析", lambda: reverse.analyze_binary(filepath)),
            ("Reverse", "加壳检测", lambda: reverse.detect_packer(filepath)),
            ("Forensics", "精确文件切割", lambda: forensics.file_carve_precise(filepath)),
        ]

        # ========== 图片类文件 ==========
        if "PNG" in ft or "JPEG" in ft or "GIF" in ft or "BMP" in ft:
            actions.append(("Forensics", "隐写分析", lambda: forensics.detect_stego(filepath)))
            actions.append(("Forensics", "图片通道分离", lambda: forensics.split_channels(filepath)))
            actions.append(("Forensics", "EXIF 篡改检测", lambda: forensics.detect_exif_tampering(filepath)))
            actions.append(("Forensics", "高级 LSB 提取", lambda: forensics.lsb_extract_advanced(filepath)))
            actions.append(("Forensics", "位平面分析", lambda: forensics.bit_plane_analysis(filepath)))
            actions.append(("Misc", "像素文本提取", lambda: misc.pixel_extract(filepath)))
            if "PNG" in ft or "BMP" in ft:
                actions.append(("Forensics", "zsteg 隐写扫描", lambda: forensics.zsteg_scan(filepath)))
            if "PNG" in ft or "JPEG" in ft or "BMP" in ft:
                actions.append(("Forensics", "盲水印提取", lambda: forensics.blind_watermark_extract(filepath)))
            if "JPEG" in ft:
                actions.append(("Forensics", "steghide 提取", lambda: forensics.steghide_extract(filepath)))
            if "PNG" in ft:
                actions.append(("Forensics", "PNG 宽高修复", lambda: forensics.png_crc_fix(filepath)))
                actions.append(("Forensics", "APNG 帧提取", lambda: forensics.apng_extract(filepath)))
            if "GIF" in ft:
                actions.append(("Forensics", "GIF 帧提取", lambda: forensics.gif_frame_extract(filepath)))

        # ========== 图片类 - QR/条码解码 ==========
        if "PNG" in ft or "JPEG" in ft or "BMP" in ft:
            actions.append(("Misc", "QR 码解码", lambda: misc.qr_decode(filepath)))
            actions.append(("Misc", "条形码解码", lambda: misc.barcode_decode(filepath)))

        # ========== 压缩包类文件 ==========
        if "ZIP" in ft or ext == '.zip':
            actions.append(("Forensics", "ZIP 密码爆破", lambda: forensics.zip_crack(filepath)))
            actions.append(("Forensics", "ZIP 伪加密修复", lambda: forensics.zip_fake_decrypt(filepath)))
        if "RAR" in ft or ext == '.rar':
            actions.append(("Forensics", "RAR 密码爆破", lambda: forensics.rar_crack(filepath)))

        # ========== 网络流量 PCAP ==========
        if "PCAP" in ft or ext in ('.pcap', '.pcapng', '.cap'):
            actions.append(("Forensics", "PCAP 流量分析", lambda: forensics.pcap_analyze(filepath)))
            actions.append(("Forensics", "PCAP HTTP 提取", lambda: forensics.pcap_extract_http(filepath)))
            actions.append(("Forensics", "USB 键盘解码", lambda: forensics.usb_keyboard_decode(filepath)))
            actions.append(("Forensics", "USB 鼠标解码", lambda: forensics.usb_mouse_decode(filepath)))
            actions.append(("Forensics", "DNS 隧道检测", lambda: forensics.detect_dns_tunnel(filepath)))
            actions.append(("Forensics", "PCAP 文件导出", lambda: forensics.pcap_extract_files(filepath)))

        # ========== 音频文件 ==========
        if "WAV" in ft or "RIFF" in ft or ext in ('.wav', '.mp3', '.ogg', '.flac'):
            actions.append(("Forensics", "音频频谱图", lambda: forensics.audio_spectrogram(filepath)))
            actions.append(("Forensics", "DTMF 拨号音解码", lambda: forensics.dtmf_decode(filepath)))
            actions.append(("Forensics", "SSTV 解码", lambda: forensics.sstv_decode_helper(filepath)))

        # ========== PDF 文件 ==========
        if "PDF" in ft or ext == '.pdf':
            actions.append(("Forensics", "PDF 分析", lambda: forensics.pdf_analyze(filepath)))

        # ========== Office 文件 ==========
        if ext in ('.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt'):
            actions.append(("Forensics", "Office 文档分析", lambda: forensics.office_analyze(filepath)))

        # ========== 邮件文件 ==========
        if ext in ('.eml', '.msg'):
            actions.append(("Forensics", "邮件分析", lambda: forensics.analyze_email(filepath)))

        # ========== 磁盘镜像 ==========
        if ext in ('.img', '.dd', '.raw', '.iso', '.vmdk', '.vhd'):
            actions.append(("Forensics", "磁盘镜像分析", lambda: forensics.analyze_disk_image(filepath)))

        # ========== 注册表文件 ==========
        if ext in ('.reg', '.dat') or (len(data) >= 4 and data[:4] == b'regf'):
            actions.append(("Forensics", "注册表分析", lambda: forensics.analyze_registry(filepath)))

        # ========== 内存转储 ==========
        if ext in ('.dmp', '.mem', '.vmem', '.raw') and ext not in ('.img',):
            actions.append(("Forensics", "内存转储分析", lambda: forensics.memory_dump_analyze(filepath)))
            actions.append(("Forensics", "内存取证增强", lambda: forensics.memory_forensics_enhanced(filepath)))

        # ========== ELF 二进制 ==========
        if "ELF" in ft:
            actions.append(("Reverse", "ELF 保护检测", lambda: reverse.check_elf_protections(filepath)))
            actions.append(("Reverse", "导入导出表", lambda: reverse.list_imports_exports(filepath)))
            actions.append(("Reverse", "反汇编", lambda: reverse.disassemble(filepath)))
            actions.append(("Reverse", "Go 二进制分析", lambda: reverse.analyze_go_binary(filepath)))
            actions.append(("Reverse", "Rust 二进制分析", lambda: reverse.analyze_rust_binary(filepath)))
            actions.append(("Reverse", "字符串反混淆", lambda: reverse.deobfuscate_strings(filepath)))
            # Pwn: ROP gadget 搜索
            from ctftool.modules.pwn import PwnModule
            _pwn = PwnModule()
            actions.append(("Pwn", "ROP Gadget 搜索", lambda: _pwn.find_rop_gadgets(filepath)))

        # ========== PE 二进制 ==========
        if "PE" in ft or "MZ" in ft or ext in ('.exe', '.dll', '.sys'):
            actions.append(("Reverse", "PE 保护检测", lambda: reverse.check_pe_protections(filepath)))
            actions.append(("Reverse", "导入导出表", lambda: reverse.list_imports_exports(filepath)))
            actions.append(("Reverse", ".NET 分析", lambda: reverse.analyze_dotnet(filepath)))
            actions.append(("Reverse", "Go 二进制分析", lambda: reverse.analyze_go_binary(filepath)))
            actions.append(("Reverse", "Rust 二进制分析", lambda: reverse.analyze_rust_binary(filepath)))
            actions.append(("Reverse", "字符串反混淆", lambda: reverse.deobfuscate_strings(filepath)))

        # ========== APK 文件 ==========
        if ext == '.apk' or (ext == '.zip' and b'classes.dex' in data[:10000] if len(data) > 100 else False):
            actions.append(("Reverse", "APK 分析", lambda: reverse.analyze_apk(filepath)))

        # ========== IPA 文件 ==========
        if ext == '.ipa':
            actions.append(("Reverse", "IPA 分析", lambda: reverse.analyze_ipa(filepath)))

        # ========== Python 字节码 ==========
        if ext in ('.pyc', '.pyo'):
            actions.append(("Reverse", "PYC 反编译", lambda: reverse.decompile_pyc(filepath)))
            actions.append(("Reverse", "字符串反混淆", lambda: reverse.deobfuscate_strings(filepath)))

        # ========== YARA 扫描（通用） ==========
        actions.append(("Reverse", "YARA 规则扫描", lambda: reverse.yara_scan(filepath)))

        for idx, (module, name, action) in enumerate(actions):
            result = ScanResult(module, name)
            result.output = f"[{idx+1}/{len(actions)}] {name}"
            try:
                output = action()
                result.output = output
                result.flags = flag_finder.search_with_decode(output)
            except Exception as e:
                result.success = False
                result.error = str(e)
            results.append(result)
            if callback:
                callback(result)

        self.results.extend(results)
        return results

    def scan_text(self, text: str, callback=None) -> list[ScanResult]:
        """对文本/密文运行所有解码和密码学分析"""
        from ctftool.modules.crypto import CryptoModule
        from ctftool.modules.misc import MiscModule

        crypto = CryptoModule()
        misc = MiscModule()
        results = []

        actions = [
            # ===== Crypto 解码/分析 =====
            ("Crypto", "自动解码", lambda: crypto.auto_decode(text)),
            ("Crypto", "Caesar 暴力破解", lambda: crypto.caesar_bruteforce(text)),
            ("Crypto", "哈希识别", lambda: crypto.identify_hash(text)),
            ("Crypto", "频率分析", lambda: crypto.frequency_analysis(text)),
            ("Crypto", "ROT47", lambda: crypto.rot47(text)),
            ("Crypto", "栅栏暴力破解", lambda: crypto.rail_fence_bruteforce(text)),
            ("Crypto", "Atbash", lambda: crypto.atbash(text)),
            ("Crypto", "仿射暴力破解", lambda: crypto.affine_bruteforce(text)),
            ("Crypto", "XOR 单字节暴力", lambda: crypto.xor_single_byte_bruteforce(text)),
            ("Crypto", "XOR 自动破解", lambda: crypto.xor_auto_crack(text)),
            ("Crypto", "替换密码自动破解", lambda: crypto.substitution_auto_crack(text)),
            ("Crypto", "Vigenere 自动破解", lambda: misc.vigenere_auto_crack(text)),
            # ===== Misc 编码解码 =====
            ("Misc", "进制转换", lambda: misc.base_convert(text)),
            ("Misc", "摩尔斯解码", lambda: misc.morse_decode(text)),
            ("Misc", "ROT 全遍历", lambda: misc.rot_all(text)),
            ("Misc", "培根密码解码", lambda: crypto.bacon_decode(text)),
            ("Misc", "盲文解码", lambda: misc.braille_decode(text)),
            ("Misc", "核心价值观解码", lambda: misc.core_values_decode(text)),
            ("Misc", "DNA 密码解码", lambda: misc.dna_decode(text)),
            ("Misc", "猪圈密码解码", lambda: misc.pigpen_decode(text)),
            ("Misc", "敲击码解码", lambda: misc.tap_code_decode(text)),
            ("Misc", "旗语解码", lambda: misc.semaphore_decode(text)),
            ("Misc", "NATO 音标解码", lambda: misc.nato_decode(text)),
            ("Misc", "Leet 语解码", lambda: misc.leet_decode(text)),
            ("Misc", "Baudot 解码", lambda: misc.baudot_decode(text)),
            ("Misc", "T9 键盘解码", lambda: misc.t9_decode(text)),
            ("Misc", "键盘坐标解码", lambda: misc.keyboard_coord_decode(text)),
            ("Misc", "零宽字符解码", lambda: misc.zwc_decode(text)),
            ("Misc", "Emoji 密码解码", lambda: misc.emoji_cipher_decode(text)),
            ("Misc", "Manchester 解码", lambda: misc.manchester_decode(text)),
            ("Misc", "颜色十六进制解码", lambda: misc.color_hex_decode(text)),
            ("Misc", "跳舞小人解码", lambda: misc.dancing_men_decode(text)),
            ("Misc", "字频统计", lambda: misc.word_frequency(text)),
            ("Misc", "字符转换", lambda: misc.char_convert(text)),
            ("Misc", "键盘布局转换", lambda: misc.keyboard_layout_convert(text)),
            ("Misc", "PHP 序列化解码", lambda: misc.php_serialize_decode(text)),
            ("Misc", "时间戳转换", lambda: misc.timestamp_convert(text)),
            ("Misc", "坐标转换", lambda: misc.coord_convert(text)),
            # ===== 额外解码 =====
            ("Misc", "Base100 解码", lambda: misc.base100_decode(text)),
            ("Misc", "JWT 解码", lambda: misc.jwt_decode(text) if text.startswith("eyJ") else ""),
            # ===== 执行类（可能产生输出） =====
            ("Misc", "Brainfuck 执行", lambda: misc.brainfuck_execute(text)),
            ("Misc", "Ook! 解码", lambda: misc.ook_decode(text)),
            ("Misc", "Whitespace 执行", lambda: misc.whitespace_execute(text)),
            ("Misc", "UUdecode", lambda: misc.uudecode(text)),
            ("Misc", "XXdecode", lambda: misc.xxdecode(text)),
            ("Misc", "Quoted-Printable 解码", lambda: misc.quoted_printable_decode(text)),
            ("Misc", "EBCDIC 转 ASCII", lambda: misc.ebcdic_to_ascii(text)),
            ("Misc", "Malbolge 执行", lambda: misc.malbolge_execute(text)),
        ]

        for idx, (module, name, action) in enumerate(actions):
            result = ScanResult(module, name)
            result.output = f"[{idx+1}/{len(actions)}] {name}"
            try:
                output = action()
                result.output = output
                result.flags = flag_finder.search_with_decode(output)
            except Exception as e:
                result.success = False
                result.error = str(e)
            results.append(result)
            if callback:
                callback(result)

        self.results.extend(results)
        return results

    def get_all_flags(self) -> list[str]:
        """获取所有扫描中发现的 flag"""
        return flag_finder.found_flags.copy()

    def clear(self):
        """清空扫描结果"""
        self.results.clear()
        flag_finder.clear()

    def export_json(self, filepath: str = "") -> str:
        """导出扫描结果为 JSON 格式"""
        import json
        import time as _time

        report = {
            "tool": "CTF-Tool",
            "timestamp": _time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_scans": len(self.results),
            "flags_found": self.get_all_flags(),
            "results": [r.to_dict() for r in self.results],
        }

        json_str = json.dumps(report, indent=2, ensure_ascii=False)

        if filepath:
            os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else '.', exist_ok=True)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(json_str)
            return f"报告已导出到: {filepath}"

        return json_str

    def export_html(self, filepath: str) -> str:
        """导出扫描结果为 HTML 报告"""
        import time as _time

        flags = self.get_all_flags()

        html_parts = [
            '<!DOCTYPE html><html><head><meta charset="utf-8">',
            '<title>CTF-Tool Scan Report</title>',
            '<style>',
            'body{font-family:Consolas,monospace;background:#1e1e2e;color:#cdd6f4;padding:20px;max-width:1000px;margin:0 auto}',
            'h1{color:#89b4fa}h2{color:#a6e3a1;border-bottom:1px solid #45475a;padding-bottom:5px}',
            '.flag{color:#a6e3a1;font-weight:bold;background:#1e1e2e;padding:2px 8px;border:1px solid #a6e3a1;border-radius:3px}',
            '.ok{color:#a6e3a1}.err{color:#f38ba8}.result{background:#313244;padding:10px;margin:5px 0;border-radius:5px;border-left:3px solid #89b4fa}',
            'pre{white-space:pre-wrap;word-wrap:break-word;font-size:13px}',
            '</style></head><body>',
            '<h1>CTF-Tool Scan Report</h1>',
            f'<p>Time: {_time.strftime("%Y-%m-%d %H:%M:%S")} | Scans: {len(self.results)}</p>',
        ]

        if flags:
            html_parts.append(f'<h2>Flags Found ({len(flags)})</h2>')
            for f in flags:
                html_parts.append(f'<p class="flag">{html.escape(f)}</p>')

        html_parts.append(f'<h2>Scan Results ({len(self.results)})</h2>')
        for r in self.results:
            status_class = "ok" if r.success else "err"
            status_text = "OK" if r.success else "ERR"
            html_parts.append('<div class="result">')
            html_parts.append(f'<strong class="{status_class}">[{status_text}]</strong> {html.escape(r.module)} - {html.escape(r.action)}')
            if r.flags:
                for f in r.flags:
                    html_parts.append(f'<br><span class="flag">Flag: {html.escape(f)}</span>')
            if r.output:
                short = r.output[:500] + ('...' if len(r.output) > 500 else '')
                html_parts.append(f'<pre>{html.escape(short)}</pre>')
            if r.error:
                html_parts.append(f'<p class="err">{html.escape(r.error)}</p>')
            html_parts.append('</div>')

        html_parts.append('</body></html>')
        html_output = '\n'.join(html_parts)

        os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else '.', exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_output)
        return f"HTML 报告已导出到: {filepath}"

    def scan_files_batch(self, filepaths: list[str], callback=None) -> list[ScanResult]:
        """批量扫描多个文件"""
        all_results = []
        for i, fp in enumerate(filepaths):
            if callback:
                callback(ScanResult("Batch", f"开始扫描 [{i+1}/{len(filepaths)}] {fp}"))
            results = self.scan_file(fp, callback=callback)
            all_results.extend(results)
        return all_results

    def scan_urls_batch(self, urls: list[str], callback=None) -> list[ScanResult]:
        """批量扫描多个 URL"""
        all_results = []
        for i, url in enumerate(urls):
            if callback:
                callback(ScanResult("Batch", f"开始扫描 [{i+1}/{len(urls)}] {url}"))
            results = self.scan_url(url, callback=callback)
            all_results.extend(results)
        return all_results
