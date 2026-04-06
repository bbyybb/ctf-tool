# CTF-Tool Usage Guide / 操作手册

> CTF-Tool v1.1.0 — All-in-one CTF detection & flag discovery tool
>
> CTF-Tool v1.1.0 — 全场景 CTF 检测与 Flag 发现工具

---

## Table of Contents / 目录

- [Launch Modes / 启动方式](#launch-modes--启动方式)
- [Interface Overview / 界面概览](#interface-overview--界面概览)
- [Auto Scan Module / 自动扫描模块](#auto-scan-module--自动扫描模块)
- [Crypto Module / 密码学模块](#crypto-module--密码学模块)
- [Web Security Module / Web 安全模块](#web-security-module--web-安全模块)
- [Forensics Module / 取证分析模块](#forensics-module--取证分析模块)
- [Reverse Engineering Module / 逆向工程模块](#reverse-engineering-module--逆向工程模块)
- [Pwn Module / Pwn 模块](#pwn-module--pwn-模块)
- [Misc Module / 杂项模块](#misc-module--杂项模块)
- [RSA Attack Module / RSA 攻击模块](#rsa-attack-module--rsa-攻击模块)
- [CLI Mode / 命令行模式](#cli-mode--命令行模式)
- [Configuration / 配置说明](#configuration--配置说明)
- [FAQ / 常见问题](#faq--常见问题)

---

## Launch Modes / 启动方式

### GUI Desktop Mode (Default) / GUI 桌面模式（默认）

```bash
python main.py
```

Launches the PyQt6 desktop interface with sidebar navigation, I/O panels, and auto flag detection.

启动 PyQt6 桌面界面，包含侧边栏导航、输入输出区域、Flag 自动检测。

### TUI Terminal Mode / TUI 终端模式

```bash
python main.py --tui
```

Launches the Textual terminal UI, suitable for headless environments (SSH, remote servers).

启动 Textual 终端界面，适合无图形环境（SSH 远程服务器等）。

### CLI Command-Line Mode / CLI 命令行模式

```bash
python main.py cli <module> <action> <input> [options]
```

For scripting and batch processing. / 适合脚本化调用和批量处理。

### Executable / 可执行文件

```bash
./ctf-tool          # GUI (default)
./ctf-tool --tui    # TUI
./ctf-tool cli crypto rot13 "Hello"  # CLI
```

---

## Interface Overview / 界面概览

### GUI/TUI Sidebar Navigation (9 Modules) / 左侧导航（9 个模块）

| # | Module / 模块 | Description / 说明 |
|---|---|---|
| 0 | Auto Scan / 自动扫描 | One-click scan (URL/File/Text) / 一键全面检测 |
| 1 | Crypto / 密码学 | Encoding, classical ciphers, modern crypto, hash / 编解码、古典密码、现代加密、哈希 |
| 2 | Web Security / Web 安全 | Vulnerability detection, fingerprint, recon, code audit / 漏洞检测、指纹识别、源码审计 |
| 3 | Forensics / 取证 | File analysis, steganography, traffic, docs / 文件分析、隐写术、流量分析、文档取证 |
| 4 | Reverse / 逆向 | Binary analysis, disassembly, protection check / 二进制分析、反汇编、保护检测 |
| 5 | Blockchain / 区块链 | Solidity audit, ABI tools, EVM disasm, exploits / 合约审计、ABI 工具、EVM 反汇编 |
| 6 | Pwn | Buffer overflow, format string, ROP, templates / 溢出利用、格式化字符串、ROP、模板生成 |
| 7 | Misc / 杂项 | Various encodings, esoteric languages, utilities / 各类编码、esoteric 语言、工具函数 |
| 8 | RSA Attack / RSA 攻击 | Dedicated RSA parameter input + attack methods / 专用 RSA 参数输入 + 多种攻击方式 |

### General Workflow / 通用操作流程

1. Select a module from the sidebar / 在左侧选择模块
2. Choose an action from the dropdown / 从顶部下拉菜单选择操作
3. Enter text or select a file / 在输入框输入文本 / 选择文件
4. Click "Run" / 点击"运行"按钮
5. View results; flags are auto-highlighted / 在输出区查看结果，Flag 会自动高亮显示

### Common Buttons / 通用按钮

- **Run / 运行** — Execute the current action / 执行当前操作
- **Select File / 选择文件** — Open file picker (for Forensics/Reverse) / 打开文件选择对话框
- **Copy / 复制** — Copy output to clipboard / 复制输出内容到剪贴板
- **Export / 导出** — Save results as .txt file / 将结果保存为 .txt 文件
- **Send to Crypto / 发送到 Crypto** — Send output to Crypto module input (chain decryption) / 将输出发送到密码学模块

---

## Auto Scan Module / 自动扫描模块

The Auto Scan is CTF-Tool's core feature, running all relevant checks in one click to find flags.

自动扫描是 CTF-Tool 的核心功能，可一键运行所有相关检测，自动寻找 Flag。

### Steps / 操作步骤

1. Select scan type: URL / File / Text / 选择扫描类型
2. Enter target / 输入目标：
   - **URL Scan**: Full URL (e.g., `http://target.com/`) / 输入完整 URL
   - **File Scan**: File path or click "Select File" / 输入文件路径或选择文件
   - **Text Scan**: Paste ciphertext/encoded text / 直接粘贴密文/编码文本
3. (Optional) Paste curl command to auto-configure Cookie/Header/Proxy / 粘贴 curl 命令自动配置
4. Click "Start Scan" / 点击"开始扫描"

### URL Scan (17 Web Checks) / URL 扫描

Parallel execution of all Web security checks / 并行执行所有 Web 安全检测：
- HTTP header analysis, robots.txt, Git leak, directory scan
- SQLi, XSS, LFI, CMDi, SSRF, SSTI, XXE, CORS
- Open Redirect, CRLF, path traversal, WAF detection, HTTP smuggling

### File Scan (30+ Smart Dispatch) / 文件扫描（30+ 项智能调度）

Auto-selects checks based on file type / 根据文件类型自动选择检测项：
- **All files**: type ID, metadata, strings, hidden files, header repair, NTFS ADS, timeline
- **Images** (PNG/JPEG/GIF/BMP): stego analysis, channel split, LSB, bit plane, QR decode
- **PNG**: width/height CRC repair
- **Archives** (ZIP/RAR): password crack, fake encryption repair
- **PCAP**: traffic analysis, HTTP extract, USB keyboard/mouse decode, DNS tunnel
- **Audio**: spectrogram, DTMF decode
- **Documents** (PDF/Office): document analysis
- **ELF binaries**: checksec, disassembly, Go/Rust analysis, ROP gadgets
- **PE/EXE**: PE protection check, .NET analysis
- **APK**: APK analysis
- **PYC**: Python decompile

### Text Scan (35+ Decode Attempts) / 文本扫描（35+ 项解码尝试）

Auto-tries all decoding and cipher analysis / 自动尝试所有解码和密码分析：
- Auto decode (Base64/32/58/85/Hex/URL etc.)
- Caesar bruteforce, ROT47, ROT all, Rail fence, Atbash, Affine
- XOR single-byte bruteforce, XOR auto crack
- Substitution auto crack, Vigenere auto crack
- Morse/Braille/Core values/DNA/Pigpen/Tap code/Semaphore/NATO/Leet/Baudot
- T9/Keyboard coords/Zero-width/Emoji/Manchester/Color hex/Dancing men
- Base100/JWT decode, Brainfuck/Ook!/Whitespace execute

---

## Crypto Module / 密码学模块

95 actions in total / 共 95 个操作

### Encoding/Decoding / 编码解码（23）

| Action / 操作 | Description / 说明 | Example Input / 示例输入 |
|---|---|---|
| `auto_decode` | Auto-try all encodings / 自动尝试所有编码 | `SGVsbG8=` |
| `base64_encode/decode` | Base64 | `Hello World` |
| `base32_encode/decode` | Base32 | `JBSWY3DPEBLW64TMMQ======` |
| `base58_encode/decode` | Base58 (Bitcoin alphabet) | `StV1DL6CwTryKyV` |
| `base85_encode/decode` | Base85/Ascii85 | `87cURD]j` |
| `base91_encode/decode` | Base91 | High-efficiency encoding |
| `base62_encode/decode` | Base62 | Alphanumeric only |
| `hex_encode/decode` | Hexadecimal / 十六进制 | `48656c6c6f` |
| `url_encode/decode` | URL encoding | `Hello%20World` |
| `html_entity_decode` | HTML entity decode | `&lt;script&gt;` |
| `unicode_decode` | Unicode escape decode | `\u0048\u0065\u006c\u006c\u006f` |
| `binary_encode/decode` | Binary / 二进制 | `01001000 01100101` |
| `octal_decode` | Octal decode / 八进制 | `110 145 154 154 157` |
| `detect_encoding` | Auto-detect encoding type / 自动检测编码类型 | Any encoded text |

### Classical Ciphers / 古典密码（29）

| Action / 操作 | Description / 说明 | Key Required / 需要密钥 |
|---|---|---|
| `caesar_bruteforce` | Caesar bruteforce / 暴力破解 | No |
| `caesar_decrypt` | Caesar with offset / 指定偏移解密 | Yes (offset) |
| `rot13` / `rot47` | ROT13/ROT47 | No |
| `vigenere_encrypt/decrypt` | Vigenere cipher | Yes |
| `vigenere_key_length` | Vigenere key length guess / 密钥长度推测 | No |
| `rail_fence_decrypt/bruteforce` | Rail fence cipher / 栅栏密码 | No (bruteforce) |
| `atbash` | Atbash (alphabet reverse) / 字母反转 | No |
| `bacon_decode` | Bacon cipher / 培根密码 | No |
| `affine_decrypt/bruteforce` | Affine cipher / 仿射密码 | No (bruteforce) |
| `playfair_encrypt/decrypt` | Playfair cipher | Yes |
| `polybius_encrypt/decrypt` | Polybius square / 方阵 | Yes (optional) |
| `hill_encrypt/decrypt` | Hill cipher | Yes (matrix) |
| `columnar_transposition_encrypt/decrypt` | Columnar transposition / 列置换 | Yes |
| `substitution_auto_crack` | Substitution auto crack / 替换密码自动破解 | No |
| `adfgvx_decrypt` | ADFGVX cipher | Yes |
| `bifid_encrypt/decrypt` | Bifid cipher | Yes |
| `four_square_decrypt` | Four-square cipher | Yes |
| `autokey_decrypt` | Autokey cipher | Yes |
| `nihilist_decrypt` | Nihilist cipher | Yes |
| `book_cipher_decode` | Book cipher / 字典密码 | Yes (book text) |

### Modern Cryptography / 现代加密（18）

| Action / 操作 | Description / 说明 | Key Required / 需要密钥 |
|---|---|---|
| `aes_ecb_encrypt/decrypt` | AES-ECB | Yes (16/24/32 bytes) |
| `aes_cbc_encrypt/decrypt` | AES-CBC | Yes (key + IV) |
| `aes_ctr_encrypt/decrypt` | AES-CTR | Yes |
| `des_ecb_encrypt/decrypt` | DES-ECB | Yes (8 bytes) |
| `triple_des_encrypt/decrypt` | 3DES | Yes (16/24 bytes) |
| `blowfish_encrypt/decrypt` | Blowfish | Yes (4-56 bytes) |
| `xor_single_byte_bruteforce` | XOR single-byte bruteforce / 单字节暴力 | No |
| `xor_decrypt` | XOR multi-byte decrypt / 多字节解密 | Yes |
| `xor_auto_crack` | XOR auto crack / 自动破解 | No |
| `rc4` | RC4 encrypt/decrypt | Yes |
| `rabbit_decrypt` | Rabbit stream cipher (helper template) | Template |
| `padding_oracle_helper` | Padding Oracle attack template | Template |

### Hash / 哈希（7）

| Action / 操作 | Description / 说明 |
|---|---|
| `identify_hash` | Identify hash type (MD5/SHA1/SHA256 etc.) / 识别哈希类型 |
| `hash_crack_dict` | Dictionary crack / 字典碰撞 |
| `hash_crack_online` | Online reverse lookup (nitrxgen API) / 在线反查 |
| `compute_hash` | Compute hash of text / 计算文本哈希 |
| `hash_length_extension` | Hash length extension attack / 哈希长度扩展攻击 |
| `crc32` | CRC32 checksum / CRC32 校验 |
| `hmac_compute` | HMAC computation (MD5/SHA1/SHA256/SHA512) |

### Advanced Cryptography / 高级密码学（18）

| Action / 操作 | Description / 说明 |
|---|---|
| `frequency_analysis` | Letter frequency analysis / 字母频率分析 |
| `ecc_point_add` | Elliptic curve point operations / 椭圆曲线点运算 |
| `dlp_bsgs` | Discrete log BSGS / 离散对数 BSGS |
| `dlp_pohlig_hellman` | Discrete log Pohlig-Hellman |
| `mt19937_predict` | MT19937 state recovery / 状态恢复 |
| `chinese_remainder_theorem` | CRT solver / 中国剩余定理 |
| `rsa_decrypt_multi_prime` | RSA multi-prime decrypt / 多素数解密 |
| `rsa_dq_leak` | RSA dq leak attack / dq 泄露攻击 |
| `rsa_auto_attack` | RSA auto attack (try all methods) / 自动攻击 |
| `rabin_decrypt` | Rabin cipher decrypt (e=2), outputs 4 candidates |
| `rsa_batch_gcd` | Batch GCD attack (multiple n, comma-separated) / 批量 GCD |
| `rsa_franklin_reiter` | Franklin-Reiter related message attack |
| `rsa_coppersmith_helper` | Coppersmith attack SageMath template |
| `rsa_boneh_durfee_helper` | Boneh-Durfee attack SageMath template |
| `rsa_williams_p1` | Williams p+1 factorization |
| `rsa_import_key` | RSA key import (PEM/DER, auto-extract n/e/d/p/q) / 密钥导入 |
| `hash_collision_generate` | Hash collision generation (MD5/SHA1/CRC32) / 碰撞生成 |
| `password_strength` | Password strength assessment (score 0-100) / 密码强度评估 |

---

## Web Security Module / Web 安全模块

39 actions in total / 共 39 个操作

### Reconnaissance / 信息收集（7）

| Action / 操作 | Input / 输入 | Description / 说明 |
|---|---|---|
| `analyze_headers` | URL | HTTP response header security analysis / 响应头安全分析 |
| `check_robots` | URL | Check robots.txt / 检查 robots.txt |
| `check_git_leak` | URL | .git leak detection / Git 信息泄露检测 |
| `dir_scan` | URL | Multi-threaded directory scan (75+ paths) / 敏感路径扫描 |
| `subdomain_enum` | Domain | Subdomain dictionary enumeration / 子域名枚举 |
| `fingerprint` | URL | Web fingerprint (CMS/framework detection) / 指纹识别 |
| `info_gather` | URL | Sensitive info gathering (email/IP/API key) / 敏感信息收集 |

### Vulnerability Detection / 漏洞检测（20）

| Action / 操作 | Description / 说明 |
|---|---|
| `detect_sqli` | SQL injection (Error-based + UNION) / SQL 注入检测 |
| `detect_xss` | Reflected XSS detection / 反射型 XSS |
| `detect_lfi` | Local file inclusion (auto flag read) / 本地文件包含 |
| `detect_cmdi` | Command injection (auto execution) / 命令注入 |
| `detect_ssrf` | SSRF detection / SSRF 探测 |
| `detect_ssti` | Template injection (with RCE attempt) / 模板注入 |
| `detect_xxe` | XXE external entity injection / 外部实体注入 |
| `detect_cors` | CORS misconfiguration / CORS 配置错误 |
| `detect_open_redirect` | Open redirect / 开放重定向 |
| `detect_crlf` | CRLF injection / CRLF 注入 |
| `detect_path_traversal` | Directory traversal (enhanced) / 目录遍历 |
| `detect_http_smuggling` | HTTP request smuggling / 请求走私 |
| `detect_waf` | WAF detection & identification / WAF 检测 |
| `detect_svn_leak` | SVN/.svn leak detection / SVN 泄露 |
| `detect_ds_store` | .DS_Store file leak / .DS_Store 泄露 |
| `detect_backup_files` | Backup file detection (.bak/.swp/.old/www.zip) / 备份文件检测 |
| `detect_env_leak` | .env file leak / .env 泄露 |
| `detect_graphql` | GraphQL introspection / GraphQL 自省 |
| `detect_host_injection` | Host header injection / Host 头注入 |
| `detect_jsonp` | JSONP hijacking / JSONP 劫持 |

### JWT / Payload / Helpers / 辅助工具（6）

| Action / 操作 | Description / 说明 |
|---|---|
| `jwt_forge_none` | JWT none algorithm forgery / JWT none 伪造 |
| `jwt_crack` | JWT weak key bruteforce / JWT 弱密钥爆破 |
| `generate_payload` | Generate test payloads / 生成测试 Payload |
| `deserialize_helper` | Deserialization vulnerability helper / 反序列化辅助 |
| `prototype_pollution_helper` | Prototype pollution helper / 原型链污染辅助 |
| `race_condition_helper` | Race condition helper / 竞争条件辅助 |

### Advanced Detection / 高级检测（6）

| Action / 操作 | Description / 说明 |
|---|---|
| `configure` | Configure HTTP context (headers/cookies/proxy/auth) |
| `parse_curl` | Parse curl command to auto-configure / 解析 curl 命令 |
| `detect_swagger` | Swagger/OpenAPI endpoint detection / 接口文档探测 |
| `sqli_auto_exploit` | SQLi auto exploit chain (6-step: detect→DB→table→column→data→flag) |
| `dir_listing_crawl` | Directory listing recursive crawl / 目录列表递归爬取 |
| `sqli_time_blind` | Time-based blind SQLi auto extraction / 时间盲注自动提取 |
| `detect_csrf` | CSRF detection (form token + SameSite + PoC) / CSRF 检测 |
| `file_upload_helper` | File upload bypass cheatsheet (extensions/image shell/race) / 文件上传绕过辅助 |
| `code_audit` | Multi-language source code audit (PHP/Python/Node/Java) / 多语言源码审计 |
| `xxe_payload_helper` | XXE payload cheatsheet (10 categories) / XXE Payload 速查 |
| `ssrf_payload_helper` | SSRF payload cheatsheet (10 categories) / SSRF Payload 速查 |
| `waf_bypass_helper` | WAF bypass cheatsheet (SQLi/XSS/CMDi/LFI/general) / WAF 绕过速查 |

---

## Forensics Module / 取证分析模块

44 actions in total / 共 44 个操作

### File Analysis / 文件基础分析（7）

| Action / 操作 | Description / 说明 |
|---|---|
| `identify_file` | File type identification + analysis / 文件类型识别 |
| `extract_strings` | Extract printable strings / 提取可打印字符串 |
| `extract_metadata` | Metadata/EXIF/GPS extraction / 元数据提取 |
| `hex_view` | Hex viewer / 十六进制查看器 |
| `file_diff` | Two-file diff comparison / 差异对比 |
| `file_timeline` | File timeline analysis / 时间线分析 |
| `fix_file_header` | Auto file header repair / 文件头自动修复 |

### Steganography / 隐写术（12）

| Action / 操作 | Description / 说明 |
|---|---|
| `detect_stego` | Comprehensive stego detection / 隐写术综合检测 |
| `lsb_extract_advanced` | Advanced LSB extraction (multi bit-plane/channel) / 高级 LSB 提取 |
| `lsb_encode` | LSB steganography write / LSB 隐写写入 |
| `bit_plane_analysis` | Full bit-plane analysis (Stegsolve-like) / 位平面全分析 |
| `split_channels` | RGB channel split / 通道分离 |
| `png_crc_fix` | PNG width/height CRC repair / PNG 宽高修复 |
| `gif_frame_extract` | GIF frame extraction / GIF 帧分离 |
| `steghide_extract` | Steghide extract + password crack / Steghide 提取 |
| `zsteg_scan` | Zsteg-style auto scan (pure Python) / 自动扫描 |
| `blind_watermark_extract` | FFT blind watermark extraction / 频域盲水印提取 |
| `apng_extract` | APNG frame extraction / APNG 帧提取 |
| `sstv_decode_helper` | SSTV slow-scan TV decode helper / SSTV 解码辅助 |

### Archives / 压缩包（4）

| Action / 操作 | Description / 说明 |
|---|---|
| `zip_crack` | ZIP password crack / ZIP 密码爆破 |
| `rar_crack` | RAR password crack / RAR 密码爆破 |
| `zip_fake_decrypt` | ZIP fake encryption repair / 伪加密修复 |
| `file_carve` | File carving by magic bytes / 文件切割 |

### Traffic Analysis / 流量分析（6）

| Action / 操作 | Description / 说明 |
|---|---|
| `pcap_analyze` | PCAP comprehensive analysis / PCAP 综合分析 |
| `pcap_extract_http` | HTTP stream extraction / HTTP 流量提取 |
| `pcap_extract_files` | Auto export files from PCAP / 自动导出文件 |
| `usb_keyboard_decode` | USB keyboard traffic decode / USB 键盘解码 |
| `usb_mouse_decode` | USB mouse trace decode / USB 鼠标轨迹解码 |
| `detect_dns_tunnel` | DNS tunnel detection / DNS 隧道检测 |

### File Extraction / 文件分离（2）

| Action / 操作 | Description / 说明 |
|---|---|
| `binwalk_scan` | Embedded file scan / 嵌入文件扫描 |
| `binwalk_extract` | Embedded file extraction / 嵌入文件提取 |

### Audio Analysis / 音频分析（2）

| Action / 操作 | Description / 说明 |
|---|---|
| `audio_spectrogram` | Audio spectrogram (detect hidden info) / 频谱图 |
| `dtmf_decode` | DTMF dial tone decode (Goertzel) / 拨号音解码 |

### Document & System Forensics / 文档与系统取证（11）

| Action / 操作 | Description / 说明 |
|---|---|
| `pdf_analyze` | PDF analysis (JavaScript/embedded files) / PDF 分析 |
| `office_analyze` | Office document analysis (macros/OLE) / Office 分析 |
| `memory_dump_analyze` | Memory dump analysis / 内存 Dump 分析 |
| `detect_ntfs_ads` | NTFS Alternate Data Stream detection / ADS 检测 |
| `detect_exif_tampering` | EXIF tampering detection / EXIF 篡改检测 |
| `analyze_disk_image` | Disk image analysis (MBR/GPT) / 磁盘镜像分析 |
| `analyze_email` | Email header analysis / 邮件头分析 |
| `analyze_registry` | Windows registry analysis / 注册表分析 |
| `stego_full_scan` | Stego full scan (8 checks combined) / 隐写全扫描 |
| `file_carve_precise` | Precise file carving (6 format markers) / 精确文件切割 |
| `memory_forensics_enhanced` | Enhanced memory forensics (9 categories) / 内存取证增强 |
| `tool_cheatsheet` | Forensics tool command cheatsheet (steghide/binwalk/volatility/wireshark etc.) / 工具命令速查 |

---

## Reverse Engineering Module / 逆向工程模块

14 actions in total / 共 14 个操作

| Action / 操作 | Description / 说明 |
|---|---|
| `analyze_binary` | Comprehensive binary analysis (type/arch/entropy/strings) / 综合分析 |
| `extract_strings_from_binary` | Extract ASCII/UTF-16 strings / 提取字符串 |
| `disassemble` | Disassembly (auto-detect arch: x86/x64/ARM/MIPS) / 反汇编 |
| `check_elf_protections` | ELF checksec (NX/RELRO/PIE/Canary) |
| `check_pe_protections` | PE protection check (DEP/ASLR/CFG/SafeSEH) |
| `decompile_pyc` | Python .pyc decompile / 反编译 |
| `detect_packer` | Packer detection (UPX/Themida/VMProtect etc.) / 加壳检测 |
| `list_imports_exports` | Import/export table / 导入导出表 |
| `analyze_apk` | Android APK analysis |
| `analyze_dotnet` | .NET assembly analysis |
| `analyze_go_binary` | Go binary analysis |
| `analyze_rust_binary` | Rust binary analysis |
| `yara_scan` | YARA rule scanning / YARA 规则扫描 |
| `deobfuscate_strings` | String deobfuscation / 字符串反混淆 |
| `analyze_ipa` | iOS IPA analysis (Info.plist/Mach-O/permissions/frameworks) / iOS IPA 分析 |
| `tool_cheatsheet` | Reverse tool command cheatsheet (GDB/IDA/Ghidra/radare2/ROPgadget etc.) / 工具命令速查 |

---

## Pwn Module / Pwn 模块

25 actions in total / 共 25 个操作

### Buffer Overflow / 溢出利用（3）

| Action / 操作 | Description / 说明 |
|---|---|
| `generate_pattern` | Generate De Bruijn sequence (find overflow offset) / 生成偏移定位序列 |
| `find_pattern_offset` | Find offset from crash value / 查找偏移量 |
| `generate_padding` | Generate buffer overflow payload / 生成溢出 payload |

### Format String / 格式化字符串（3）

| Action / 操作 | Description / 说明 |
|---|---|
| `format_string_read` | Format string read payload |
| `format_string_write` | Format string write payload |
| `find_format_offset` | Find format string offset |

### ROP / Shellcode（3）

| Action / 操作 | Description / 说明 |
|---|---|
| `find_rop_gadgets` | ROP gadget search |
| `shellcode_template` | Shellcode template / Shellcode 模板 |
| `check_bad_chars` | Shellcode bad character detection / 坏字符检测 |

### Utilities / 工具（2）

| Action / 操作 | Description / 说明 |
|---|---|
| `addr_convert` | Address format conversion / 地址格式转换 |
| `pwntools_template` | pwntools script template / 脚本模板 |

### Exploit Templates / 利用模板（14）

| Action / 操作 | Description / 说明 |
|---|---|
| `ret2libc_template` | ret2libc template |
| `ret2syscall_template` | ret2syscall template |
| `srop_template` | SROP template |
| `ret2csu_template` | ret2csu template |
| `stack_pivot_template` | Stack pivot template / 栈迁移模板 |
| `got_overwrite_template` | GOT overwrite template |
| `heap_exploit_template` | Heap exploit template (tcache/fastbin/house_of_force) |
| `one_gadget_helper` | one_gadget usage guide |
| `seccomp_helper` | seccomp sandbox analysis / 沙箱分析 |
| `io_file_template` | IO_FILE exploit template |
| `house_of_orange_template` | House of Orange template |
| `auto_ret2text` | Auto ret2text (find backdoor + calc offset + gen exploit) / 自动分析 |
| `auto_ret2shellcode` | Auto ret2shellcode (NX disabled → shellcode exploit) / 自动分析 |
| `auto_pwn_analyze` | Comprehensive Pwn analysis (checksec + vuln + exploit route + script) / 综合分析 |

---

## Misc Module / 杂项模块

66 actions in total / 共 66 个操作

### Encoding & Ciphers / 编码与密码（38）

| Action / 操作 | Description / 说明 |
|---|---|
| `morse_encode/decode` | Morse code / 摩尔斯电码 |
| `braille_encode/decode` | Braille / 盲文 |
| `core_values_encode/decode` | Core values encoding / 核心价值观编码 |
| `pigpen_decode` | Pigpen cipher / 猪圈密码 |
| `dna_encode/decode` | DNA cipher / DNA 密码 |
| `bacon_encode` | Bacon cipher encoding / 培根密码 |
| `base100_encode/decode` | Base100 (Emoji encoding) |
| `tap_code_encode/decode` | Tap code / 敲击码 |
| `semaphore_encode/decode` | Semaphore flag / 旗语 |
| `nato_encode/decode` | NATO phonetic alphabet / 音标字母 |
| `leet_encode/decode` | Leet Speak (1337) |
| `emoji_cipher_encode/decode` | Emoji substitution cipher / Emoji 替换密码 |
| `manchester_encode/decode` | Manchester encoding |
| `baudot_decode` | Baudot/ITA2 teleprinter / 电传打字机 |
| `color_hex_decode` | Color hex decode / 颜色十六进制 |
| `dancing_men_decode` | Dancing men (Sherlock Holmes) / 跳舞小人 |
| `uuencode` / `uudecode` | UUencode encoding |
| `xxencode` / `xxdecode` | XXencode encoding |
| `quoted_printable_encode/decode` | Quoted-Printable encoding |
| `audio_morse_decode` | Audio Morse decode (WAV auto-recognition) / 音频摩尔斯 |
| `piet_helper` | Piet programming language helper |
| `malbolge_execute` | Malbolge interpreter / 执行器 |
| `ebcdic_to_ascii` / `ascii_to_ebcdic` | EBCDIC ↔ ASCII conversion |

### Utilities / 工具（12）

| Action / 操作 | Description / 说明 |
|---|---|
| `base_convert` | Base conversion / 进制转换 |
| `char_convert` | Character encoding conversion / 字符编码互转 |
| `ascii_table` | ASCII table / ASCII 码表 |
| `rot_all` / `rot47` | ROT all offsets / ROT47 |
| `coord_convert` | Coordinate system conversion (decimal/DMS/Geohash) / 坐标转换 |
| `keyboard_layout_convert` | Keyboard layout convert (QWERTY/Dvorak/Colemak) / 键盘布局 |
| `timestamp_convert` | Multi-format timestamp conversion / 时间戳转换 |
| `word_frequency` | Word frequency analysis / 字频统计 |
| `generate_wordlist` | Social engineering wordlist generator / 社工字典 |
| `enigma_decrypt` | Enigma cipher machine simulator / Enigma 模拟器 |
| `vigenere_auto_crack` | Vigenere auto crack / 自动破解 |

### Decode & Parse / 解码与解析（8）

| Action / 操作 | Description / 说明 |
|---|---|
| `qr_decode` | QR code decode / 二维码解码 |
| `qr_generate` | QR code generate / 二维码生成 |
| `qr_batch_decode` | Batch QR code scan / 批量扫描 |
| `barcode_decode` | Barcode decode / 条形码 |
| `jwt_decode` | JWT token decode |
| `t9_decode` | T9 keyboard decode / 九宫格 |
| `keyboard_coord_decode` | Keyboard coordinate decode / 键盘坐标 |
| `php_serialize_decode` | PHP serialization parse / PHP 序列化 |

### Stego & Execute / 隐写与执行（8）

| Action / 操作 | Description / 说明 |
|---|---|
| `zwc_encode/decode` | Zero-width character steganography / 零宽字符隐写 |
| `brainfuck_execute` | Brainfuck interpreter / 解释器 |
| `ook_decode/execute` | Ook! decode/execute |
| `whitespace_execute` | Whitespace interpreter / 解释器 |
| `pixel_extract` | Image pixel text extraction / 像素提取 |
| `ocr_extract` | Image OCR text extraction / OCR 提取 |

---

## RSA Attack Module / RSA 攻击模块

Dedicated panel with n/e/c/Extra parameter inputs. / 专用面板，输入 n/e/c/Extra 参数：

| Attack / 攻击方式 | Description / 说明 | Extra Parameter / 参数 |
|---|---|---|
| `small_e` | Small exponent attack / 小指数攻击 | — |
| `common_modulus` | Common modulus attack / 共模攻击 | `e2,c2` |
| `wiener` | Wiener attack (small d) | — |
| `fermat` | Fermat factorization (p≈q) / 分解 | — |
| `pollard_p1` | Pollard p-1 factorization | — |
| `pollard_rho` | Pollard rho factorization | — |
| `dp_leak` | dp leak attack / dp 泄露 | `dp value` |
| `dq_leak` | dq leak attack / dq 泄露 | `dq value` |
| `hastad` | Hastad broadcast attack / 广播攻击 | `n2,c2;n3,c3;...` |
| `factordb` | factordb online lookup / 在线查询 | — |
| `direct` | Direct decrypt (known p,q) / 直接解密 | `p,q` |
| `multi_prime` | Multi-prime RSA / 多素数 | `p1,p2,p3,...` |
| `rsa_auto_attack` | Auto attack (try all methods) / 自动攻击 | — |

---

## Blockchain Module / 区块链安全模块

15 actions in total / 共 15 个操作

### Vulnerability Detection / 漏洞检测（6）

| Action / 操作 | Input / 输入 | Description / 说明 |
|---|---|---|
| `analyze_contract` | Solidity source / 源码 | Comprehensive analysis (all checks) / 综合分析 |
| `detect_reentrancy` | Solidity source | Reentrancy vulnerability / 重入漏洞检测 |
| `detect_integer_overflow` | Solidity source | Integer overflow (SafeMath check) / 整数溢出检测 |
| `detect_tx_origin` | Solidity source | tx.origin auth vulnerability / tx.origin 身份验证漏洞 |
| `detect_selfdestruct` | Solidity source | selfdestruct permission / selfdestruct 权限检查 |
| `detect_unchecked_call` | Solidity source | Unchecked external call return / 未检查外部调用返回值 |

### ABI Tools / ABI 工具（3）

| Action / 操作 | Input / 输入 | Description / 说明 |
|---|---|---|
| `abi_decode` | Hex calldata | Decode selector + parameters / 解码选择器+参数 |
| `abi_encode` | `transfer(address,uint256)` | Encode function call / 编码函数调用 |
| `selector_lookup` | Signature or `0x...` | Compute or lookup selector / 计算或反查选择器 |

### Bytecode Analysis / 字节码分析（2）

| Action / 操作 | Input / 输入 | Description / 说明 |
|---|---|---|
| `disasm_bytecode` | Hex bytecode | EVM disassembly / EVM 操作码反汇编 |
| `storage_layout_helper` | Variable declarations | Calculate storage slots / 计算存储布局 |

### Exploit Templates / 攻击模板（4）

| Action / 操作 | Description / 说明 |
|---|---|
| `flashloan_template` | Flash loan attack (Aave V3/Uniswap V2) / 闪电贷攻击模板 |
| `reentrancy_exploit_template` | Reentrancy exploit contract / 重入攻击合约模板 |
| `evm_puzzle_helper` | EVM Puzzles solving guide / EVM 谜题解题辅助 |
| `common_patterns` | CTF blockchain vulnerability cheatsheet (12 types) / 常见漏洞速查表 |

---

## CLI Mode / 命令行模式

### Syntax / 基本语法

```bash
python main.py cli <module> <action> <input> [options]
```

### Examples / 示例

```bash
# Crypto / 密码学
python main.py cli crypto base64-decode "SGVsbG8gV29ybGQ="
python main.py cli crypto caesar-bruteforce "Khoor Zruog"
python main.py cli crypto aes-ecb-decrypt "ciphertext_hex" --key "key_hex"
python main.py cli crypto vigenere-decrypt "ciphertext" --key "KEY"

# RSA Attack / RSA 攻击
python main.py cli rsa wiener --n 1234567 --e 65537 --c 9876543
python main.py cli rsa small-e --n 1234567 --e 3 --c 9876543
python main.py cli rsa direct --n 3233 --e 17 --c 2790 --extra "61,53"

# Web Security / Web 安全
python main.py cli web detect-sqli "http://target.com/?id=1"
python main.py cli web jwt-forge-none "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.xxx"

# Forensics / 取证分析
python main.py cli forensics identify-file challenge.png
python main.py cli forensics png-crc-fix broken.png
python main.py cli forensics pcap-analyze traffic.pcap

# Reverse Engineering / 逆向工程
python main.py cli reverse analyze-binary pwn_challenge
python main.py cli reverse check-elf-protections pwn_challenge

# Pwn
python main.py cli pwn generate-pattern 200
python main.py cli pwn find-pattern-offset 0x41366141
python main.py cli pwn find-rop-gadgets pwn_challenge

# Misc / 杂项
python main.py cli misc morse-decode ".... . .-.. .-.. ---"
python main.py cli misc jwt-decode "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.xxx"
python main.py cli misc timestamp-convert "1700000000"

# Blockchain / 区块链
python main.py cli blockchain abi-decode "a9059cbb00000000000000000000000012345..."
python main.py cli blockchain selector-lookup "transfer(address,uint256)"
python main.py cli blockchain disasm-bytecode "6060604052"

# Auto Scan / 自动扫描
python main.py cli scan-text "SGVsbG8gV29ybGQ=" --output result.json --format json
python main.py cli scan-file challenge.png --output report.html --format html
python main.py cli scan-url "http://target.com/" --output scan.json --format json

# Operation History / 操作历史
python main.py cli history                    # View recent 20 / 查看最近 20 条
python main.py cli history --search "rsa"     # Search / 搜索
python main.py cli history --flags            # View found flags / 查看 Flag
python main.py cli history --clear            # Clear history / 清空历史
python main.py cli history --limit 50         # View recent 50 / 最近 50 条
```

### Global Options / 全局选项

```bash
python main.py cli --verbose crypto rot13 "Hello"   # Enable debug logging / 启用详细日志
```

---

## Configuration / 配置说明

### Config Directory / 配置目录

All config files are stored in `~/.ctf-tool/`:

所有配置文件存放在 `~/.ctf-tool/` 目录下：

| File / 文件 | Description / 说明 |
|---|---|
| `language.json` | Language preference (zh/en) / 语言偏好 |
| `flag_patterns.json` | Custom flag regex patterns / 自定义 Flag 正则 |
| `history.json` | Operation history (max 500) / 操作历史 |
| `config.json` | Global config (timeout/proxy/output dir) / 全局配置 |

### Custom Flag Format / 自定义 Flag 格式

In GUI, click the Flag settings button and enter examples (one per line):

在 GUI 中点击 Flag 设置按钮，每行输入一个示例：

```
DASCTF{this_is_flag}
HGAME{sample_flag}
MyCustom{example}
```

The program auto-converts examples to regex patterns. / 程序会自动转换为正则表达式。

### Language Switch / 语言切换

- GUI: Click the language button (CN/EN) in the top-right corner / 点击右上角语言按钮
- Settings auto-save to `~/.ctf-tool/language.json` / 自动保存
- Default: English (auto-detects Chinese systems) / 默认英文（自动检测中文系统）

### Optional Dependencies / 可选依赖

```bash
pip install pyzbar      # QR/Barcode decode / 二维码解码
pip install rarfile     # RAR archives / RAR 压缩包
pip install uncompyle6  # Python .pyc decompile / 反编译
pip install hashpumpy   # Hash length extension / 哈希长度扩展
pip install pytesseract # OCR text recognition / OCR 识别
```

---

## FAQ / 常见问题

### Q: Program shows integrity check failed at startup?
### Q: 程序启动时提示完整性校验失败？
A: The program verifies critical file integrity. Download from official Release and don't modify files in the `docs/` directory.

A: 程序会校验关键文件的完整性。请从官方 Release 下载，不要修改 docs/ 目录下的文件。

### Q: How to select files during auto scan?
### Q: 自动扫描文件时如何选择文件？
A: After selecting "File Scan" type, click the "Select File" button or enter the file path directly.

A: 选择"文件扫描"类型后，点击"选择文件"按钮或直接输入文件路径。

### Q: How to configure Cookie/Header for Web scan?
### Q: Web 扫描如何配置 Cookie/Header？
A: Paste a curl command in the curl input box (e.g., `curl 'http://target.com' -H 'Cookie: session=abc'`). The program auto-parses and configures the request context.

A: 在 curl 输入框中粘贴 curl 命令，程序会自动解析并配置请求上下文。

### Q: Which flag formats are auto-detected?
### Q: Flag 自动检测支持哪些格式？
A: 30+ CTF competition formats (flag{}, CTF{}, DASCTF{}, picoCTF{}, HTB{}, etc.) and the generic `XXX{...}` pattern. Auto recursive decode (Base64/Hex/URL/Base32/ROT13) up to 5 layers.

A: 支持 30+ 种 CTF 比赛格式，以及通用 `XXX{...}` 格式。自动递归解码最多 5 层。

### Q: Which OS are supported?
### Q: 支持哪些操作系统？
A: Windows (x64), macOS (ARM64/Intel), Linux (x64). Pre-built executables for all 4 platforms available on the Release page.

A: Windows (x64)、macOS (ARM64/Intel)、Linux (x64)。Release 页面提供四个平台的可执行文件。

### Q: Does the tool work offline?
### Q: 离线环境能使用吗？
A: Yes. 292 out of 294 features work fully offline. Only `rsa_factordb` (factordb.com API) and `hash_crack_online` (nitrxgen.net API) require internet access; they return a helpful error message when offline.

A: 可以。294 个功能中 292 个完全离线可用。仅 `rsa_factordb` 和 `hash_crack_online` 需要外网，离线时返回错误提示。
