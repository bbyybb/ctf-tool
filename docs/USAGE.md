# CTF-Tool 操作手册 / Usage Guide

> CTF-Tool v1.0.0 — 全场景 CTF 检测与 Flag 发现工具
>
> made by: 白白LOVE尹尹

---

## 目录

- [启动方式](#启动方式)
- [界面概览](#界面概览)
- [自动扫描模块](#自动扫描模块)
- [密码学模块 (Crypto)](#密码学模块-crypto)
- [Web 安全模块](#web-安全模块)
- [取证分析模块 (Forensics)](#取证分析模块-forensics)
- [逆向工程模块 (Reverse)](#逆向工程模块-reverse)
- [Pwn 模块](#pwn-模块)
- [杂项模块 (Misc)](#杂项模块-misc)
- [RSA 攻击模块](#rsa-攻击模块)
- [CLI 命令行模式](#cli-命令行模式)
- [配置说明](#配置说明)
- [常见问题](#常见问题)

---

## 启动方式

### GUI 桌面模式（默认）

```bash
python main.py
```

启动 PyQt6 桌面界面，包含侧边栏导航、输入输出区域、Flag 自动检测。

### TUI 终端模式

```bash
python main.py --tui
```

启动 Textual 终端界面，适合无图形环境（SSH 远程服务器等）。

### CLI 命令行模式

```bash
python main.py cli <模块> <操作> <输入> [选项]
```

适合脚本化调用和批量处理。

### 可执行文件

```bash
./ctf-tool.exe                    # GUI（默认）
./ctf-tool.exe --tui              # TUI
./ctf-tool.exe cli crypto rot13 "Hello"  # CLI
```

---

## 界面概览

### GUI/TUI 左侧导航（8 个模块）

| 编号 | 模块 | 说明 |
|------|------|------|
| 0 | 自动扫描 | 一键全面检测（URL/文件/文本） |
| 1 | 密码学 (Crypto) | 编解码、古典密码、现代加密、哈希 |
| 2 | Web 安全 | 漏洞检测、指纹识别、信息收集 |
| 3 | 取证 (Forensics) | 文件分析、隐写术、流量分析、文档取证 |
| 4 | 逆向 (Reverse) | 二进制分析、反汇编、保护检测 |
| 5 | Pwn | 溢出利用、格式化字符串、ROP、模板生成 |
| 6 | 杂项 (Misc) | 各类编码、esoteric 语言、工具函数 |
| 7 | RSA 攻击 | 专用 RSA 参数输入 + 多种攻击方式 |

### 通用操作流程

1. 在左侧选择模块
2. 从顶部下拉菜单选择操作
3. 在输入框输入文本 / 选择文件
4. 点击"运行"按钮
5. 在输出区查看结果，Flag 会自动高亮显示

### 通用按钮

- **运行** — 执行当前操作
- **选择文件** — 打开文件选择对话框（Forensics/Reverse 等文件类模块）
- **复制** — 复制输出内容到剪贴板
- **导出** — 将结果保存为 .txt 文件
- **发送到 Crypto** — 将输出发送到密码学模块的输入框（方便链式解密）

---

## 自动扫描模块

自动扫描是 CTF-Tool 的核心功能，可一键运行所有相关检测，自动寻找 Flag。

### 操作步骤

1. 选择扫描类型：URL 扫描 / 文件扫描 / 文本扫描
2. 输入目标：
   - **URL 扫描**：输入完整 URL（如 `http://target.com/`）
   - **文件扫描**：输入文件路径或点击"选择文件"按钮
   - **文本扫描**：直接粘贴密文/编码文本
3. （可选）在 curl 输入框粘贴 curl 命令，自动配置 Cookie/Header/代理
4. 点击"开始扫描"

### 三种扫描模式覆盖范围

#### URL 扫描（17 项 Web 检测）

并行执行所有 Web 安全检测：
- HTTP 头分析、robots.txt、Git 泄露、敏感路径扫描
- SQL 注入、XSS、LFI、命令注入、SSRF、SSTI
- XXE、CORS 配置、Open Redirect、CRLF 注入
- 目录遍历、WAF 检测、HTTP 走私

#### 文件扫描（30+ 项智能调度）

根据文件类型自动选择检测项：
- **所有文件**：类型识别、元数据提取、字符串提取、隐藏文件扫描、文件头修复、NTFS ADS、时间线
- **图片**（PNG/JPEG/GIF/BMP）：隐写分析、通道分离、LSB 提取、位平面分析、QR 码解码
- **PNG**：宽高 CRC 修复
- **压缩包**（ZIP/RAR）：密码爆破、伪加密修复
- **PCAP**：流量分析、HTTP 提取、USB 键盘/鼠标解码、DNS 隧道检测
- **音频**：频谱图分析、DTMF 解码
- **文档**（PDF/Office）：文档分析
- **ELF 二进制**：保护检测、反汇编、Go/Rust 分析、ROP Gadget 搜索
- **PE/EXE**：PE 保护检测、.NET 分析
- **APK**：APK 分析
- **PYC**：Python 反编译

#### 文本扫描（35+ 项解码尝试）

自动尝试所有解码和密码分析：
- 自动解码（Base64/32/58/85/Hex/URL 等）
- Caesar 暴力破解、ROT47、ROT 全遍历
- 栅栏暴力破解、Atbash、仿射暴力破解
- XOR 单字节暴力、XOR 自动破解
- 替换密码自动破解、Vigenere 自动破解
- 摩尔斯/盲文/核心价值观/DNA/猪圈/敲击码/旗语/NATO/Leet/Baudot 解码
- T9 键盘/键盘坐标/零宽字符/Emoji/Manchester/颜色十六进制/跳舞小人 解码
- Base100/JWT 解码、Brainfuck/Ook!/Whitespace 执行
- 字频统计、字符转换、PHP 序列化解码

---

## 密码学模块 (Crypto)

共 95 个操作，分为以下类别：

### 编码/解码（23 个）

| 操作 | 说明 | 示例输入 |
|------|------|---------|
| `auto_decode` | 自动尝试所有编码 | `SGVsbG8=` |
| `base64_encode/decode` | Base64 编解码 | `Hello World` |
| `base32_encode/decode` | Base32 编解码 | `JBSWY3DPEBLW64TMMQ======` |
| `base58_encode/decode` | Base58 编解码（Bitcoin 字母表） | `StV1DL6CwTryKyV` |
| `base85_encode/decode` | Base85/Ascii85 编解码 | `87cURD]j` |
| `base91_encode/decode` | Base91 编解码 | 高效编码 |
| `base62_encode/decode` | Base62 编解码 | 纯字母数字 |
| `hex_encode/decode` | 十六进制编解码 | `48656c6c6f` |
| `url_encode/decode` | URL 编解码 | `Hello%20World` |
| `html_entity_decode` | HTML 实体解码 | `&lt;script&gt;` |
| `unicode_decode` | Unicode 转义解码 | `\u0048\u0065\u006c\u006c\u006f` |
| `binary_encode/decode` | 二进制编解码 | `01001000 01100101` |
| `octal_decode` | 八进制解码 | `110 145 154 154 157` |
| `detect_encoding` | 自动检测编码类型 | 任意编码文本 |

### 古典密码（29 个）

| 操作 | 说明 | 需要密钥 |
|------|------|---------|
| `caesar_bruteforce` | Caesar 暴力破解 | 否 |
| `caesar_decrypt` | Caesar 指定偏移解密 | 是（偏移量） |
| `rot13` / `rot47` | ROT13/ROT47 | 否 |
| `vigenere_encrypt/decrypt` | Vigenere 加解密 | 是 |
| `vigenere_key_length` | Vigenere 密钥长度推测 | 否 |
| `rail_fence_decrypt/bruteforce` | 栅栏密码解密/暴力 | 否（暴力） |
| `atbash` | Atbash 字母反转 | 否 |
| `bacon_decode` | 培根密码解码 | 否 |
| `affine_decrypt/bruteforce` | 仿射密码 | 否（暴力） |
| `playfair_encrypt/decrypt` | Playfair 密码 | 是 |
| `polybius_encrypt/decrypt` | Polybius 方阵 | 是（可选） |
| `hill_encrypt/decrypt` | Hill 密码 | 是（矩阵） |
| `columnar_transposition_encrypt/decrypt` | 列置换 | 是 |
| `substitution_auto_crack` | 替换密码自动破解 | 否 |
| `adfgvx_decrypt` | ADFGVX 解密 | 是 |
| `bifid_encrypt/decrypt` | Bifid 密码 | 是 |
| `four_square_decrypt` | Four-square 解密 | 是 |
| `autokey_decrypt` | Autokey 解密 | 是 |
| `nihilist_decrypt` | Nihilist 解密 | 是 |
| `book_cipher_decode` | Book 密码解码 | 是（密码本） |

### 现代加密（18 个）

| 操作 | 说明 | 需要密钥 |
|------|------|---------|
| `aes_ecb_encrypt/decrypt` | AES-ECB 加解密 | 是（16/24/32字节） |
| `aes_cbc_encrypt/decrypt` | AES-CBC 加解密 | 是（密钥 + IV） |
| `aes_ctr_encrypt/decrypt` | AES-CTR 加解密 | 是 |
| `des_ecb_encrypt/decrypt` | DES-ECB 加解密 | 是（8字节） |
| `triple_des_encrypt/decrypt` | 3DES 加解密 | 是（16/24字节） |
| `blowfish_encrypt/decrypt` | Blowfish 加解密 | 是（4-56字节） |
| `xor_single_byte_bruteforce` | XOR 单字节暴力 | 否 |
| `xor_decrypt` | XOR 多字节解密 | 是 |
| `xor_auto_crack` | XOR 自动破解 | 否 |
| `rc4` | RC4 加解密 | 是 |
| `rabbit_decrypt` | Rabbit 流密码 | 帮助模板 |
| `padding_oracle_helper` | Padding Oracle 攻击模板 | 模板 |

### 哈希（7 个）

| 操作 | 说明 |
|------|------|
| `identify_hash` | 识别哈希类型（MD5/SHA1/SHA256 等） |
| `hash_crack_dict` | 字典碰撞 |
| `hash_crack_online` | 在线反查（nitrxgen API） |
| `compute_hash` | 计算文本哈希 |
| `hash_length_extension` | 哈希长度扩展攻击 |
| `crc32` | CRC32 校验 |
| `hmac_compute` | HMAC 计算 |

### 高级密码学（18 个）

| 操作 | 说明 |
|------|------|
| `frequency_analysis` | 字母频率分析 |
| `ecc_point_add` | 椭圆曲线点运算 |
| `dlp_bsgs` | 离散对数 BSGS 算法 |
| `dlp_pohlig_hellman` | 离散对数 Pohlig-Hellman |
| `mt19937_predict` | MT19937 状态恢复 |
| `chinese_remainder_theorem` | 中国剩余定理 |
| `rsa_decrypt_multi_prime` | RSA 多素数解密 |
| `rsa_dq_leak` | RSA dq 泄露攻击 |
| `rsa_auto_attack` | RSA 自动攻击（依次尝试所有方式） |
| `rabin_decrypt` | Rabin 密码解密 (e=2)，输出 4 个候选明文 |
| `rsa_batch_gcd` | 批量 GCD 攻击，输入多个 n（逗号分隔） |
| `rsa_franklin_reiter` | Franklin-Reiter 相关消息攻击 |
| `rsa_coppersmith_helper` | Coppersmith 攻击 SageMath 脚本模板 |
| `rsa_boneh_durfee_helper` | Boneh-Durfee 攻击 SageMath 脚本模板 |
| `rsa_williams_p1` | Williams p+1 分解 |
| `rsa_import_key` | RSA 密钥文件导入（支持 PEM/DER 格式，自动提取 n/e/d/p/q） |
| `hash_collision_generate` | 哈希碰撞生成（MD5/SHA1/CRC32，生成指定前缀的碰撞对） |
| `password_strength` | 密码强度评估（评分 0-100 + 预计破解时间估算） |

---

## Web 安全模块

共 39 个操作：

### 信息收集（7 个）

| 操作 | 输入 | 说明 |
|------|------|------|
| `analyze_headers` | URL | HTTP 响应头安全分析 |
| `check_robots` | URL | 检查 robots.txt |
| `check_git_leak` | URL | .git 信息泄露检测 |
| `dir_scan` | URL | 敏感路径多线程扫描（75+ 路径） |
| `subdomain_enum` | 域名 | 子域名字典枚举 |
| `fingerprint` | URL | Web 指纹识别（CMS/框架检测） |
| `info_gather` | URL | 敏感信息收集（邮箱/IP/API Key） |

### 漏洞检测（20 个）

| 操作 | 说明 |
|------|------|
| `detect_sqli` | SQL 注入检测（Error-based + UNION） |
| `detect_xss` | 反射型 XSS 检测 |
| `detect_lfi` | 本地文件包含（含自动读取 flag） |
| `detect_cmdi` | 命令注入检测（含自动执行） |
| `detect_ssrf` | SSRF 探测 |
| `detect_ssti` | 模板注入检测（含 RCE 尝试） |
| `detect_xxe` | XXE 外部实体注入 |
| `detect_cors` | CORS 配置错误 |
| `detect_open_redirect` | 开放重定向 |
| `detect_crlf` | CRLF 注入 |
| `detect_path_traversal` | 目录遍历（增强版） |
| `detect_http_smuggling` | HTTP 请求走私 |
| `detect_waf` | WAF 检测与识别 |
| `detect_svn_leak` | SVN/.svn 泄露检测 |
| `detect_ds_store` | .DS_Store 文件泄露检测 |
| `detect_backup_files` | 备份文件检测 (.bak/.swp/.old/www.zip 等) |
| `detect_env_leak` | .env 配置文件泄露检测 |
| `detect_graphql` | GraphQL 自省检测 |
| `detect_host_injection` | Host 头注入检测 |
| `detect_jsonp` | JSONP 劫持检测 |

### JWT / Payload / 辅助（6 个）

| 操作 | 说明 |
|------|------|
| `jwt_forge_none` | JWT none 算法伪造 |
| `jwt_crack` | JWT 弱密钥爆破 |
| `generate_payload` | 生成测试 Payload |
| `deserialize_helper` | 反序列化漏洞辅助 |
| `prototype_pollution_helper` | 原型链污染辅助 |
| `race_condition_helper` | 竞争条件辅助 |

### 配置与高级检测（6 个）

| 操作 | 说明 |
|------|------|
| `configure` | 配置 HTTP 请求上下文 |
| `parse_curl` | 解析 curl 命令并配置 |
| `detect_swagger` | Swagger/OpenAPI 接口文档探测（自动发现 API 文档端点） |
| `sqli_auto_exploit` | SQLi 自动化利用链（6步：检测→数据库→表→列→数据→Flag） |
| `dir_listing_crawl` | 目录列表递归爬取（自动遍历 Apache/Nginx Index of 页面，发现隐藏文件和 Flag） |
| `sqli_time_blind` | SQL 时间盲注自动化提取（无回显场景，通过 SLEEP 延迟逐字符提取 database/tables/flag） |

---

## 取证分析模块 (Forensics)

共 44 个操作：

### 文件基础分析（7 个）

| 操作 | 说明 |
|------|------|
| `identify_file` | 文件类型识别 + 基础分析 |
| `extract_strings` | 提取可打印字符串 |
| `extract_metadata` | 元数据/EXIF/GPS 提取 |
| `hex_view` | 十六进制查看器 |
| `file_diff` | 两文件差异对比 |
| `file_timeline` | 文件时间线分析 |
| `fix_file_header` | 文件头自动修复 |

### 隐写术（12 个）

| 操作 | 说明 |
|------|------|
| `detect_stego` | 隐写术综合检测 |
| `lsb_extract_advanced` | 高级 LSB 提取（多位平面/通道） |
| `lsb_encode` | LSB 隐写写入 |
| `bit_plane_analysis` | 位平面全分析（类 Stegsolve） |
| `split_channels` | RGB 通道分离 |
| `png_crc_fix` | PNG 宽高 CRC 修复 |
| `gif_frame_extract` | GIF 帧分离 |
| `steghide_extract` | Steghide 隐写提取 + 密码爆破（支持字典） |
| `zsteg_scan` | Zsteg 式自动扫描（遍历所有位平面/通道/扫描顺序组合） |
| `blind_watermark_extract` | 频域盲水印提取（FFT 分析） |
| `apng_extract` | APNG 动态 PNG 帧提取 |
| `sstv_decode_helper` | SSTV 慢扫描电视解码辅助 |

### 压缩包（4 个）

| 操作 | 说明 |
|------|------|
| `zip_crack` | ZIP 密码爆破 |
| `rar_crack` | RAR 密码爆破 |
| `zip_fake_decrypt` | ZIP 伪加密修复 |
| `file_carve` | 基于 magic bytes 的文件切割 |

### 流量分析（6 个）

| 操作 | 说明 |
|------|------|
| `pcap_analyze` | PCAP 综合分析 |
| `pcap_extract_http` | HTTP 流量提取 |
| `pcap_extract_files` | 从 PCAP 自动导出文件 |
| `usb_keyboard_decode` | USB 键盘流量解码 |
| `usb_mouse_decode` | USB 鼠标轨迹解码 |
| `detect_dns_tunnel` | DNS 隧道检测 |

### 文件分离（2 个）

| 操作 | 说明 |
|------|------|
| `binwalk_scan` | 嵌入文件扫描 |
| `binwalk_extract` | 嵌入文件提取并保存 |

### 音频分析（2 个）

| 操作 | 说明 |
|------|------|
| `audio_spectrogram` | 音频频谱图（检测隐藏信息） |
| `dtmf_decode` | DTMF 拨号音解码 |

### 文档/系统取证（11 个）

| 操作 | 说明 |
|------|------|
| `pdf_analyze` | PDF 分析（JavaScript/嵌入文件） |
| `office_analyze` | Office 文档分析（宏/OLE 对象） |
| `memory_dump_analyze` | 内存 Dump 分析 |
| `detect_ntfs_ads` | NTFS 备用数据流检测 |
| `detect_exif_tampering` | EXIF 篡改检测 |
| `analyze_disk_image` | 磁盘镜像分析 |
| `analyze_email` | Email 头分析 |
| `analyze_registry` | Windows 注册表分析 |
| `stego_full_scan` | 隐写术全扫描（8项检测汇总：LSB/位平面/通道/尾部/频域/Steghide/Zsteg/盲水印） |
| `file_carve_precise` | 精确文件切割（6种格式头尾标记：JPEG/PNG/GIF/PDF/ZIP/RAR） |
| `memory_forensics_enhanced` | 内存取证增强（9类信息提取：进程/网络/注册表/文件/密码/命令行/DLL/服务/驱动） |

---

## 逆向工程模块 (Reverse)

共 14 个操作：

| 操作 | 说明 |
|------|------|
| `analyze_binary` | 综合二进制分析（类型/架构/熵值/字符串） |
| `extract_strings_from_binary` | 提取 ASCII/UTF-16 字符串 |
| `disassemble` | 反汇编（自动检测架构，支持 x86/x64/ARM/MIPS） |
| `check_elf_protections` | ELF checksec（NX/RELRO/PIE/Canary） |
| `check_pe_protections` | PE 保护检测（DEP/ASLR/CFG/SafeSEH） |
| `decompile_pyc` | Python .pyc 反编译 |
| `detect_packer` | 加壳检测（UPX/Themida/VMProtect 等） |
| `list_imports_exports` | 导入导出表 |
| `analyze_apk` | Android APK 分析 |
| `analyze_dotnet` | .NET 程序集分析 |
| `analyze_go_binary` | Go 二进制分析 |
| `analyze_rust_binary` | Rust 二进制分析 |
| `yara_scan` | YARA 规则扫描 |
| `deobfuscate_strings` | 字符串反混淆 |

---

## Pwn 模块

共 25 个操作：

### 溢出利用（3 个）

| 操作 | 说明 |
|------|------|
| `generate_pattern` | 生成 De Bruijn 序列（定位溢出偏移） |
| `find_pattern_offset` | 查找偏移量（输入崩溃值） |
| `generate_padding` | 生成缓冲区溢出 payload |

### 格式化字符串（3 个）

| 操作 | 说明 |
|------|------|
| `format_string_read` | 格式化字符串读取 payload |
| `format_string_write` | 格式化字符串写入 payload |
| `find_format_offset` | 查找格式化字符串偏移 |

### ROP / Shellcode（3 个）

| 操作 | 说明 |
|------|------|
| `find_rop_gadgets` | ROP Gadget 搜索 |
| `shellcode_template` | Shellcode 模板 |
| `check_bad_chars` | Shellcode 坏字符检测 |

### 工具（2 个）

| 操作 | 说明 |
|------|------|
| `addr_convert` | 地址格式转换 |
| `pwntools_template` | pwntools 脚本模板 |

### 利用模板（14 个）

| 操作 | 说明 |
|------|------|
| `ret2libc_template` | ret2libc 模板 |
| `ret2syscall_template` | ret2syscall 模板 |
| `srop_template` | SROP 模板 |
| `ret2csu_template` | ret2csu 模板 |
| `stack_pivot_template` | 栈迁移模板 |
| `got_overwrite_template` | GOT 覆写模板 |
| `heap_exploit_template` | 堆利用模板（tcache/fastbin/house_of_force） |
| `one_gadget_helper` | one_gadget 使用指南 |
| `seccomp_helper` | seccomp 沙箱分析 |
| `io_file_template` | IO_FILE 利用模板 |
| `house_of_orange_template` | House of Orange 模板 |
| `auto_ret2text` | 自动 ret2text 分析（找后门函数+计算偏移+生成 exploit 脚本） |
| `auto_ret2shellcode` | 自动 ret2shellcode 分析（NX 关闭时自动生成 shellcode exploit） |
| `auto_pwn_analyze` | 综合 Pwn 分析（checksec+漏洞定位+推荐利用路线+生成完整脚本） |

---

## 杂项模块 (Misc)

共 66 个操作：

### 编码/密码（38 个）

| 操作 | 说明 |
|------|------|
| `morse_encode/decode` | 摩尔斯电码 |
| `braille_encode/decode` | 盲文 |
| `core_values_encode/decode` | 核心价值观编码 |
| `pigpen_decode` | 猪圈密码 |
| `dna_encode/decode` | DNA 密码 |
| `bacon_encode` | 培根密码编码 |
| `base100_encode/decode` | Base100（Emoji 编码） |
| `tap_code_encode/decode` | 敲击码 |
| `semaphore_encode/decode` | 旗语 |
| `nato_encode/decode` | NATO 音标 |
| `leet_encode/decode` | Leet Speak |
| `emoji_cipher_encode/decode` | Emoji 替换密码 |
| `manchester_encode/decode` | Manchester 编码 |
| `baudot_decode` | Baudot/ITA2 电传打字机 |
| `color_hex_decode` | 颜色十六进制解码 |
| `dancing_men_decode` | 跳舞小人（福尔摩斯） |
| `uuencode` / `uudecode` | UUencode 编解码 |
| `xxencode` / `xxdecode` | XXencode 编解码 |
| `quoted_printable_encode` / `quoted_printable_decode` | Quoted-Printable 编解码 |
| `audio_morse_decode` | 音频摩尔斯解码（从 WAV 文件自动识别） |
| `piet_helper` | Piet 图像编程语言辅助 |
| `malbolge_execute` | Malbolge 语言执行器 |
| `ebcdic_to_ascii` / `ascii_to_ebcdic` | EBCDIC 与 ASCII 互转 |

### 工具（12 个）

| 操作 | 说明 |
|------|------|
| `base_convert` | 进制转换 |
| `char_convert` | 字符编码互转 |
| `ascii_table` | ASCII 码表 |
| `rot_all` / `rot47` | ROT 全遍历 / ROT47 |
| `coord_convert` | 坐标系转换 |
| `keyboard_layout_convert` | 键盘布局转换（QWERTY/Dvorak/Colemak） |
| `timestamp_convert` | 多格式时间戳转换 |
| `word_frequency` | 字频统计 |
| `generate_wordlist` | 社工字典生成 |
| `enigma_decrypt` | Enigma 密码机模拟器 |
| `vigenere_auto_crack` | Vigenere 自动破解 |

### 解码/解析（8 个）

| 操作 | 说明 |
|------|------|
| `qr_decode` | QR 码解码 |
| `qr_generate` | QR 码生成 |
| `qr_batch_decode` | 二维码批量扫描 |
| `barcode_decode` | 条形码解码 |
| `jwt_decode` | JWT Token 解码 |
| `t9_decode` | T9 九宫格解码 |
| `keyboard_coord_decode` | 键盘坐标解码 |
| `php_serialize_decode` | PHP 序列化解析 |

### 隐写/执行（8 个）

| 操作 | 说明 |
|------|------|
| `zwc_encode/decode` | 零宽字符隐写 |
| `brainfuck_execute` | Brainfuck 解释器 |
| `ook_decode/execute` | Ook! 解码/执行 |
| `whitespace_execute` | Whitespace 解释器 |
| `pixel_extract` | 图片像素提取 |
| `ocr_extract` | 图片 OCR 文字提取 |

---

## RSA 攻击模块

专用面板，输入 n/e/c/Extra 参数：

| 攻击方式 | 说明 | Extra 参数 |
|----------|------|-----------|
| `small_e` | 小指数攻击 | — |
| `common_modulus` | 共模攻击 | `e2,c2` |
| `wiener` | Wiener 攻击（d 较小） | — |
| `fermat` | Fermat 分解（p,q 接近） | — |
| `pollard_p1` | Pollard p-1 分解 | — |
| `pollard_rho` | Pollard rho 分解 | — |
| `dp_leak` | dp 泄露攻击 | `dp 值` |
| `dq_leak` | dq 泄露攻击 | `dq 值` |
| `hastad` | Hastad 广播攻击 | `n2,c2;n3,c3;...` |
| `factordb` | factordb 在线查询 | — |
| `direct` | 已知 p,q 直接解密 | `p,q` |
| `multi_prime` | 多素数 RSA | `p1,p2,p3,...` |
| `rsa_auto_attack` | 自动攻击（依次尝试全部） | — |

---

## CLI 命令行模式

### 基本语法

```bash
python main.py cli <模块> <操作> <输入> [选项]
```

### 示例

```bash
# 密码学
python main.py cli crypto base64-decode "SGVsbG8gV29ybGQ="
python main.py cli crypto caesar-bruteforce "Khoor Zruog"
python main.py cli crypto aes-ecb-decrypt "密文hex" --key "密钥hex"
python main.py cli crypto vigenere-decrypt "密文" --key "KEY"

# RSA 攻击
python main.py cli rsa wiener --n 1234567 --e 65537 --c 9876543
python main.py cli rsa small-e --n 1234567 --e 3 --c 9876543
python main.py cli rsa direct --n 3233 --e 17 --c 2790 --extra "61,53"

# Web 安全
python main.py cli web detect-sqli "http://target.com/?id=1"
python main.py cli web jwt-forge-none "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.xxx"

# 取证分析
python main.py cli forensics identify-file challenge.png
python main.py cli forensics png-crc-fix broken.png
python main.py cli forensics pcap-analyze traffic.pcap

# 逆向工程
python main.py cli reverse analyze-binary pwn_challenge
python main.py cli reverse check-elf-protections pwn_challenge

# Pwn
python main.py cli pwn generate-pattern 200
python main.py cli pwn find-pattern-offset 0x41366141
python main.py cli pwn find-rop-gadgets pwn_challenge

# 杂项
python main.py cli misc morse-decode ".... . .-.. .-.. ---"
python main.py cli misc jwt-decode "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.xxx"
python main.py cli misc timestamp-convert "1700000000"

# 自动扫描
python main.py cli scan-text "SGVsbG8gV29ybGQ=" --output result.json --format json
python main.py cli scan-file challenge.png --output report.html --format html
python main.py cli scan-url "http://target.com/" --output scan.json --format json

# 操作历史
python main.py cli history                    # 查看最近 20 条
python main.py cli history --search "rsa"     # 搜索包含 rsa 的记录
python main.py cli history --flags            # 只看发现的 Flag
python main.py cli history --clear            # 清空历史
python main.py cli history --limit 50         # 查看最近 50 条
```

### CLI 全局选项

```bash
python main.py cli --verbose crypto rot13 "Hello"   # 启用详细日志
```

---

## 配置说明

### 配置目录

所有配置文件存放在 `~/.ctf-tool/` 目录下：

| 文件 | 说明 |
|------|------|
| `language.json` | 语言偏好（zh/en） |
| `flag_patterns.json` | 自定义 Flag 正则表达式 |
| `history.json` | 操作历史（最多 500 条） |
| `config.json` | 全局配置（超时/代理/输出目录等） |

### 自定义 Flag 格式

在 GUI 中点击工具栏的 Flag 设置按钮，可以添加自定义 Flag 格式。每行输入一个示例：

```
DASCTF{this_is_flag}
HGAME{sample_flag}
MyCustom{example}
```

程序会自动将示例转换为正则表达式进行匹配。

### 语言切换

- GUI：点击右上角语言切换按钮（中/EN）
- 设置会自动保存到 `~/.ctf-tool/language.json`

### 可选依赖

```bash
pip install pyzbar      # QR码/条码解码
pip install rarfile     # RAR 压缩包
pip install uncompyle6  # Python .pyc 反编译
pip install hashpumpy   # 哈希长度扩展攻击
pip install pytesseract # OCR 文字识别
```

---

## 常见问题

### Q: 程序启动时提示完整性校验失败？
A: 程序会校验关键文件的完整性。请从官方 Release 下载，不要修改 docs/ 目录下的文件。

### Q: 自动扫描文件时如何选择文件？
A: 选择"文件扫描"类型后，可以点击"选择文件"按钮，或直接在输入框中输入文件路径。

### Q: Web 扫描如何配置 Cookie/Header？
A: 在自动扫描面板的 curl 输入框中粘贴 curl 命令（如 `curl 'http://target.com' -H 'Cookie: session=abc'`），程序会自动解析并配置请求上下文。

### Q: Flag 自动检测支持哪些格式？
A: 支持 30+ 种 CTF 比赛 Flag 格式（flag{}, CTF{}, DASCTF{}, picoCTF{}, HTB{} 等），以及通用的 `XXX{...}` 格式。还会自动递归解码（Base64/Hex/URL/Base32/ROT13）最多 5 层。

### Q: 如何添加自定义 Flag 格式？
A: GUI 中点击 Flag 设置按钮，输入示例即可。CLI 模式不支持自定义 Flag。

### Q: 支持哪些操作系统？
A: Windows (x64)、macOS (ARM64/Intel)、Linux (x64)。Release 页面提供四个平台的可执行文件。
