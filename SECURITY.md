# Security Policy / 安全策略

## Intended Use / 使用范围

CTF-Tool is designed for **authorized security testing**, **CTF competitions**, and **educational purposes only**.

本工具仅用于**授权安全测试**、**CTF 竞赛**和**教育目的**。

Do not use against systems without explicit permission.

请勿对未授权的系统使用本工具。

## Supported Versions / 支持的版本

| Version / 版本 | Supported / 支持 |
|---|---|
| 1.0.x | Yes |
| < 1.0 | No |

## Reporting a Vulnerability / 报告漏洞

If you discover a vulnerability in CTF-Tool itself:

如果你发现本工具自身的安全漏洞：

1. **Do NOT** open a public issue / **不要**公开提 issue
2. Email: **ctftool.security@proton.me** or contact via [GitHub profile](https://github.com/bbyybb)
3. Include: description, steps to reproduce, impact / 包含：描述、复现步骤、影响

邮箱：**ctftool.security@proton.me** 或通过 [GitHub 个人主页](https://github.com/bbyybb)联系。

### Response Timeline / 响应时间线

| Action / 动作 | Timeframe / 时间 |
|---|---|
| Acknowledgment / 确认收到 | Within 48 hours / 48 小时内 |
| Initial assessment / 初步评估 | Within 7 days / 7 天内 |
| Fix release / 修复发布 | Within 30 days (critical) / 30 天内（严重漏洞） |

## Scope / 范围

- Vulnerabilities in the tool's own code / 工具自身代码漏洞
- Dependencies with known CVEs / 已知 CVE 的依赖

## Out of Scope / 不在范围内

- Vulnerabilities in target systems / 目标系统的漏洞
- Social engineering against maintainers / 对维护者的社工攻击

## Attribution Protection / 署名保护

This software includes a three-layer integrity protection:

本软件包含三层完整性保护：

1. **Startup check / 启动检查**: Verifies QR image hashes, signature, and code integrity. **Program refuses to start if check fails** (exit code 78). / 校验图片哈希、签名和代码完整性。**校验失败则程序拒绝启动**。
2. **GUI integration / GUI 集成**: Donation URLs loaded from integrity module, not hardcoded. / 打赏链接从完整性模块加载。
3. **CI check / CI 校验**: GitHub Actions verifies attribution before every build. / CI 在每次构建前校验署名信息。

Removing or modifying donation info will prevent the program from running.

移除或修改打赏信息将导致程序无法运行。
