# Contributing / 贡献指南

Thank you for considering contributing! / 感谢你考虑为本项目做贡献！

## Development Setup / 开发环境

```bash
git clone https://github.com/bbyybb/ctf-tool.git
cd ctf-tool
pip install -r requirements.txt
pip install pytest
```

## Running Tests / 运行测试

```bash
python -m pytest tests/ -v
```

All tests must pass before submitting a PR.

提交 PR 前所有测试必须通过。

## Code Guidelines / 代码规范

- Python 3.10+
- UTF-8 encoding for all files / 所有文件使用 UTF-8 编码
- Backend modules (`ctftool/modules/`) must be UI-independent / 后端模块与 UI 解耦
- New features should include unit tests / 新功能需附带单元测试
- i18n: Add translations in `ctftool/core/i18n_en.json` and `ctftool/core/i18n_zh.json` / 国际化：在 `ctftool/core/i18n_en.json` 和 `ctftool/core/i18n_zh.json` 中添加翻译

## Code Style / 代码风格

We use [ruff](https://github.com/astral-sh/ruff) for linting:

我们使用 [ruff](https://github.com/astral-sh/ruff) 进行代码检查：

```bash
pip install ruff
ruff check ctftool/ tests/    # Check / 检查
ruff check --fix ctftool/     # Auto-fix / 自动修复
```

Configuration is in `pyproject.toml`. CI will run `ruff check` on every PR.

配置位于 `pyproject.toml`，CI 会在每个 PR 上自动运行。

## Branch Strategy / 分支策略

- `main` — stable release branch / 稳定发布分支
- `master` — development branch / 开发分支
- Feature branches: `feature/<name>` / 功能分支
- Bug fixes: `fix/<name>` / 修复分支

## Commit Convention / 提交规范

Use clear, descriptive commit messages / 使用清晰的提交信息：

```
<type>: <description>

Types: feat, fix, docs, test, refactor, ci, chore
```

Examples / 示例:
- `feat: add RAR password crack support`
- `fix: handle empty input in morse_decode`
- `docs: add configuration section to README`

## Building / 构建

```bash
# Local build / 本地构建
./scripts/build-release.sh

# Update QR hashes after replacing images / 更换二维码后更新哈希
./scripts/update-hashes.sh
```

## CLI Mode / 命令行模式

```bash
# CLI mode for scripting / 脚本化命令行模式
python main.py cli crypto rot13 "synt{grfg}"
python main.py cli forensics identify /path/to/file
python main.py cli scan-text "ZmxhZ3t0ZXN0fQ=="
```

## PR Checklist / PR 检查清单

- [ ] All tests pass / 所有测试通过 (`python -m pytest tests/ -v`)
- [ ] New features include tests / 新功能包含测试
- [ ] No hardcoded secrets / 无硬编码密钥
- [ ] Donation/support info not modified / 打赏信息未被修改
- [ ] i18n translations added for new strings / 新字符串已添加中英文翻译

## Reporting Bugs / 报告 Bug

Please use [GitHub Issues](https://github.com/bbyybb/ctf-tool/issues).

请使用 [GitHub Issues](https://github.com/bbyybb/ctf-tool/issues) 报告。
