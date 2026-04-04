# -*- coding: utf-8 -*-
"""完整性校验模块单元测试"""

import pytest

from ctftool.core.integrity import (
    AUTHOR,
    AUTHOR_CN,
    BMC_URL,
    EXPECTED_HASHES,
    README_MARKERS,
    SPONSOR_URL,
    _compute_signature,
    _verify_gui_integration,
    _verify_self,
    get_footer_text,
    verify_integrity,
)


class TestIntegrity:
    def test_author_info(self):
        """作者信息正确"""
        assert AUTHOR == "bbyybb"
        assert len(AUTHOR_CN) > 3

    def test_urls(self):
        """URL 包含作者名"""
        assert "bbyybb" in BMC_URL
        assert "buymeacoffee" in BMC_URL
        assert "bbyybb" in SPONSOR_URL
        assert "sponsors" in SPONSOR_URL

    def test_signature_consistent(self):
        """签名一致性"""
        sig1 = _compute_signature()
        sig2 = _compute_signature()
        assert sig1 == sig2
        assert len(sig1) == 16

    def test_self_check(self):
        """模块自检通过"""
        errors = _verify_self()
        assert errors == [], f"Self-check failed: {errors}"

    def test_gui_integration(self):
        """GUI 中包含打赏入口标记"""
        errors = _verify_gui_integration()
        assert errors == [], f"GUI markers missing: {errors}"

    def test_expected_hashes_format(self):
        """哈希格式正确（64 字符 hex）"""
        for path, h in EXPECTED_HASHES.items():
            assert len(h) == 64, f"{path}: hash length {len(h)}"
            assert all(c in '0123456789abcdef' for c in h)

    def test_readme_markers(self):
        """README 标记非空"""
        assert len(README_MARKERS) >= 5
        assert any("bbyybb" in m for m in README_MARKERS)

    def test_full_verify(self):
        """完整校验通过"""
        passed, errors = verify_integrity(strict=True)
        assert passed, f"Integrity check failed: {errors}"

    def test_footer_text(self):
        """底栏文本包含关键信息"""
        text = get_footer_text()
        assert "bbyybb" in text
        assert "CTF-Tool" in text or "ctf-tool" in text.lower()

    def test_tamper_detection(self):
        """篡改作者信息后校验必须失败"""
        import ctftool.core.integrity as m
        original_author = m.AUTHOR
        try:
            m.AUTHOR = "hacker"
            passed, errors = m.verify_integrity(strict=False)
            assert not passed, "Tampered author should fail integrity check"
            assert any("Signature" in e or "mismatch" in e for e in errors)
        finally:
            m.AUTHOR = original_author  # 恢复

    def test_blocking_behavior(self):
        """main.py 的 _check_integrity 在校验失败时应调用 sys.exit"""
        from unittest.mock import MagicMock, patch

        import ctftool.core.integrity as m
        original_author = m.AUTHOR
        try:
            m.AUTHOR = "hacker"
            from main import _check_integrity
            # Mock QMessageBox 避免弹出阻塞对话框
            mock_qmb = MagicMock()
            with patch.dict('sys.modules', {
                'PyQt6': MagicMock(),
                'PyQt6.QtWidgets': MagicMock(QMessageBox=mock_qmb),
            }):
                with pytest.raises(SystemExit) as exc_info:
                    _check_integrity()
            assert exc_info.value.code == 78
        finally:
            m.AUTHOR = original_author
