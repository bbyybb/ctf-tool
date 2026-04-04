# -*- coding: utf-8 -*-
"""共享测试 fixture"""
import os
import tempfile

import pytest


@pytest.fixture
def crypto_module():
    from ctftool.modules.crypto import CryptoModule
    return CryptoModule()


@pytest.fixture
def web_module():
    from ctftool.modules.web import WebModule
    return WebModule()


@pytest.fixture
def forensics_module():
    from ctftool.modules.forensics import ForensicsModule
    return ForensicsModule()


@pytest.fixture
def reverse_module():
    from ctftool.modules.reverse import ReverseModule
    return ReverseModule()


@pytest.fixture
def pwn_module():
    from ctftool.modules.pwn import PwnModule
    return PwnModule()


@pytest.fixture
def misc_module():
    from ctftool.modules.misc import MiscModule
    return MiscModule()


@pytest.fixture
def tmp_file():
    """创建临时文件，测试后自动清理"""
    files = []
    def _create(content: bytes = b"", suffix: str = ".tmp"):
        f = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
        f.write(content)
        f.close()
        files.append(f.name)
        return f.name
    yield _create
    for f in files:
        if os.path.exists(f):
            os.unlink(f)
