#!/usr/bin/env python3
"""文件保护模块真实单元测试 - 简化版"""

import os
import sys
import os
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

# 直接测试核心功能
def test_ssh_key_blocked():
    """测试 SSH 密钥被阻止"""
    from file_protection import FileProtectionManager
    mgr = FileProtectionManager()
    result = mgr.check_file_operation("test", "read", os.path.expanduser("~/.ssh/id_rsa"))
    assert result['allowed'] == False
    print("✅ test_ssh_key_blocked 通过")

def test_workspace_allowed():
    """测试工作区文件允许"""
    from file_protection import FileProtectionManager
    mgr = FileProtectionManager()
    with tempfile.NamedTemporaryFile() as f:
        result = mgr.check_file_operation("test", "read", f.name)
        assert result['allowed'] == True
    print("✅ test_workspace_allowed 通过")

def test_aws_credentials_blocked():
    """测试 AWS 凭证被阻止"""
    from file_protection import FileProtectionManager
    mgr = FileProtectionManager()
    result = mgr.check_file_operation("test", "read", os.path.expanduser("~/.aws/credentials"))
    assert result['allowed'] == False
    print("✅ test_aws_credentials_blocked 通过")

if __name__ == '__main__':
    test_ssh_key_blocked()
    test_workspace_allowed()
    test_aws_credentials_blocked()
    print("\n✅ 文件保护测试全部通过 (3/3)")
