#!/usr/bin/env python3
"""
文件保护模块真实单元测试
测试 src/file_protection.py 的实际功能
"""

import os
import sys
import tempfile
import json

# 添加 src 到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from file_protection import FileProtectionManager


def test_critical_file_blocked():
    """测试 critical 级别文件被阻止"""
    mgr = FileProtectionManager()
    result = mgr.check_file_operation("test-skill", "read", "~/.ssh/id_rsa")
    assert result['allowed'] == False
    assert result['level'] == 'critical'
    assert result['action'] == 'block'
    print("✅ test_critical_file_blocked 通过")


def test_allowed_file_pass():
    """测试 allowed 级别文件被允许"""
    mgr = FileProtectionManager()
    result = mgr.check_file_operation("test-skill", "read", "~/.openclaw/workspace/test.txt")
    assert result['allowed'] == True
    assert result['level'] == 'allowed'
    assert result['action'] == 'allow'
    print("✅ test_allowed_file_pass 通过")


def test_add_critical_rule():
    """测试添加 critical 规则并生效"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump({}, f)
        temp_config = f.name
    
    try:
        mgr = FileProtectionManager(config_path=temp_config)
        mgr.add_protection_rule('critical', '~/my-secret.txt')
        result = mgr.check_file_operation("test-skill", "read", "~/my-secret.txt")
        assert result['allowed'] == False
        assert result['level'] == 'critical'
        print("✅ test_add_critical_rule 通过")
    finally:
        os.unlink(temp_config)


def test_authorization_flow():
    """测试授权流程"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump({}, f)
        temp_config = f.name
    
    try:
        mgr = FileProtectionManager(config_path=temp_config)
        
        # 添加规则
        mgr.add_protection_rule('restricted', '~/auth-test.txt')
        
        # 未授权时阻止
        result1 = mgr.check_file_operation("skill", "read", "~/auth-test.txt")
        assert result1['allowed'] == False
        
        # 授权
        mgr.authorize("skill", "~/auth-test.txt")
        
        # 授权后允许
        result2 = mgr.check_file_operation("skill", "read", "~/auth-test.txt")
        assert result2['allowed'] == True
        
        print("✅ test_authorization_flow 通过")
    finally:
        os.unlink(temp_config)


def test_operation_history():
    """测试操作历史记录"""
    mgr = FileProtectionManager()
    mgr.check_file_operation("skill-1", "read", "~/.ssh/id_rsa")
    mgr.check_file_operation("skill-1", "read", "~/.openclaw/workspace/test.txt")
    mgr.check_file_operation("skill-2", "write", "/tmp/test.txt")
    
    history = mgr.get_operation_history()
    assert len(history) == 3
    
    history_skill1 = mgr.get_operation_history("skill-1")
    assert len(history_skill1) == 2
    
    print("✅ test_operation_history 通过")


def test_list_protection_rules():
    """测试列出保护规则"""
    mgr = FileProtectionManager()
    rules = mgr.list_protection_rules()
    
    assert 'default' in rules
    assert 'critical' in rules['default']
    assert len(rules['default']['critical']) > 5
    
    print("✅ test_list_protection_rules 通过")


def test_config_persistence():
    """测试配置持久化"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_config = f.name
    
    try:
        mgr = FileProtectionManager(config_path=temp_config)
        mgr.add_protection_rule('critical', '~/persist-test.txt')
        
        # 重新加载
        mgr2 = FileProtectionManager(config_path=temp_config)
        result = mgr2.check_file_operation("skill", "read", "~/persist-test.txt")
        assert result['allowed'] == False
        assert result['level'] == 'critical'
        
        print("✅ test_config_persistence 通过")
    finally:
        os.unlink(temp_config)


if __name__ == '__main__':
    print("运行文件保护模块真实单元测试\n")
    
    test_critical_file_blocked()
    test_allowed_file_pass()
    test_add_critical_rule()
    test_authorization_flow()
    test_operation_history()
    test_list_protection_rules()
    test_config_persistence()
    
    print("\n" + "="*50)
    print("✅ 文件保护模块真实单元测试全部通过 (7/7)")
    print("="*50)
