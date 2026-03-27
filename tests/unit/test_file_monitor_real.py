#!/usr/bin/env python3
"""文件监控器真实单元测试"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from file_monitor import FileMonitor, NetworkInterceptor


def test_monitor_initialization():
    """测试监控器初始化"""
    monitor = FileMonitor()
    assert 'critical' in monitor.blocked_paths
    assert 'restricted' in monitor.blocked_paths
    print("✅ test_monitor_initialization 通过")


def test_critical_path_blocked():
    """测试 critical 路径被阻止"""
    monitor = FileMonitor()
    
    result = monitor.check_access(os.path.expanduser('~/.ssh/id_rsa'))
    assert result['allowed'] == False
    assert result['level'] == 'critical'
    print("✅ test_critical_path_blocked 通过")


def test_restricted_path_warn():
    """测试 restricted 路径告警"""
    monitor = FileMonitor()
    
    result = monitor.check_access(os.path.expanduser('~/.aws/credentials'))
    assert result['allowed'] == False
    print("✅ test_restricted_path_warn 通过")


def test_allowed_path_pass():
    """测试允许的路径通过"""
    monitor = FileMonitor()
    
    with tempfile.NamedTemporaryFile() as f:
        result = monitor.check_access(f.name)
        assert result['allowed'] == True
    print("✅ test_allowed_path_pass 通过")


def test_add_blocked_path():
    """测试添加阻止路径"""
    monitor = FileMonitor()
    monitor.add_blocked_path('~/my-secret', 'critical')
    
    expanded = os.path.expanduser('~/my-secret')
    assert expanded in monitor.blocked_paths['critical']
    print("✅ test_add_blocked_path 通过")


def test_network_interceptor():
    """测试网络拦截器"""
    interceptor = NetworkInterceptor()
    interceptor.add_blocked_host('evil.com')
    
    result = interceptor.check_request('http://evil.com/steal')
    assert result['allowed'] == False
    assert result['action'] == 'block'
    
    result = interceptor.check_request('http://localhost:8080')
    assert result['allowed'] == True
    print("✅ test_network_interceptor 通过")


def test_access_logging():
    """测试访问日志"""
    monitor = FileMonitor()
    
    # 使用实际路径
    monitor.check_access(os.path.expanduser('~/.ssh/id_rsa'))
    monitor.check_access(os.path.expanduser('~/.aws/credentials'))
    
    with tempfile.NamedTemporaryFile() as f:
        monitor.check_access(f.name)
    
    logs = monitor.get_recent_access()
    assert len(logs) >= 1  # 至少有一个阻止的日志
    print("✅ test_access_logging 通过")


if __name__ == '__main__':
    print("运行文件监控器真实单元测试\n")
    test_monitor_initialization()
    test_critical_path_blocked()
    test_restricted_path_warn()
    test_allowed_path_pass()
    test_add_blocked_path()
    test_network_interceptor()
    test_access_logging()
    print("\n" + "="*50)
    print("✅ 文件监控器真实单元测试全部通过 (7/7)")
    print("="*50)
