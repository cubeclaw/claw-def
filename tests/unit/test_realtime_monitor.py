#!/usr/bin/env python3
"""实时监控测试"""

import os
import sys
import os
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))


def test_hosts_blocker():
    """测试 hosts 文件拦截器"""
    from file_monitor import HostsFileBlocker
    
    blocker = HostsFileBlocker()
    blocks = blocker.list_blocks()
    assert isinstance(blocks, list)
    print("✅ test_hosts_blocker 通过")


def test_process_info():
    """测试进程信息获取"""
    from file_monitor import ProcessAwareMonitor
    
    monitor = ProcessAwareMonitor()
    info = monitor.get_process_info()
    
    # psutil 可能未安装，只要有 pid 字段就行
    assert 'pid' in info
    print(f"✅ test_process_info 通过 (pid={info['pid']})")


def test_file_monitor_basic():
    """测试基础文件监控"""
    from file_monitor import FileMonitor
    
    monitor = FileMonitor()
    result = monitor.check_access(os.path.expanduser('~/.ssh/id_rsa'), 'read')
    assert result['allowed'] == False
    print("✅ test_file_monitor_basic 通过")


def test_realtime_monitor_init():
    """测试实时监控器初始化"""
    from file_monitor import RealTimeFileMonitor
    
    monitor = RealTimeFileMonitor()
    # inotify 可能未安装，但对象应该能创建
    assert monitor is not None
    print("✅ test_realtime_monitor_init 通过")


if __name__ == '__main__':
    test_hosts_blocker()
    test_process_info()
    test_file_monitor_basic()
    test_realtime_monitor_init()
    print("\n✅ 实时监控测试全部通过 (4/4)")
