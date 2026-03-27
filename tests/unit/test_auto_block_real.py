#!/usr/bin/env python3
"""自动阻断模块真实单元测试"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from auto_block import AutoBlocker, RuntimeMonitor

def test_blocker_init():
    blocker = AutoBlocker()
    assert len(blocker.block_list) > 5
    print("✅ test_blocker_init 通过")

def test_eval_blocked():
    blocker = AutoBlocker()
    result = blocker.check_and_block('eval')
    assert result['blocked'] == True
    print("✅ test_eval_blocked 通过")

def test_sensitive_file_blocked():
    blocker = AutoBlocker()
    # 使用展开后的路径
    ssh_path = os.path.expanduser('~/.ssh/id_rsa')
    result = blocker.check_and_block('open', ssh_path)
    assert result['blocked'] == True
    print("✅ test_sensitive_file_blocked 通过")

def test_normal_file_allowed():
    blocker = AutoBlocker()
    result = blocker.check_and_block('open', '/tmp/test.txt')
    assert result['blocked'] == False
    print("✅ test_normal_file_allowed 通过")

def test_statistics():
    blocker = AutoBlocker()
    blocker.check_and_block('eval')
    blocker.check_and_block('exec')
    stats = blocker.get_statistics()
    assert stats['blocked_count'] == 2
    print("✅ test_statistics 通过")

def test_runtime_monitor():
    monitor = RuntimeMonitor()
    monitor.start()
    assert monitor.monitoring == True
    print("✅ test_runtime_monitor 通过")

if __name__ == '__main__':
    test_blocker_init()
    test_eval_blocked()
    test_sensitive_file_blocked()
    test_normal_file_allowed()
    test_statistics()
    test_runtime_monitor()
    print("\n✅ 自动阻断测试全部通过 (6/6)")
