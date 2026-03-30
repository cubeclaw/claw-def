#!/usr/bin/env python3
"""边界情况测试"""

import os
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

def test_auto_block_edge_cases():
    """测试自动阻断边界情况"""
    from auto_block import AutoBlocker
    
    blocker = AutoBlocker()
    
    # 空操作名
    result = blocker.check_and_block('')
    assert 'operation' in result
    
    # 空目标
    result = blocker.check_and_block('open', '')
    assert result is not None
    
    # 超长操作名
    result = blocker.check_and_block('a' * 1000)
    assert result is not None
    
    print("✅ test_auto_block_edge_cases 通过")

def test_crypto_edge_cases():
    """测试加密边界情况"""
    from crypto import CredentialProtector
    
    protector = CredentialProtector("test_edge")
    
    # 空字符串加密
    encrypted = protector.encrypt("")
    decrypted = protector.decrypt(encrypted)
    assert decrypted == ""
    
    # 超长字符串加密
    long_text = "x" * 10000
    encrypted = protector.encrypt(long_text)
    decrypted = protector.decrypt(encrypted)
    assert decrypted == long_text
    
    # 特殊字符
    special = "!@#$%^&*()_+{}|:<>?"
    encrypted = protector.encrypt(special)
    decrypted = protector.decrypt(encrypted)
    assert decrypted == special
    
    print("✅ test_crypto_edge_cases 通过")

def test_performance_basic():
    """测试基础性能"""
    import time
    from auto_block import AutoBlocker
    from crypto import CredentialProtector
    
    # 阻断性能
    blocker = AutoBlocker()
    start = time.time()
    for i in range(100):
        blocker.check_and_block('eval')
    duration = time.time() - start
    assert duration < 1.0  # 100 次阻断应小于 1 秒
    
    # 加密性能
    protector = CredentialProtector("perf_test")
    start = time.time()
    for i in range(10):
        protector.encrypt("test_key")
    duration = time.time() - start
    assert duration < 5.0  # 10 次加密应小于 5 秒
    
    print(f"✅ test_performance_basic 通过 (阻断：{duration:.3f}s)")

if __name__ == '__main__':
    test_auto_block_edge_cases()
    test_crypto_edge_cases()
    test_performance_basic()
    print("\n✅ 边界情况测试全部通过 (3/3)")
