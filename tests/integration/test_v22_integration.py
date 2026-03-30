#!/usr/bin/env python3
"""ClawDef v2.2 集成测试"""

import os
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

def test_auto_block_integration():
    """测试自动阻断集成"""
    from auto_block import AutoBlocker
    blocker = AutoBlocker()
    result = blocker.check_and_block('eval')
    assert result['blocked'] == True
    print("✅ test_auto_block_integration 通过")

def test_crypto_integration():
    """测试加密模块集成"""
    from crypto import CredentialProtector
    protector = CredentialProtector("test_integration")
    encrypted = protector.encrypt("test_key", "integration_test")
    decrypted = protector.get_credential("integration_test")
    assert decrypted == "test_key"
    print("✅ test_crypto_integration 通过")

def test_threat_detector_integration():
    """测试威胁检测集成"""
    from threat_detector import ThreatDetector
    detector = ThreatDetector()
    assert len(detector.compiled_patterns) > 50
    print("✅ test_threat_detector_integration 通过")

def test_code_analyzer_integration():
    """测试代码分析集成"""
    from code_analyzer import StaticCodeAnalyzer
    analyzer = StaticCodeAnalyzer()
    assert analyzer.ast_analyzer is not None
    print("✅ test_code_analyzer_integration 通过")

def test_file_monitor_integration():
    """测试文件监控集成"""
    from file_monitor import FileMonitor
    monitor = FileMonitor()
    result = monitor.check_access(os.path.expanduser('~/.ssh/id_rsa'), 'read')
    assert result['allowed'] == False
    print("✅ test_file_monitor_integration 通过")

def test_full_workflow():
    """测试完整工作流"""
    from auto_block import AutoBlocker
    from crypto import CredentialProtector
    from threat_detector import ThreatDetector
    
    # 1. 阻断危险操作
    blocker = AutoBlocker()
    blocker.check_and_block('eval')
    
    # 2. 加密存储凭证
    protector = CredentialProtector("workflow_test")
    protector.encrypt("api_key_123", "test_api")
    
    # 3. 威胁检测
    detector = ThreatDetector()
    assert len(detector.compiled_patterns) > 50
    
    print("✅ test_full_workflow 通过")

if __name__ == '__main__':
    print("运行 ClawDef v2.2 集成测试\n")
    test_auto_block_integration()
    test_crypto_integration()
    test_threat_detector_integration()
    test_code_analyzer_integration()
    test_file_monitor_integration()
    test_full_workflow()
    print("\n✅ ClawDef v2.2 集成测试全部通过 (6/6)")
