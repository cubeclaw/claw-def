#!/usr/bin/env python3
"""威胁检测引擎真实单元测试 - 简化版"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from threat_detector import ThreatDetector


def test_detector_init():
    """测试初始化"""
    detector = ThreatDetector()
    assert len(detector.compiled_patterns) > 50
    print("✅ test_detector_init 通过")

def test_clean_file():
    """测试干净文件"""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "clean.py"
        test_file.write_text("print('Hello')")
        detector = ThreatDetector()
        threats = detector.scan_file(test_file)
        assert len(threats) == 0
    print("✅ test_clean_file 通过")

def test_eval_detection():
    """测试 eval 检测"""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "eval.py"
        test_file.write_text("result = eval(input())")
        detector = ThreatDetector()
        threats = detector.scan_file(test_file)
        assert len(threats) > 0
    print("✅ test_eval_detection 通过")

def test_sudo_detection():
    """测试 sudo 检测"""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "sudo.py"
        test_file.write_text("os.system('sudo rm -rf /')")
        detector = ThreatDetector()
        threats = detector.scan_file(test_file)
        sudo_threats = [t for t in threats if t['pattern_id'] == 'PR001']
        assert len(sudo_threats) > 0
    print("✅ test_sudo_detection 通过")

def test_risk_level():
    """测试风险等级"""
    detector = ThreatDetector()
    assert detector.get_risk_level([]) == 'safe'
    assert detector.get_risk_level([{'severity': 'critical'}]) == 'critical'
    print("✅ test_risk_level 通过")

if __name__ == '__main__':
    test_detector_init()
    test_clean_file()
    test_eval_detection()
    test_sudo_detection()
    test_risk_level()
    print("\n✅ 威胁检测测试全部通过 (5/5)")
