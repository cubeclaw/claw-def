#!/usr/bin/env python3
"""威胁检测引擎真实单元测试"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from threat_detector import ThreatDetector


def test_detector_initialization():
    """测试检测器初始化"""
    detector = ThreatDetector()
    assert len(detector.compiled_patterns) > 50
    print("✅ test_detector_initialization 通过")


def test_scan_clean_file():
    """测试扫描干净文件"""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "clean.py"
        test_file.write_text("print('Hello, World!')")
        
        detector = ThreatDetector()
        threats = detector.scan_file(test_file)
        assert len(threats) == 0
        print("✅ test_scan_clean_file 通过")


def test_detect_eval_usage():
    """测试检测 eval 使用"""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "eval.py"
        test_file.write_text("result = eval(user_input)")
        
        detector = ThreatDetector()
        threats = detector.scan_file(test_file)
        eval_threats = [t for t in threats if t['pattern_id'] == 'CE001']
        assert len(eval_threats) > 0
        print("✅ test_detect_eval_usage 通过")


def test_detect_sudo_usage():
    """测试检测 sudo 使用"""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "sudo.py"
        test_file.write_text("os.system('sudo rm -rf /')")
        
        detector = ThreatDetector()
        threats = detector.scan_file(test_file)
        sudo_threats = [t for t in threats if t['pattern_id'] == 'PR001']
        assert len(sudo_threats) > 0
        print("✅ test_detect_sudo_usage 通过")


def test_detect_subprocess():
    """测试检测 subprocess 调用"""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "sub.py"
        test_file.write_text("import subprocess\nsubprocess.call('ls -la')")
        
        detector = ThreatDetector()
        threats = detector.scan_file(test_file)
        sub_threats = [t for t in threats if t['pattern_id'] == 'CE003']
        assert len(sub_threats) > 0
        print("✅ test_detect_subprocess 通过")


def test_scan_directory():
    """测试扫描目录"""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "clean.py").write_text("print('safe')")
        (Path(tmpdir) / "malicious.py").write_text("eval(input())")
        
        detector = ThreatDetector()
        result = detector.scan_directory(Path(tmpdir))
        
        assert result['summary']['files_scanned'] == 2
        assert result['summary']['files_with_threats'] == 1
        print("✅ test_scan_directory 通过")


def test_risk_level_calculation():
    """测试风险等级计算"""
    detector = ThreatDetector()
    assert detector.get_risk_level([]) == 'safe'
    assert detector.get_risk_level([{'severity': 'low'}]) == 'low'
    assert detector.get_risk_level([{'severity': 'high'}]) == 'medium'
    assert detector.get_risk_level([{'severity': 'critical'}]) == 'critical'
    print("✅ test_risk_level_calculation 通过")


if __name__ == '__main__':
    print("运行威胁检测引擎真实单元测试\n")
    test_detector_initialization()
    test_scan_clean_file()
    test_detect_eval_usage()
    test_detect_sudo_usage()
    test_detect_subprocess()
    test_scan_directory()
    test_risk_level_calculation()
    print("\n" + "="*50)
    print("✅ 威胁检测引擎真实单元测试全部通过 (7/7)")
    print("="*50)
