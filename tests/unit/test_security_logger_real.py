#!/usr/bin/env python3
"""安全日志中心真实单元测试"""

import os
import sys
import tempfile
import json
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from security_logger import SecurityLogger


def test_logger_initialization():
    """测试日志器初始化"""
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_file = f.name
    
    logger = SecurityLogger(log_file)
    assert os.path.exists(log_file)
    os.unlink(log_file)
    print("✅ test_logger_initialization 通过")


def test_log_threat():
    """测试威胁日志"""
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_file = f.name
    
    try:
        logger = SecurityLogger(log_file)
        logger.log_threat({
            'pattern_id': 'CE001',
            'pattern_name': 'eval() 调用',
            'severity': 'high',
            'file': '/tmp/test.py',
        })
        
        events = logger.query(event_type='threat_detected')
        assert len(events) == 1
        assert events[0]['data']['pattern_id'] == 'CE001'
        print("✅ test_log_threat 通过")
    finally:
        os.unlink(log_file)


def test_log_file_access():
    """测试文件访问日志"""
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_file = f.name
    
    try:
        logger = SecurityLogger(log_file)
        logger.log_file_access({
            'file': '~/.ssh/id_rsa',
            'operation': 'read',
            'level': 'critical',
        })
        
        events = logger.query(event_type='file_access')
        assert len(events) == 1
        print("✅ test_log_file_access 通过")
    finally:
        os.unlink(log_file)


def test_query_by_type():
    """测试按类型查询"""
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_file = f.name
    
    try:
        logger = SecurityLogger(log_file)
        logger.log_threat({'pattern_id': 'CE001'})
        logger.log_file_access({'file': '~/.ssh/id_rsa'})
        logger.log_threat({'pattern_id': 'CE002'})
        
        threats = logger.query(event_type='threat_detected')
        accesses = logger.query(event_type='file_access')
        
        assert len(threats) == 2
        assert len(accesses) == 1
        print("✅ test_query_by_type 通过")
    finally:
        os.unlink(log_file)


def test_get_summary():
    """测试摘要统计"""
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_file = f.name
    
    try:
        logger = SecurityLogger(log_file)
        logger.log_threat({'pattern_id': 'CE001', 'severity': 'high'})
        logger.log_threat({'pattern_id': 'CT001', 'severity': 'critical'})
        logger.log_file_access({'file': '~/.ssh/id_rsa'})
        
        summary = logger.get_summary(hours=1)
        assert summary['total_events'] == 3
        assert summary['by_severity']['critical'] == 1
        assert summary['by_severity']['high'] == 1
        print("✅ test_get_summary 通过")
    finally:
        os.unlink(log_file)


def test_export_json():
    """测试 JSON 导出"""
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_file = f.name
    
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        output_file = f.name
    
    try:
        logger = SecurityLogger(log_file)
        logger.log_threat({'pattern_id': 'CE001'})
        
        count = logger.export(output_file, format='json')
        assert count == 1
        
        with open(output_file) as f:
            data = json.load(f)
            assert len(data) == 1
        print("✅ test_export_json 通过")
    finally:
        os.unlink(log_file)
        os.unlink(output_file)


if __name__ == '__main__':
    print("运行安全日志中心真实单元测试\n")
    test_logger_initialization()
    test_log_threat()
    test_log_file_access()
    test_query_by_type()
    test_get_summary()
    test_export_json()
    print("\n" + "="*50)
    print("✅ 安全日志中心真实单元测试全部通过 (6/6)")
    print("="*50)
