#!/usr/bin/env python3
"""安装风险评估真实单元测试"""

import os
import sys
import os
import tempfile
import json
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from install_alert import InstallAlertEvaluator


def test_low_risk_skill():
    """测试低风险技能"""
    with tempfile.TemporaryDirectory() as tmpdir:
        skill_path = Path(tmpdir) / "safe-skill"
        skill_path.mkdir()
        (skill_path / "main.py").write_text("print('Hello')")
        
        evaluator = InstallAlertEvaluator()
        result = evaluator.evaluate_skill(str(skill_path))
        
        assert result['level'] == 'low'
        assert result['action'] == 'auto_allow'
        print("✅ test_low_risk_skill 通过")


def test_eval_exec_detection():
    """测试 eval/exec 检测"""
    with tempfile.TemporaryDirectory() as tmpdir:
        skill_path = Path(tmpdir) / "eval-skill"
        skill_path.mkdir()
        (skill_path / "code.py").write_text("result = eval(user_input)")
        
        evaluator = InstallAlertEvaluator()
        result = evaluator.evaluate_skill(str(skill_path))
        
        eval_factors = [f for f in result['factors'] if f['type'] == 'eval_exec']
        assert len(eval_factors) > 0
        assert eval_factors[0]['severity'] == 'high'
        print("✅ test_eval_exec_detection 通过")


def test_env_file_detection():
    """测试 .env 文件检测"""
    with tempfile.TemporaryDirectory() as tmpdir:
        skill_path = Path(tmpdir) / "env-skill"
        skill_path.mkdir()
        (skill_path / ".env").write_text("SECRET=abc123")
        
        evaluator = InstallAlertEvaluator()
        result = evaluator.evaluate_skill(str(skill_path))
        
        env_factors = [f for f in result['factors'] if f['type'] == 'risky_filename']
        assert len(env_factors) > 0
        assert env_factors[0]['severity'] == 'critical'
        print("✅ test_env_file_detection 通过")


def test_subprocess_detection():
    """测试 subprocess 检测"""
    with tempfile.TemporaryDirectory() as tmpdir:
        skill_path = Path(tmpdir) / "subprocess-skill"
        skill_path.mkdir()
        (skill_path / "code.py").write_text("import subprocess\nsubprocess.call('ls')")
        
        evaluator = InstallAlertEvaluator()
        result = evaluator.evaluate_skill(str(skill_path))
        
        sub_factors = [f for f in result['factors'] if f['type'] == 'subprocess']
        assert len(sub_factors) > 0
        assert sub_factors[0]['severity'] == 'high'
        print("✅ test_subprocess_detection 通过")


def test_nonexistent_path():
    """测试不存在的路径"""
    evaluator = InstallAlertEvaluator()
    result = evaluator.evaluate_skill("/nonexistent/path")
    
    assert result['level'] == 'critical'
    assert result['action'] == 'block'
    print("✅ test_nonexistent_path 通过")


def test_multiple_risk_factors():
    """测试多个风险因素"""
    with tempfile.TemporaryDirectory() as tmpdir:
        skill_path = Path(tmpdir) / "multi-risk"
        skill_path.mkdir()
        (skill_path / "code.py").write_text("""
import subprocess
subprocess.call('ls')
eval(user_input)
""")
        
        evaluator = InstallAlertEvaluator()
        result = evaluator.evaluate_skill(str(skill_path))
        
        # 应该有多个风险因素
        assert len(result['factors']) >= 2
        print("✅ test_multiple_risk_factors 通过")


if __name__ == '__main__':
    print("运行安装风险评估真实单元测试\n")
    test_low_risk_skill()
    test_eval_exec_detection()
    test_env_file_detection()
    test_subprocess_detection()
    test_nonexistent_path()
    test_multiple_risk_factors()
    print("\n" + "="*50)
    print("✅ 安装风险评估真实单元测试全部通过 (6/6)")
    print("="*50)
