#!/usr/bin/env python3
"""静态代码分析器真实单元测试"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from code_analyzer import StaticCodeAnalyzer, CodeAnalyzer


def test_analyzer_initialization():
    """测试分析器初始化"""
    analyzer = StaticCodeAnalyzer()
    assert analyzer.ast_analyzer is not None
    print("✅ test_analyzer_initialization 通过")


def test_detect_eval_call():
    """测试检测 eval 调用"""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test.py"
        test_file.write_text("result = eval(user_input)")
        
        analyzer = CodeAnalyzer()
        result = analyzer.analyze_file(test_file)
        
        eval_issues = [i for i in result['issues'] if i.get('api') == 'eval']
        assert len(eval_issues) > 0
        print("✅ test_detect_eval_call 通过")


def test_detect_exec_call():
    """测试检测 exec 调用"""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test.py"
        test_file.write_text("exec(code)")
        
        analyzer = CodeAnalyzer()
        result = analyzer.analyze_file(test_file)
        
        exec_issues = [i for i in result['issues'] if i.get('api') == 'exec']
        assert len(exec_issues) > 0
        print("✅ test_detect_exec_call 通过")


def test_detect_subprocess():
    """测试检测 subprocess"""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test.py"
        test_file.write_text("import subprocess\nsubprocess.call('ls')")
        
        analyzer = CodeAnalyzer()
        result = analyzer.analyze_file(test_file)
        
        sub_issues = [i for i in result['issues'] if 'subprocess' in i.get('api', '')]
        assert len(sub_issues) > 0
        print("✅ test_detect_subprocess 通过")


def test_clean_code():
    """测试干净代码"""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "clean.py"
        test_file.write_text("def add(a, b): return a + b")
        
        analyzer = CodeAnalyzer()
        result = analyzer.analyze_file(test_file)
        
        assert result['risk_score'] == 0
        assert len(result['issues']) == 0
        print("✅ test_clean_code 通过")


def test_import_detection():
    """测试导入检测"""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test.py"
        test_file.write_text("import os\nimport sys\nfrom pathlib import Path")
        
        analyzer = CodeAnalyzer()
        result = analyzer.analyze_file(test_file)
        
        assert len(result['imports']) == 3
        print("✅ test_import_detection 通过")


def test_directory_analysis():
    """测试目录分析"""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "safe.py").write_text("print('safe')")
        (Path(tmpdir) / "unsafe.py").write_text("eval(input())")
        
        analyzer = StaticCodeAnalyzer()
        result = analyzer.analyze_directory(Path(tmpdir))
        
        assert result['summary']['files_analyzed'] == 2
        assert result['summary']['total_issues'] >= 1
        print("✅ test_directory_analysis 通过")


if __name__ == '__main__':
    print("运行静态代码分析器真实单元测试\n")
    test_analyzer_initialization()
    test_detect_eval_call()
    test_detect_exec_call()
    test_detect_subprocess()
    test_clean_code()
    test_import_detection()
    test_directory_analysis()
    print("\n" + "="*50)
    print("✅ 静态代码分析器真实单元测试全部通过 (7/7)")
    print("="*50)
