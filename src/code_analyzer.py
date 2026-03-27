#!/usr/bin/env python3
"""
静态代码分析器 - ClawDef 核心组件

功能:
- AST 代码解析
- 敏感 API 检测
- 可疑模式识别
- 代码复杂度分析
"""

import ast
import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

LOG_PATH = os.path.expanduser("~/.openclaw/logs/clawdef.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()]
)
logger = logging.getLogger("ClawDef.CodeAnalyzer")


# 敏感 API 列表
SENSITIVE_APIS = {
    'dangerous_functions': ['eval', 'exec', 'compile', '__import__', 'getattr', 'setattr', 'delattr'],
    'system_calls': ['os.system', 'os.popen', 'os.spawn*', 'os.exec*'],
    'subprocess': ['subprocess.call', 'subprocess.run', 'subprocess.Popen', 'subprocess.check_output'],
    'file_operations': ['open', 'os.remove', 'os.unlink', 'shutil.rmtree'],
    'network': ['socket.socket', 'requests.get', 'requests.post', 'urllib.request.urlopen'],
    'crypto': ['hashlib', 'cryptography', 'Crypto'],
    'encoding': ['base64.b64encode', 'base64.b64decode', 'gzip.compress'],
}

# 可疑模式
SUSPICIOUS_PATTERNS = [
    {'name': '动态属性访问', 'pattern': 'getattr.*__name__', 'severity': 'medium'},
    {'name': '反射调用', 'pattern': 'globals\\(\\)|locals\\(\\)', 'severity': 'medium'},
    {'name': '字节码执行', 'pattern': 'types.CodeType', 'severity': 'high'},
    {'name': '内存执行', 'pattern': 'ctypes.CDLL', 'severity': 'high'},
    {'name': '隐藏导入', 'pattern': 'importlib.import_module', 'severity': 'medium'},
]


class CodeAnalyzer(ast.NodeVisitor):
    """代码分析器 - 基于 AST"""
    
    def __init__(self):
        self.issues = []
        self.imports = []
        self.function_calls = []
        self.string_literals = []
        self.current_file = ""
        self.current_line = 0
    
    def analyze_file(self, file_path: Path) -> Dict:
        """分析单个文件"""
        self.current_file = str(file_path)
        self.issues = []
        self.imports = []
        self.function_calls = []
        self.string_literals = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            tree = ast.parse(content)
            self.current_line = 0
            self.visit(tree)
            
            # 检查可疑模式
            self._check_suspicious_patterns(content)
            
            return {
                'file': str(file_path),
                'issues': self.issues,
                'imports': self.imports,
                'function_calls': self.function_calls,
                'risk_score': self._calculate_risk_score(),
            }
        except SyntaxError as e:
            logger.debug(f"语法错误 {file_path}: {e}")
            return {'file': str(file_path), 'issues': [], 'imports': [], 'function_calls': [], 'risk_score': 0}
        except Exception as e:
            logger.error(f"分析失败 {file_path}: {e}")
            return {'file': str(file_path), 'issues': [], 'imports': [], 'function_calls': [], 'risk_score': 0}
    
    def visit_Import(self, node):
        for alias in node.names:
            self.imports.append({
                'module': alias.name,
                'line': node.lineno,
                'file': self.current_file,
            })
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            self.imports.append({
                'module': f"{module}.{alias.name}",
                'line': node.lineno,
                'file': self.current_file,
            })
        self.generic_visit(node)
    
    def visit_Call(self, node):
        func_name = self._get_func_name(node)
        if func_name:
            self.function_calls.append({
                'function': func_name,
                'line': node.lineno,
                'file': self.current_file,
            })
            
            # 检查敏感 API
            self._check_sensitive_api(func_name, node.lineno)
        
        self.generic_visit(node)
    
    def visit_Str(self, node):
        self.string_literals.append({
            'value': node.s[:100] if len(node.s) > 100 else node.s,
            'line': getattr(node, 'lineno', 0),
            'file': self.current_file,
        })
        self.generic_visit(node)
    
    def _get_func_name(self, node) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        return None
    
    def _check_sensitive_api(self, func_name: str, line: int):
        """检查敏感 API 调用"""
        for category, apis in SENSITIVE_APIS.items():
            for api in apis:
                if api.endswith('*'):
                    if func_name.startswith(api[:-1]):
                        self.issues.append({
                            'type': 'sensitive_api',
                            'category': category,
                            'api': func_name,
                            'line': line,
                            'file': self.current_file,
                            'severity': 'high' if category in ['dangerous_functions', 'system_calls'] else 'medium',
                        })
                elif func_name == api:
                    self.issues.append({
                        'type': 'sensitive_api',
                        'category': category,
                        'api': func_name,
                        'line': line,
                        'file': self.current_file,
                        'severity': 'high' if category in ['dangerous_functions', 'system_calls'] else 'medium',
                    })
    
    def _check_suspicious_patterns(self, content: str):
        """检查可疑模式"""
        import re
        for pattern_info in SUSPICIOUS_PATTERNS:
            matches = re.finditer(pattern_info['pattern'], content)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.issues.append({
                    'type': 'suspicious_pattern',
                    'name': pattern_info['name'],
                    'pattern': pattern_info['pattern'],
                    'line': line_num,
                    'file': self.current_file,
                    'severity': pattern_info['severity'],
                    'match': match.group()[:50],
                })
    
    def _calculate_risk_score(self) -> int:
        """计算风险分数 (0-100)"""
        score = 0
        severity_weights = {'critical': 20, 'high': 10, 'medium': 5, 'low': 2}
        
        for issue in self.issues:
            weight = severity_weights.get(issue.get('severity', 'low'), 2)
            score += weight
        
        return min(score, 100)


class StaticCodeAnalyzer:
    """静态代码分析器 - 主类"""
    
    def __init__(self):
        self.ast_analyzer = CodeAnalyzer()
    
    def analyze_directory(self, dir_path: Path) -> Dict:
        """分析目录"""
        results = []
        total_issues = 0
        files_analyzed = 0
        
        for file_path in dir_path.rglob('*.py'):
            if file_path.is_file():
                files_analyzed += 1
                result = self.ast_analyzer.analyze_file(file_path)
                if result['issues'] or result['imports']:
                    results.append(result)
                total_issues += len(result['issues'])
        
        return {
            'results': results,
            'summary': {
                'files_analyzed': files_analyzed,
                'total_issues': total_issues,
                'files_with_issues': len(results),
                'analyzed_at': datetime.now().isoformat(),
            }
        }
    
    def print_report(self, result: Dict, target_name: str):
        """打印分析报告"""
        summary = result['summary']
        
        print("\n" + "="*70)
        print(f"🔍 ClawDef 静态代码分析报告 - {target_name}")
        print("="*70)
        
        print(f"\n📁 分析文件：{summary['files_analyzed']} 个")
        print(f"⚠️  问题文件：{summary['files_with_issues']} 个")
        print(f"🔍 问题总数：{summary['total_issues']} 个")
        
        if result['results']:
            print(f"\n📋 问题详情:")
            print("-"*70)
            
            for file_result in result['results']:
                if file_result['issues']:
                    print(f"\n文件：{file_result['file']}")
                    print(f"风险分数：{file_result['risk_score']}/100")
                    
                    for issue in file_result['issues'][:10]:
                        severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
                        emoji = severity_emoji.get(issue.get('severity', 'low'), '⚪')
                        print(f"  {emoji} 行 {issue['line']}: {issue.get('api', issue.get('name', 'unknown'))}")
        
        print("\n" + "="*70 + "\n")


def main():
    """CLI 入口"""
    import sys
    
    if len(sys.argv) < 2:
        print("用法：python3 code_analyzer.py <directory>")
        sys.exit(1)
    
    target = Path(sys.argv[1])
    analyzer = StaticCodeAnalyzer()
    
    if target.is_file():
        result = analyzer.ast_analyzer.analyze_file(target)
        result = {'results': [result], 'summary': {'files_analyzed': 1, 'total_issues': len(result['issues']), 'files_with_issues': 1 if result['issues'] else 0, 'analyzed_at': datetime.now().isoformat()}}
    else:
        result = analyzer.analyze_directory(target)
    
    analyzer.print_report(result, target.name)


if __name__ == '__main__':
    main()
