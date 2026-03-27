#!/usr/bin/env python3
"""
威胁检测引擎 - ClawDef 核心组件

功能:
- 加载威胁特征库
- 扫描代码文件
- 匹配恶意模式
- 生成威胁报告
"""

import os
import re
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

# 配置日志
LOG_PATH = os.path.expanduser("~/.openclaw/logs/clawdef.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()]
)
logger = logging.getLogger("ClawDef.ThreatDetector")


class ThreatDetector:
    """威胁检测器"""
    
    def __init__(self, signatures_path: Optional[str] = None):
        """
        初始化检测器
        
        Args:
            signatures_path: 特征库路径，默认使用内置特征
        """
        if signatures_path:
            self.signatures_path = Path(signatures_path)
        else:
            # 默认使用内置特征库
            self.signatures_path = Path(__file__).parent.parent / "data" / "threat_signatures.json"
        
        self.signatures = self._load_signatures()
        self.compiled_patterns = self._compile_patterns()
        
        logger.info(f"威胁检测器初始化完成，加载 {len(self.compiled_patterns)} 个特征")
    
    def _load_signatures(self) -> Dict:
        """加载特征库"""
        if not self.signatures_path.exists():
            logger.warning(f"特征库不存在：{self.signatures_path}")
            return {"categories": {}, "metadata": {}}
        
        try:
            with open(self.signatures_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"加载特征库失败：{e}")
            return {"categories": {}, "metadata": {}}
    
    def _compile_patterns(self) -> List[Tuple[str, Dict, object]]:
        """预编译正则表达式"""
        compiled = []
        
        for category_id, category in self.signatures.get('categories', {}).items():
            for pattern in category.get('patterns', []):
                try:
                    regex = re.compile(pattern['pattern'], re.IGNORECASE | re.MULTILINE)
                    compiled.append((category_id, pattern, regex))
                except re.error as e:
                    logger.warning(f"无效的正则表达式 {pattern['id']}: {e}")
        
        return compiled
    
    def scan_file(self, file_path: Path) -> List[Dict]:
        """扫描单个文件"""
        threats = []
        
        # 跳过二进制文件
        skip_extensions = {'.pyc', '.pyo', '.so', '.dll', '.exe', '.bin', '.jpg', '.png', '.gif', '.woff', '.ttf'}
        if file_path.suffix in skip_extensions:
            return threats
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"无法读取文件 {file_path}: {e}")
            return threats
        
        # 匹配所有特征
        for category_id, pattern, regex in self.compiled_patterns:
            matches = regex.finditer(content)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                threats.append({
                    'category': category_id,
                    'pattern_id': pattern['id'],
                    'pattern_name': pattern['name'],
                    'severity': pattern['severity'],
                    'description': pattern['description'],
                    'file': str(file_path),
                    'line': line_num,
                    'match': match.group()[:100],
                    'confidence': self._calculate_confidence(match, pattern),
                })
        
        return threats
    
    def _calculate_confidence(self, match: object, pattern: Dict) -> float:
        """计算置信度 (0-1)"""
        # 基础置信度
        confidence = 0.7
        
        # 匹配长度越长，置信度越高
        match_len = len(match.group())
        if match_len > 50:
            confidence += 0.1
        if match_len > 100:
            confidence += 0.1
        
        # 关键模式提高置信度
        if pattern['severity'] == 'critical':
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def scan_directory(self, dir_path: Path) -> Dict:
        """扫描目录"""
        all_threats = []
        files_scanned = 0
        files_with_threats = 0
        
        for file_path in dir_path.rglob('*'):
            if file_path.is_file():
                files_scanned += 1
                threats = self.scan_file(file_path)
                if threats:
                    files_with_threats += 1
                    all_threats.extend(threats)
        
        # 按严重程度排序
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        all_threats.sort(key=lambda x: (severity_order.get(x['severity'], 4), x['file']))
        
        return {
            'threats': all_threats,
            'summary': {
                'files_scanned': files_scanned,
                'files_with_threats': files_with_threats,
                'total_threats': len(all_threats),
                'by_severity': self._count_by_severity(all_threats),
                'by_category': self._count_by_category(all_threats),
                'scanned_at': datetime.now().isoformat(),
            }
        }
    
    def _count_by_severity(self, threats: List[Dict]) -> Dict:
        """按严重程度统计"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for threat in threats:
            severity = threat.get('severity', 'low')
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def _count_by_category(self, threats: List[Dict]) -> Dict:
        """按类别统计"""
        counts = {}
        for threat in threats:
            category = threat.get('category', 'unknown')
            counts[category] = counts.get(category, 0) + 1
        return counts
    
    def get_risk_level(self, threats: List[Dict]) -> str:
        """根据威胁列表确定风险等级"""
        if not threats:
            return 'safe'
        
        critical_count = sum(1 for t in threats if t['severity'] == 'critical')
        high_count = sum(1 for t in threats if t['severity'] == 'high')
        
        if critical_count > 0:
            return 'critical'
        elif high_count > 3:
            return 'high'
        elif high_count > 0:
            return 'medium'
        else:
            return 'low'
    
    def print_report(self, result: Dict, target_name: str):
        """打印检测报告"""
        summary = result['summary']
        threats = result['threats']
        
        print("\n" + "="*70)
        print(f"🛡️  ClawDef 威胁检测报告 - {target_name}")
        print("="*70)
        
        # 总体统计
        risk_level = self.get_risk_level(threats)
        risk_emoji = {'critical': '🚨', 'high': '⚠️', 'medium': '⚡', 'low': '✅', 'safe': '✅'}
        
        print(f"\n{risk_emoji.get(risk_level, '❓')} 风险等级：{risk_level.upper()}")
        print(f"📁 扫描文件：{summary['files_scanned']} 个")
        print(f"⚠️  问题文件：{summary['files_with_threats']} 个")
        print(f"🔍 威胁总数：{summary['total_threats']} 个")
        
        # 按严重程度统计
        print(f"\n📊 威胁分布:")
        print(f"  🔴 Critical: {summary['by_severity'].get('critical', 0)}")
        print(f"  🟠 High:     {summary['by_severity'].get('high', 0)}")
        print(f"  🟡 Medium:   {summary['by_severity'].get('medium', 0)}")
        print(f"  🟢 Low:      {summary['by_severity'].get('low', 0)}")
        
        # 详细威胁列表
        if threats:
            print(f"\n📋 威胁详情 (前 20 个):")
            print("-"*70)
            
            for i, threat in enumerate(threats[:20], 1):
                severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
                print(f"{i}. {severity_emoji.get(threat['severity'], '⚪')} [{threat['severity'].upper()}] {threat['pattern_name']}")
                print(f"   文件：{threat['file']}:{threat['line']}")
                print(f"   类别：{threat['category']} | 置信度：{threat['confidence']*100:.0f}%")
                if threat['match']:
                    print(f"   匹配：{threat['match'][:60]}...")
                print()
            
            if len(threats) > 20:
                print(f"... 还有 {len(threats) - 20} 个威胁")
        else:
            print("\n✅ 未检测到威胁")
        
        print("="*70 + "\n")


def main():
    """CLI 入口"""
    import sys
    
    if len(sys.argv) < 2:
        print("用法：python3 threat_detector.py <file_or_directory>")
        print("示例：python3 threat_detector.py /path/to/skill")
        sys.exit(1)
    
    target = Path(sys.argv[1])
    detector = ThreatDetector()
    
    if target.is_file():
        threats = detector.scan_file(target)
        result = {'threats': threats, 'summary': {'files_scanned': 1, 'files_with_threats': 1 if threats else 0, 'total_threats': len(threats), 'by_severity': detector._count_by_severity(threats), 'by_category': detector._count_by_category(threats), 'scanned_at': datetime.now().isoformat()}}
    else:
        result = detector.scan_directory(target)
    
    detector.print_report(result, target.name)
    
    # 根据风险等级返回退出码
    risk = detector.get_risk_level(result['threats'])
    if risk == 'critical':
        sys.exit(2)
    elif risk == 'high':
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
