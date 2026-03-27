#!/usr/bin/env python3
"""
安装风险评估模块 - ClawDef 核心组件

功能:
- 技能安装前风险扫描
- 风险等级评估 (low/medium/high/critical)
- 敏感模式检测 (密钥/恶意代码/危险权限)
- 用户提示与确认
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
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ClawDef.InstallAlert")


class InstallAlertEvaluator:
    """安装风险评估器"""
    
    # 风险模式定义
    RISK_PATTERNS = {
        'api_key': (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\'][a-zA-Z0-9]{16,}["\']', 'critical'),
        'secret_key': (r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\'][a-zA-Z0-9]{16,}["\']', 'critical'),
        'password': (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']', 'critical'),
        'token': (r'(?i)(token|auth[_-]?token)\s*[=:]\s*["\'][a-zA-Z0-9]{16,}["\']', 'critical'),
        'private_key': (r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----', 'critical'),
        'aws_key': (r'AKIA[0-9A-Z]{16}', 'critical'),
        'eval_exec': (r'(?i)\b(eval|exec|compile)\s*\(', 'high'),
        'subprocess': (r'(?i)subprocess\.(call|run|Popen|check_output)', 'high'),
        'os_system': (r'(?i)os\.system\s*\(', 'high'),
        'pickle': (r'(?i)pickle\.(load|loads)', 'high'),
        'sensitive_paths': (r'(?i)(~\/\.ssh|~\/\.aws|~\/\.gnupg|\/etc\/passwd|\/etc\/shadow)', 'medium'),
        'file_write': (r'(?i)open\s*\([^)]+,?\s*[\'"]w[+]?[\'"]', 'medium'),
        'shutil_rm': (r'(?i)shutil\.(rmtree|remove)', 'medium'),
        'network_request': (r'(?i)(requests|urllib|httpx)\.(get|post|put|delete)\s*\(', 'low'),
        'socket': (r'(?i)socket\.(socket|connect)', 'medium'),
        'sudo': (r'(?i)sudo\s+', 'high'),
        'chmod_777': (r'(?i)chmod\s+0?777', 'high'),
        'cron': (r'(?i)(crontab|\/etc\/cron)', 'medium'),
        'systemd': (r'(?i)systemctl\s+enable', 'medium'),
    }
    
    RISK_SCORES = {'critical': 40, 'high': 25, 'medium': 10, 'low': 5}
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or os.path.expanduser("~/.openclaw/clawdef_config.json")
        self.config = self._load_config()
    
    def _load_config(self) -> Dict:
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"加载配置文件失败：{e}")
        return {}
    
    def evaluate_skill(self, skill_path: str) -> Dict:
        skill_path = Path(skill_path)
        if not skill_path.exists():
            return {'level': 'critical', 'score': 100, 'factors': [{'type': 'error', 'message': '技能路径不存在'}], 'action': 'block', 'summary': '❌ 技能路径不存在'}
        
        factors = []
        total_score = 0
        
        for file_path in skill_path.rglob('*'):
            if file_path.is_file():
                file_factors = self._scan_file(file_path)
                factors.extend(file_factors)
        
        for factor in factors:
            total_score += self.RISK_SCORES.get(factor['severity'], 0)
        total_score = min(total_score, 100)
        
        level, action = self._get_risk_level(total_score)
        summary = self._generate_summary(level, factors, total_score)
        
        result = {
            'level': level, 'score': total_score, 'factors': factors, 'action': action,
            'summary': summary, 'scanned_at': datetime.now().isoformat(),
            'scanned_files': len(list(skill_path.rglob('*'))),
        }
        
        logger.info(f"技能风险评估：{skill_path.name} - {level} ({total_score}分)")
        return result
    
    def _scan_file(self, file_path: Path) -> List[Dict]:
        factors = []
        skip_extensions = {'.pyc', '.pyo', '.so', '.dll', '.exe', '.bin', '.jpg', '.png', '.gif'}
        if file_path.suffix in skip_extensions:
            return factors
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"无法读取文件 {file_path}: {e}")
            return factors
        
        file_factors = self._check_filename(file_path)
        factors.extend(file_factors)
        
        for pattern_name, (pattern, severity) in self.RISK_PATTERNS.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                factors.append({
                    'type': pattern_name, 'severity': severity,
                    'file': str(file_path.relative_to(file_path.parent.parent)),
                    'line': line_num, 'match': match.group()[:100],
                    'message': self._get_pattern_message(pattern_name),
                })
        
        return factors
    
    def _check_filename(self, file_path: Path) -> List[Dict]:
        factors = []
        risky_names = {
            '.env': ('critical', '包含环境变量的 .env 文件'),
            '.env.local': ('critical', '本地环境配置文件'),
            'credentials': ('critical', '凭证文件'),
            'secrets': ('critical', '密钥文件'),
            '.netrc': ('critical', '网络凭证文件'),
            'id_rsa': ('critical', 'SSH 私钥'),
            'id_ed25519': ('critical', 'SSH 私钥'),
        }
        for risky_name, (severity, message) in risky_names.items():
            if risky_name in file_path.name.lower():
                factors.append({
                    'type': 'risky_filename', 'severity': severity,
                    'file': str(file_path.name), 'line': 0, 'match': file_path.name, 'message': message,
                })
        return factors
    
    def _get_pattern_message(self, pattern_name: str) -> str:
        messages = {
            'api_key': '检测到 API 密钥', 'secret_key': '检测到密钥', 'password': '检测到密码',
            'token': '检测到认证令牌', 'private_key': '检测到私钥', 'aws_key': '检测到 AWS 访问密钥',
            'eval_exec': '检测到动态代码执行', 'subprocess': '检测到子进程调用',
            'os_system': '检测到系统命令执行', 'pickle': '检测到 pickle 反序列化',
            'sensitive_paths': '检测到敏感路径访问', 'file_write': '检测到文件写入',
            'shutil_rm': '检测到文件删除', 'network_request': '检测到网络请求',
            'socket': '检测到 socket 连接', 'sudo': '检测到提权操作',
            'chmod_777': '检测到权限设置 (777)', 'cron': '检测到定时任务', 'systemd': '检测到系统服务',
        }
        return messages.get(pattern_name, '检测到风险模式')
    
    def _get_risk_level(self, score: int) -> Tuple[str, str]:
        if score >= 80: return 'critical', 'block'
        elif score >= 50: return 'high', 'confirm'
        elif score >= 25: return 'medium', 'ask'
        else: return 'low', 'auto_allow'
    
    def _generate_summary(self, level: str, factors: List[Dict], score: int) -> str:
        if level == 'critical': return f"🚨 严重风险 ({score}分) - 建议阻止安装"
        elif level == 'high': return f"⚠️ 高风险 ({score}分) - 需要用户确认"
        elif level == 'medium': return f"⚡ 中等风险 ({score}分) - 需要用户授权"
        else: return f"✅ 低风险 ({score}分) - 自动允许安装"
    
    def print_report(self, result: Dict, skill_name: str):
        print("\n" + "="*60)
        print(f"🛡️  ClawDef 技能风险评估 - {skill_name}")
        print("="*60)
        level_emoji = {'critical': '🚨', 'high': '⚠️', 'medium': '⚡', 'low': '✅'}
        print(f"\n{level_emoji.get(result['level'], '❓')} 风险等级：{result['level'].upper()}")
        print(f"📊 风险分数：{result['score']}/100")
        print(f"📁 扫描文件：{result['scanned_files']} 个")
        print(f"🔧 建议操作：{result['action']}")
        print(f"📝 摘要：{result['summary']}")
        
        if result['factors']:
            print(f"\n📋 风险因素 ({len(result['factors'])} 个):")
            print("-"*60)
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            sorted_factors = sorted(result['factors'], key=lambda x: severity_order.get(x['severity'], 4))
            for i, factor in enumerate(sorted_factors[:20], 1):
                severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
                print(f"{i}. {severity_emoji.get(factor['severity'], '⚪')} [{factor['severity'].upper()}] {factor['message']}")
                print(f"   文件：{factor['file']}:{factor['line']}")
                if factor['match']: print(f"   匹配：{factor['match'][:60]}...")
                print()
            if len(sorted_factors) > 20: print(f"... 还有 {len(sorted_factors) - 20} 个风险因素")
        else:
            print("\n✅ 未检测到风险因素")
        print("="*60 + "\n")


def main():
    import sys
    if len(sys.argv) < 2:
        print("用法：python3 install_alert.py <skill_path>")
        sys.exit(1)
    skill_path = sys.argv[1]
    evaluator = InstallAlertEvaluator()
    result = evaluator.evaluate_skill(skill_path)
    evaluator.print_report(result, Path(skill_path).name)
    if result['action'] == 'block': sys.exit(2)
    elif result['action'] == 'confirm': sys.exit(1)
    else: sys.exit(0)


if __name__ == '__main__':
    main()
