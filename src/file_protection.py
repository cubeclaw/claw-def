#!/usr/bin/env python3
"""
文件保护模块 - ClawDef 核心组件

功能:
- 敏感文件保护 (SSH/密钥/凭证)
- 三级保护级别 (禁止/询问/允许)
- 用户自定义规则
- 安全日志记录
"""

import os
import fnmatch
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

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
logger = logging.getLogger("ClawDef.FileProtection")


class FileProtectionManager:
    """文件保护管理器"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        初始化文件保护管理器
        
        Args:
            config_path: 配置文件路径，默认 ~/.openclaw/clawdef_config.json
        """
        self.config_path = config_path or os.path.expanduser("~/.openclaw/clawdef_config.json")
        self.config = self._load_config()
        
        # 默认保护规则
        self.default_protection_levels = {
            'critical': [
                '~/.ssh/*',
                '~/.gnupg/*',
                '/etc/passwd',
                '/etc/shadow',
                '~/.aws/credentials',
                '~/.azure/credentials',
                '~/.git-credentials',
                '~/.netrc',
                '~/*key*',
                '~/*secret*',
                '~/*password*',
            ],
            'restricted': [
                '~/.aws/*',
                '~/.azure/*',
                '~/.config/*',
                '~/.npmrc',
                '~/.pypirc',
                '~/.docker/config.json',
                '~/.kube/config',
                '~/.gitconfig',
                '~/.bashrc',
                '~/.zshrc',
                '~/.profile',
            ],
            'allowed': [
                '~/.openclaw/workspace/*',
                '~/projects/*',
                '~/tmp/*',
                '/tmp/*',
            ]
        }
        
        # 合并配置
        self.protection_levels = self._merge_protection_rules()
        
        # 操作历史记录
        self.operation_history: List[Dict] = []
    
    def _load_config(self) -> Dict:
        """加载配置文件"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"加载配置文件失败：{e}")
        return {}
    
    def _save_config(self):
        """保存配置文件"""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=2, ensure_ascii=False)
    
    def _merge_protection_rules(self) -> Dict:
        """合并默认规则和用户自定义规则"""
        merged = {
            'critical': list(self.default_protection_levels.get('critical', [])),
            'restricted': list(self.default_protection_levels.get('restricted', [])),
            'allowed': list(self.default_protection_levels.get('allowed', []))
        }
        
        # 添加用户自定义规则
        user_rules = self.config.get('protection_rules', {})
        for level in ['critical', 'restricted', 'allowed']:
            if level in user_rules:
                merged[level].extend(user_rules[level])
        
        return merged
    
    def check_file_operation(
        self,
        skill_name: str,
        operation: str,
        file_path: str
    ) -> Dict:
        """
        检查文件操作权限
        
        Args:
            skill_name: 技能名称
            operation: 操作类型 (read/write/delete)
            file_path: 文件路径
        
        Returns:
            Dict: {
                'allowed': bool,
                'reason': str,
                'level': str,
                'action': str (可选)
            }
        """
        level = self._get_protection_level(file_path)
        
        # 记录操作
        result = {
            'timestamp': datetime.now().isoformat(),
            'skill': skill_name,
            'operation': operation,
            'file': file_path,
            'level': level,
        }
        
        if level == 'critical':
            result['allowed'] = False
            result['reason'] = f'访问受保护文件：{file_path}'
            result['action'] = 'block'
            logger.warning(f"🚫 BLOCKED: {skill_name} 尝试访问 {file_path}")
        
        elif level == 'restricted':
            # 检查是否已授权
            if self._is_authorized(skill_name, file_path):
                result['allowed'] = True
                result['reason'] = '已授权访问'
                result['action'] = 'allow'
                logger.info(f"✅ ALLOWED (授权): {skill_name} 访问 {file_path}")
            else:
                result['allowed'] = False
                result['reason'] = f'首次访问受限文件：{file_path}'
                result['action'] = 'ask'
                logger.warning(f"⚠️ ASK: {skill_name} 请求访问 {file_path}")
        
        else:  # allowed
            result['allowed'] = True
            result['reason'] = '允许访问'
            result['action'] = 'allow'
            logger.debug(f"✅ ALLOWED: {skill_name} 访问 {file_path}")
        
        # 记录历史
        self.operation_history.append(result)
        self._log_operation(result)
        
        return result
    
    def _get_protection_level(self, file_path: str) -> str:
        """获取文件保护级别"""
        file_path_abs = os.path.abspath(os.path.expanduser(file_path))
        
        # 检查 critical
        for pattern in self.protection_levels.get('critical', []):
            pattern_expanded = os.path.expanduser(pattern)
            if self._match_path(file_path_abs, pattern_expanded):
                return 'critical'
        
        # 检查 restricted
        for pattern in self.protection_levels.get('restricted', []):
            pattern_expanded = os.path.expanduser(pattern)
            if self._match_path(file_path_abs, pattern_expanded):
                return 'restricted'
        
        # 检查 allowed
        for pattern in self.protection_levels.get('allowed', []):
            pattern_expanded = os.path.expanduser(pattern)
            if self._match_path(file_path_abs, pattern_expanded):
                return 'allowed'
        
        # 默认允许
        return 'allowed'
    
    def _match_path(self, file_path: str, pattern: str) -> bool:
        """匹配文件路径"""
        pattern_abs = os.path.abspath(pattern)
        
        # 处理通配符
        if '*' in pattern_abs:
            return fnmatch.fnmatch(file_path, pattern_abs)
        else:
            return file_path.startswith(pattern_abs) or file_path == pattern_abs
    
    def _is_authorized(self, skill_name: str, file_path: str) -> bool:
        """检查技能是否已授权访问文件"""
        authorizations = self.config.get('authorizations', {})
        skill_auths = authorizations.get(skill_name, [])
        
        for auth in skill_auths:
            if auth['file'] == file_path or self._match_path(file_path, auth['file']):
                return True
        
        return False
    
    def authorize(self, skill_name: str, file_path: str, permanent: bool = True):
        """
        授权技能访问文件
        
        Args:
            skill_name: 技能名称
            file_path: 文件路径
            permanent: 是否永久授权
        """
        if 'authorizations' not in self.config:
            self.config['authorizations'] = {}
        
        if skill_name not in self.config['authorizations']:
            self.config['authorizations'][skill_name] = []
        
        self.config['authorizations'][skill_name].append({
            'file': file_path,
            'permanent': permanent,
            'granted_at': datetime.now().isoformat()
        })
        
        self._save_config()
        logger.info(f"✅ 授权 {skill_name} 访问 {file_path}")
    
    def add_protection_rule(self, level: str, pattern: str):
        """
        添加保护规则
        
        Args:
            level: 保护级别 (critical/restricted/allowed)
            pattern: 文件模式
        """
        if level not in ['critical', 'restricted', 'allowed']:
            raise ValueError(f"无效的保护级别：{level}")
        
        if 'protection_rules' not in self.config:
            self.config['protection_rules'] = {'critical': [], 'restricted': [], 'allowed': []}
        
        if pattern not in self.config['protection_rules'][level]:
            self.config['protection_rules'][level].append(pattern)
            self._save_config()
            self.protection_levels = self._merge_protection_rules()
            logger.info(f"✅ 添加保护规则：{level} - {pattern}")
    
    def list_protection_rules(self) -> Dict:
        """列出所有保护规则"""
        return {
            'default': self.default_protection_levels,
            'custom': self.config.get('protection_rules', {})
        }
    
    def get_operation_history(self, skill_name: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """获取操作历史"""
        if skill_name:
            return [op for op in self.operation_history if op['skill'] == skill_name][-limit:]
        return self.operation_history[-limit:]
    
    def _log_operation(self, operation: Dict):
        """记录操作到日志文件"""
        log_entry = json.dumps(operation, ensure_ascii=False)
        logger.info(f"OPERATION: {log_entry}")


# CLI 入口
def main():
    """CLI 入口函数"""
    import sys
    
    mgr = FileProtectionManager()
    
    if len(sys.argv) < 2:
        print("用法：python3 file_protection.py <command> [args]")
        print("命令:")
        print("  check <skill> <operation> <file>  - 检查文件操作权限")
        print("  authorize <skill> <file>          - 授权访问")
        print("  add-rule <level> <pattern>        - 添加保护规则")
        print("  list-rules                        - 列出保护规则")
        print("  history [skill]                   - 查看操作历史")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'check':
        if len(sys.argv) < 5:
            print("用法：python3 file_protection.py check <skill> <operation> <file>")
            sys.exit(1)
        result = mgr.check_file_operation(sys.argv[2], sys.argv[3], sys.argv[4])
        print(json.dumps(result, indent=2, ensure_ascii=False))
    
    elif command == 'authorize':
        if len(sys.argv) < 4:
            print("用法：python3 file_protection.py authorize <skill> <file>")
            sys.exit(1)
        mgr.authorize(sys.argv[2], sys.argv[3])
        print(f"✅ 已授权 {sys.argv[2]} 访问 {sys.argv[3]}")
    
    elif command == 'add-rule':
        if len(sys.argv) < 4:
            print("用法：python3 file_protection.py add-rule <level> <pattern>")
            sys.exit(1)
        mgr.add_protection_rule(sys.argv[2], sys.argv[3])
        print(f"✅ 已添加规则：{sys.argv[2]} - {sys.argv[3]}")
    
    elif command == 'list-rules':
        rules = mgr.list_protection_rules()
        print("默认规则:")
        for level, patterns in rules['default'].items():
            print(f"  {level}:")
            for p in patterns[:5]:
                print(f"    - {p}")
            if len(patterns) > 5:
                print(f"    ... 还有 {len(patterns) - 5} 条")
        if rules['custom']:
            print("自定义规则:")
            for level, patterns in rules['custom'].items():
                print(f"  {level}:")
                for p in patterns:
                    print(f"    - {p}")
    
    elif command == 'history':
        skill = sys.argv[2] if len(sys.argv) > 2 else None
        history = mgr.get_operation_history(skill)
        for op in history[-10:]:
            print(f"{op['timestamp']} | {op['skill']} | {op['operation']} | {op['file']} | {op['action']}")
    
    else:
        print(f"未知命令：{command}")
        sys.exit(1)


if __name__ == '__main__':
    main()
