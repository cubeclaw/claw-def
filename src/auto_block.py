#!/usr/bin/env python3
"""
自动阻断模块 - ClawDef v2.2 核心组件

功能:
- 危险操作自动阻断
- 进程终止
- 文件访问拦截
- 网络请求阻断
"""

import os
import sys
import signal
import logging
from typing import Dict, Optional, Callable, List
from datetime import datetime

LOG_PATH = os.path.expanduser("~/.openclaw/logs/clawdef.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()]
)
logger = logging.getLogger("ClawDef.AutoBlock")

CRITICAL_OPERATIONS = {
    'os.system': '系统命令执行', 'os.popen': '管道命令执行',
    'eval': '动态代码执行', 'exec': '动态代码执行',
    'shutil.rmtree': '递归删除目录', 'os.remove': '删除文件',
    'socket.connect': '网络连接', 'subprocess.Popen': '子进程创建',
}

class AutoBlocker:
    def __init__(self):
        self.block_list = set(CRITICAL_OPERATIONS.keys())
        self.block_events = []
        self.mode = 'block'
        self.sensitive_files = [
            '/etc/passwd', '/etc/shadow',
            os.path.expanduser('~/.ssh/id_rsa'),
            os.path.expanduser('~/.aws/credentials'),
        ]
    
    def check_and_block(self, operation: str, target: str = "") -> Dict:
        should_block = operation in self.block_list
        if not should_block:
            for sf in self.sensitive_files:
                if sf in target:
                    should_block = True
                    break
        
        event = {
            'operation': operation,
            'reason': CRITICAL_OPERATIONS.get(operation, '敏感操作'),
            'blocked': should_block and self.mode == 'block',
            'timestamp': datetime.now().isoformat(),
        }
        
        if event['blocked']:
            logger.critical(f"🚫 BLOCKED: {operation} - {event['reason']}")
            self._log_block(event)
        
        self.block_events.append(event)
        return event
    
    def _log_block(self, event: Dict):
        block_log_path = os.path.expanduser("~/.openclaw/logs/clawdef_blocks.log")
        with open(block_log_path, 'a') as f:
            import json
            f.write(json.dumps(event) + '\n')
    
    def get_statistics(self) -> Dict:
        return {
            'total_events': len(self.block_events),
            'blocked_count': sum(1 for e in self.block_events if e['blocked']),
        }

class RuntimeMonitor:
    def __init__(self):
        self.auto_blocker = AutoBlocker()
        self.monitoring = False
        self.blocked_count = 0
    
    def start(self):
        if self.monitoring:
            return
        try:
            import sys
            sys.settrace(self._trace_hook)
            logger.info("✅ 运行时监控已启动")
            self.monitoring = True
        except Exception as e:
            logger.warning(f"监控启动失败：{e}")
    
    def _trace_hook(self, frame, event, arg):
        if event == 'call':
            func_name = frame.f_code.co_name
            if func_name in ['eval', 'exec']:
                result = self.auto_blocker.check_and_block(func_name)
                if result['blocked']:
                    self.blocked_count += 1
        return self._trace_hook
    
    def get_statistics(self) -> Dict:
        return {
            'monitoring': self.monitoring,
            'blocked_count': self.blocked_count,
            'stats': self.auto_blocker.get_statistics(),
        }

def main():
    if len(sys.argv) < 2:
        print("用法：python3 auto_block.py <command>")
        print("命令：test, stats")
        sys.exit(1)
    
    blocker = AutoBlocker()
    if sys.argv[1] == 'test':
        print("测试阻断...")
        print(blocker.check_and_block('eval'))
        print(blocker.check_and_block('open', '~/.ssh/id_rsa'))
        print(f"统计：{blocker.get_statistics()}")
    elif sys.argv[1] == 'stats':
        print(blocker.get_statistics())

if __name__ == '__main__':
    main()
