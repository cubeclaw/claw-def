#!/usr/bin/env python3
"""
文件访问监控器 - ClawDef 核心组件

功能:
- 监控文件访问
- 敏感路径拦截
- 实时告警
"""

import os
import time
import json
import logging
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Callable

LOG_PATH = os.path.expanduser("~/.openclaw/logs/clawdef.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()]
)
logger = logging.getLogger("ClawDef.FileMonitor")


# 敏感路径列表
SENSITIVE_PATHS = {
    'critical': [
        '~/.ssh',
        '~/.gnupg',
        '~/.aws/credentials',
        '~/.azure/credentials',
        '/etc/passwd',
        '/etc/shadow',
        '~/.git-credentials',
        '~/.netrc',
    ],
    'restricted': [
        '~/.aws',
        '~/.azure',
        '~/.config',
        '~/.docker',
        '~/.kube',
        '~/.bashrc',
        '~/.zshrc',
        '~/.profile',
    ],
}


class FileAccessEvent:
    """文件访问事件"""
    
    def __init__(self, file_path: str, operation: str, process_name: str = "unknown"):
        self.file_path = file_path
        self.operation = operation
        self.process_name = process_name
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict:
        return {
            'file_path': self.file_path,
            'operation': self.operation,
            'process_name': self.process_name,
            'timestamp': self.timestamp.isoformat(),
        }


class FileMonitor:
    """文件监控器"""
    
    def __init__(self, watch_paths: Optional[List[str]] = None):
        self.watch_paths = watch_paths or []
        self.blocked_paths = self._load_sensitive_paths()
        self.access_log = []
        self.callbacks = []
        self.running = False
        self._thread = None
    
    def _load_sensitive_paths(self) -> Dict:
        """加载敏感路径"""
        sensitive = {'critical': [], 'restricted': []}
        for level, paths in SENSITIVE_PATHS.items():
            for path in paths:
                sensitive[level].append(os.path.expanduser(path))
        return sensitive
    
    def add_callback(self, callback: Callable):
        """添加回调函数"""
        self.callbacks.append(callback)
    
    def check_access(self, file_path: str, operation: str = "read") -> Dict:
        """检查文件访问权限"""
        file_path_abs = os.path.abspath(file_path)
        
        # 检查 critical 路径
        for sensitive_path in self.blocked_paths['critical']:
            if file_path_abs.startswith(sensitive_path) or file_path_abs == sensitive_path:
                event = FileAccessEvent(file_path, operation)
                self._log_access(event, 'blocked')
                return {
                    'allowed': False,
                    'level': 'critical',
                    'reason': f'访问受保护文件：{file_path}',
                    'action': 'block',
                }
        
        # 检查 restricted 路径
        for sensitive_path in self.blocked_paths['restricted']:
            if file_path_abs.startswith(sensitive_path) or file_path_abs == sensitive_path:
                event = FileAccessEvent(file_path, operation)
                self._log_access(event, 'warn')
                return {
                    'allowed': False,
                    'level': 'restricted',
                    'reason': f'访问受限文件：{file_path}',
                    'action': 'ask',
                }
        
        return {'allowed': True, 'level': 'allowed', 'action': 'allow'}
    
    def _log_access(self, event: FileAccessEvent, action: str):
        """记录访问日志"""
        log_entry = {
            'event': event.to_dict(),
            'action': action,
        }
        self.access_log.append(log_entry)
        
        # 限制日志大小
        if len(self.access_log) > 1000:
            self.access_log = self.access_log[-500:]
        
        logger.info(f"文件访问：{event.file_path} [{event.operation}] -> {action}")
        
        # 触发回调
        for callback in self.callbacks:
            try:
                callback(log_entry)
            except Exception as e:
                logger.error(f"回调执行失败：{e}")
    
    def get_recent_access(self, limit: int = 100) -> List[Dict]:
        """获取最近访问记录"""
        return self.access_log[-limit:]
    
    def add_blocked_path(self, path: str, level: str = 'restricted'):
        """添加阻止路径"""
        if level not in ['critical', 'restricted']:
            level = 'restricted'
        
        expanded = os.path.expanduser(path)
        if expanded not in self.blocked_paths[level]:
            self.blocked_paths[level].append(expanded)
            logger.info(f"添加阻止路径：{path} ({level})")
    
    def remove_blocked_path(self, path: str):
        """移除阻止路径"""
        expanded = os.path.expanduser(path)
        for level in ['critical', 'restricted']:
            if expanded in self.blocked_paths[level]:
                self.blocked_paths[level].remove(expanded)
                logger.info(f"移除阻止路径：{path}")


class NetworkInterceptor:
    """网络请求拦截器"""
    
    def __init__(self):
        self.blocked_hosts = set()
        self.allowed_hosts = {'localhost', '127.0.0.1'}
        self.request_log = []
    
    def add_blocked_host(self, host: str):
        """添加阻止的主机"""
        self.blocked_hosts.add(host)
        logger.info(f"添加阻止主机：{host}")
    
    def check_request(self, url: str) -> Dict:
        """检查网络请求"""
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        host = parsed.hostname or ''
        
        # 检查阻止列表
        if host in self.blocked_hosts:
            return {
                'allowed': False,
                'reason': f'主机被阻止：{host}',
                'action': 'block',
            }
        
        # 检查允许列表
        if host in self.allowed_hosts:
            return {'allowed': True, 'action': 'allow'}
        
        # 未知主机，需要确认
        return {
            'allowed': False,
            'reason': f'未知主机：{host}',
            'action': 'ask',
        }
    
    def log_request(self, url: str, method: str = 'GET'):
        """记录请求"""
        self.request_log.append({
            'url': url,
            'method': method,
            'timestamp': datetime.now().isoformat(),
        })
        
        # 限制日志大小
        if len(self.request_log) > 500:
            self.request_log = self.request_log[-200:]
        
        logger.info(f"网络请求：{method} {url}")
    
    def get_recent_requests(self, limit: int = 50) -> List[Dict]:
        """获取最近请求"""
        return self.request_log[-limit:]


def main():
    """CLI 入口"""
    import sys
    
    if len(sys.argv) < 2:
        print("用法：python3 file_monitor.py <command> [args]")
        print("命令:")
        print("  check <file>        - 检查文件访问权限")
        print("  add-block <path>    - 添加阻止路径")
        print("  list-blocks         - 列出阻止路径")
        print("  recent              - 查看最近访问")
        sys.exit(1)
    
    monitor = FileMonitor()
    command = sys.argv[1]
    
    if command == 'check':
        if len(sys.argv) < 3:
            print("用法：python3 file_monitor.py check <file>")
            sys.exit(1)
        result = monitor.check_access(sys.argv[2])
        print(json.dumps(result, indent=2, ensure_ascii=False))
    
    elif command == 'add-block':
        if len(sys.argv) < 3:
            print("用法：python3 file_monitor.py add-block <path> [level]")
            sys.exit(1)
        level = sys.argv[3] if len(sys.argv) > 3 else 'restricted'
        monitor.add_blocked_path(sys.argv[2], level)
        print(f"✅ 已添加阻止路径：{sys.argv[2]} ({level})")
    
    elif command == 'list-blocks':
        print("Critical 路径:")
        for p in monitor.blocked_paths['critical']:
            print(f"  - {p}")
        print("\nRestricted 路径:")
        for p in monitor.blocked_paths['restricted']:
            print(f"  - {p}")
    
    elif command == 'recent':
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        events = monitor.get_recent_access(limit)
        for event in events:
            print(f"{event['event']['timestamp']} | {event['action']} | {event['event']['file_path']}")
    
    else:
        print(f"未知命令：{command}")
        sys.exit(1)


if __name__ == '__main__':
    main()


# ============================================================
# 实时监控模块 (inotify/Linux)
# ============================================================

class RealTimeFileMonitor(FileMonitor):
    """实时文件监控器 (基于 inotify)"""
    
    def __init__(self, watch_paths: Optional[List[str]] = None):
        super().__init__(watch_paths)
        self.wm = None
        self.notifier = None
        self.running = False
        
        try:
            import pyinotify
            self.wm = pyinotify.WatchManager()
            self.mask = (pyinotify.IN_ACCESS | pyinotify.IN_OPEN | 
                        pyinotify.IN_CLOSE_NOWRITE | pyinotify.IN_CLOSE_WRITE)
        except ImportError:
            logger.warning("pyinotify 未安装，实时监控功能不可用")
    
    def add_watch(self, path: str, recursive: bool = False):
        """添加监控路径"""
        if not self.wm:
            logger.error("inotify 不可用")
            return
        
        import pyinotify
        path = os.path.expanduser(path)
        
        if recursive:
            for root, dirs, files in os.walk(path):
                self.wm.add_watch(root, self.mask)
        else:
            self.wm.add_watch(path, self.mask)
        
        logger.info(f"添加监控：{path}")
    
    def on_event(self, event):
        """处理 inotify 事件"""
        file_path = event.pathname
        op_map = {
            'IN_ACCESS': 'read',
            'IN_OPEN': 'open',
            'IN_CLOSE_NOWRITE': 'close_read',
            'IN_CLOSE_WRITE': 'close_write',
        }
        operation = op_map.get(event.maskname, 'unknown')
        
        # 检查是否敏感路径
        result = self.check_access(file_path, operation)
        
        if result['allowed'] == False:
            logger.warning(f"🚫 阻止访问：{file_path} [{operation}] - {result['level']}")
    
    def start(self, blocking: bool = True):
        """启动实时监控"""
        if not self.wm:
            logger.error("无法启动：inotify 不可用")
            return
        
        import pyinotify
        self.notifier = pyinotify.Notifier(self.wm, self.on_event)
        self.running = True
        
        logger.info("启动实时监控...")
        
        if blocking:
            self.notifier.loop()
        else:
            import threading
            thread = threading.Thread(target=self.notifier.loop)
            thread.daemon = True
            thread.start()
    
    def stop(self):
        """停止监控"""
        if self.notifier:
            self.notifier.stop()
            self.running = False
            logger.info("停止实时监控")


# ============================================================
# 网络拦截增强 (基于 hosts 文件)
# ============================================================

class HostsFileBlocker:
    """hosts 文件拦截器"""
    
    def __init__(self):
        if os.name == 'nt':  # Windows
            self.hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
        else:  # Linux/Mac
            self.hosts_path = '/etc/hosts'
        self.blocked_hosts = set()
    
    def add_block(self, host: str) -> bool:
        """添加主机拦截"""
        if host in self.blocked_hosts:
            return False
        
        try:
            # 检查是否已存在
            with open(self.hosts_path, 'r') as f:
                content = f.read()
                if f'127.0.0.1 {host}' in content:
                    return False
            
            # 追加拦截规则
            with open(self.hosts_path, 'a') as f:
                f.write(f'\n127.0.0.1 {host}  # Blocked by ClawDef\n')
            
            self.blocked_hosts.add(host)
            logger.info(f"已拦截主机：{host}")
            return True
        except PermissionError:
            logger.error(f"需要 root 权限修改 {self.hosts_path}")
            return False
        except Exception as e:
            logger.error(f"修改 hosts 失败：{e}")
            return False
    
    def remove_block(self, host: str) -> bool:
        """移除拦截"""
        try:
            with open(self.hosts_path, 'r') as f:
                lines = f.readlines()
            
            with open(self.hosts_path, 'w') as f:
                for line in lines:
                    if host not in line or 'ClawDef' not in line:
                        f.write(line)
            
            self.blocked_hosts.discard(host)
            logger.info(f"已移除拦截：{host}")
            return True
        except Exception as e:
            logger.error(f"修改 hosts 失败：{e}")
            return False
    
    def list_blocks(self) -> List[str]:
        """列出所有拦截的主机"""
        blocks = []
        try:
            with open(self.hosts_path, 'r') as f:
                for line in f:
                    if 'ClawDef' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            blocks.append(parts[1])
        except Exception as e:
            logger.error(f"读取 hosts 失败：{e}")
        return blocks


# ============================================================
# 进程级拦截 (基于 psutil)
# ============================================================

class ProcessAwareMonitor(FileMonitor):
    """进程感知文件监控器"""
    
    def __init__(self):
        super().__init__()
        try:
            import psutil
            self.psutil = psutil
        except ImportError:
            logger.warning("psutil 未安装，进程追踪功能不可用")
            self.psutil = None
    
    def get_process_info(self, pid: Optional[int] = None) -> Dict:
        """获取进程信息"""
        if not self.psutil:
            return {'pid': pid, 'name': 'unknown', 'exe': 'unknown'}
        
        try:
            if pid is None:
                pid = self.psutil.Process().pid
            
            proc = self.psutil.Process(pid)
            return {
                'pid': pid,
                'name': proc.name(),
                'exe': proc.exe() if hasattr(proc, 'exe') else 'unknown',
                'cmdline': ' '.join(proc.cmdline()) if hasattr(proc, 'cmdline') else 'unknown',
            }
        except Exception as e:
            logger.debug(f"获取进程信息失败：{e}")
            return {'pid': pid, 'name': 'unknown', 'exe': 'unknown'}
    
    def check_access_with_process(self, file_path: str, operation: str, pid: Optional[int] = None) -> Dict:
        """带进程信息的文件访问检查"""
        result = self.check_access(file_path, operation)
        result['process'] = self.get_process_info(pid)
        return result
