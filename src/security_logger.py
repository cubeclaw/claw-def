#!/usr/bin/env python3
"""
安全日志中心 - ClawDef 核心组件

功能:
- 统一日志记录
- 日志查询
- 日志导出
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

LOG_DIR = os.path.expanduser("~/.openclaw/logs")
os.makedirs(LOG_DIR, exist_ok=True)

class SecurityLogger:
    """安全日志记录器"""
    
    def __init__(self, log_file: Optional[str] = None):
        self.log_file = log_file or os.path.join(LOG_DIR, "clawdef_security.log")
        self._ensure_log_file()
    
    def _ensure_log_file(self):
        """确保日志文件存在"""
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        if not os.path.exists(self.log_file):
            Path(self.log_file).touch()
    
    def log_threat(self, threat: Dict):
        """记录威胁事件"""
        self._write('threat_detected', threat)
    
    def log_file_access(self, event: Dict):
        """记录文件访问"""
        self._write('file_access', event)
    
    def log_install_alert(self, alert: Dict):
        """记录安装告警"""
        self._write('install_alert', alert)
    
    def log_network_request(self, request: Dict):
        """记录网络请求"""
        self._write('network_request', request)
    
    def _write(self, event_type: str, data: Dict):
        """写入日志"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'data': data,
        }
        
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    
    def query(self, event_type: Optional[str] = None, 
              start_time: Optional[str] = None,
              end_time: Optional[str] = None,
              limit: int = 100) -> List[Dict]:
        """查询日志"""
        results = []
        
        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        
                        # 过滤事件类型
                        if event_type and entry.get('type') != event_type:
                            continue
                        
                        # 过滤时间
                        entry_time = entry.get('timestamp', '')
                        if start_time and entry_time < start_time:
                            continue
                        if end_time and entry_time > end_time:
                            continue
                        
                        results.append(entry)
                        
                        if len(results) >= limit:
                            break
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass
        
        return results
    
    def export(self, output_path: str, format: str = 'json'):
        """导出日志"""
        events = self.query(limit=10000)
        
        if format == 'json':
            with open(output_path, 'w') as f:
                json.dump(events, f, indent=2, ensure_ascii=False)
        elif format == 'csv':
            with open(output_path, 'w') as f:
                f.write("timestamp,type,file,severity,details\n")
                for event in events:
                    data = event.get('data', {})
                    f.write(f"{event.get('timestamp','')},{event.get('type','')},{data.get('file','')},{data.get('severity','')},\n")
        
        return len(events)
    
    def get_summary(self, hours: int = 24) -> Dict:
        """获取摘要统计"""
        from datetime import timedelta
        
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        events = self.query(start_time=cutoff, limit=10000)
        
        summary = {
            'total_events': len(events),
            'by_type': {},
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'time_range': {
                'start': cutoff,
                'end': datetime.now().isoformat(),
            }
        }
        
        for event in events:
            event_type = event.get('type', 'unknown')
            summary['by_type'][event_type] = summary['by_type'].get(event_type, 0) + 1
            
            severity = event.get('data', {}).get('severity', '')
            if severity in summary['by_severity']:
                summary['by_severity'][severity] += 1
        
        return summary


def main():
    """CLI 入口"""
    import sys
    
    if len(sys.argv) < 2:
        print("用法：python3 security_logger.py <command> [args]")
        print("命令:")
        print("  query [type]        - 查询日志")
        print("  summary [hours]     - 查看摘要")
        print("  export <file>       - 导出日志")
        sys.exit(1)
    
    logger = SecurityLogger()
    command = sys.argv[1]
    
    if command == 'query':
        event_type = sys.argv[2] if len(sys.argv) > 2 else None
        events = logger.query(event_type=event_type, limit=20)
        for event in events:
            print(f"{event['timestamp']} | {event['type']} | {json.dumps(event['data'])[:60]}")
    
    elif command == 'summary':
        hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        summary = logger.get_summary(hours)
        print(f"时间范围：{summary['time_range']['start']} - {summary['time_range']['end']}")
        print(f"总事件数：{summary['total_events']}")
        print("\n按类型:")
        for t, c in summary['by_type'].items():
            print(f"  {t}: {c}")
        print("\n按严重程度:")
        for s, c in summary['by_severity'].items():
            print(f"  {s}: {c}")
    
    elif command == 'export':
        if len(sys.argv) < 3:
            print("用法：python3 security_logger.py export <file>")
            sys.exit(1)
        count = logger.export(sys.argv[2])
        print(f"✅ 已导出 {count} 条事件到 {sys.argv[2]}")
    
    else:
        print(f"未知命令：{command}")
        sys.exit(1)


if __name__ == '__main__':
    main()
