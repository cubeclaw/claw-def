#!/usr/bin/env python3
"""
ClawDef CLI 工具

功能:
- 统一命令行接口
- 技能检查
- 状态查看
- 日志管理
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

# 添加 src 到路径
sys.path.insert(0, os.path.dirname(__file__))

from threat_detector import ThreatDetector
from code_analyzer import StaticCodeAnalyzer
from install_alert import InstallAlertEvaluator
from file_monitor import FileMonitor
from security_logger import SecurityLogger


def cmd_check(args):
    """检查技能风险"""
    print(f"🔍 检查技能：{args.path}\n")
    
    target_path = Path(args.path)
    
    # 威胁检测 - 支持文件和目录
    detector = ThreatDetector()
    if target_path.is_file():
        threats = detector.scan_file(target_path)
        threat_result = {
            'threats': threats,
            'summary': {
                'files_scanned': 1,
                'files_with_threats': 1 if threats else 0,
                'total_threats': len(threats),
                'by_severity': detector._count_by_severity(threats),
                'by_category': detector._count_by_category(threats),
                'scanned_at': datetime.now().isoformat(),
            }
        }
    else:
        threat_result = detector.scan_directory(target_path)
    
    # 代码分析 - 支持文件和目录
    from code_analyzer import CodeAnalyzer
    analyzer_cls = CodeAnalyzer()
    if target_path.is_file():
        code_issue = analyzer_cls.analyze_file(target_path)
        code_result = {
            'issues': code_issue.get('issues', []),
            'summary': {
                'files_analyzed': 1,
                'total_issues': len(code_issue.get('issues', [])),
                'risk_score': code_issue.get('risk_score', 0),
            }
        }
    else:
        code_result = analyzer_cls.analyze_directory(target_path)
    
    # 安装评估
    evaluator = InstallAlertEvaluator()
    install_result = evaluator.evaluate_skill(args.path)
    
    # 汇总报告
    print("="*70)
    print("🛡️  ClawDef 技能安全检查报告")
    print("="*70)
    print(f"\n技能路径：{args.path}")
    print(f"扫描时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    print(f"\n📊 威胁检测:")
    print(f"  文件数：{threat_result['summary']['files_scanned']}")
    print(f"  威胁数：{threat_result['summary']['total_threats']}")
    
    print(f"\n🔍 代码分析:")
    print(f"  文件数：{code_result['summary']['files_analyzed']}")
    print(f"  问题数：{code_result['summary']['total_issues']}")
    
    print(f"\n⚠️  安装风险:")
    print(f"  风险等级：{install_result['level']}")
    print(f"  风险分数：{install_result['score']}/100")
    print(f"  建议操作：{install_result['action']}")
    
    # 综合评级
    if threat_result['summary']['total_threats'] > 5 or install_result['score'] >= 80:
        print(f"\n🚨 综合评级：HIGH RISK - 不建议安装")
        return 2
    elif threat_result['summary']['total_threats'] > 0 or install_result['score'] >= 50:
        print(f"\n⚠️  综合评级：MEDIUM RISK - 请谨慎安装")
        return 1
    else:
        print(f"\n✅ 综合评级：LOW RISK - 可以安装")
        return 0


def cmd_status(args):
    """查看系统状态"""
    print("="*70)
    print("🛡️  ClawDef 系统状态")
    print("="*70)
    
    monitor = FileMonitor()
    logger = SecurityLogger()
    
    print(f"\n📁 文件保护:")
    print(f"  Critical 路径：{len(monitor.blocked_paths['critical'])} 个")
    print(f"  Restricted 路径：{len(monitor.blocked_paths['restricted'])} 个")
    
    print(f"\n📊 安全日志:")
    summary = logger.get_summary(hours=24)
    print(f"  24h 事件数：{summary['total_events']}")
    print(f"  Critical: {summary['by_severity']['critical']}")
    print(f"  High: {summary['by_severity']['high']}")
    
    print(f"\n📦 威胁特征库:")
    detector = ThreatDetector()
    print(f"  特征数：{len(detector.compiled_patterns)} 个")
    
    print("\n✅ 系统运行正常")


def cmd_logs(args):
    """查看日志"""
    logger = SecurityLogger()
    
    if args.export:
        count = logger.export(args.export)
        print(f"✅ 已导出 {count} 条事件到 {args.export}")
        return
    
    events = logger.query(event_type=args.type, limit=args.limit)
    
    print(f"最近 {len(events)} 条事件:\n")
    for event in events:
        print(f"{event['timestamp']} | {event['type']} | {str(event['data'])[:60]}")


def cmd_scan(args):
    """扫描目录"""
    print(f"🔍 扫描目录：{args.path}\n")
    
    detector = ThreatDetector()
    result = detector.scan_directory(Path(args.path))
    detector.print_report(result, args.path)
    
    return 0 if result['summary']['total_threats'] == 0 else 1


def main():
    parser = argparse.ArgumentParser(
        description='ClawDef - OpenClaw 原生安全防护系统',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  clawdef check ./my-skill     检查技能风险
  clawdef status               查看系统状态
  clawdef logs                 查看最近日志
  clawdef scan ./suspicious    扫描目录
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='命令')
    
    # check 命令
    p_check = subparsers.add_parser('check', help='检查技能风险')
    p_check.add_argument('path', help='技能路径')
    p_check.set_defaults(func=cmd_check)
    
    # status 命令
    p_status = subparsers.add_parser('status', help='查看系统状态')
    p_status.set_defaults(func=cmd_status)
    
    # logs 命令
    p_logs = subparsers.add_parser('logs', help='查看日志')
    p_logs.add_argument('--type', '-t', help='事件类型')
    p_logs.add_argument('--limit', '-l', type=int, default=20, help='显示数量')
    p_logs.add_argument('--export', '-e', help='导出到文件')
    p_logs.set_defaults(func=cmd_logs)
    
    # scan 命令
    p_scan = subparsers.add_parser('scan', help='扫描目录')
    p_scan.add_argument('path', help='目录路径')
    p_scan.set_defaults(func=cmd_scan)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    sys.exit(args.func(args))


if __name__ == '__main__':
    main()
