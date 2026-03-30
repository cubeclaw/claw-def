# 🛡️ 运行时拦截功能说明

**版本**: v2.1  
**状态**: ✅ 完整功能

---

## 📦 功能列表

### 1. 文件访问监控 ✅

**功能**:
- 敏感路径拦截 (critical/restricted)
- 文件访问检查
- 访问日志记录
- 自定义阻止路径

**API**:
```python
from file_monitor import FileMonitor

monitor = FileMonitor()

# 检查访问
result = monitor.check_access('~/.ssh/id_rsa', 'read')
# {'allowed': False, 'level': 'critical', 'action': 'block'}

# 添加阻止路径
monitor.add_blocked_path('~/secret', 'critical')
```

**保护路径**:
- Critical (8 个): `~/.ssh`, `~/.gnupg`, `~/.aws/credentials`, etc.
- Restricted (8 个): `~/.aws`, `~/.config`, `~/.docker`, etc.

---

### 2. 实时监控 (inotify) ✅

**功能**:
- Linux inotify 实时通知
- 文件访问自动触发
- 后台监控线程

**API**:
```python
from file_monitor import RealTimeFileMonitor

monitor = RealTimeFileMonitor()

# 添加监控目录
monitor.add_watch('/home/admin/.openclaw', recursive=True)

# 启动监控
monitor.start(blocking=False)  # 非阻塞
```

**依赖**: `pip install pyinotify` (可选)

---

### 3. 网络请求拦截 ✅

**功能**:
- 阻止主机列表
- 允许主机白名单
- 请求日志

**API**:
```python
from file_monitor import NetworkInterceptor

interceptor = NetworkInterceptor()

# 添加阻止主机
interceptor.add_blocked_host('evil.com')

# 检查请求
result = interceptor.check_request('http://evil.com/steal')
# {'allowed': False, 'action': 'block'}
```

---

### 4. hosts 文件拦截 ✅

**功能**:
- 系统级主机拦截
- 修改 hosts 文件
- 持久化拦截

**API**:
```python
from file_monitor import HostsFileBlocker

blocker = HostsFileBlocker()

# 拦截主机
blocker.add_block('malware-c2.net')

# 列出拦截
blocks = blocker.list_blocks()

# 移除拦截
blocker.remove_block('malware-c2.net')
```

**注意**: 需要 root 权限

---

### 5. 进程级追踪 ✅

**功能**:
- 获取进程信息
- 带进程的访问检查
- 进程名/路径追踪

**API**:
```python
from file_monitor import ProcessAwareMonitor

monitor = ProcessAwareMonitor()

# 获取进程信息
info = monitor.get_process_info(pid=1234)
# {'pid': 1234, 'name': 'python3', 'exe': '/usr/bin/python3'}

# 带进程的访问检查
result = monitor.check_access_with_process('~/.ssh/id_rsa', 'read', pid=1234)
```

**依赖**: `pip install psutil` (可选)

---

## 🧪 测试

```bash
# 运行测试
python3 -m pytest tests/unit/test_realtime_monitor.py -v

# 测试结果
✅ test_hosts_blocker
✅ test_process_info
✅ test_file_monitor_basic
✅ test_realtime_monitor_init
```

---

## 📊 功能对比

| 功能 | 基础版 | 增强版 |
|------|--------|--------|
| 文件访问检查 | ✅ | ✅ |
| 敏感路径拦截 | ✅ | ✅ |
| 访问日志 | ✅ | ✅ |
| **实时监控** | ❌ | ✅ (inotify) |
| **hosts 拦截** | ❌ | ✅ |
| **进程追踪** | ❌ | ✅ (psutil) |
| Windows 支持 | ⚠️ | ⚠️ |
| macOS 支持 | ⚠️ | ⚠️ |

---

## ⚠️ 下一步改进

### P1 - 短期 (1-2 周)

| 功能 | 说明 | 工时 |
|------|------|------|
| Windows 支持 | ReadDirectoryChangesW API | 1 周 |
| macOS 支持 | FSEvents 集成 | 1 周 |
| 实际拦截 | 系统调用 hook | 2 周 |

### P2 - 中期 (2-4 周)

| 功能 | 说明 | 工时 |
|------|------|------|
| 内核模块 | Linux kernel module | 4 周 |
| 行为分析 | 异常行为检测 | 2 周 |
| 自动响应 | 自动隔离/终止 | 1 周 |

---

## 🔧 CLI 命令

```bash
# 检查文件访问
python3 src/file_monitor.py check ~/.ssh/id_rsa

# 添加阻止路径
python3 src/file_monitor.py add-block ~/secret critical

# 列出阻止路径
python3 src/file_monitor.py list-blocks

# 查看最近访问
python3 src/file_monitor.py recent 20
```

---

**最后更新**: 2026-03-27
