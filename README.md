# 🛡️ ClawDef - OpenClaw 原生安全防护系统

> 为 AI Agent 提供全方位安全防护

**版本**: v2.0  
**状态**: ✅ 核心功能完成  
**测试**: 50+ 测试通过

---

## 🎯 核心功能

### 1. 威胁检测引擎 🔍
- **54 个威胁特征** - 覆盖 7 大类攻击模式
- **实时扫描** - 支持文件/目录扫描
- **风险评级** - critical/high/medium/low

### 2. 静态代码分析 🔬
- **AST 解析** - 深度代码分析
- **敏感 API 检测** - 识别危险调用
- **VirusTotal 集成** - 云端威胁情报

### 3. 安装风险评估 ⚠️
- **4 级风险评分** - 0-100 分
- **自动拦截** - 高风险技能阻止安装
- **详细报告** - 完整风险因素列表

### 4. 运行时保护 🛡️
- **文件访问监控** - 敏感文件保护
- **网络请求拦截** - 恶意主机阻止
- **实时日志** - 所有操作可追溯

### 5. 安全日志中心 📋
- **统一日志** - 所有安全事件集中记录
- **查询导出** - 支持多种查询条件
- **摘要统计** - 24h/7d/30d 统计

### 6. WebSocket 推送 📡
- **实时通知** - 安全事件即时推送
- **客户端管理** - 多客户端支持

---

## 📦 安装

```bash
# ClawHub 安装
clawhub install claw-def

# 手动安装
git clone https://github.com/clawdef/claw-def.git
cd claw-def
pip install -r requirements.txt
```

---

## 🚀 快速开始

### 检查技能风险
```bash
python3 src/cli.py check ./target-skill
```

### 扫描目录
```bash
python3 src/cli.py scan ./suspicious-dir
```

### 查看系统状态
```bash
python3 src/cli.py status
```

### 查看日志
```bash
python3 src/cli.py logs --limit 50
```

---

## 📊 测试结果

### 单元测试
```
50 passed in 0.10s
```

### E2E 测试
- ✅ 恶意技能检测
- ✅ 安全技能检测
- ✅ 凭证窃取检测
- ✅ 代码执行检测
- ✅ 数据外传检测
- ✅ 持久化检测
- ✅ 提权检测
- ✅ 误报率测试

### 性能指标
| 指标 | 目标 | 实测 |
|------|------|------|
| 威胁查询 | <100ms | 45ms |
| 文件保护 | <10ms | 5ms |
| 代码分析 | <1s/文件 | 0.3s |

---

## 📁 目录结构

```
claw-def/
├── src/
│   ├── threat_detector.py    # 威胁检测引擎
│   ├── code_analyzer.py      # 静态代码分析
│   ├── install_alert.py      # 安装风险评估
│   ├── file_protection.py    # 文件保护
│   ├── file_monitor.py       # 文件监控
│   ├── ws_server.py          # WebSocket 服务器
│   ├── security_logger.py    # 安全日志
│   └── cli.py                # CLI 工具
├── data/
│   └── threat_signatures.json # 威胁特征库
├── tests/
│   ├── unit/                 # 单元测试
│   ├── integration/          # 集成测试
│   └── e2e/                  # E2E 测试
└── README.md
```

---

## 🔧 配置

### 添加自定义保护路径
```python
from file_monitor import FileMonitor

monitor = FileMonitor()
monitor.add_blocked_path('~/my-secret', 'critical')
```

### 配置 VirusTotal API
```bash
export VT_API_KEY=your_api_key
```

---

## 📝 更新日志

### v2.0 (2026-03-27)
- ✅ 威胁检测引擎 (54 特征)
- ✅ 静态代码分析 (AST)
- ✅ 安装风险评估
- ✅ 运行时文件拦截
- ✅ 安全日志中心
- ✅ WebSocket 推送
- ✅ CLI 工具
- ✅ 50+ 测试用例

### v1.0 (2026-03-23)
- 初始版本

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

## 📄 许可证

MIT License

---

## 📞 联系

- GitHub: https://github.com/clawdef/claw-def
- Issues: https://github.com/clawdef/claw-def/issues

---

**⭐ 如果对你有帮助，请给个 Star！**
