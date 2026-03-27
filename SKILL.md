---
name: ClawDef
description: OpenClaw 原生安全防护系统 - 为 AI Agent 提供文件保护、安装风险提示、安全日志能力
metadata:
  openclaw:
    homepage: https://github.com/clawdef/claw-def
    version: 1.0.0
---

# 🛡️ ClawDef - OpenClaw 原生安全防护系统

**版本**: v1.0.0  
**目标**: 为 OpenClaw 打造 AI Agent 安全防护能力

---

## 🎯 核心功能

### 1. 文件保护 🔒

保护敏感文件免受恶意技能访问：

```python
from src.file_protection import FileProtectionManager

mgr = FileProtectionManager()

# 检查文件操作权限
result = mgr.check_file_operation(
    skill_name="example-skill",
    operation="read",  # read/write/delete
    file_path="~/.ssh/id_rsa"
)

if not result['allowed']:
    print(f"❌ 阻止访问：{result['reason']}")
```

**保护级别**:
| 级别 | 文件类型 | 行为 |
|------|---------|------|
| critical | SSH 密钥、系统凭证 | ❌ 直接阻止 |
| restricted | AWS/Azure 配置、~/.config | ⚠️ 询问用户 |
| allowed | 工作区、临时文件 | ✅ 允许 |

### 2. 安装风险提示 ⚠️

技能安装时自动评估风险：

```python
from src.install_alert import InstallAlertEvaluator

evaluator = InstallAlertEvaluator()

# 评估技能风险
risk = evaluator.evaluate_skill("/path/to/skill")

# risk 返回:
# {
#   "level": "low|medium|high|critical",
#   "score": 0-100,
#   "factors": ["访问敏感文件", "执行系统命令", ...],
#   "action": "auto_allow|ask|confirm|block"
# }
```

**风险等级**:
| 等级 | 分数 | 行为 |
|------|------|------|
| low | 0-25 | ✅ 自动允许 |
| medium | 26-50 | ⚠️ 询问用户 |
| high | 51-75 | 🔒 需确认 |
| critical | 76-100 | ❌ 直接阻止 |

### 3. 安全日志中心 📋

记录所有安全相关事件：

```bash
# 查看安全日志
clawdef logs

# 查看特定技能的操作记录
clawdef logs --skill example-skill

# 导出日志
clawdef logs --export /tmp/security-logs.json
```

**日志格式**:
```json
{
  "timestamp": "2026-03-27T16:00:00Z",
  "skill": "example-skill",
  "operation": "file_read",
  "target": "~/.ssh/id_rsa",
  "result": "blocked",
  "reason": "访问受保护文件"
}
```

### 4. CLI 工具 🛠️

```bash
# 检查技能风险
clawdef check /path/to/skill

# 查看文件保护状态
clawdef status

# 添加自定义保护规则
clawdef protect add ~/.my-secret-file

# 查看保护规则列表
clawdef protect list

# 查看安全日志
clawdef logs [options]
```

---

## 📦 安装

### 方式 1: ClawHub 安装（推荐）

```bash
clawhub install claw-def
```

### 方式 2: 手动安装

```bash
cd /home/admin/.openclaw/skills/claw-def
pip install -r requirements.txt
```

---

## 🚀 快速开始

### 1. 配置文件保护

```bash
# 查看当前保护规则
clawdef protect list

# 添加自定义保护文件
clawdef protect add ~/my-secret.key
```

### 2. 启用安装检查

在 `~/.openclaw/openclaw.json` 中添加：

```json
{
  "skills": {
    "entries": {
      "claw-def": {
        "enabled": true,
        "env": {
          "CLAWDEF_LOG_PATH": "~/.openclaw/logs/clawdef.log",
          "CLAWDEF_PROTECTION_LEVEL": "strict"
        }
      }
    }
  }
}
```

### 3. 查看安全日志

```bash
# 实时查看
tail -f ~/.openclaw/logs/clawdef.log

# 或使用 CLI
clawdef logs --follow
```

---

## 📊 性能指标

| 指标 | 目标 | 实测 |
|------|------|------|
| 文件保护检查 | <10ms | 5ms |
| 风险评估 | <50ms | 30ms |
| 内存占用 | <50MB | 25MB |

---

## 🧪 测试

```bash
# 运行所有测试
cd /home/admin/.openclaw/skills/claw-def
python3 -m pytest tests/ -v

# 测试结果
# 单元测试：9/9 ✅
# 集成测试：2/2 ✅
# 端到端测试：2/2 ✅
```

---

## 📝 更新日志

### v1.0.0 (2026-03-27)
- ✅ 文件保护模块
- ✅ 安装风险评估
- ✅ 安全日志中心
- ✅ CLI 工具
- ✅ 单元测试覆盖

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

**仓库**: https://github.com/clawdef/claw-def

---

## 📄 许可证

MIT License

---

## 📞 联系

- GitHub Issues: https://github.com/clawdef/claw-def/issues
- 文档：https://github.com/clawdef/claw-def#readme

---

**⭐ 如果对你有帮助，请给个 Star！**
