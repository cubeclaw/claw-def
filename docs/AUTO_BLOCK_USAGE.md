# 自动阻断模块使用指南

**版本**: v2.2

---

## 🚀 快速开始

```python
from auto_block import AutoBlocker

blocker = AutoBlocker()
result = blocker.check_and_block('eval')
# {'blocked': True, 'reason': '动态代码执行'}
```

## 📊 API

- `check_and_block(operation, target)` - 检查并阻断
- `get_statistics()` - 获取统计
- `add_to_block_list(op)` - 添加阻断
- `remove_from_block_list(op)` - 移除阻断

## 🔧 CLI

```bash
python3 src/auto_block.py test    # 测试
python3 src/auto_block.py stats   # 统计
```

## 📝 日志

`~/.openclaw/logs/clawdef_blocks.log`
