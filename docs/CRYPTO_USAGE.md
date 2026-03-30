# 凭证加密模块使用指南

**版本**: v2.2

---

## 🚀 快速开始

```python
from crypto import CredentialProtector

# 创建保护器
protector = CredentialProtector("master_password")

# 加密凭证
encrypted = protector.encrypt("api_key_123", "github_api")

# 解密凭证
decrypted = protector.get_credential("github_api")
# "api_key_123"

# 删除凭证
protector.delete_credential("github_api")
```

## 📊 API

- `encrypt(plaintext, label)` - 加密
- `decrypt(ciphertext)` - 解密
- `get_credential(label)` - 获取
- `delete_credential(label)` - 删除
- `list_credentials()` - 列出所有

## 🔧 CLI

```bash
python3 src/crypto.py encrypt "api_key" "label"
python3 src/crypto.py decrypt "ciphertext"
python3 src/crypto.py get "label"
python3 src/crypto.py list
```

## 🔐 加密规格

- **算法**: AES-256-GCM
- **密钥派生**: PBKDF2-SHA256
- **迭代次数**: 100,000
- **存储**: 加密 JSON (~/.openclaw/clawdef_credentials.json)

## ⚠️ 注意

- 主密码丢失 = 所有凭证无法恢复
- 建议备份主密码密钥
