#!/usr/bin/env python3
"""
凭证加密模块 - ClawDef v2.2 核心组件

功能:
- AES-256-GCM 加密
- PBKDF2 密钥派生 (10 万次迭代)
- 凭证安全存储
"""

import os
import json
import base64
import logging
from typing import Dict, Optional
from datetime import datetime

LOG_PATH = os.path.expanduser("~/.openclaw/logs/clawdef.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()]
)
logger = logging.getLogger("ClawDef.Crypto")

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logger.warning("cryptography 未安装，运行：pip install cryptography")


class CredentialProtector:
    """凭证保护器"""
    
    def __init__(self, master_password: Optional[str] = None):
        self.master_password = master_password or self._get_default_password()
        self.key = self._derive_key()
        self.storage_path = os.path.expanduser("~/.openclaw/clawdef_credentials.json")
        self._ensure_storage()
    
    def _get_default_password(self) -> str:
        """获取默认主密码"""
        default_path = os.path.expanduser("~/.openclaw/clawdef_master.key")
        if os.path.exists(default_path):
            with open(default_path, 'r') as f:
                return f.read().strip()
        
        # 生成新密码
        password = base64.b64encode(os.urandom(32)).decode()
        os.makedirs(os.path.dirname(default_path), exist_ok=True)
        with open(default_path, 'w') as f:
            f.write(password)
        os.chmod(default_path, 0o600)
        logger.info("已生成主密码密钥")
        return password
    
    def _derive_key(self) -> bytes:
        """从主密码派生密钥 (PBKDF2 10 万次迭代)"""
        if not CRYPTO_AVAILABLE:
            return os.urandom(32)
        
        salt_path = os.path.expanduser("~/.openclaw/clawdef_salt.bin")
        if os.path.exists(salt_path):
            with open(salt_path, 'rb') as f:
                salt = f.read()
        else:
            salt = os.urandom(16)
            os.makedirs(os.path.dirname(salt_path), exist_ok=True)
            with open(salt_path, 'wb') as f:
                f.write(salt)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(self.master_password.encode())
        logger.info("密钥已派生 (PBKDF2 10 万次)")
        return key
    
    def encrypt(self, plaintext: str, label: str = "") -> str:
        """加密凭证 (AES-256-GCM)"""
        if not CRYPTO_AVAILABLE:
            logger.warning("加密库不可用，使用 base64 编码")
            return base64.b64encode(plaintext.encode()).decode()
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        encrypted = base64.b64encode(iv + ciphertext + encryptor.tag).decode()
        
        if label:
            self._save_credential(label, encrypted)
        
        logger.info(f"凭证已加密：{label or '未命名'}")
        return encrypted
    
    def decrypt(self, ciphertext: str) -> str:
        """解密凭证"""
        if not CRYPTO_AVAILABLE:
            return base64.b64decode(ciphertext.encode()).decode()
        
        data = base64.b64decode(ciphertext.encode())
        iv = data[:16]
        ciphertext_bytes = data[16:-16]
        tag = data[-16:]
        
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext_bytes) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()
        
        return plaintext.decode()
    
    def _save_credential(self, label: str, encrypted: str):
        """保存加密凭证"""
        credentials = self._load_credentials()
        credentials[label] = {
            'encrypted': encrypted,
            'created_at': datetime.now().isoformat(),
        }
        self._save_credentials(credentials)
    
    def get_credential(self, label: str) -> Optional[str]:
        """获取凭证"""
        credentials = self._load_credentials()
        if label not in credentials:
            return None
        
        encrypted = credentials[label]['encrypted']
        return self.decrypt(encrypted)
    
    def delete_credential(self, label: str) -> bool:
        """删除凭证"""
        credentials = self._load_credentials()
        if label in credentials:
            del credentials[label]
            self._save_credentials(credentials)
            logger.info(f"凭证已删除：{label}")
            return True
        return False
    
    def _load_credentials(self) -> Dict:
        """加载凭证库"""
        if os.path.exists(self.storage_path):
            with open(self.storage_path, 'r') as f:
                return json.load(f)
        return {}
    
    def _save_credentials(self, credentials: Dict):
        """保存凭证库"""
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        with open(self.storage_path, 'w') as f:
            json.dump(credentials, f, indent=2)
        os.chmod(self.storage_path, 0o600)
    
    def _ensure_storage(self):
        """确保存储文件存在"""
        if not os.path.exists(self.storage_path):
            self._save_credentials({})
    
    def list_credentials(self) -> list:
        """列出所有凭证标签"""
        credentials = self._load_credentials()
        return list(credentials.keys())
    
    def get_statistics(self) -> Dict:
        """获取统计信息"""
        credentials = self._load_credentials()
        return {
            'total_credentials': len(credentials),
            'labels': list(credentials.keys()),
        }


def main():
    """CLI 入口"""
    import sys
    
    protector = CredentialProtector()
    
    if len(sys.argv) < 2:
        print("用法：python3 crypto.py <command> [args]")
        print("命令:")
        print("  encrypt <text> [label]  - 加密")
        print("  decrypt <ciphertext>    - 解密")
        print("  get <label>             - 获取凭证")
        print("  list                    - 列出凭证")
        print("  stats                   - 统计信息")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'encrypt':
        if len(sys.argv) < 3:
            print("用法：python3 crypto.py encrypt <text> [label]")
            sys.exit(1)
        text = sys.argv[2]
        label = sys.argv[3] if len(sys.argv) > 3 else ""
        encrypted = protector.encrypt(text, label)
        print(f"加密结果：{encrypted}")
        if label:
            print(f"已保存到：{label}")
    
    elif command == 'decrypt':
        if len(sys.argv) < 3:
            print("用法：python3 crypto.py decrypt <ciphertext>")
            sys.exit(1)
        decrypted = protector.decrypt(sys.argv[2])
        print(f"解密结果：{decrypted}")
    
    elif command == 'get':
        if len(sys.argv) < 3:
            print("用法：python3 crypto.py get <label>")
            sys.exit(1)
        credential = protector.get_credential(sys.argv[2])
        if credential:
            print(f"凭证：{credential}")
        else:
            print("凭证不存在")
    
    elif command == 'list':
        labels = protector.list_credentials()
        print(f"凭证列表 ({len(labels)} 个):")
        for label in labels:
            print(f"  - {label}")
    
    elif command == 'stats':
        stats = protector.get_statistics()
        print(f"凭证总数：{stats['total_credentials']}")
        print(f"标签：{stats['labels']}")
    
    else:
        print(f"未知命令：{command}")
        sys.exit(1)


if __name__ == '__main__':
    main()
