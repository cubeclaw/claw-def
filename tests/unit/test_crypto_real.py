#!/usr/bin/env python3
"""凭证加密模块真实单元测试"""

import os
import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from crypto import CredentialProtector

def test_protector_init():
    """测试初始化"""
    protector = CredentialProtector()
    assert protector.key is not None
    print("✅ test_protector_init 通过")

def test_encrypt_decrypt():
    """测试加密解密"""
    protector = CredentialProtector("test_password_123")
    plaintext = "sk-1234567890abcdef"
    encrypted = protector.encrypt(plaintext)
    decrypted = protector.decrypt(encrypted)
    assert decrypted == plaintext
    print("✅ test_encrypt_decrypt 通过")

def test_encrypt_with_label():
    """测试带标签加密"""
    protector = CredentialProtector("test_password_123")
    protector.encrypt("api_key_123", "github_api")
    credential = protector.get_credential("github_api")
    assert credential == "api_key_123"
    print("✅ test_encrypt_with_label 通过")

def test_delete_credential():
    """测试删除凭证"""
    protector = CredentialProtector("test_password_123")
    protector.encrypt("temp_key", "temp_label")
    result = protector.delete_credential("temp_label")
    assert result == True
    credential = protector.get_credential("temp_label")
    assert credential is None
    print("✅ test_delete_credential 通过")

def test_list_credentials():
    """测试列出凭证"""
    protector = CredentialProtector("test_password_123")
    protector.encrypt("key1", "label1")
    protector.encrypt("key2", "label2")
    labels = protector.list_credentials()
    assert 'label1' in labels
    assert 'label2' in labels
    print("✅ test_list_credentials 通过")

def test_statistics():
    """测试统计"""
    protector = CredentialProtector("test_password_123")
    protector.encrypt("key1", "label1")
    stats = protector.get_statistics()
    assert stats['total_credentials'] >= 1
    print("✅ test_statistics 通过")

if __name__ == '__main__':
    test_protector_init()
    test_encrypt_decrypt()
    test_encrypt_with_label()
    test_delete_credential()
    test_list_credentials()
    test_statistics()
    print("\n✅ 凭证加密测试全部通过 (6/6)")
