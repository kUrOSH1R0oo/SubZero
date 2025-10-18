#!/usr/bin/env python3
"""Symmetric encryption using Fernet, AES, DES, and ChaCha20 (cryptography and pycryptodome libraries)."""

from __future__ import annotations
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Cipher import AES, DES, ChaCha20
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from camellia import CamelliaCipher, MODE_CBC
import base64
import os

def generate_salt() -> str:
    try:
        return base64.b64encode(os.urandom(16)).decode()
    except Exception as e:
        return f"error: {e}"

def generate_fernet_key(password: str | None = None, salt: str | None = None) -> str:
    try:
        if password is None:
            return Fernet.generate_key().decode()
        try:
            salt_bytes = base64.b64decode(salt)
        except:
            salt_bytes = salt.encode() if salt else os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key.decode()
    except Exception as e:
        return f"error: {e}"

def fernet_encrypt(text: str, key: str) -> str:
    try:
        f = Fernet(key.encode())
        return f.encrypt(text.encode()).decode()
    except Exception as e:
        return f"error: {e}"

def fernet_decrypt(ciphertext: str, key: str) -> str:
    try:
        f = Fernet(key.encode())
        return f.decrypt(ciphertext.encode()).decode()
    except Exception as e:
        return f"error: {e}"

def aes_key(password: str | None = None, salt: str | None = None, key_length: int = 256) -> str:
    try:
        valid_lengths = [128, 192, 256]
        if key_length not in valid_lengths:
            return f"error: key_length must be one of {valid_lengths}"
        key_bytes = key_length // 8
        if password is None:
            return base64.b64encode(get_random_bytes(key_bytes)).decode()
        try:
            salt_bytes = base64.b64decode(salt)
        except:
            salt_bytes = salt.encode() if salt else get_random_bytes(16)
        key = PBKDF2(password.encode(), salt_bytes, dkLen=key_bytes, count=100000)
        return base64.b64encode(key).decode()
    except Exception as e:
        return f"error: {e}"

def aes_encrypt(text: str, key: str) -> str:
    try:
        key_bytes = base64.b64decode(key)
        if len(key_bytes) not in [16, 24, 32]:
            return f"error: key length must be 16, 24, or 32 bytes (128, 192, or 256 bits)"
        iv = get_random_bytes(16)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        padded_text = pad(text.encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded_text)
        return base64.b64encode(iv + ciphertext).decode()
    except Exception as e:
        return f"error: {e}"

def aes_decrypt(ciphertext: str, key: str) -> str:
    try:
        key_bytes = base64.b64decode(key)
        if len(key_bytes) not in [16, 24, 32]:
            return f"error: key length must be 16, 24, or 32 bytes (128, 192, or 256 bits)"
        data = base64.b64decode(ciphertext)
        if len(data) < 16:
            return "error: ciphertext too short (missing IV)"
        iv = data[:16]
        ciphertext = data[16:]
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        padded_text = cipher.decrypt(ciphertext)
        return unpad(padded_text, AES.block_size).decode()
    except Exception as e:
        return f"error: {e}"

def des_key(password: str | None = None, salt: str | None = None) -> str:
    try:
        if password is None:
            return base64.b64encode(get_random_bytes(8)).decode()
        try:
            salt_bytes = base64.b64decode(salt)
        except:
            salt_bytes = salt.encode() if salt else get_random_bytes(16)
        key = PBKDF2(password.encode(), salt_bytes, dkLen=8, count=100000)
        return base64.b64encode(key).decode()
    except Exception as e:
        return f"error: {e}"

def des_encrypt(text: str, key: str) -> str:
    try:
        key_bytes = base64.b64decode(key)
        if len(key_bytes) != 8:
            return "error: DES key must be 8 bytes (64 bits)"
        iv = get_random_bytes(8)
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
        padded_text = pad(text.encode(), DES.block_size)
        ciphertext = cipher.encrypt(padded_text)
        return base64.b64encode(iv + ciphertext).decode()
    except Exception as e:
        return f"error: {e}"

def des_decrypt(ciphertext: str, key: str) -> str:
    try:
        key_bytes = base64.b64decode(key)
        if len(key_bytes) != 8:
            return "error: DES key must be 8 bytes (64 bits)"
        data = base64.b64decode(ciphertext)
        if len(data) < 8:
            return "error: ciphertext too short (missing IV)"
        iv = data[:8]
        ciphertext = data[8:]
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
        padded_text = cipher.decrypt(ciphertext)
        return unpad(padded_text, DES.block_size).decode()
    except Exception as e:
        return f"error: {e}"

def chacha20_key(password: str | None = None, salt: str | None = None) -> str:
    try:
        if password is None:
            return base64.b64encode(get_random_bytes(32)).decode()
        try:
            salt_bytes = base64.b64decode(salt)
        except:
            salt_bytes = salt.encode() if salt else get_random_bytes(16)
        key = PBKDF2(password.encode(), salt_bytes, dkLen=32, count=100000)
        return base64.b64encode(key).decode()
    except Exception as e:
        return f"error: {e}"

def chacha20_encrypt(text: str, key: str) -> str:
    try:
        key_bytes = base64.b64decode(key)
        if len(key_bytes) != 32:
            return "error: ChaCha20 key must be 32 bytes (256 bits)"
        nonce = get_random_bytes(12)
        cipher = ChaCha20.new(key=key_bytes, nonce=nonce)
        ciphertext = cipher.encrypt(text.encode())
        return base64.b64encode(nonce + ciphertext).decode()
    except Exception as e:
        return f"error: {e}"

def chacha20_decrypt(ciphertext: str, key: str) -> str:
    try:
        key_bytes = base64.b64decode(key)
        if len(key_bytes) != 32:
            return "error: ChaCha20 key must be 32 bytes (256 bits)"
        data = base64.b64decode(ciphertext)
        if len(data) < 12:
            return "error: ciphertext too short (missing nonce)"
        nonce = data[:12]
        ciphertext = data[12:]
        cipher = ChaCha20.new(key=key_bytes, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode()
    except Exception as e:
        return f"error: {e}"

def camellia_key(password: str | None = None, salt: str | None = None, key_length: int = 128) -> str:
    try:
        valid_lengths = [128, 192, 256]
        if key_length not in valid_lengths:
            return f"error: key_length must be one of {valid_lengths}"
        key_bytes = key_length // 8
        if password is None:
            return base64.b64encode(get_random_bytes(key_bytes)).decode()
        try:
            salt_bytes = base64.b64decode(salt)
        except:
            salt_bytes = salt.encode() if salt else get_random_bytes(16)
        key = PBKDF2(password.encode(), salt_bytes, dkLen=key_bytes, count=100000)
        return base64.b64encode(key).decode()
    except Exception as e:
        return f"error: {e}"

def camellia_encrypt(text: str, key: str) -> str:
    try:
        key_bytes = base64.b64decode(key)
        if len(key_bytes) not in [16, 24, 32]:
            return f"error: key length must be 16, 24, or 32 bytes (128, 192, or 256 bits)"
        iv = get_random_bytes(16)
        def pad(data: bytes) -> bytes:
            padding_len = 16 - len(data) % 16
            return data + bytes([padding_len] * padding_len)
        padded_text = pad(text.encode())
        cipher = CamelliaCipher(key=key_bytes, IV=iv, mode=MODE_CBC)
        ciphertext = cipher.encrypt(padded_text)
        return base64.b64encode(iv + ciphertext).decode()
    except Exception as e:
        return f"error: {e}"

def camellia_decrypt(ciphertext: str, key: str) -> str:
    try:
        key_bytes = base64.b64decode(key)
        if len(key_bytes) not in [16, 24, 32]:
            return f"error: key length must be 16, 24, or 32 bytes (128, 192, or 256 bits)"
        data = base64.b64decode(ciphertext)
        if len(data) < 16:
            return "error: ciphertext too short (missing IV)"
        iv = data[:16]
        ciphertext = data[16:]
        def unpad(data: bytes) -> bytes:
            padding_len = data[-1]
            return data[:-padding_len]
        cipher = CamelliaCipher(key=key_bytes, IV=iv, mode=MODE_CBC)
        padded_text = cipher.decrypt(ciphertext)
        return unpad(padded_text).decode()
    except Exception as e:
        return f"error: {e}"