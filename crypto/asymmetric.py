#!/usr/bin/env python3
"""Asymmetric encryption and signing using RSA, ECC (ECDSA, ECDH), and DSA (pycryptodome)."""

from __future__ import annotations
from Crypto.PublicKey import RSA, ECC, DSA
from Crypto.Signature import DSS, pkcs1_15, pss
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64

def rsa_key() -> str:
    try:
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return f"Private: {base64.b64encode(private_key).decode()}\nPublic: {base64.b64encode(public_key).decode()}"
    except Exception as e:
        return f"error: {e}"

def rsa_encrypt(text: str, public_key: str) -> str:
    try:
        key = RSA.import_key(base64.b64decode(public_key))
        cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
        ciphertext = cipher.encrypt(text.encode())
        return base64.b64encode(ciphertext).decode()
    except Exception as e:
        return f"error: {e}"

def rsa_decrypt(ciphertext: str, private_key: str) -> str:
    try:
        key = RSA.import_key(base64.b64decode(private_key))
        cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
        plaintext = cipher.decrypt(base64.b64decode(ciphertext))
        return plaintext.decode()
    except Exception as e:
        return f"error: {e}"

def rsa_sign(text: str, private_key: str) -> str:
    try:
        key = RSA.import_key(base64.b64decode(private_key))
        h = SHA256.new(text.encode())
        signature = pss.new(key).sign(h)
        return base64.b64encode(signature).decode()
    except Exception as e:
        return f"error: {e}"

def rsa_verify(text: str, public_key: str, signature: str) -> str:
    try:
        key = RSA.import_key(base64.b64decode(public_key))
        h = SHA256.new(text.encode())
        pss.new(key).verify(h, base64.b64decode(signature))
        return "valid"
    except Exception as e:
        return f"invalid: {e}"

def ecdsa_key() -> str:
    try:
        key = ECC.generate(curve='P-256')
        private_key = key.export_key(format='DER')
        public_key = key.public_key().export_key(format='DER')
        return f"Private: {base64.b64encode(private_key).decode()}\nPublic: {base64.b64encode(public_key).decode()}"
    except Exception as e:
        return f"error: {e}"

def ecdsa_sign(text: str, private_key: str) -> str:
    try:
        key = ECC.import_key(base64.b64decode(private_key))
        h = SHA256.new(text.encode())
        signer = DSS.new(key, 'fips-186-3')
        signature = signer.sign(h)
        return base64.b64encode(signature).decode()
    except Exception as e:
        return f"error: {e}"

def ecdsa_verify(text: str, public_key: str, signature: str) -> str:
    try:
        key = ECC.import_key(base64.b64decode(public_key))
        h = SHA256.new(text.encode())
        verifier = DSS.new(key, 'fips-186-3')
        verifier.verify(h, base64.b64decode(signature))
        return "valid"
    except Exception as e:
        return f"invalid: {e}"

def ecdh_key() -> str:
    try:
        key = ECC.generate(curve='P-256')
        private_key = key.export_key(format='DER')
        public_key = key.public_key().export_key(format='DER')
        return f"Private: {base64.b64encode(private_key).decode()}\nPublic: {base64.b64encode(public_key).decode()}"
    except Exception as e:
        return f"error: {e}"

def ecdh_derive(private_key: str, public_key: str, salt: str | None = None) -> str:
    try:
        priv_key = ECC.import_key(base64.b64decode(private_key))
        pub_key = ECC.import_key(base64.b64decode(public_key))
        shared_secret = priv_key.d * pub_key.pointQ
        shared_bytes = shared_secret.x.to_bytes(32)
        try:
            salt_bytes = base64.b64decode(salt)
        except:
            salt_bytes = salt.encode() if salt else get_random_bytes(16)
        key = PBKDF2(shared_bytes, salt_bytes, dkLen=32, count=100000)
        return base64.b64encode(key).decode()
    except Exception as e:
        return f"error: {e}"

def dsa_key() -> str:
    try:
        key = DSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return f"Private: {base64.b64encode(private_key).decode()}\nPublic: {base64.b64encode(public_key).decode()}"
    except Exception as e:
        return f"error: {e}"

def dsa_sign(text: str, private_key: str) -> str:
    try:
        key = DSA.import_key(base64.b64decode(private_key))
        h = SHA256.new(text.encode())
        signer = DSS.new(key, 'fips-186-3')
        signature = signer.sign(h)
        return base64.b64encode(signature).decode()
    except Exception as e:
        return f"error: {e}"

def dsa_verify(text: str, public_key: str, signature: str) -> str:
    try:
        key = DSA.import_key(base64.b64decode(public_key))
        h = SHA256.new(text.encode())
        verifier = DSS.new(key, 'fips-186-3')
        verifier.verify(h, base64.b64decode(signature))
        return "valid"
    except Exception as e:
        return f"invalid: {e}"
