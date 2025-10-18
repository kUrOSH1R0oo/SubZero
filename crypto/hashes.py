#!/usr/bin/env python3

from __future__ import annotations
import hashlib
from typing import Callable
try:
    from passlib.registry import get_crypt_handler
    PASSLIB_AVAILABLE = True
except ImportError:
    PASSLIB_AVAILABLE = False

PASSLIB_SCHEMES = [
    "apr_md5_crypt", "argon2", "atlassian_pbkdf2_sha1", "bcrypt", "bcrypt_sha256",
    "bigcrypt", "bsd_nthash", "bsdi_crypt", "cisco_asa", "cisco_pix",
    "cisco_type7", "crypt16", "cta_pbkdf2_sha1", "des_crypt", "django_argon2",
    "django_bcrypt", "django_bcrypt_sha256", "django_des_crypt", "django_disabled",
    "django_pbkdf2_sha1", "django_pbkdf2_sha256", "django_salted_md5",
    "django_salted_sha1", "dlitz_pbkdf2_sha1", "fshp", "grub_pbkdf2_sha512",
    "hex_md4", "hex_md5", "hex_sha1", "hex_sha256", "hex_sha512", "htdigest",
    "ldap_bcrypt", "ldap_bsdi_crypt", "ldap_des_crypt", "ldap_hex_md5",
    "ldap_hex_sha1", "ldap_md5", "ldap_md5_crypt", "ldap_pbkdf2_sha1",
    "ldap_pbkdf2_sha256", "ldap_pbkdf2_sha512", "ldap_plaintext",
    "ldap_salted_md5", "ldap_salted_sha1", "ldap_salted_sha256",
    "ldap_salted_sha512", "ldap_sha1", "ldap_sha1_crypt", "ldap_sha256_crypt",
    "ldap_sha512_crypt", "lmhash", "md5_crypt", "msdcc", "msdcc2",
    "mssql2000", "mssql2005", "mysql323", "mysql41", "nthash", "oracle10",
    "oracle11", "pbkdf2_sha1", "pbkdf2_sha256", "pbkdf2_sha512", "phpass",
    "plaintext", "postgres_md5", "roundup_plaintext", "scram", "scrypt",
    "sha1_crypt", "sha256_crypt", "sha512_crypt", "sun_md5_crypt",
    "unix_disabled", "unix_fallback"
]

def _digest(data: str, algo: str) -> str:
    try:
        h = hashlib.new(algo)
        h.update(data.encode())
        return h.hexdigest()
    except ValueError as e:
        return f"error: {e}"

def _passlib_digest(data: str, scheme: str, user: str | None = None, realm: str | None = None) -> str:
    if not PASSLIB_AVAILABLE:
        return "error: passlib not installed"
    try:
        handler = get_crypt_handler(scheme)
        if scheme == "htdigest":
            if user is None or realm is None:
                return "error: htdigest requires user and realm"
            return f"{user}:{realm}:{handler.hash(data, user=user, realm=realm).split(':')[-1]}"
        elif scheme in ("msdcc", "msdcc2"):
            if user is None:
                return "error: {} requires user".format(scheme)
            return handler.hash(data, user=user)
        else:
            return handler.hash(data)
    except Exception as e:
        return f"error: {e}"

for algo in hashlib.algorithms_available:
    globals()[f"hash_{algo}"] = lambda data, a=algo: _digest(data, a)

for scheme in PASSLIB_SCHEMES:
    if scheme == "htdigest":
        globals()[f"hash_{scheme}"] = lambda data, user, realm, s=scheme: _passlib_digest(data, s, user, realm)
    elif scheme in ("msdcc", "msdcc2"):
        globals()[f"hash_{scheme}"] = lambda data, user, s=scheme: _passlib_digest(data, s, user)
    else:
        globals()[f"hash_{scheme}"] = lambda data, s=scheme: _passlib_digest(data, s)