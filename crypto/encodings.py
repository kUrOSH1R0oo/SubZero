#!/usr/bin/env python3
"""Encoding helpers — stable, forgiving decode behavior."""

from __future__ import annotations
import base64
import binascii
import urllib.parse
from typing import Optional

def _safe_decode(fn, data: bytes, errors: str = "ignore") -> str:
    try:
        return fn(data).decode(errors=errors)
    except Exception:
        return ""

def b32e(text: str) -> str:
    try:
        return base64.b32encode(text.encode()).decode()
    except Exception as e:
        return f"error: {e}"

def b32d(text: str) -> str:
    s = text.strip()
    rem = len(s) % 8
    if rem:
        s += "=" * (8 - rem)
    try:
        return base64.b32decode(s, casefold=True).decode(errors="ignore")
    except Exception as e:
        return f"error: {e}"

def b64e(text: str) -> str:
    try:
        return base64.b64encode(text.encode()).decode()
    except Exception as e:
        return f"error: {e}"

def b64d(text: str) -> str:
    s = text.strip()
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    try:
        return base64.b64decode(s, validate=False).decode(errors="ignore")
    except Exception as e:
        return f"error: {e}"

def b85e(text: str) -> str:
    try:
        return base64.b85encode(text.encode()).decode()
    except Exception as e:
        return f"error: {e}"

def b85d(text: str) -> str:
    try:
        return base64.b85decode(text.strip()).decode(errors="ignore")
    except Exception as e:
        return f"error: {e}"

def hex_encode(text: str) -> str:
    try:
        return binascii.hexlify(text.encode()).decode()
    except Exception as e:
        return f"error: {e}"

def hex_decode(text: str) -> str:
    s = text.strip().replace(" ", "")
    try:
        return binascii.unhexlify(s).decode(errors="ignore")
    except Exception as e:
        return f"error: {e}"

def url_encode(text: str) -> str:
    try:
        return urllib.parse.quote(text, safe="")
    except Exception as e:
        return f"error: {e}"

def url_decode(text: str) -> str:
    try:
        return urllib.parse.unquote(text)
    except Exception as e:
        return f"error: {e}"