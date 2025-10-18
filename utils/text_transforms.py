#!/usr/bin/env python3
"""Text transformation functions: replace, reverse, and case transformation"""

from __future__ import annotations
from typing import Iterable

def replace_text(text: str, find: str, replace: str) -> str:
	try:
		return text.replace(find, replace)
	except Exception as e:
		return f"error: {e}"

def reverse_by_char(text: str) -> str:
	try:
		return text[::-1]
	except Exception as e:
		return f"error: {e}"

def reverse_by_byte(text: str) -> str:
	try:
		return text.encode()[::-1].decode(errors='replace')
	except Exception as e:
		return f"error: {e}"

def reverse_by_line(text: str) -> str:
	try:
		lines = text.splitlines()
		return '\n'.join(lines[::-1])
	except Exception as e:
		return f"error: {e}"

def to_upper(text: str) -> str:
	try:
		return text.upper()
	except Exception as e:
		return f"error: {e}"

def to_lower(text: str) -> str:
	try:
		return text.lower()
	except Exception as e:
		return f"error: {e}"

def to_capitalize(text: str) -> str:
	try:
		return text.title()
	except Exception as e:
		return f"error: {e}"

def to_alternating(text: str) -> str:
	try:
		return ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(text.lower()))
	except Exception as e:
		return f"error: {e}"

def to_inverse(text: str) -> str:
	try:
		return ''.join(c.lower() if c.isupper() else c.upper() for c in text)
	except Exception as e:
		return f"error: {e}"