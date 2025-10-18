#!/usr/bin/env python3
"""Classic ciphers: ROT, Caesar, Vigenère, substitution, XOR, Bacon, A1Z26, Brainfuck, Rail Fence, ADFGX."""

from __future__ import annotations
from typing import Iterable
import math

BACON_CODE = {
    "A": "AAAAA", "B": "AAAAB", "C": "AAABA", "D": "AAABB",
    "E": "AABAA", "F": "AABAB", "G": "AABBA", "H": "AABBB",
    "I": "ABAAA", "J": "ABAAA",  # I/J combined
    "K": "ABAAB", "L": "ABABA", "M": "ABABB", "N": "ABBAA",
    "O": "ABBAB", "P": "ABBBA", "Q": "ABBBB", "R": "BAAAA",
    "S": "BAAAB", "T": "BAABA", "U": "BAABB",
    "V": "BAABB",  # U/V combined
    "W": "BABAA", "X": "BABAB", "Y": "BABBA", "Z": "BABBB"
}

def rot5(text: str) -> str:
    try:
        out = []
        for c in text:
            if c.isdigit():
                out.append(str((int(c) + 5) % 10))
            else:
                out.append(c)
        return "".join(out)
    except Exception as e:
        return f"error: {e}"

def rot13(text: str) -> str:
    try:
        return text.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
        ))
    except Exception as e:
        return f"error: {e}"

def rot18(text: str) -> str:
    try:
        out = []
        for c in text:
            if c.isdigit():
                out.append(str((int(c) + 5) % 10))
            elif c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                out.append(chr((ord(c) - base + 13) % 26 + base))
            else:
                out.append(c)
        return "".join(out)
    except Exception as e:
        return f"error: {e}"

def rot47(text: str) -> str:
    try:
        out = []
        for c in text:
            if 33 <= ord(c) <= 126:
                out.append(chr(33 + ((ord(c) - 33 + 47) % 94)))
            else:
                out.append(c)
        return "".join(out)
    except Exception as e:
        return f"error: {e}"

def caesar_encode(text: str, shift: int) -> str:
    try:
        shift = shift % 26
        out = []
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                out.append(chr((ord(c) - base + shift) % 26 + base))
            else:
                out.append(c)
        return "".join(out)
    except Exception as e:
        return f"error: {e}"

def caesar_decode(text: str, shift: int) -> str:
    try:
        return caesar_encode(text, -shift)
    except Exception as e:
        return f"error: {e}"

def vigenere_encode(text: str, key: str) -> str:
    try:
        key = key.upper()
        if not key:
            return "error: key cannot be empty"
        key_vals = [ord(c) - ord('A') for c in key if c.isalpha()]
        if not key_vals:
            return "error: key must contain at least one letter"
        out = []
        key_idx = 0
        for c in text:
            if c.isalpha():
                shift = key_vals[key_idx % len(key_vals)]
                base = ord('A') if c.isupper() else ord('a')
                out.append(chr((ord(c) - base + shift) % 26 + base))
                key_idx += 1
            else:
                out.append(c)
        return "".join(out)
    except Exception as e:
        return f"error: {e}"

def vigenere_decode(text: str, key: str) -> str:
    try:
        key = key.upper()
        if not key:
            return "error: key cannot be empty"
        key_vals = [ord(c) - ord('A') for c in key if c.isalpha()]
        if not key_vals:
            return "error: key must contain at least one letter"
        out = []
        key_idx = 0
        for c in text:
            if c.isalpha():
                shift = key_vals[key_idx % len(key_vals)]
                base = ord('A') if c.isupper() else ord('a')
                out.append(chr((ord(c) - base - shift) % 26 + base))
                key_idx += 1
            else:
                out.append(c)
        return "".join(out)
    except Exception as e:
        return f"error: {e}"

def substitution_encode(text: str, key: str) -> str:
    try:
        key = key.upper()
        if len(set(key) - {" "}) != 26:
            return "error: key must be a permutation of 26 letters"
        key_map = {chr(65+i): key[i] for i in range(26)}
        out = []
        for c in text:
            if c.isalpha():
                base = 'A' if c.isupper() else 'a'
                out.append(key_map.get(c.upper(), c).lower() if c.islower() else key_map.get(c, c))
            else:
                out.append(c)
        return "".join(out)
    except Exception as e:
        return f"error: {e}"

def substitution_decode(text: str, key: str) -> str:
    try:
        key = key.upper()
        if len(set(key) - {" "}) != 26:
            return "error: key must be a permutation of 26 letters"
        reverse = {key[i]: chr(65+i) for i in range(26)}
        out = []
        for c in text:
            if c.isalpha():
                base = 'A' if c.isupper() else 'a'
                out.append(reverse.get(c.upper(), c).lower() if c.islower() else reverse.get(c, c))
            else:
                out.append(c)
        return "".join(out)
    except Exception as e:
        return f"error: {e}"

def xor_cipher(text: str, key: str) -> str:
    try:
        if not key:
            return "error: key cannot be empty"
        out = []
        key_idx = 0
        for c in text:
            k = key[key_idx % len(key)]
            out.append(chr(ord(c) ^ ord(k)))
            key_idx += 1
        return "".join(out)
    except Exception as e:
        return f"error: {e}"

def bacon_encode(text: str, letter1: str = "a", letter2: str = "b") -> str:
    try:
        if len(letter1) != 1 or len(letter2) != 1:
            return "error: letters must be single characters"
        text = text.upper()
        out = []
        for c in text:
            if c.isalpha():
                out.append(BACON_CODE.get(c, "?????").replace("A", letter1).replace("B", letter2))
            elif c == " ":
                out.append(" ")
            else:
                out.append("?????")
        return "".join(out)
    except Exception as e:
        return f"error: {e}"

def bacon_decode(text: str, letter1: str = "a", letter2: str = "b") -> str:
    try:
        if len(letter1) != 1 or len(letter2) != 1:
            return "error: letters must be single characters"
        reverse = {v.replace("A", letter1).replace("B", letter2): k for k, v in BACON_CODE.items()}
        space_positions = [i for i, c in enumerate(text) if c == " "]
        cleaned_text = text.replace(" ", "")
        if not cleaned_text:
            return ""
        # Split into chunks of 5
        chunks = [cleaned_text[i:i+5] for i in range(0, len(cleaned_text), 5)]
        out = []
        for chunk in chunks:
            if len(chunk) == 5:
                out.append(reverse.get(chunk, "?"))
            else:
                out.append("?")
        result = []
        chunk_idx = 0
        text_idx = 0
        while text_idx < len(text):
            if text_idx in space_positions:
                result.append(" ")
                text_idx += 1
            elif chunk_idx < len(out):
                result.append(out[chunk_idx])
                chunk_idx += 1
                text_idx += 5 if text_idx + 5 <= len(text) else len(text) - text_idx
            else:
                break
        return "".join(result)
    except Exception as e:
        return f"error: {e}"
        
def a1z26_encode(text: str, separator: str = '-') -> str:
    try:
        if not separator:
            return "error: separator cannot be empty"
        text = text.upper()
        out = []
        for c in text:
            if c.isalpha():
                num = str(ord(c) - ord('A') + 1)
                out.append(num)
            elif c == " ":
                out.append(" ")
            else:
                out.append(c)
        return separator.join(out).replace(f"{separator} {separator}", " ")
    except Exception as e:
        return f"error: {e}"

def a1z26_decode(code: str, separator: str = '-') -> str:
    try:
        if not separator:
            return "error: separator cannot be empty"
        tokens = code.strip().replace(" ", f" {separator} ").split(separator)
        out = []
        for t in tokens:
            t = t.strip()
            if not t:
                continue
            if t.isdigit():
                n = int(t)
                if 1 <= n <= 26:
                    out.append(chr(ord('A') + n - 1))
                else:
                    out.append('?')
            elif t == " ":
                out.append(" ")
            else:
                out.append('?')
        return "".join(out)
    except Exception as e:
        return f"error: {e}"

def bf_encode(text: str) -> str:
    try:
        if not text:
            return ""
        out = []
        for char in text:
            ascii_val = ord(char)
            factor = max(1, ascii_val // 10)
            count = ascii_val // factor
            remainder = ascii_val % factor
            code = ">"                      # move to a fresh cell
            code += "+" * factor            # set loop counter
            code += "[<" + "+" * count + ">-]"  # multiply into prev cell
            code += "<"                     # move back
            code += "+" * remainder         # add remainder
            code += "."                     # output
            code += "[-]"                   # clear/reset cell
            out.append(code)
        return "".join(out)
    except Exception as e:
        return f"error: {e}"

def bf_decode(code: str) -> str:
    try:
        tape = [0] * 30000
        pointer = 0
        output = []
        code_ptr = 0
        max_steps = 1000000
        jump_table = {}
        stack = []
        for i, c in enumerate(code):
            if c == "[":
                stack.append(i)
            elif c == "]":
                if not stack:
                    return "error: unmatched closing bracket"
                open_idx = stack.pop()
                jump_table[open_idx] = i
                jump_table[i] = open_idx
        if stack:
            return "error: unmatched opening bracket"
        steps = 0
        while code_ptr < len(code):
            if steps >= max_steps:
                return "error: execution limit exceeded"
            cmd = code[code_ptr]
            if cmd == ">":
                pointer += 1
                if pointer >= len(tape):
                    return "error: tape overflow"
            elif cmd == "<":
                pointer -= 1
                if pointer < 0:
                    return "error: tape underflow"
            elif cmd == "+":
                tape[pointer] = (tape[pointer] + 1) % 256
            elif cmd == "-":
                tape[pointer] = (tape[pointer] - 1) % 256
            elif cmd == ".":
                output.append(chr(tape[pointer]))
            elif cmd == ",":
                return "error: input operation not supported"
            elif cmd == "[" and tape[pointer] == 0:
                code_ptr = jump_table[code_ptr]
            elif cmd == "]" and tape[pointer] != 0:
                code_ptr = jump_table[code_ptr]
            code_ptr += 1
            steps += 1
        return "".join(output)
    except Exception as e:
        return f"error: {e}"

def rail_fence_encode(text: str, key: int = 3, offset: int = 0) -> str:
    try:
        if key < 2:
            return "error: key must be at least 2"
        if not text:
            return ""
        # Initialize rail matrix
        rails = [[] for _ in range(key)]
        pos = offset % key
        direction = 1  # 1 for down, -1 for up
        for c in text:
            rails[pos].append(c)
            pos += direction
            if pos == key - 1:
                direction = -1
            elif pos == 0:
                direction = 1
        result = []
        for rail in rails:
            result.extend(rail)
        return ''.join(result)
    except Exception as e:
        return f"error: {e}"

def rail_fence_decode(text: str, key: int = 3, offset: int = 0) -> str:
    try:
        if key < 2:
            return "error: key must be at least 2"
        if not text:
            return ""
        n = len(text)
        rails = [[] for _ in range(key)]
        positions = []
        pos = offset % key
        direction = 1
        for _ in range(n):
            positions.append(pos)
            pos += direction
            if pos == key - 1:
                direction = -1
            elif pos == 0:
                direction = 1
        rail_lengths = [0] * key
        for p in positions:
            rail_lengths[p] += 1
        idx = 0
        for i in range(key):
            rails[i] = list(text[idx:idx + rail_lengths[i]])
            idx += rail_lengths[i]
        result = []
        pos = offset % key
        direction = 1
        rail_indices = [0] * key
        for _ in range(n):
            if rail_indices[pos] < len(rails[pos]):
                result.append(rails[pos][rail_indices[pos]])
                rail_indices[pos] += 1
            pos += direction
            if pos == key - 1:
                direction = -1
            elif pos == 0:
                direction = 1
        return ''.join(result)
    except Exception as e:
        return f"error: {e}"

def adfgx_encode(text: str, keyword: str, key_square: str = "ABCDEFGHIKLMNOPQRSTUVWXYZ") -> str:
    try:
        if not keyword:
            return "error: keyword cannot be empty"
        if len(set(key_square.upper().replace("J", "I")) - {" "}) != 25:
            return "error: key square must be a permutation of 25 letters (excluding J)"
        key_square = key_square.upper().replace("J", "I")
        coords = ['A', 'D', 'F', 'G', 'X']
        sub_table = {}
        for i, ch in enumerate(key_square):
            row, col = divmod(i, 5)
            sub_table[ch] = coords[row] + coords[col]
        text = text.upper().replace("J", "I")
        substituted = ""
        for ch in text:
            if ch.isalpha():
                substituted += sub_table.get(ch, "")
        n = len(keyword)
        rows = math.ceil(len(substituted) / n)
        padded = substituted.ljust(rows * n, 'X')  # pad with X
        grid = [padded[i:i+n] for i in range(0, len(padded), n)]
        order = sorted(range(n), key=lambda i: keyword.upper()[i])
        ciphertext = ''.join(''.join(row[i] for row in grid) for i in order)
        return ' '.join(ciphertext[i:i+4] for i in range(0, len(ciphertext), 4))
    except Exception as e:
        return f"error: {e}"

def adfgx_decode(ciphertext: str, keyword: str, key_square: str = "ABCDEFGHIKLMNOPQRSTUVWXYZ", trim_padding: bool = True) -> str:
    try:
        if not keyword:
            return "error: keyword cannot be empty"
        key_square = key_square.upper().replace("J", "I")
        if len(set(key_square) - {" "}) != 25:
            return "error: key square must be a permutation of 25 letters (excluding J)"
        coords = ['A', 'D', 'F', 'G', 'X']
        sub_table = {ch: coords[i // 5] + coords[i % 5] for i, ch in enumerate(key_square)}
        rev_table = {v: k for k, v in sub_table.items()}
        ciphertext = ciphertext.replace(" ", "")
        n = len(keyword)
        rows = math.ceil(len(ciphertext) / n)
        order = sorted(range(n), key=lambda i: keyword.upper()[i])
        columns = {}
        idx = 0
        col_len = rows
        for i in order:
            columns[i] = ciphertext[idx:idx + col_len]
            idx += col_len
        substituted = ''.join(columns[i][r] for r in range(col_len) for i in range(n))
        if trim_padding:
            substituted = substituted.rstrip("X")
        plaintext = ""
        for i in range(0, len(substituted), 2):
            pair = substituted[i:i + 2]
            if pair in rev_table:
                plaintext += rev_table[pair]
        return plaintext
    except Exception as e:
        return f"error: {e}"