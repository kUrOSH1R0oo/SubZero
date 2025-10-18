import os
import string

def vigenere_brute(ciphertext: str, wordlist_path: str) -> str:
    if not os.path.exists(wordlist_path):
        raise ValueError(f"Wordlist file {wordlist_path} does not exist")
    
    ctext = ciphertext.lower()
    a_ord = ord('a')
    results = []

    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        raw_keys = [line.strip() for line in f if line.strip()]

    for raw_key in raw_keys:
        key = ''.join(ch for ch in raw_key if ch.isalpha()).lower()
        if not key:
            continue

        shifts = [ord(k) - a_ord for k in key]

        decoded_chars = []
        key_index = 0
        for ch in ctext:
            if 'a' <= ch <= 'z':
                shift = shifts[key_index % len(shifts)]
                new_char = chr((ord(ch) - a_ord - shift) % 26 + a_ord)
                decoded_chars.append(new_char)
                key_index += 1
            else:
                decoded_chars.append(ch)

        results.append(f"Key '{key}': {''.join(decoded_chars)}")

    return '\n'.join(results)
