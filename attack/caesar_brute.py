import string

def caesar_brute(ciphertext: str, range_str: str) -> str:
    try:
        start, end = map(int, range_str.split('-'))
    except ValueError:
        raise ValueError("Invalid range format, use start-end (e.g., 1-25)")
    
    alphabet = string.ascii_lowercase
    results = []
    low_text = ciphertext.lower()

    for shift in range(start, end + 1):
        trans = {c: alphabet[(i - shift) % 26] for i, c in enumerate(alphabet)}
        decoded = ''.join(trans.get(ch, ch) for ch in low_text)
        results.append(f"Shift {shift:2}: {decoded}")

    return '\n'.join(results)
