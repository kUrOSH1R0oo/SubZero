import pikepdf
import os

def pdf_brute(pdf_path: str, wordlist_path: str) -> str:
    if not os.path.exists(pdf_path):
        raise ValueError(f"PDF file {pdf_path} does not exist")
    if not os.path.exists(wordlist_path):
        raise ValueError(f"Wordlist file {wordlist_path} does not exist")
    
    print("Starting PDF password brute-force...")
    print("-" * 50)
    
    try:
        with open(wordlist_path, 'r', encoding='latin-1') as f:
            words = [line.rstrip('\n') for line in f if line.rstrip('\n')]
    except UnicodeDecodeError as e:
        raise ValueError(f"Failed to read wordlist {wordlist_path}: {e}. Try converting the wordlist to UTF-8 or another compatible encoding.")
    
    for word in words:
        print(f"Trying: {repr(word)}")
        try:
            with pikepdf.open(pdf_path, password=word) as pdf:
                result = f"Success! Password: {word}"
                print("-" * 50)
                return result
        except pikepdf.PasswordError:
            continue
        except Exception as e:
            print(f"Error with password '{word}': {e}")
            continue
    
    print("-" * 50)
    print("Brute-force complete.")
    return "Password not found in wordlist"