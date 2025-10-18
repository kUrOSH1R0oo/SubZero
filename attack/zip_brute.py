import zipfile
import os

def zip_brute(zip_path: str, wordlist_path: str) -> str:
    if not os.path.exists(zip_path):
        raise ValueError(f"Zip file {zip_path} does not exist")
    if not os.path.exists(wordlist_path):
        raise ValueError(f"Wordlist file {wordlist_path} does not exist")
    
    print("Starting ZIP password brute-force...")
    print("-" * 50)
    
    try:
        with open(wordlist_path, 'r', encoding='latin-1') as f:
            words = [line.rstrip('\n') for line in f if line.rstrip('\n')]
    except UnicodeDecodeError as e:
        raise ValueError(f"Failed to read wordlist {wordlist_path}: {e}. Try converting the wordlist to UTF-8 or another compatible encoding.")
    
    z = zipfile.ZipFile(zip_path)
    for word in words:
        print(f"Trying: {repr(word)}")
        try:
            z.extractall(pwd=word.encode('utf-8', errors='ignore'))
            result = f"Success! Password: {word}"
            print("-" * 50)
            return result
        except RuntimeError:
            continue
        except Exception as e:
            raise ValueError(f"Error extracting zip with password '{word}': {e}")
    
    print("-" * 50)
    print("Brute-force complete.")
    return "Password not found in wordlist"