import hashlib
import os
import re
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

HASH_PATTERNS = {
    'argon2': r'^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$',
    'bcrypt': r'^\$(2a|2b)\$\d{2}\$[A-Za-z0-9./]{53}$',
    'bcrypt_sha256': r'^\$(2a|2b)\$\d{2}\$[A-Za-z0-9./]{53}$',
    'md5_crypt': r'^\$1\$[A-Za-z0-9./]{1,8}\$[A-Za-z0-9./]{22}$',
    'sha1_crypt': r'^\$sha1\$\d+\$[A-Za-z0-9+/=]{8}\$[A-Za-z0-9+/=]{28}$',
    'sha256_crypt': r'^\$5\$(rounds=\d+\$)?[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{43}$',
    'sha512_crypt': r'^\$6\$(rounds=\d+\$)?[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{86}$',
    'apr_md5_crypt': r'^\$apr1\$[A-Za-z0-9./]{1,8}\$[A-Za-z0-9./]{22}$',
    'ldap_md5_crypt': r'^\$1\$[A-Za-z0-9./]{1,8}\$[A-Za-z0-9./]{22}$',
    'ldap_sha1_crypt': r'^\$sha1\$\d+\$[A-Za-z0-9+/=]{8}\$[A-Za-z0-9+/=]{28}$',
    'ldap_sha256_crypt': r'^\$5\$(rounds=\d+\$)?[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{43}$',
    'ldap_sha512_crypt': r'^\$6\$(rounds=\d+\$)?[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{86}$',
    'ldap_bcrypt': r'^\$(2a|2b)\$\d{2}\$[A-Za-z0-9./]{53}$',
    'django_bcrypt': r'^bcrypt\$\$(2a|2b)\$\d{2}\$[A-Za-z0-9./]{53}$',
    'django_bcrypt_sha256': r'^bcrypt_sha256\$\$(2a|2b)\$\d{2}\$[A-Za-z0-9./]{53}$',
    'django_argon2': r'^argon2\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$',
    'django_pbkdf2_sha256': r'^pbkdf2_sha256\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$',
    'django_pbkdf2_sha1': r'^pbkdf2_sha1\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$',
    'phpass': r'^\$[PH]\$[A-Za-z0-9./]{8}\$[A-Za-z0-9./]{22}$',
    'scrypt': r'^\$scrypt\$ln=\d+,r=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$',
    'sun_md5_crypt': r'^\$md5\$(rounds=\d+\$)?[A-Za-z0-9./]+\$[A-Za-z0-9./]{22}$',
    'htdigest': r'^[^:]+:[^:]+:[0-9a-fA-F]{32}$',
    'msdcc': r'^[0-9a-fA-F]{32}$',
    'msdcc2': r'^[0-9a-fA-F]{32}$',
}

def hash_brute(target_hash: str, wordlist_path: str, algo: str, user: str | None = None, realm: str | None = None) -> str:
    if not os.path.exists(wordlist_path):
        raise ValueError(f"Wordlist file {wordlist_path} does not exist")
    
    print(f"Starting hash brute-force for {algo}...")
    print(f"Target hash: {target_hash}")
    print("-" * 50)
    
    if algo not in hashlib.algorithms_available and algo not in PASSLIB_SCHEMES:
        raise ValueError(f"Unsupported hash algorithm: {algo}")
    
    if algo in HASH_PATTERNS:
        pattern = HASH_PATTERNS[algo]
        if not re.match(pattern, target_hash):
            raise ValueError(f"Invalid {algo} hash: {target_hash}. Must match expected format (e.g., for {algo}, use '{pattern}'). For htdigest, ensure format is user:realm:md5hash.")
    
    if algo == "htdigest" and (user is None or realm is None):
        raise ValueError(f"{algo} requires user and realm parameters")
    if algo in ("msdcc", "msdcc2") and user is None:
        raise ValueError(f"{algo} requires user parameter")
    
    if not PASSLIB_AVAILABLE and algo in PASSLIB_SCHEMES:
        raise ValueError(f"Passlib not installed, cannot use {algo}")
    
    with open(wordlist_path, 'r', encoding='utf-8') as f:
        words = [line.rstrip('\r\n').strip() for line in f if line.strip()]
    
    if algo in hashlib.algorithms_available:
        for word in words:
            print(f"Trying: {word}")
            hash_obj = hashlib.new(algo)
            hash_obj.update(word.encode('utf-8'))
            computed_hash = hash_obj.hexdigest()
            if computed_hash == target_hash:
                result = f"Success! Password: {word}"
                print("-" * 50)
                return result
    else:
        handler = get_crypt_handler(algo)
        if not handler:
            raise ValueError(f"Passlib hash function for {algo} not found")
        for word in words:
            print(f"Trying: {word}")
            try:
                if algo == "htdigest":
                    computed_hash = handler.hash(word, user=user, realm=realm)
                    computed_md5 = computed_hash.split(':')[-1]
                    target_md5 = target_hash.split(':')[-1]
                    if computed_md5 == target_md5:
                        result = f"Success! Password: {word}"
                        print("-" * 50)
                        return result
                elif algo in ("msdcc", "msdcc2"):
                    if handler.verify(word, target_hash, user=user):
                        result = f"Success! Password: {word}"
                        print("-" * 50)
                        return result
                else:
                    if handler.verify(word, target_hash):
                        result = f"Success! Password: {word}"
                        print("-" * 50)
                        return result
            except ValueError as e:
                if "malformed" in str(e).lower() or "not a valid" in str(e).lower():
                    raise ValueError(f"Invalid {algo} hash: {target_hash}. Ensure the hash is valid and properly formatted (e.g., for {algo}, use '{HASH_PATTERNS.get(algo, 'valid format')}').")
                print(f"Error verifying '{word}': {e}")
                continue
    
    print("-" * 50)
    print("Brute-force complete.")
    return "Password not found in wordlist"