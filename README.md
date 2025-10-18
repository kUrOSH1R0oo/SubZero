# SubZero: Putting the A1S in Your Cryptography Problems

![SUBZERO Banner](https://github.com/kUrOSH1R0oo/SubZero/blob/master/A1S.png)  

## Overview

SubZero is a sleek, command-line interface (CLI) tool designed for performing a wide array of encoding, decoding, hashing, cryptographic operations, text transformations, conversions, and brute-force attacks. Inspired by tools like CyberChef, it provides a modular, chainable command system with rich console output for an engaging user experience. Built in Python, SubZero emphasizes stability, error handling, and flexibility, making it ideal for cybersecurity enthusiasts, developers, and researchers.

Key highlights:
- **Chainable Commands**: Execute multiple operations in sequence (e.g., `b64e,caesar_encode:3`), allowing for complex pipelines in a single invocation.
- **Comprehensive Crypto Support**: Includes classic ciphers, symmetric/asymmetric encryption, hashing (with passlib integration for advanced schemes), and signing/verification with robust key management.
- **Brute-Force Capabilities**: Targeted attack tools for ciphers, hashes, ZIP files, and PDFs using customizable wordlists, with progress indicators and early stopping on success.
- **Conversions and Utilities**: Handle Morse code (including audio generation), phonetic alphabets, base conversions, text reversals, and more, with support for various input formats.
- **Rich UI**: Leverages the `rich` library for colorful panels, banners, progress bars, and detailed error messages to improve usability.
- **Extensible Registry**: Commands are registered dynamically via a central registry, enabling easy additions of new features without modifying core code.
- **Input/Output Versatility**: Supports stdin, direct arguments, file inputs/outputs, and handles large data streams efficiently.

## Features

- **Encodings & Decodings**: Base32, Base64, Base85, Hex, URL encoding/decoding with forgiving error handling (e.g., auto-padding, ignoring invalid characters where possible).
- **Hashing**: Supports all `hashlib` algorithms (e.g., MD5, SHA256) and over 70 passlib schemes (e.g., bcrypt, argon2, PBKDF2), including salt generation and verification. Brute-force support for both.
- **Classic Ciphers**: ROT variants (ROT5, ROT13, ROT18, ROT47), Caesar (with brute-force), Vigenère (with brute-force), Substitution, XOR, Baconian, A1Z26, Brainfuck interpreter, Rail Fence, ADFGX – all with customizable parameters.
- **Symmetric Encryption**: Fernet, AES (CBC mode with PKCS7 padding), DES (CBC), ChaCha20, Camellia. Includes PBKDF2-based key derivation for secure key generation from passwords.
- **Asymmetric Encryption & Signing**: RSA (OAEP encryption, PSS signing), ECDSA/ECDH (NIST P-256 curve for modern security), DSA – with key generation, export in PEM format, and verification.
- **Text Transformations**: Replace, reverse (by char/byte/line), case changes (upper, lower, capitalize, alternating, inverse) – efficient for large texts.
- **Conversions**: ASCII ↔ Binary/Octal/Decimal/Hex, Morse Code (with WAV audio generation using numpy for customizable frequency and duration), NATO/ICAO Phonetic Alphabet.
- **Brute-Force Attacks**: Multi-threaded where applicable for Caesar/Vigenère ciphers, hashes (hashlib/passlib), ZIP archives (standard ZIP encryption), PDF passwords (using pikepdf for efficient cracking).
- **Input/Output Flexibility**: Read from stdin, files (`-f`), or arguments; write to files (`-o`); supports binary data where needed.
- **Error Resilience**: Custom exceptions for graceful failure, safe decoding (e.g., skipping invalid bytes), and verbose error messages with suggestions for fixes.

SUBZERO is designed for educational and testing purposes. **Do not use for illegal activities.** Always comply with local laws regarding cryptography and brute-forcing. Note that brute-force operations can be computationally intensive and should be used responsibly.

## Installation

### Prerequisites
- Python 3.8+ (tested up to 3.12).
- Required libraries:
  - `rich`: For enhanced console UI (banners, panels, tables).
  - `passlib`: For advanced hashing schemes like bcrypt and argon2.
  - `cryptography`: For Fernet encryption and PBKDF2 key derivation.
  - `pycryptodome`: For AES, DES, ChaCha20, RSA, ECC, DSA implementations.
  - `pikepdf`: For PDF brute-forcing.
  - `python-camellia`: For Camellia cipher support.
  - `numpy`: For audio generation in Morse-to-WAV conversions.

These are installed automatically via the setup script.

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/Kur0Sh1r0/subzero.git
   cd subzero
   ```

2. Execute the installation script as root (installs dependencies and sets up CLI entry point):
   ```bash
   sudo ./install.sh
   ```

3. Verify installation and access help:
   ```bash
   subzero -h
   ```

If issues arise, ensure Python is in your PATH and try running `python -m pip install -r requirements.txt` manually.

## Usage

### Basic Syntax
```
subzero [commands] [input] [-f input_file] [-o output_file] [-h/--help]
```

- **commands**: Comma-separated chain of operations (e.g., `b64e,caesar_encode:3`). Use `:` to separate command from arguments (e.g., `caesar_encode:3` for shift=3). Multiple args use additional `:` (e.g., `replace_text:old:new`).
- **input**: The text or data to process. If omitted, reads from stdin. For file-based inputs, use `-f`.
- **-f/--file**: Read input from a specified file (supports text and binary files).
- **-o/--output**: Save the final result to a file (overwrites if exists; supports binary output where applicable).
- **-h/--help**: Display basic usage help. For full command list, use `subzero help_full`.
- No arguments: Displays the tool's banner and version info.

Special notes:
- For inputs with special characters (e.g., `$` in hashes), escape them or enclose in quotes: `subzero hash_bcrypt '\$2b\$...'`.
- Binary data is handled automatically for relevant commands (e.g., encryption outputs).
- Chaining is limited to compatible commands (see tables below); non-chainable commands must be run solo.

### Chaining Commands
Chainable commands can be sequenced for multi-step processing: `subzero b64e,hex_encode "hello"`. This applies each operation to the output of the previous one. Non-chainable commands (e.g., brute-force attacks) cannot be chained and must be used independently to avoid conflicts.

### Examples

1. **Basic Encoding**:
   ```
   subzero b64e "Hello, World!"
   ```
   Output: `SGVsbG8sIFdvcmxkIQ==` (displayed in a rich panel).

2. **Chained Operations**:
   ```
   subzero b64e,caesar_encode:3 "Hello"
   ```
   Output: `VKhoo` (Base64 encoded first, then Caesar shifted).

3. **Hashing**:
   ```
   subzero hash_sha256 "password"
   ```
   Output: `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8`

   For passlib schemes (with random salt):
   ```
   subzero hash_bcrypt "password"
   ```
   Output: `$2b$12$<random_salt_and_hash>` (exact output varies due to salt).

4. **Brute-Force** (Non-Chainable)**:
   ```
   subzero hash_brute_sha256:target_hash:wordlist.txt
   ```
   Attempts passwords from wordlist.txt until match or exhaustion.

   ```
   subzero caesar_brute:1-25 "Khoor"
   ```
   Tries shifts 1-25 and lists possible plaintexts.

   ```
   subzero vigenere_brute:wordlist.txt "ciphertext"
   ```
   Tests keys from wordlist.

   ```
   subzero zip_brute:file.zip:wordlist.txt
   ```
   Brute-forces ZIP password.

   ```
   subzero pdf_brute:file.pdf:wordlist.txt
   ```
   Brute-forces PDF password.

5. **Symmetric Encryption**:
   ```
   subzero generate_fernet_key "mysecret"
   ```
   Output: Base64-encoded Fernet key derived from password.

   ```
   subzero fernet_encrypt:mykey "secret message"
   ```
   Output: Encrypted token (includes IV and authentication).

6. **Asymmetric Encryption**:
   ```
   subzero rsa_key
   ```
   Output: PEM-formatted private and public keys.

   ```
   subzero rsa_encrypt:publickey "message"
   ```
   Output: Base64-encoded ciphertext.

7. **Conversions**:
   ```
   subzero asc_to_morse "SOS"
   ```
   Output: `... --- ...`

   ```
   subzero morse_to_wav "SOS" output.wav:800:22050:0.1
   ```
   Generates `output.wav` with custom frequency (800 Hz), sample rate (22050), and dot duration (0.1s).

8. **Text Transformations**:
   ```
   subzero to_upper,reverse_by_char "hello"
   ```
   Output: `OLLEH`

9. **File Input/Output**:
   ```
   subzero b64d -f encoded.txt -o decoded.txt
   ```
   Decodes Base64 from encoded.txt and saves to decoded.txt.

10. **Full Help**:
    ```
    subzero help_full
    ```
    Displays a comprehensive list of all commands in a formatted table.

## Command Reference

Commands are categorized by module for clarity. Arguments are specified after the command using `:` separators (e.g., `caesar_encode:3`). For hashes, replace `<algo>` or `<scheme>` with the specific name (e.g., `hash_md5` or `hash_bcrypt`). See the tables below for a complete overview.

### Table 1: Commands and Definitions

| Category          | Command                          | Arguments (Format)                          | Description                                                                 |
|-------------------|----------------------------------|---------------------------------------------|-----------------------------------------------------------------------------|
| Encodings        | b32e                            | None                                        | Base32 encode.                                                              |
| Encodings        | b32d                            | None                                        | Base32 decode (case-insensitive, auto-pads).                                |
| Encodings        | b64e                            | None                                        | Base64 encode.                                                              |
| Encodings        | b64d                            | None                                        | Base64 decode (auto-pads).                                                  |
| Encodings        | b85e                            | None                                        | Base85 encode.                                                              |
| Encodings        | b85d                            | None                                        | Base85 decode.                                                              |
| Encodings        | hex_encode                      | None                                        | Hex encode.                                                                 |
| Encodings        | hex_decode                      | None                                        | Hex decode (ignores spaces).                                                |
| Encodings        | url_encode                      | None                                        | URL encode (percent-encoding).                                              |
| Encodings        | url_decode                      | None                                        | URL decode.                                                                 |
| Hashes           | hash_<algo>                     | None (e.g., hash_md5, hash_sha256)          | Compute hash using hashlib algorithm (supports md5, sha1, sha224, sha256, sha384, sha512, blake2b, blake2s, etc.). |
| Hashes           | hash_<scheme>                   | Optional (e.g., hash_bcrypt; some like htdigest require :user:realm) | Compute hash using passlib scheme (supports over 70, including apr_md5_crypt, argon2, bcrypt, pbkdf2_sha256, etc.; see code for full list). |
| Classic Ciphers  | rot5                            | None                                        | ROT5 (digits only).                                                         |
| Classic Ciphers  | rot13                           | None                                        | ROT13 (letters).                                                            |
| Classic Ciphers  | rot18                           | None                                        | ROT18 (letters + digits).                                                   |
| Classic Ciphers  | rot47                           | None                                        | ROT47 (printable ASCII).                                                    |
| Classic Ciphers  | caesar_encode                   | :shift (int)                                | Caesar encode with specified shift.                                         |
| Classic Ciphers  | caesar_decode                   | :shift (int)                                | Caesar decode with specified shift.                                         |
| Classic Ciphers  | vigenere_encode                 | :key (str)                                  | Vigenère encode with key.                                                   |
| Classic Ciphers  | vigenere_decode                 | :key (str)                                  | Vigenère decode with key.                                                   |
| Classic Ciphers  | sub_encode                      | :alphabet (26-letter str)                   | Substitution encode with custom alphabet.                                   |
| Classic Ciphers  | sub_decode                      | :alphabet (26-letter str)                   | Substitution decode with custom alphabet.                                   |
| Classic Ciphers  | xor_encode                      | :key (hex)                                  | XOR encode with hex key.                                                    |
| Classic Ciphers  | xor_decode                      | :key (hex)                                  | XOR decode with hex key.                                                    |
| Classic Ciphers  | bacon_encode                    | None                                        | Baconian encode.                                                            |
| Classic Ciphers  | bacon_decode                    | None                                        | Baconian decode.                                                            |
| Classic Ciphers  | a1z26_encode                    | None                                        | A1Z26 encode (letters to numbers).                                          |
| Classic Ciphers  | a1z26_decode                    | None                                        | A1Z26 decode (numbers to letters).                                          |
| Classic Ciphers  | brainfuck                       | None (input is code)                        | Brainfuck interpreter.                                                      |
| Classic Ciphers  | rail_encode                     | :key:offset (int key, optional int offset)  | Rail Fence encode.                                                          |
| Classic Ciphers  | rail_decode                     | :key:offset (int key, optional int offset)  | Rail Fence decode.                                                          |
| Classic Ciphers  | adfgx_encode                    | :keyword:key_square (str keyword, optional 25-letter str) | ADFGX encode.                                                               |
| Classic Ciphers  | adfgx_decode                    | :keyword:key_square (str keyword, optional 25-letter str) | ADFGX decode.                                                               |
| Symmetric        | generate_salt                   | None                                        | Generate base64-encoded salt.                                               |
| Symmetric        | generate_fernet_key             | :password:salt (optional str)               | Generate Fernet key (PBKDF2-derived if password provided).                  |
| Symmetric        | fernet_encrypt                  | :key (base64)                               | Fernet encrypt.                                                             |
| Symmetric        | fernet_decrypt                  | :key (base64)                               | Fernet decrypt.                                                             |
| Symmetric        | aes_key                         | :password:salt:length (optional str, int: 128/192/256) | Generate AES key.                                                           |
| Symmetric        | aes_encrypt                     | :key (hex)                                  | AES-CBC encrypt.                                                            |
| Symmetric        | aes_decrypt                     | :key (hex)                                  | AES-CBC decrypt.                                                            |
| Symmetric        | des_key                         | :password:salt (optional str)               | Generate DES key (64-bit).                                                  |
| Symmetric        | des_encrypt                     | :key (hex)                                  | DES-CBC encrypt.                                                            |
| Symmetric        | des_decrypt                     | :key (hex)                                  | DES-CBC decrypt.                                                            |
| Symmetric        | chacha20_key                    | :password:salt (optional str)               | Generate ChaCha20 key (256-bit).                                            |
| Symmetric        | chacha20_encrypt                | :key (hex)                                  | ChaCha20 encrypt.                                                           |
| Symmetric        | chacha20_decrypt                | :key (hex)                                  | ChaCha20 decrypt.                                                           |
| Symmetric        | camellia_key                    | :password:salt:length (optional str, int: 128/192/256) | Generate Camellia key.                                                      |
| Symmetric        | camellia_encrypt                | :key (hex)                                  | Camellia-CBC encrypt.                                                       |
| Symmetric        | camellia_decrypt                | :key (hex)                                  | Camellia-CBC decrypt.                                                       |
| Asymmetric       | rsa_key                         | None                                        | Generate RSA key pair (2048-bit, PEM format).                               |
| Asymmetric       | rsa_encrypt                     | :public_key (PEM)                           | RSA-OAEP encrypt.                                                           |
| Asymmetric       | rsa_decrypt                     | :private_key (PEM)                          | RSA-OAEP decrypt.                                                           |
| Asymmetric       | rsa_sign                        | :private_key (PEM)                          | RSA-PSS sign.                                                               |
| Asymmetric       | rsa_verify                      | :public_key:signature (PEM, base64)         | RSA-PSS verify (returns "valid" or "invalid").                              |
| Asymmetric       | ecdsa_key                       | None                                        | Generate ECDSA key pair (P-256).                                            |
| Asymmetric       | ecdsa_sign                      | :private_key (PEM)                          | ECDSA sign.                                                                 |
| Asymmetric       | ecdsa_verify                    | :public_key:signature (PEM, base64)         | ECDSA verify.                                                               |
| Asymmetric       | ecdh_key                        | None                                        | Generate ECDH key (P-256).                                                  |
| Asymmetric       | ecdh_derive                     | :private_key:public_key:salt (PEM, PEM, optional base64) | Derive shared secret key.                                                   |
| Asymmetric       | dsa_key                         | None                                        | Generate DSA key pair (2048-bit).                                           |
| Asymmetric       | dsa_sign                        | :private_key (PEM)                          | DSA sign.                                                                   |
| Asymmetric       | dsa_verify                      | :public_key:signature (PEM, base64)         | DSA verify.                                                                 |
| Text Transforms  | replace_text                    | :find:replace (str, str)                    | Replace substring.                                                          |
| Text Transforms  | reverse_by_char                 | None                                        | Reverse by characters.                                                      |
| Text Transforms  | reverse_by_byte                 | None                                        | Reverse by bytes (handles non-ASCII).                                       |
| Text Transforms  | reverse_by_line                 | None                                        | Reverse by lines.                                                           |
| Text Transforms  | to_upper                        | None                                        | Convert to uppercase.                                                       |
| Text Transforms  | to_lower                        | None                                        | Convert to lowercase.                                                       |
| Text Transforms  | to_capitalize                   | None                                        | Convert to title case.                                                      |
| Text Transforms  | to_alternating                  | None                                        | Convert to alternating case (e.g., "HeLlO").                                |
| Text Transforms  | to_inverse                      | None                                        | Invert case.                                                                |
| Conversions      | asc_to_morse                    | None                                        | ASCII to Morse code.                                                        |
| Conversions      | morse_to_asc                    | None                                        | Morse code to ASCII.                                                        |
| Conversions      | asc_to_nato                     | None                                        | ASCII to NATO phonetic alphabet.                                            |
| Conversions      | nato_to_asc                     | None                                        | NATO phonetic to ASCII.                                                     |
| Conversions      | morse_to_wav                    | :filename:freq:sample_rate:dot_duration (str, int, int, float) | Generate WAV audio from Morse code.                                         |
| Conversions      | ascii_to_bin                    | None                                        | ASCII to binary.                                                            |
| Conversions      | bin_to_ascii                    | None                                        | Binary to ASCII.                                                            |
| Conversions      | ascii_to_hex                    | None                                        | ASCII to hex.                                                               |
| Conversions      | hex_to_ascii                    | None                                        | Hex to ASCII.                                                               |
| Conversions      | ascii_to_dec                    | None                                        | ASCII to decimal.                                                           |
| Conversions      | dec_to_ascii                    | None                                        | Decimal to ASCII.                                                           |
| Conversions      | bin_to_hex                      | None                                        | Binary to hex.                                                              |
| Conversions      | hex_to_bin                      | None                                        | Hex to binary.                                                              |
| Conversions      | ascii_to_oct                    | None                                        | ASCII to octal.                                                             |
| Conversions      | oct_to_ascii                    | None                                        | Octal to ASCII.                                                             |
| Conversions      | bin_to_oct                      | None                                        | Binary to octal.                                                            |
| Conversions      | oct_to_bin                      | None                                        | Octal to binary.                                                            |
| Conversions      | hex_to_oct                      | None                                        | Hex to octal.                                                               |
| Conversions      | oct_to_hex                      | None                                        | Octal to hex.                                                               |
| Conversions      | dec_to_oct                      | None                                        | Decimal to octal.                                                           |
| Conversions      | oct_to_dec                      | None                                        | Octal to decimal.                                                           |
| Attacks          | caesar_brute                    | :start-end (e.g., 1-25)                     | Brute-force Caesar shifts.                                                  |
| Attacks          | vigenere_brute                  | :wordlist.txt (path)                        | Brute-force Vigenère with wordlist.                                         |
| Attacks          | hashlib_brute_<algo>            | :target_hash:wordlist.txt (str, path)       | Brute-force hashlib hash (e.g., hashlib_brute_sha256).                      |
| Attacks          | hash_brute_<scheme>             | :target_hash:wordlist.txt:user:realm (str, path, optional str) | Brute-force passlib scheme (user/realm for some schemes).                   |
| Attacks          | zip_brute                       | :zip_path:wordlist.txt (path, path)         | Brute-force ZIP password.                                                   |
| Attacks          | pdf_brute                       | :pdf_path:wordlist.txt (path, path)         | Brute-force PDF password.                                                   |
| Utility          | help_full                       | None                                        | List all commands in a formatted table.                                     |

Note: Chainable commands process data sequentially, while unchainable ones (primarily attacks and utilities) perform standalone operations like brute-forcing or listing.

## License

MIT License

Copyright (c) 2025 Kur0Sh1r0

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Acknowledgments

- Inspired by CyberChef for its operation chaining concept.
