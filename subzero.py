#!/usr/bin/env python3
from __future__ import annotations
import argparse
import sys
from typing import Callable, Dict, List, Optional, Type
from dataclasses import dataclass
import os
from rich.console import Console
from rich.panel import Panel
import hashlib
from passlib import hash as passlib_hash

from crypto import encodings as enc, hashes as hsh, classic as cls, symmetric as sym, asymmetric as asym
from utils import conversions as conv, text_transforms as txtf
from attack.caesar_brute import caesar_brute
from attack.vigenere_brute import vigenere_brute
from attack.hash_brute import hash_brute
from attack.zip_brute import zip_brute
from attack.pdf_brute import pdf_brute

console = Console()

BANNER = r"""
   _____       __ _____                 
  / ___/__  __/ //__  /  ___  _________ 
  \__ \/ / / / __ \/ /  / _ \/ ___/ __ \
 ___/ / /_/ / /_/ / /__/  __/ /  / /_/ /
/____/\__,_/_.___/____/\___/_/   \____/ 
                        - Kur0Sh1r0
"""

# Supported passlib schemes
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

@dataclass
class Command:
    """Represents a command with its execution function and properties."""
    func: Callable
    chainable: bool
    min_args: int = 0
    max_args: int = 0
    arg_types: List[Type] = None
    arg_names: List[str] = None
    takes_input: bool = True

class SubzeroError(Exception):
    """Custom exception for Subzero errors."""
    pass

class CommandRegistry:
    """Registry for managing and executing commands."""
    def __init__(self):
        self.commands: Dict[str, Command] = {}
        self._register_commands()

    def register(self, name: str, func: Callable, chainable: bool = True, 
                min_args: int = 0, max_args: int = 0, 
                arg_types: List[Type] = None, arg_names: List[str] = None,
                takes_input: bool = True):
        """Register a new command."""
        self.commands[name] = Command(
            func=func, 
            chainable=chainable, 
            min_args=min_args, 
            max_args=max_args,
            arg_types=arg_types or [str] * max_args,
            arg_names=arg_names or [f"arg{i+1}" for i in range(max_args)],
            takes_input=takes_input
        )

    def execute(self, cmd_full: str, input_text: str) -> str:
        """Execute a command with given input."""
        cmd_parts = cmd_full.split(':')
        cmd_name = cmd_parts[0].replace("hash_brute.", "hash_brute_")
        args = cmd_parts[1:]

        if cmd_name not in self.commands:
            raise SubzeroError(f"Unknown command: {cmd_name}")

        cmd = self.commands[cmd_name]
        
        if len(args) < cmd.min_args or len(args) > cmd.max_args:
            raise SubzeroError(
                f"{cmd_name} requires {cmd.min_args} to {cmd.max_args} args: "
                f"{', '.join(cmd.arg_names)}"
            )

        try:
            # Convert args to appropriate types
            converted_args = []
            for arg, arg_type in zip(args, cmd.arg_types or []):
                try:
                    converted_args.append(arg_type(arg))
                except ValueError:
                    raise SubzeroError(f"Invalid {arg_type.__name__} for {cmd_name}")

            # Execute command
            if converted_args:
                if cmd.takes_input:
                    return cmd.func(input_text, *converted_args)
                else:
                    return cmd.func(*converted_args)
            else:
                if cmd.takes_input:
                    return cmd.func(input_text)
                else:
                    return cmd.func()
        except Exception as e:
            raise SubzeroError(f"Error in {cmd_name}: {str(e)}")

    def _register_commands(self):
        """Register all supported commands."""
        # Encodings
        self.register("b32e", enc.b32e, chainable=True)
        self.register("b32d", enc.b32d, chainable=True)
        self.register("b64e", enc.b64e, chainable=True)
        self.register("b64d", enc.b64d, chainable=True)
        self.register("b85e", enc.b85e, chainable=True)
        self.register("b85d", enc.b85d, chainable=True)
        self.register("hex_encode", enc.hex_encode, chainable=True)
        self.register("hex_decode", enc.hex_decode, chainable=True)
        self.register("url_encode", enc.url_encode, chainable=True)
        self.register("url_decode", enc.url_decode, chainable=True)

        # Classic ciphers
        self.register("rot5", cls.rot5, chainable=True)
        self.register("rot13", cls.rot13, chainable=True)
        self.register("rot18", cls.rot18, chainable=True)
        self.register("rot47", cls.rot47, chainable=True)
        self.register("caesar_encode", cls.caesar_encode, chainable=True, min_args=1, max_args=1, 
                     arg_types=[int], arg_names=["shift"])
        self.register("caesar_decode", cls.caesar_decode, chainable=True, min_args=1, max_args=1, 
                     arg_types=[int], arg_names=["shift"])
        self.register("vigenere_encode", cls.vigenere_encode, chainable=True, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["key"])
        self.register("vigenere_decode", cls.vigenere_decode, chainable=True, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["key"])
        self.register("substitution_encode", cls.substitution_encode, chainable=True, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["key"])
        self.register("substitution_decode", cls.substitution_decode, chainable=True, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["key"])
        self.register("xor", cls.xor_cipher, chainable=True, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["key"])
        self.register("bacon_encode", cls.bacon_encode, chainable=True, min_args=0, max_args=2, 
                     arg_types=[str, str], arg_names=["letter1", "letter2"])
        self.register("bacon_decode", cls.bacon_decode, chainable=True, min_args=0, max_args=2, 
                     arg_types=[str, str], arg_names=["letter1", "letter2"])
        self.register("a1z26_encode", cls.a1z26_encode, chainable=True, min_args=0, max_args=1, 
                     arg_types=[str], arg_names=["separator"])
        self.register("a1z26_decode", cls.a1z26_decode, chainable=True, min_args=0, max_args=1, 
                     arg_types=[str], arg_names=["separator"])
        self.register("brainfuck_encode", cls.bf_encode, chainable=True)
        self.register("brainfuck_decode", cls.bf_decode, chainable=True)
        self.register("rail_fence_encode", cls.rail_fence_encode, chainable=True, min_args=1, max_args=2, 
                     arg_types=[int, int], arg_names=["key", "offset"])
        self.register("rail_fence_decode", cls.rail_fence_decode, chainable=True, min_args=1, max_args=2, 
                     arg_types=[int, int], arg_names=["key", "offset"])
        self.register("adfgx_encode", cls.adfgx_encode, chainable=True, min_args=1, max_args=2, 
                     arg_types=[str, str], arg_names=["keyword", "key_square"])
        self.register("adfgx_decode", cls.adfgx_decode, chainable=True, min_args=1, max_args=2, 
                     arg_types=[str, str], arg_names=["keyword", "key_square"])

        # Conversions
        self.register("asc2morse", conv.asc_to_morse, chainable=True)
        self.register("morse2asc", conv.morse_to_asc, chainable=True)
        self.register("morse2wav", conv.morse_to_wav, chainable=True, min_args=0, max_args=4, 
                     arg_types=[str, int, int, float], 
                     arg_names=["filename", "frequency", "sample_rate", "dot_duration"])
        self.register("wav2morse", conv.wav_to_morse, chainable=False, min_args=1, max_args=2, 
                     arg_types=[str, float], arg_names=["filename", "dot_duration"], takes_input=False)
        self.register("asc2nato", conv.asc_to_nato, chainable=True)
        self.register("nato2asc", conv.nato_to_asc, chainable=True)
        self.register("asc2bin", conv.ascii_to_bin, chainable=True)
        self.register("bin2asc", conv.bin_to_ascii, chainable=True)
        self.register("asc2hex", conv.ascii_to_hex, chainable=True)
        self.register("hex2asc", conv.hex_to_ascii, chainable=True)
        self.register("asc2dec", conv.ascii_to_dec, chainable=True)
        self.register("dec2asc", conv.dec_to_ascii, chainable=True)
        self.register("bin2hex", conv.bin_to_hex, chainable=True)
        self.register("hex2bin", conv.hex_to_bin, chainable=True)
        self.register("asc2oct", conv.ascii_to_oct, chainable=True)
        self.register("oct2asc", conv.oct_to_ascii, chainable=True)
        self.register("bin2oct", conv.bin_to_oct, chainable=True)
        self.register("oct2bin", conv.oct_to_bin, chainable=True)
        self.register("hex2oct", conv.hex_to_oct, chainable=True)
        self.register("oct2hex", conv.oct_to_hex, chainable=True)
        self.register("dec2oct", conv.dec_to_oct, chainable=True)
        self.register("oct2dec", conv.oct_to_dec, chainable=True)

        # Text manipulation
        self.register("replace", txtf.replace_text, chainable=True, min_args=2, max_args=2, 
                     arg_types=[str, str], arg_names=["find", "replace"])
        self.register("reverse_char", txtf.reverse_by_char, chainable=True)
        self.register("reverse_byte", txtf.reverse_by_byte, chainable=True)
        self.register("reverse_line", txtf.reverse_by_line, chainable=True)
        self.register("upper", txtf.to_upper, chainable=True)
        self.register("lower", txtf.to_lower, chainable=True)
        self.register("capitalize", txtf.to_capitalize, chainable=True)
        self.register("alternating", txtf.to_alternating, chainable=True)
        self.register("inverse", txtf.to_inverse, chainable=True)

        # Symmetric encryption
        self.register("generate_salt", sym.generate_salt, chainable=True, takes_input=False)
        self.register("fernet_key", sym.generate_fernet_key, chainable=True, min_args=0, max_args=2, 
                     arg_types=[str, str], arg_names=["password", "salt"], takes_input=False)
        self.register("fernet_encrypt", sym.fernet_encrypt, chainable=True, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["key"])
        self.register("fernet_decrypt", sym.fernet_decrypt, chainable=True, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["key"])
        self.register("aes_key", sym.aes_key, chainable=True, min_args=0, max_args=3, 
                     arg_types=[str, str, int], arg_names=["password", "salt", "key_length"], takes_input=False)
        self.register("aes_encrypt", sym.aes_encrypt, chainable=True, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["key"])
        self.register("aes_decrypt", sym.aes_decrypt, chainable=True, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["key"])
        self.register("des_key", sym.des_key, chainable=True, min_args=0, max_args=2, 
                     arg_types=[str, str], arg_names=["password", "salt"], takes_input=False)
        self.register("des_encrypt", sym.des_encrypt, chainable=True, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["key"])
        self.register("des_decrypt", sym.des_decrypt, chainable=True, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["key"])
        self.register("chacha20_key", sym.chacha20_key, chainable=True, min_args=0, max_args=2, 
                     arg_types=[str, str], arg_names=["password", "salt"], takes_input=False)
        self.register("chacha20_encrypt", sym.chacha20_encrypt, chainable=True, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["key"])
        self.register("chacha20_decrypt", sym.chacha20_decrypt, chainable=True, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["key"])
        self.register("camellia_key", sym.camellia_key, chainable=True, min_args=0, max_args=3, 
                     arg_types=[str, str, int], arg_names=["password", "salt", "key_length"], takes_input=False)
        self.register("camellia_encrypt", sym.camellia_encrypt, chainable=True, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["key"])
        self.register("camellia_decrypt", sym.camellia_decrypt, chainable=True, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["key"])

        # Asymmetric encryption
        self.register("rsa_key", asym.rsa_key, chainable=True, takes_input=False)
        self.register("rsa_encrypt", asym.rsa_encrypt, chainable=True, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["key"])
        self.register("rsa_decrypt", asym.rsa_decrypt, chainable=True, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["key"])
        self.register("rsa_sign", asym.rsa_sign, chainable=True, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["key"])
        self.register("rsa_verify", asym.rsa_verify, chainable=True, min_args=2, max_args=2, 
                     arg_types=[str, str], arg_names=["key", "signature"])
        self.register("ecdsa_key", asym.ecdsa_key, chainable=True, takes_input=False)
        self.register("ecdsa_sign", asym.ecdsa_sign, chainable=True, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["key"])
        self.register("ecdsa_verify", asym.ecdsa_verify, chainable=True, min_args=2, max_args=2, 
                     arg_types=[str, str], arg_names=["key", "signature"])
        self.register("ecdh_key", asym.ecdh_key, chainable=True, takes_input=False)
        self.register("ecdh_derive", asym.ecdh_derive, chainable=True, min_args=2, max_args=3, 
                     arg_types=[str, str, str], arg_names=["private_key", "public_key", "salt"])
        self.register("dsa_key", asym.dsa_key, chainable=True, takes_input=False)
        self.register("dsa_sign", asym.dsa_sign, chainable=True, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["key"])
        self.register("dsa_verify", asym.dsa_verify, chainable=True, min_args=2, max_args=2, 
                     arg_types=[str, str], arg_names=["key", "signature"])

        # Hashing
        for algo in hashlib.algorithms_available:
            self.register(f"hash_{algo}", lambda txt, a=algo: hsh.__dict__[f"hash_{a}"](txt), chainable=True)
            self.register(f"hash_brute_{algo}", lambda th, wl, a=algo: hash_brute(th, wl, a), 
                         chainable=False, min_args=1, max_args=1, arg_types=[str], arg_names=["wordlist"])

        for scheme in PASSLIB_SCHEMES:
            if scheme == "htdigest":
                self.register(f"hash_{scheme}", lambda txt, user, realm, s=scheme: hsh.__dict__[f"hash_{s}"](txt, user, realm),
                             chainable=True, min_args=2, max_args=2, arg_types=[str, str], 
                             arg_names=["user", "realm"])
                self.register(f"hash_brute_{scheme}", 
                             lambda th, wl, user, realm, s=scheme: hash_brute(th, wl, s, user, realm),
                             chainable=False, min_args=3, max_args=3, arg_types=[str, str, str], 
                             arg_names=["wordlist", "user", "realm"])
            elif scheme in ("msdcc", "msdcc2"):
                self.register(f"hash_{scheme}", lambda txt, user, s=scheme: hsh.__dict__[f"hash_{s}"](txt, user),
                             chainable=True, min_args=1, max_args=1, arg_types=[str], arg_names=["user"])
                self.register(f"hash_brute_{scheme}", 
                             lambda th, wl, user, s=scheme: hash_brute(th, wl, s, user),
                             chainable=False, min_args=2, max_args=2, arg_types=[str, str], 
                             arg_names=["wordlist", "user"])
            else:
                self.register(f"hash_{scheme}", lambda txt, s=scheme: hsh.__dict__[f"hash_{s}"](txt), chainable=True)
                self.register(f"hash_brute_{scheme}", lambda th, wl, s=scheme: hash_brute(th, wl, s),
                             chainable=False, min_args=1, max_args=1, arg_types=[str], arg_names=["wordlist"])

        # Brute force
        self.register("caesar_brute", caesar_brute, chainable=False, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["range"])
        self.register("vigenere_brute", vigenere_brute, chainable=False, min_args=1, max_args=1, 
                     arg_types=[str], arg_names=["wordlist"])
        self.register("zip_brute", zip_brute, chainable=False, min_args=2, max_args=2, 
                     arg_types=[str, str], arg_names=["wordlist", "zip_file"], takes_input=False)
        self.register("pdf_brute", pdf_brute, chainable=False, min_args=2, max_args=2, 
                     arg_types=[str, str], arg_names=["wordlist", "pdf_file"], takes_input=False)

        # Help command
        self.register("help_full", self._help_command, chainable=False, takes_input=False)

    def _help_command(self) -> str:
        """Generate help text for all commands."""
        chainable = sorted(k for k, v in self.commands.items() if v.chainable)
        non_chainable = sorted(k for k, v in self.commands.items() if not v.chainable)
        help_text = (
            "SUBZERO Command List\n"
            "===================\n\n"
            "Chainable Commands:\n" +
            "\n".join(f"- {cmd}" for cmd in chainable) +
            "\n\nNon-Chainable Commands:\n" +
            "\n".join(f"- {cmd}" for cmd in non_chainable) +
            "\n\nUse 'subzero <command> <input>' to execute a command. "
            "Chain commands with commas, e.g., 'subzero b64e,caesar_encode:3 <input>'. "
            "See 'subzero' for usage examples."
        )
        return help_text

def process_commands(commands: str, input_text: str, input_file: Optional[str], 
                    output_file: Optional[str], registry: CommandRegistry) -> int:
    """Process a sequence of commands."""
    try:
        if input_file:
            if not os.path.exists(input_file):
                console.print(f"[red]Error: Input file {input_file} does not exist[/red]")
                return 2
            with open(input_file, 'r') as f:
                input_text = f.read().strip()

        cmd_list = commands.split(',')
        if not cmd_list or any(not cmd for cmd in cmd_list):
            console.print("[red]Error: Empty command[/red]")
            return 2

        result = input_text
        for cmd in cmd_list:
            cmd_name = cmd.split(':')[0].replace("hash_brute.", "hash_brute_")
            if cmd_name not in registry.commands:
                console.print(f"[red]Error: Unknown command: {cmd_name}[/red]")
                return 2
            if not registry.commands[cmd_name].chainable and len(cmd_list) > 1:
                console.print(f"[red]Error: {cmd_name} is not chainable[/red]")
                return 2
            result = registry.execute(cmd, result)

        console.print(Panel(result, title="[green]Result[/green]", border_style="cyan"))
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(result)
        return 0

    except SubzeroError as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        return 1
    except Exception as e:
        console.print(f"[red]Unexpected error: {str(e)}[/red]")
        return 1

def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    p = argparse.ArgumentParser(
        prog="subzero", 
        description="SUBZERO — CyberChef-like CLI for crypto operations",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument(
        "commands",
        help="Comma-separated commands (e.g., b64e,caesar_encode:3) or single command "
             "(e.g., hash_brute_bcrypt:wordlist.txt). Supports all passlib hash schemes. "
             "For hashes with $, use single quotes or escape (e.g., '\\$2b\\$...'). "
             "Use help_full to list all commands."
    )
    p.add_argument(
        "input",
        nargs='?',
        default="",
        help="Input text or file path for decoding/decrypting"
    )
    p.add_argument("-f", "--file", help="Input file for decoding/decrypting")
    p.add_argument("-o", "--output", help="Output file to save result")
    return p

def main(argv: Optional[List[str]] = None) -> int:
    """Main entrypoint for SUBZERO CLI."""
    argv = argv if argv is not None else sys.argv[1:]
    registry = CommandRegistry()

    if not argv:
        print(BANNER)
        print("\n[+] Run 'subzero help_full' to see the full command list.")
        return 0

    parser = build_parser()
    args = parser.parse_args(argv)
    return process_commands(args.commands, args.input, args.file, args.output, registry)

if __name__ == "__main__":
    raise SystemExit(main())