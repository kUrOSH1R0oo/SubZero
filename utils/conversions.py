#!/usr/bin/env python3
"""Conversions between ASCII, binary, octal, decimal, hexadecimal, Morse code, and NATO/ICAO phonetic."""

from __future__ import annotations
from typing import Iterable
import math
import struct
import wave
import numpy as np

MORSE_CODE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    ' ': '/'
}

NATO_CODE = {
    'A': 'Alpha', 'B': 'Bravo', 'C': 'Charlie', 'D': 'Delta', 'E': 'Echo',
    'F': 'Foxtrot', 'G': 'Golf', 'H': 'Hotel', 'I': 'India', 'J': 'Juliett',
    'K': 'Kilo', 'L': 'Lima', 'M': 'Mike', 'N': 'November', 'O': 'Oscar',
    'P': 'Papa', 'Q': 'Quebec', 'R': 'Romeo', 'S': 'Sierra', 'T': 'Tango',
    'U': 'Uniform', 'V': 'Victor', 'W': 'Whiskey', 'X': 'Xray', 'Y': 'Yankee',
    'Z': 'Zulu',
    '0': 'Zero', '1': 'One', '2': 'Two', '3': 'Three', '4': 'Four',
    '5': 'Five', '6': 'Six', '7': 'Seven', '8': 'Eight', '9': 'Niner'
}

def asc_to_morse(text: str) -> str:
    try:
        text = text.upper()
        out = []
        for c in text:
            if c in MORSE_CODE:
                out.append(MORSE_CODE[c])
            else:
                out.append(c)
        return ' '.join(out)
    except Exception as e:
        return f"error: {e}"

def morse_to_asc(morse: str) -> str:
    try:
        reverse = {v: k for k, v in MORSE_CODE.items()}
        toks = morse.strip().split()
        out = []
        for t in toks:
            if t in reverse:
                out.append(reverse[t])
            else:
                out.append('?')
        return ''.join(out)
    except Exception as e:
        return f"error: {e}"

def asc_to_nato(text: str) -> str:
    try:
        text = text.upper()
        out = []
        for c in text:
            if c in NATO_CODE:
                out.append(NATO_CODE[c])
            else:
                out.append(c)
        return ' '.join(out)
    except Exception as e:
        return f"error: {e}"

def nato_to_asc(nato: str) -> str:
    try:
        reverse = {v.lower(): k for k, v in NATO_CODE.items()}
        toks = nato.strip().split()
        out = []
        for t in toks:
            t_lower = t.lower()
            if t_lower in reverse:
                out.append(reverse[t_lower])
            else:
                out.append('?')
        return ''.join(out)
    except Exception as e:
        return f"error: {e}"

def morse_to_wav(text: str, filename: str = 'output.wav', freq: int = 800, sample_rate: int = 44100, dot_duration: float = 0.1) -> str:
    try:
        morse = asc_to_morse(text)
        if morse.startswith("error:"):
            return morse
        frames = []
        char_space = dot_duration * 3
        word_space = dot_duration * 7
        intra_char_gap = dot_duration
        fade_samples = int(sample_rate * 0.01)
        for symbol in morse:
            if symbol == '.':
                duration = dot_duration
                tone = generate_tone(freq, duration, sample_rate, fade_samples)
                frames.extend(tone)
                frames.extend(generate_silence(intra_char_gap, sample_rate))
            elif symbol == '-':
                duration = dot_duration * 3
                tone = generate_tone(freq, duration, sample_rate, fade_samples)
                frames.extend(tone)
                frames.extend(generate_silence(intra_char_gap, sample_rate))
            elif symbol == ' ':
                frames.extend(generate_silence(char_space - intra_char_gap, sample_rate))
            elif symbol == '/':
                frames.extend(generate_silence(word_space - intra_char_gap, sample_rate))
            else:
                frames.extend(generate_silence(dot_duration, sample_rate))
        with wave.open(filename, 'wb') as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(sample_rate)
            wav_file.writeframes(b''.join(frames))
        return f"WAV saved to {filename}"
    except Exception as e:
        return f"error: {e}"

def wav_to_morse(filename: str, freq: int = 800, sample_rate: int = 44100, dot_duration: float = 0.1) -> str:
    try:
        with wave.open(filename, 'rb') as wav_file:
            if wav_file.getnchannels() != 1 or wav_file.getsampwidth() != 2 or wav_file.getframerate() != sample_rate:
                return "error: WAV must be mono, 16-bit, 44100 Hz"
            frames = wav_file.readframes(wav_file.getnframes())
            samples = np.frombuffer(frames, dtype=np.int16)
        window_size = int(sample_rate * 0.02)
        envelope = np.abs(samples)
        envelope = np.convolve(envelope, np.ones(window_size)/window_size, mode='same')
        threshold = np.max(envelope) * 0.1
        dot_samples = int(dot_duration * sample_rate)
        dash_samples = int(dot_duration * 3 * sample_rate)
        intra_char_samples = int(dot_duration * sample_rate)
        char_space_samples = int(dot_duration * 3 * sample_rate)
        word_space_samples = int(dot_duration * 7 * sample_rate)
        tolerance = int(dot_duration * sample_rate * 0.3)
        morse = []
        i = 0
        while i < len(envelope):
            if envelope[i] > threshold:
                tone_start = i
                while i < len(envelope) and envelope[i] > threshold:
                    i += 1
                tone_length = i - tone_start
                if abs(tone_length - dot_samples) < abs(tone_length - dash_samples) + tolerance:
                    morse.append('.')
                else:
                    morse.append('-')
                gap_start = i
                while i < len(envelope) and envelope[i] <= threshold:
                    i += 1
                gap_length = i - gap_start
                if gap_length > char_space_samples - tolerance:
                    morse.append(' ')
                if gap_length > word_space_samples - tolerance:
                    morse.append('/')
            else:
                i += 1
        morse_str = ''.join(morse).strip()
        return morse_to_asc(morse_str)
    except Exception as e:
        return f"error: {e}"

def generate_tone(freq: int, duration: float, sample_rate: int, fade_samples: int = 0):
    num_samples = int(sample_rate * duration)
    frames = []
    for i in range(num_samples):
        amplitude = 32767.0
        if fade_samples > 0:
            if i < fade_samples:
                amplitude *= i / fade_samples
            elif i >= num_samples - fade_samples:
                amplitude *= (num_samples - i) / fade_samples
        value = int(amplitude * math.sin(2 * math.pi * freq * i / sample_rate))
        frames.append(struct.pack('h', value))
    return frames

def generate_silence(duration: float, sample_rate: int):
    num_samples = int(sample_rate * duration)
    return [struct.pack('h', 0)] * num_samples

def ascii_to_bin(text: str) -> str:
    try:
        return " ".join(f"{ord(c):08b}" for c in text)
    except Exception as e:
        return f"error: {e}"

def bin_to_ascii(bits: str) -> str:
    toks = bits.strip().split()
    out = []
    for t in toks:
        try:
            out.append(chr(int(t, 2)))
        except Exception:
            out.append("?")
    return "".join(out)

def ascii_to_hex(text: str) -> str:
    try:
        return "".join(f"{ord(c):02x}" for c in text)
    except Exception as e:
        return f"error: {e}"

def hex_to_ascii(h: str) -> str:
    s = h.strip().replace(" ", "")
    if len(s) % 2 != 0:
        s = "0" + s
    out = []
    for i in range(0, len(s), 2):
        try:
            out.append(chr(int(s[i:i+2], 16)))
        except Exception:
            out.append("?")
    return "".join(out)

def ascii_to_dec(text: str) -> str:
    try:
        return " ".join(f"{ord(c)}" for c in text)
    except Exception as e:
        return f"error: {e}"

def dec_to_ascii(dec: str) -> str:
    toks = dec.strip().split()
    out = []
    for t in toks:
        try:
            num = int(t)
            if 0 <= num <= 127:
                out.append(chr(num))
            else:
                out.append("?")
        except Exception:
            out.append("?")
    return "".join(out)

def bin_to_hex(bits: str) -> str:
    try:
        toks = bits.strip().split()
        hex_vals = []
        for t in toks:
            num = int(t, 2)
            hex_vals.append(f"{num:02x}")
        return "".join(hex_vals)
    except Exception as e:
        return f"error: {e}"

def hex_to_bin(h: str) -> str:
    try:
        s = h.strip().replace(" ", "")
        if len(s) % 2 != 0:
            s = "0" + s
        bin_vals = []
        for i in range(0, len(s), 2):
            num = int(s[i:i+2], 16)
            bin_vals.append(f"{num:08b}")
        return " ".join(bin_vals)
    except Exception as e:
        return f"error: {e}"

def ascii_to_oct(text: str) -> str:
    try:
        return " ".join(f"{ord(c):03o}" for c in text)
    except Exception as e:
        return f"error: {e}"

def oct_to_ascii(oct: str) -> str:
    toks = oct.strip().split()
    out = []
    for t in toks:
        try:
            num = int(t, 8)
            if 0 <= num <= 127:
                out.append(chr(num))
            else:
                out.append("?")
        except Exception:
            out.append("?")
    return "".join(out)

def bin_to_oct(bits: str) -> str:
    try:
        toks = bits.strip().split()
        oct_vals = []
        for t in toks:
            num = int(t, 2)
            oct_vals.append(f"{num:03o}")
        return " ".join(oct_vals)
    except Exception as e:
        return f"error: {e}"

def oct_to_bin(oct: str) -> str:
    try:
        toks = oct.strip().split()
        bin_vals = []
        for t in toks:
            num = int(t, 8)
            bin_vals.append(f"{num:08b}")
        return " ".join(bin_vals)
    except Exception as e:
        return f"error: {e}"

def hex_to_oct(h: str) -> str:
    try:
        s = h.strip().replace(" ", "")
        if len(s) % 2 != 0:
            s = "0" + s
        oct_vals = []
        for i in range(0, len(s), 2):
            num = int(s[i:i+2], 16)
            oct_vals.append(f"{num:03o}")
        return " ".join(oct_vals)
    except Exception as e:
        return f"error: {e}"

def oct_to_hex(oct: str) -> str:
    try:
        toks = oct.strip().split()
        hex_vals = []
        for t in toks:
            num = int(t, 8)
            hex_vals.append(f"{num:02x}")
        return "".join(hex_vals)
    except Exception as e:
        return f"error: {e}"

def dec_to_oct(dec: str) -> str:
    try:
        toks = dec.strip().split()
        oct_vals = []
        for t in toks:
            num = int(t)
            oct_vals.append(f"{num:03o}")
        return " ".join(oct_vals)
    except Exception as e:
        return f"error: {e}"

def oct_to_dec(oct: str) -> str:
    try:
        toks = oct.strip().split()
        dec_vals = []
        for t in toks:
            num = int(t, 8)
            dec_vals.append(f"{num}")
        return " ".join(dec_vals)
    except Exception as e:
        return f"error: {e}"