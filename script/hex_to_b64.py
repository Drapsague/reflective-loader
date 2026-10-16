#!/usr/bin/env python3
"""
Simple script: read a file containing C-style hex bytes like:
  {0x78, 0x98, 0xab, 0x01, ...}
and print the Base64 encoding of those bytes.

Usage:
  python3 hex_to_base64.py input.txt
  python3 hex_to_base64.py input.txt -o out.b64
"""
import argparse
import re
import base64
import sys
from pathlib import Path

HEX_RE_0X = re.compile(r'0x([0-9A-Fa-f]{2})')
HEX_RE_PLAIN = re.compile(r'\b([0-9A-Fa-f]{2})\b')

def parse_hex_bytes(text: str):
    # Prefer explicit 0xNN tokens (safer). If none found, fall back to bare NN tokens.
    matches = HEX_RE_0X.findall(text)
    if not matches:
        matches = HEX_RE_PLAIN.findall(text)
    return bytes(int(h, 16) for h in matches)

def main():
    p = argparse.ArgumentParser(description="Encode C-style hex bytes to base64")
    p.add_argument("input", type=Path, help="Input file containing {0xAA, 0xBB, ...}")
    p.add_argument("-o", "--output", type=Path, help="Write base64 to file (default stdout)")
    p.add_argument("--urlsafe", action="store_true", help="Use URL-safe base64 (base64.urlsafe_b64encode)")
    args = p.parse_args()

    text = args.input.read_text(encoding="utf-8", errors="ignore")
    try:
        data = parse_hex_bytes(text)
    except Exception as e:
        print("Error parsing hex bytes:", e, file=sys.stderr)
        return 2

    if args.urlsafe:
        b64 = base64.urlsafe_b64encode(data).decode("ascii")
    else:
        b64 = base64.b64encode(data).decode("ascii")

    if args.output:
        args.output.write_text(b64, encoding="ascii")
    else:
        print(b64)

if __name__ == "__main__":
    main()
