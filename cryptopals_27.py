#!/usr/bin/env python
import os
import re
import sys

from cryptopals_10 import cbc_decrypt, xor
from cryptopals_16 import encrypt as escaped_cbc_encrypt

PRINTABLE_ASCII = set(range(32, 127))
ESCAPED_ASCII = {
    r'\t': 9,
    r'\n': 10,
    r'\r': 13,
    r'\'': 39,
    r'\\': 92
}

ERROR_RE = re.compile(r'plaintext is "(.*)"$')


def str_to_bytes(inp: str) -> bytes:
    """ Converts a passed string to bytes, checking for \x00-style escaped bytes
    and converting to single bytes as necessary.
    """
    output = []
    input_len = len(inp)
    i = 0
    while i < input_len:
        c = inp[i]

        # Base, single-character case
        v = ord(c)
        offset = 1
   
        # Multi-character escaped cases, all beginning with a leading '\'
        if inp[i] == '\\':
            if (i + 4 <= input_len and inp[i+1] == 'x'):
                v = int(inp[i+2:i+4], 16)
                offset = 4
            elif (i + 2 <= input_len and inp[i:i+2] in ESCAPED_ASCII):
                v = ESCAPED_ASCII[inp[i:i+2]]
                offset = 2

        i += offset
        output.append(v)

    return bytes(output)


def verify_plaintext(msg: bytes):
    """ Verifies that byte values are within valid, printable ASCII ranges.
    If not, raises a `ValueError`.
    """
    for b in msg:
        if b not in PRINTABLE_ASCII:
            # Produce an error with the complete plaintext, stripping off the
            # leading "b'" and trailing "'" in the plaintext
            raise ValueError(f'{b} is not a printable ASCII byte, plaintext is "{str(msg)[2:-1]}"')


if __name__ == '__main__':
    print("Challenge #27 - Recover the key from CBC with IV=Key")

    limit = 10000
    for i in range(1, limit + 1):
        sys.stdout.write(f'\rRunning... {i} / {limit}')
        sys.stdout.flush()

        # Generate enough plaintext to guarantee 3 blocks of ciphertext
        plaintext = b'.' * 16 * 3

        # Generate a random key, and encrypt the (padded, from challenge #16) ciphertext
        key = iv = os.urandom(16)
        ciphertext = escaped_cbc_encrypt(plaintext, key, iv) 

        # Compose a new ciphertext, composed of:
        # 1. First ciphertext block (unchanged)
        # 2. Completely zeroed block
        # 3. First ciphertext block
        ciphertext = list(ciphertext)
        ciphertext = ciphertext[0:16] + [0x00] * 16 + ciphertext[0:16]
        ciphertext = bytes(ciphertext)

        # Decrypt our ciphertext, then run it through the plaintext
        # verification function, which will raise an error indicating the ascii
        # isn't printable with the decrypted plaintext
        plaintext = cbc_decrypt(ciphertext, key, iv)
        try:
            verify_plaintext(plaintext)
        except Exception as e:
            # Search the output for the plaintext, and convert back to a format we can use (bytes)
            match = ERROR_RE.search(str(e))
            plaintext = str_to_bytes(match.group(1))

        # Now XOR the first and last decrypted blocks
        discovered_key = xor(plaintext[0:16], plaintext[32:48]) 

        assert key == discovered_key, f"Discovered key {discovered_key} doesn't match actual key {key}" 

    print()
