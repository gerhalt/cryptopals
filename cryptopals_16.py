#!/usr/bin/env python
"""
You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:

    Completely scrambles the block the error occurs in
    Produces the identical 1-bit error(/edit) in the next ciphertext block.

Before you implement this attack, answer this question:

    Why does CBC mode have this property?

Because the prior encrypted block is XORed with the next block's plaintext
before encryption.
"""

import os
import re

from Crypto.Cipher import AES

from cryptopals_9 import pkcs7_pad
from cryptopals_10 import cbc_decrypt, cbc_encrypt


KEY = os.urandom(16)
IV = os.urandom(16)
BLOCK_SIZE = 16
CLEAN_RE = re.compile(r'([;=])')

PREFIX = b'comment1=cooking%20MCs;userdata='
SUFFIX = b';comment2=%20like%20a%20pound%20of%20bacon'


def encrypt(msg: bytes, key: bytes = None, iv: bytes = None) -> bytes:
    """ Sandwiches user input between two existing strings, surrounding any ';'
    or '=' characters in single quotes. Pads and encrypts in AES CBC using the
    random key and a random IV, then returns the encrypted messge.
    """
    # Fall back to module defaults for local tests
    key = key or KEY
    iv = iv or IV

    # I interpreted "quote out" to mean surround disallowed characters with
    # single quotes
    msg_str = msg.decode()
    msg = CLEAN_RE.sub(r"'\1'", msg_str)

    # Convert string (necessary for regex replacement) back to bytes
    msg = bytes(msg.encode())

    # Tack on the prefix and suffix
    msg = PREFIX + msg + SUFFIX

    return cbc_encrypt(msg, key, iv)


def is_admin(ciphertext: bytes) -> bytes:
    """ Returns whether or not an admin key-value pair is present in the
    decrypted string.
    """
    msg = cbc_decrypt(ciphertext, KEY, IV)
    return b';admin=true;' in msg


if __name__ == '__main__':
    print('Challenge #16 - CBC bitflipping attacks')

    # Assumption: the IV stays consistent

    # Attempting to gain admin through input should fail by default, as the
    # input is escaped
    ciphertext = encrypt(b';admin=true;')
    assert not is_admin(ciphertext)

    # Operate on the second block, because our input is on the third block
    # (This knowledge might be cheating, unsure how else to derive except
    #  by knowing the prefix)
    #print(f'Prefix is {len(PREFIX)} bytes')

    # Will be escaped to:
    # ';'dmi'='ru';'
    # with the leading ' on the first byte of the third block. We can then XOR
    # each of the inner single quotes by modifying the corresponding index in
    # the prior block with a byte than, when xor'ed with a single quote, will
    # create our desired plaintext
    ciphertext = encrypt(b';dmi=ru;')

    # bytes are immutable, so briefly work with a list
    ciphertext = list(ciphertext)

    # In the third block, the indexes with the block and the desired
    # replacement characters
    #
    # ';'dmi'='ru';'
    desired = {
        2: 'a',
        6: 'n',
        8: 't',
        11: 'e'
    }
    for idx, desired in desired.items():
        # Get the decrypted value before XORing with the previous ciphertext
        # block, so we can figure out what we need to XOR with it
        old_pre_xor = ord('\'') ^ ciphertext[BLOCK_SIZE * 1 + idx]

        # With our desired value, and the pre-xor value, determine the value
        # needed in the previous block
        new_xor = ord(desired) ^ old_pre_xor

        # Set the new xor value in the prior block
        ciphertext[BLOCK_SIZE * 1 + idx] = new_xor

    ciphertext = bytes(ciphertext)

    # Now, when the ciphertext is decrypted it should have the
    # ";admin=true;" portion
    assert is_admin(ciphertext)
