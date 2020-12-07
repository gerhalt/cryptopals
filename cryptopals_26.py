#!/usr/bin/env python

import os
import re

from Crypto.Cipher import AES

from cryptopals_18 import aes_ctr


KEY = os.urandom(16)
NONCE = os.urandom(16)
CLEAN_RE = re.compile(r'([;=])')

PREFIX = b'comment1=cooking%20MCs;userdata='
SUFFIX = b';comment2=%20like%20a%20pound%20of%20bacon'


def encrypt(msg: bytes) -> bytes:
    """ Sandwiches user input between two existing strings, surrounding any ';'
    or '=' characters in single quotes. Pads and encrypts in AES CTR and returns
    the encrypted messge.
    """
    # I interpreted "quote out" to mean surround disallowed characters with
    # single quotes
    msg_str = msg.decode()
    msg = CLEAN_RE.sub(r"'\1'", msg_str)

    # Convert string (necessary for regex replacement) back to bytes
    msg = bytes(msg.encode())

    # Tack on the prefix and suffix
    msg = PREFIX + msg + SUFFIX
    return aes_ctr(KEY, NONCE, msg)


def is_admin(ciphertext: bytes) -> bytes:
    """ Returns whether or not an admin key-value pair is present in the
    decrypted string.
    """
    msg = aes_ctr(KEY, NONCE, ciphertext)
    return b';admin=true;' in msg


if __name__ == '__main__':
    print('Challenge #26 - CTR bitflipping')

    # Attempting to gain admin through input should fail by default, as the
    # input is escaped
    ciphertext = encrypt(b';admin=true;')
    assert not is_admin(ciphertext)

    # Will be escaped to ';'dmi'='ru';'
    ciphertext = encrypt(b';dmi=ru;')

    # bytes are immutable, so briefly work with a list
    ciphertext = list(ciphertext)

    # Indexes here are relative to the start of the user input, after it has
    # been escaped, where it will look like:
    #
    # ';'dmi'='ru';'
    desired = {
        2: 'a',
        6: 'n',
        8: 't',
        11: 'e'
    }
    for local_idx, desired in desired.items():
        # Determine where to work from, based on knowledge of the length of
        # the prefix. As in #16, unsure how to derive unless we know the
        # length. Absolute index is therefore the prefix length plus local
        # offset.
        idx = len(PREFIX) + local_idx

        # Find the byte in the keystream by xor-ing with the known input byte
        key_byte = ord('\'') ^ ciphertext[idx]

        # xor with the desired byte to determine what we need to feed in
        ciphertext[idx] = ord(desired) ^ key_byte

    ciphertext = bytes(ciphertext)

    # Now, when the ciphertext is decrypted it should have the
    # ";admin=true;" portion
    assert is_admin(ciphertext)
