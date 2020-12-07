#!/usr/bin/env python

import base64
import os

from Crypto.Cipher import AES

from cryptopals_10 import xor
from cryptopals_18 import aes_ctr


NONCE = 0xBADBAD


def edit_ctr(ciphertext: bytes, key: bytes, offset: int, newtext: bytes) -> bytes:
    """
    Given the input `ciphertext`, decrypts using the `key`, seeks into the
    text to the `offset`, and overwrites `newtext` in. If `offset` is greater
    than the length of the original ciphertext, throws a ValueError.
    """
    if offset > len(ciphertext):
        raise ValueError('Offset must be less than or equal to the length of the ciphertext')

    plaintext = aes_ctr(key, NONCE, ciphertext)

    modified_plaintext = plaintext[:offset] + newtext + plaintext[offset + len(newtext):]
    return aes_ctr(key, NONCE, modified_plaintext)


def ecb_decrypt(key, file_path):
    with open(file_path, 'rb') as f:
        text = base64.b64decode(f.read())

        cipher = AES.new(key, AES.MODE_ECB)  # IV is ignored
        return cipher.decrypt(text)


if __name__ == '__main__':
    print('Challenge #25 - Break "random access read/write" AES CTR')

    key = os.urandom(16)
    unknown_plaintext = ecb_decrypt(b'YELLOW SUBMARINE', 'data/25.txt')
    ciphertext = aes_ctr(key, NONCE, unknown_plaintext)

    newtext = b'.' * len(ciphertext)
    modified_ciphertext = edit_ctr(ciphertext, key, 0, newtext)

    assert unknown_plaintext == xor(ciphertext, xor(newtext, modified_ciphertext))
