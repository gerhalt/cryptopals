#!/usr/bin/env python


import os
from random import choice
from typing import Tuple

from cryptopals_15 import pkcs7_strip
from cryptopals_10 import cbc_decrypt, cbc_encrypt


KEY = os.urandom(16)


POSSIBLE_INPUTS = (
    b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
    b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
    b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
    b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
    b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
    b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
    b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
    b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
    b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
    b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93',
)


def randcrypt() -> Tuple[bytes, bytes]:
    """
    Selects one of the strings above, at random, encrypts it using our random
    global key, and returns the ciphertext and iv.
    """
    msg = choice(POSSIBLE_INPUTS)

    iv = os.urandom(16)
    ciphertext = cbc_encrypt(msg, KEY, iv)

    return ciphertext, iv


def has_valid_padding(ciphertext: bytes, iv: bytes) -> bool:
    """
    Decrypts the input ciphertext using the provided IV and returns a boolean
    representing whether or not it has valid padding.
    """
    msg = cbc_decrypt(ciphertext, KEY, iv)
    
    valid = True
    try:
        # Strip the padding; raises an exception if padding is invalid
        pkcs7_strip(msg)
    except ValueError:
        valid = False

    return valid

  
if __name__ == '__main__':
    print('Challenge #17 - The CBC Padding Oracle')

    ciphertext, iv = randcrypt()
    assert has_valid_padding(ciphertext, iv)

