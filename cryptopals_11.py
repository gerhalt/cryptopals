#!/usr/bin/env python

import os
from random import randint

from Crypto.Cipher import AES

from cryptopals_8 import detect_duplicate_blocks 
from cryptopals_9 import pkcs7_pad
from cryptopals_10 import cbc_encrypt


def generate_aes_key() -> bytes:
    """
    Generates a random AES key.
    """
    return os.urandom(16)


def randcryptor(msg: bytes) -> bytes:
    """
    Encrypts the input with AES in either ECB or CBC, randomly.
    """
    # Pad the message with 5-10 random bytes
    padding = os.urandom(randint(5, 10))
    padded_msg = pkcs7_pad(padding + msg + padding, 16)

    # Generate a random key
    key = generate_aes_key()

    # Randomly choose whether to use ECB or CBC
    mode = 'cbc' if bool(randint(0, 1)) else 'ecb'
    if mode == 'cbc':
        iv = os.urandom(16)
        encrypted_msg = cbc_encrypt(padded_msg, key, iv)
    else:  # ECB
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted_msg = cipher.encrypt(padded_msg)

    return encrypted_msg, mode  # FOR TESTING ONLY


if __name__ == '__main__':
    print('Challenge #11 - ECB / CBC Detection Oracle')

    msg = b'josh' * 1000
    encrypted_msg, encryption_mode = randcryptor(msg)

    duplicates = detect_duplicate_blocks(encrypted_msg)
    dup_count = sum([c for c in duplicates.values()])

    # Base our guess on the ratio of duplicates to total block count
    ratio = dup_count / (len(encrypted_msg) // 16)
    guess_mode = 'cbc' if ratio <= 0.01 else 'ecb'

    print(f'Encrypted in {encryption_mode}, guess is {guess_mode}')
    assert guess_mode == encryption_mode 
