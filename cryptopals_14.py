#!/usr/bin/env python

import math
import os
from base64 import b64decode
from random import randint

from Crypto.Cipher import AES

from cryptopals_8 import detect_duplicate_blocks
from cryptopals_9 import pkcs7_pad
from cryptopals_11 import aes_oracle


MYSTERY_PREFIX = os.urandom(randint(10, 40))
print(f'MYSTERY PREFIX IS LENGTH {len(MYSTERY_PREFIX)}')
MYSTERY_PADDING = (
    b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
    b'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
    b'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
    b'YnkK'
)
KEY = os.urandom(16)


def aes_encrypt(msg: bytes) -> bytes:
    """
    Encrypts the input with AES, adding mystery padding! Spooky!
    """
    padding = b64decode(MYSTERY_PADDING)
    padded_msg = pkcs7_pad(MYSTERY_PREFIX + msg + padding, 16)

    # Use our unknown but consistent key
    cipher = AES.new(KEY, AES.MODE_ECB)
    encrypted_msg = cipher.encrypt(padded_msg)

    return encrypted_msg


if __name__ == '__main__':
    print('Challenge #14 - Byte-at-a-time ECB decryption (Harder)')

    # Discover the block size of the cipher
    last_len = None
    block_size = None
    for i in range(0, 256):
        msg = b'A' * i
        out = aes_encrypt(msg)

        if not last_len:
            last_len = len(out)
        elif last_len < len(out):
            block_size = len(out) - last_len
            break

    print(f'Block size is {block_size}')

    # Detect the mode (known to be ECB, do anyway)
    out = aes_encrypt(b'j' * (block_size * 3))
    guess_mode = aes_oracle(out)
    print(f'Mode is {guess_mode}')

    block_count = len(aes_encrypt(b'')) // block_size
    print(f'Resolving {block_count} blocks')

    # Build a prefix to align everything after the user-controlled portion to
    # the start of the next block
    for i in range(block_size * 2, block_size * 3):
        out = aes_encrypt(i * b'J')
        dups = detect_duplicate_blocks(out)
        if dups:
            break

    first_block_idx = min(map(min, dups.values()))
    initial_padding = (i - block_size * 2) * b'J'
    print(f'First block index is {first_block_idx}, initial padding is {len(initial_padding)}')

    known_bytes = []
    for i in range(0, block_count * block_size):
        block_idx = len(known_bytes) // block_size

        filler = b'_' * ((block_idx + 1) * block_size - len(known_bytes) - 1)
        print(f'Know {len(known_bytes)}, next block boundary is {(block_idx + 1) * block_size}')
        print(f'    need {len(filler)} bytes of filler ({filler})')

        known = {}
        # Build possible value lookup dictionary
        block_start = first_block_idx + block_idx * block_size
        block_end = block_start + block_size
        #print(f'Block is from {block_start} to {block_end}')
        for possible_value in range(0, 0xFF):
            # initial_padding (to align the discoverable portion to the start
            #                  of a block)
            # + filler (to shift unknown index to next block idx - 1)
            # + known bytes
            # + possible byte value
            msg = initial_padding + filler + b''.join(known_bytes) + possible_value.to_bytes(1, byteorder='little')
            encrypted_block = aes_encrypt(msg)[block_start:block_end]
            known[encrypted_block] = msg
        
        # Now test with the initial padding + filler, without the known bytes
        test_block = aes_encrypt(initial_padding + filler)[block_start:block_end]

        try:
            known_bytes.append(known[test_block][-1:])
        except KeyError:
            # Second byte of dynamic padding will trigger, strip off the first
            # byte for cleanliness
            print('UNKNOWN KEY')
            known_bytes = known_bytes[:-1]
            break

    print(b''.join(known_bytes))
