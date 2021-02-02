#!/usr/bin/env python

import os
import struct
from collections import deque
from random import randint
from typing import Iterable, Generator, Tuple

from cryptopals_28 import leftrotate
from cryptopals_29 import bytes_to_registers, digest_padding


def md4(msg: bytes, initial_len: int = 0,
        a: int = None, b: int = None,
        c: int = None, d: int = None) -> bytes:
    """Implementation of the insecure MD4 hash.

    Based on the psuedocode from the RFC: https://tools.ietf.org/html/rfc1320
    """
    msg = bytearray(msg)

    a = a if a is not None else 0x67452301
    b = b if b is not None else 0xEFCDAB89
    c = c if c is not None else 0x98BADCFE
    d = d if d is not None else 0x10325476


    # after the padding is appended to the message, its length should be a
    # multiple of 64 bytes
    msg = msg + digest_padding(len(msg) + initial_len, 'little')
    if len(msg) % 64 != 0:
        raise ValueError('Length of message should be evenly divisible by 64 '
                         f'after padding has been appended, actually is {len(msg)}')

    # For each 16-word block
    for i in range(0, len(msg), 64):

        # Carve out the block
        x = msg[i : i + 64]

        # Save our current hash values
        aa = a
        bb = b
        cc = c
        dd = d

        args = [a, b, c, d]

        # Round #1
        for j in range(0, 16):
            k = j
            s = [3, 7, 11, 19][j % 4]

            xk = int.from_bytes(x[k * 4:(k + 1) * 4], 'little')

            a, b, c, d = args
            a += ((b & c) | (~b & d)) + xk
            a = leftrotate(a, s)

            # Move the last item to the front of the queue
            args = [d, a, b, c]

        # Round #2
        for j in range(0, 16):
            k = (j % 4) * 4 + (j // 4)
            s = [3, 5, 9, 13][j % 4]

            xk = int.from_bytes(x[k * 4:(k + 1) * 4], 'little')

            a, b, c, d = args
            a += ((b & c) | (b & d) | (c & d)) + xk + 0x5A827999
            a = leftrotate(a, s)

            # Move the last item to the front of the queue
            args = [d, a, b, c]

        # Round #3
        for j in range(0, 16):
            k = [0, 8, 4, 12,
                 2, 10, 6, 14,
                 1, 9, 5, 13,
                 3, 11, 7, 15][j]
            s = [3, 9, 11, 15][j % 4]
            
            xk = int.from_bytes(x[k * 4:(k + 1) * 4], 'little')

            a, b, c, d = args
            a += (b ^ c ^ d) + xk + 0x6ED9EBA1
            a = leftrotate(a, s)

            args = [d, a, b, c]

        a, b, c, d = args
        a += aa
        b += bb
        c += cc
        d += dd

        # Mask, due to potential for overflow
        a &= 0xFFFFFFFF
        b &= 0xFFFFFFFF
        c &= 0xFFFFFFFF
        d &= 0xFFFFFFFF

    # Produce the final hash value as a 128-bit number
    return bytes(struct.pack("<4L", a, b, c, d))


if __name__ == '__main__':
    print('Challenge #30 - Break an MD4 keyed MAC using length extension')

    h = md4(b"The quick brown fox jumps over the lazy dog")
    assert h == 0x1bee69a46ba811185c194762abaeae90.to_bytes(16, 'big')

    h = md4(b"The quick brown fox jumps over the lazy cog")
    assert h == 0xb86e130ce7028da59e672d56ad0113df.to_bytes(16, 'big')

    h = md4(b'')
    assert h == 0x31d6cfe0d16ae931b73c59d7e0c089c0.to_bytes(16, 'big')

    # Given a random key of random length, unknown to us
    key = os.urandom(randint(8, 16))

    # Generate a secret-prefix MAC under a
    original_msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    forged_suffix = b";admin=true"

    original_mac = md4(key + original_msg)
    registers = bytes_to_registers(original_mac, 'little')

    # Guess the key length
    for key_len in range(1, 33):
        glue_padding = digest_padding(key_len + len(original_msg), 'little')

        # Calculate the length of the old message, which we know will be a multiple
        # of 512 bits. We'll need to pass this in so the final message length winds
        # up being correct.
        original_len = key_len + len(original_msg) + len(glue_padding)

        # Create a forged MAC by setting up the SHA state with the final a-e
        # registers as well as the length of the original message
        forged_mac = md4(forged_suffix, original_len, *registers)

        # Test it against the MAC we'd expect to see if we created the
        # secret-prefix MAC legimately
        expected_mac = md4(key + original_msg + glue_padding + forged_suffix)
        if forged_mac == expected_mac:
            print(f'Found secret length length of {key_len}')
            print(f'Forged MAC is: {forged_mac.hex()}')
            break
    else:
        raise Exception("Couldn't guess secret key length") 

