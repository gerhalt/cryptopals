#!/usr/bin/env python

import os
from math import ceil
from random import randint
from typing import Tuple

from cryptopals_28 import secret_prefix_mac, sha1


def digest_padding(msg_len: int) -> bytes:
    """Calculates the SHA1/MD4 padding of message. Assumes the message is
    neatly bounded to the nearest byte.

    Args:
        msg_len (int): Length of the message, in bytes

    Returns:
        (bytes): MD4 padding for a message of the given length
    """
    # NOTE: This implementation assumes the original message ends neatly on a
    #       byte boundary (length in bits % 8 == 0)
    padding = [0x80]

    # append 0 <= k < 512 bits '0', such that the resulting message length in
    # bits is congruent to -64 ≡ 448 (mod 512)
    k = 448 - ((msg_len + len(padding)) * 8) % 512
    if k < 0:
        k = 512 + k

    padding += [0x00] * int(k // 8)

    # append ml, the original message length in bits, as a 64-bit little-endian integer
    padding += (msg_len * 8).to_bytes(8, 'little')

    return bytes(padding)


def break_sha1_mac_into_registers(h: int) -> Tuple[int, int, int, int, int]:
    """Takes a 160-bit SHA1 MAC and breaks it into it's 5 component registers.
    """
    return tuple([(h >> (i * 32)) & 0xFFFFFFFF for i in range(4, -1, -1)])


if __name__ == '__main__':
    print('Challenge #29 - Break a SHA-1 keyed MAC using length extension')

    # Test calculating the SHA-1 padding of a message against known padding
    msg_len = len(b"The quick brown fox jumps over the lazy cog")
    calculated_padding = digest_padding(msg_len)
    expected_padding = 0x800000000000000000000000000000000000000158.to_bytes(21, 'big')
    assert calculated_padding == expected_padding

    h = sha1(b'The sand was wet as wet could be, the sands were dry as dry')
    assert break_sha1_mac_into_registers(h) == (3252765203, 1579508993, 1320547169, 1279034732, 2416568672)

    # Given a random key of random length, unknown to us
    key = os.urandom(randint(8, 16))

    # Generate a secret-prefix MAC under a
    original_msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    forged_suffix = b";admin=true"

    original_mac = secret_prefix_mac(sha1, key, original_msg)
    registers = break_sha1_mac_into_registers(original_mac)

    # Guess the key length
    for key_len in range(1, 33):
        glue_padding = digest_padding(key_len + len(original_msg))

        # Calculate the length of the old message, which we know will be a multiple
        # of 512 bits. We'll need to pass this in so the final message length winds
        # up being correct.
        original_len = key_len + len(original_msg) + len(glue_padding)

        # Create a forged MAC by setting up the SHA state with the final a-e
        # registers as well as the length of the original message
        forged_mac = sha1(forged_suffix, original_len, *registers).to_bytes(20, 'big')

        # Test it against the MAC we'd expect to see if we created the
        # secret-prefix MAC legimately
        expected_mac = sha1(key + original_msg + glue_padding + forged_suffix).to_bytes(20, 'big')
        if forged_mac == expected_mac:
            print(f'Found secret length length of {key_len}')
            print(f'Forged MAC is: {forged_mac.hex()}')
            break
    else:
        raise Exception("Couldn't guess secret key length") 

