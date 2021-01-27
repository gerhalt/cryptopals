#!/usr/bin/env python

import os
from typing import Callable, Union

from cryptopals_10 import xor


def leftrotate(n: Union[int, bytes], l: bytes) -> Union[int, bytes]:
    """ Shifts the 32-bit number `n` `l` bits to the left, taking any bits that
    fall off the left end and re-adding them to the right. Accepts either bytes
    or an integer, and returns the same type.
    """
    use_bytes = isinstance(n, bytes)
    if use_bytes:
        n = int.from_bytes(n, 'big')

    # Get the leading bit, shifted into the trailing position
    n &= 0xFFFFFFFF
    n = (n << l & 0xFFFFFFFF) | (n >> (32 - l))

    # Convert back to bytes if we need to
    if use_bytes:
        n = n.to_bytes(4, 'big')

    return n


def sha1(msg: bytes, initial_len: int = 0,
         a: int = None, b: int = None,
         c: int = None, d: int = None, e: int = None) -> int:
    """ Implementation of the SHA-1 has function, taking an input and producing
    a 160-bit hash digest.

    Implemented from the psuedocode here:
    https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode

    Note 1: All variables are unsigned 32-bit quantities and wrap modulo 2^32
            when calculating, except for ml, the message length, which is a
            64-bit quantity, and hh, the message digest, which is a 160-bit
            quantity.
    Note 2: All constants in this pseudo code are in big endian.
            Within each word, the most significant byte is stored in the
            leftmost byte position

    Args:
        msg (bytes): The message to hash
        initial_len (int, optional): Length of message already hashed, in
            bytes. Used when appending to an existing messages, in conjunction
            with setting the state.
        a, b, c, d, e (int, optional): 32-bit state integers, used to snap the
            state to a certain point for appending to an existing message.
    """
    h0 = a if a is not None else 0x67452301
    h1 = b if b is not None else 0xEFCDAB89
    h2 = c if c is not None else 0x98BADCFE
    h3 = d if d is not None else 0x10325476
    h4 = e if e is not None else 0xC3D2E1F0

    # Pre-processing
    # append the bit '1' to the message
    # NOTE: This implementation assumes the original message ends neatly on a
    #       byte boundary (length in bits % 8 == 0)
    padding = [0x80]

    # append 0 <= k < 512 bits '0', such that the resulting message length in
    # bits is congruent to -64 ≡ 448 (mod 512)
    k = 448 - ((len(msg) + len(padding)) * 8) % 512
    if k < 0:
        k = 448 + -k

    padding += [0x00] * int(k / 8)

    # append ml, the original message length in bits, as a 64-bit big-endian integer
    padding += ((len(msg) + initial_len) * 8).to_bytes(8, 'big')

    # after the padding is appended to the message, its length should be a
    # multiple of 64 bytes
    msg = list(msg) + padding
    if len(msg) % 64 != 0:
        raise ValueError('Length of message should be evenly divisible by 64 '
                         f'after padding has been appended {len(msg)}')

    # Processing, in 512-bit chunks
    for i in range(0, len(msg), 64):
        chunk = msg[i:i+64]

        # break chunk into sixteen 32-bit big-endian words
        words = [int.from_bytes(bytes(chunk[j:j+4]), 'big') for j in range(0, len(chunk), 4)]

        # Message schedule: extend the sixteen 32-bit words into eighty 32-bit words
        for j in range(16, 80):
            w = words[j-3] ^ words[j-8] ^ words[j-14] ^ words[j-16]
            w = leftrotate(w, 1)
            words.append(w)

        # Initialize hash values for this chunk
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for j in range(0, 80):
            if 0 <= j <= 19:
                #               bitwise not
                f = (b & c) | ((0xFFFFFFFF - b) & d)
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= j <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (leftrotate(a, 5) + f + e + k + words[j]) & 0xFFFFFFFF
            e = d
            d = c
            c = leftrotate(b, 30)
            b = a
            a = temp

        # Add this chunk's hash to result so far
        h0 += a
        h1 += b
        h2 += c
        h3 += d
        h4 += e

    # Mask, due to note #1 (above)
    h0 &= 0xFFFFFFFF
    h1 &= 0xFFFFFFFF
    h2 &= 0xFFFFFFFF
    h3 &= 0xFFFFFFFF
    h4 &= 0xFFFFFFFF

    # Produce the final hash value as a 160-bit number
    return (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4


def secret_prefix_mac(hash_algo: Callable[[bytes], bytes], key: bytes, msg: bytes) -> bytes:
    """Generates a secret-prefix MAC, which is the result of `hash_algo(key || msg)`.

    Returns:
        bytes: the secret-prefix MAC
    """
    return hash_algo(key + msg)


def authenticate_secret_prefix_mac(key: bytes, msg: bytes, mac: bytes) -> bool:
    """Generates a secret-prefix MAC from the passed key and message, and
    compares it to the input MAC.

    Returns:
        bool: Represents whether the generated MAC matches the one passed in.
    """
    return secret_prefix_mac(sha1, key, msg) == mac


if __name__ == '__main__':
    print("Challenge #28 - Implement a SHA-1 keyed MAC")

    # Tests for left-rotate
    n = 0x0000FFFF
    assert leftrotate(n, 16) == 0xFFFF0000
    assert leftrotate(n, 24) == 0xFF0000FF
    assert leftrotate(n, 25) == 0xFE0001FF

    # Tests for SHA-1 hash
    h = sha1(b"The quick brown fox jumps over the lazy dog")
    assert h == 0x2fd4e1c67a2d28fced849ee1bb76e7391b93eb12

    h = sha1(b"The quick brown fox jumps over the lazy cog")
    assert h == 0xde9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3

    h = sha1(b"")
    assert h == 0xda39a3ee5e6b4b0d3255bfef95601890afd80709

    # Basic verification that tampering with the message results in a
    # completely different MAC
    key = os.urandom(16)
    original_msg = b"Some message"
    original_mac = secret_prefix_mac(sha1, key, original_msg)

    # now if we increment a byte in the original message
    modified_msg = list(original_msg)
    modified_msg[0] += 1
    modified_msg = bytes(modified_msg)

    # it should produce a completely different mac using the same secret key
    modified_mac = secret_prefix_mac(sha1, key, modified_msg)
    assert original_mac != modified_mac

    print('>> When message is modified:')
    print('Original MAC: ' + ''.join([f'{b:02x}' for b in original_mac.to_bytes(20, 'big')]))
    print('Modified MAC: ' + ''.join([f'{b:02x}' for b in modified_mac.to_bytes(20, 'big')]))

    # if we pass in a different secret key, where one byte is incremented
    new_key = list(key)
    new_key[0] += 1
    new_key = bytes(new_key)

    # it should produce a completely different mac using the same message
    modified_mac = secret_prefix_mac(sha1, key, modified_msg)
    assert original_mac != modified_mac

    print('>> When secret key is different:')
    print('Original MAC: ' + ''.join([f'{b:02x}' for b in original_mac.to_bytes(20, 'big')]))
    print('Modified MAC: ' + ''.join([f'{b:02x}' for b in modified_mac.to_bytes(20, 'big')]))
