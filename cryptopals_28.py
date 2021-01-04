#!/usr/bin/env python

from typing import Union

from cryptopals_10 import xor


def leftrotate(n: Union[int, bytes], l: bytes) -> Union[int, bytes]:
    """ Shifts the 32-bit number `n` `l` bits to the left, taking any bits that
    fall off the left end and re-adding them to the right. Accepts either bytes
    or an integer, and returns the same type.
    """
    use_bytes = isinstance(n, bytes)
    if use_bytes:
        n = int.from_bytes(n, 'big')

    for _ in range(0, l):
        # Get the leading bit, shifted into the trailing position
        x = ((0b1 << 31) & n) >> 31
        n = (n << 1) & 0xFFFFFFFF | x

    # Convert back to bytes if we need to
    if use_bytes:
        n = n.to_bytes(4, 'big')

    return n


def sha1(msg: bytes) -> bytes:
    """ Implementation of the SHA-1 has function, taking an input and producing
    a 160-bit hash digest.

    Implemented from the psuedocode here:
    https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode

    Note 1: All variables are unsigned 32-bit quantities and wrap modulo 232 when calculating, except for
            ml, the message length, which is a 64-bit quantity, and
            hh, the message digest, which is a 160-bit quantity.
    Note 2: All constants in this pseudo code are in big endian.
            Within each word, the most significant byte is stored in the leftmost byte position
    """
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    ml = len(msg) * 8  # Message length in bits

    msg = list(msg)

    # Pre-processing
    # append the bit '1' to the message
    msg.append(0x80)

    # append 0 <= k < 512 bits '0', such that the resulting message length in
    # bits is congruent to -64 ≡ 448 (mod 512)
    k = 448 - (len(msg) * 8) % 512
    if k < 0:
        k = 448 + -k

    msg += [0x00] * int(k / 8)

    # append ml, the original message length in bits, as a 64-bit big-endian integer
    msg += ml.to_bytes(8, 'big')

    # the message length should be a multiple of 64 bytes
    assert len(msg) % 64 == 0

    # Processing, in 512-bit chunks
    for i in range(0, len(msg), 64):
        chunk = msg[i:i+64]

        # break chunk into sixteen 32-bit big-endian words
        words = [int.from_bytes(bytes(chunk[j:j+4]), 'big') for j in range(0, len(chunk), 4)]

        # Message schedule: extend the sixteen 32-bit words into eighty 32-bit words
        for j in range(16, 80):
            w = words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16]
            w = leftrotate(w, 1)
            words.append(w)

        print(words)

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

    # Produce the final hash value as a 160-bit number
    return (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4


if __name__ == '__main__':
    print("Challenge #28 - Implement a SHA-1 keyed MAC")

    # Tests for left-rotate
    n = 0x0000FFFF
    assert leftrotate(n, 16) == 0xFFFF0000
    assert leftrotate(n, 24) == 0xFF0000FF
    assert leftrotate(n, 25) == 0xFE0001FF

    # Tests for SHA-1 hash
    print(hex(sha1(b'')))
