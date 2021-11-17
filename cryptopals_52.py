#!/usr/bin/env python
import os
from collections import defaultdict
from typing import Callable, List

from Crypto.Cipher import AES

from cryptopals_9 import pkcs7_pad
from cryptopals_13 import aes_encrypt


def merkle_damgard(msg: bytes, h: bytes) -> bytes:
    """

    Arguments:
        msg
        h: initial state
    """
    padded_msg = pkcs7_pad(msg)
    for i in range(0, len(padded_msg), 16):
        padded_h = pkcs7_pad(h)
        cipher = AES.new(padded_h, AES.MODE_ECB)

        # h becomes the first 16 bits of the cipher output
        h = cipher.encrypt(padded_msg[i:i+16])[:2]

    return h


def generate_many_collisions(n: int) -> List[bytes]:
    """
    Generate 2^n collissions
    """
    h = os.urandom(2)
    blocks = []
    hashes = defaultdict(list)

    while True:
        # Check whether we've generated enough collisions
        # `blocks` has one more H than we have pairs of collisions, so the
        # compared value is actually N + 1
        if len(blocks) >= n + 1:
            break

        # if we have two known collisions, calculate the next H and move along
        if len(hashes[h]) >= 2:
            h = merkle_damgard(hashes[h][0], h)
            blocks.append(h)
            continue

        msg = os.urandom(2)
        new_h = merkle_damgard(msg, h)
        if new_h in hashes:
            h = new_h

        hashes[h].append(msg)

    # Build the set of collusions from the blocks
    collisions = set(hashes[blocks[0]][:2]) 
    for h in blocks[1:-1]:
        new_collisions = set()
        for c in collisions:
            for b in hashes[h][:2]:
                new_collisions.add(c + b)
        collisions = new_collisions

    return collisions


if __name__ == '__main__':
    print('Challenge #52 - Iterated Hash Function Multicollisions')

    collisions = generate_many_collisions(n=4)

    for c in sorted(collisions):
        print(c)
