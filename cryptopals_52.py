#!/usr/bin/env python
import os
from collections import defaultdict
from functools import partial
from typing import Callable, List

from Crypto.Cipher import AES

from cryptopals_9 import pkcs7_pad
from cryptopals_13 import aes_encrypt


def count_calls(fn):
    """Counts the number of calls made to the wrapped function.
    Use `fn.call_count` to see the current number, or call `fn.reset_calls`
    to set the count back to zero.
    """
    def wrapper(*args, **kwargs):
        wrapper.call_count += 1
        return fn(*args, **kwargs)

    def reset_calls():
        wrapper.call_count = 0

    wrapper.reset_calls = reset_calls
    wrapper.reset_calls()

    return wrapper


def cipher(key: bytes, msg: bytes, output_size: int = 2) -> bytes:
    """Inexpensive AES-ECB cipher returning the first `output_size` bytes of
    ciphertext as the hash.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(msg)[:output_size]


def merkle_damgard(msg: bytes, h: bytes, c: Callable[[bytes, bytes], bytes]) -> bytes:
    """Iterative hash function construction. Given some initial state H, feeds
    that into the cipher to produce some output, which is padded and used as
    the input state for the next block. Returns the final H when the end of the
    padded message is reached.

    Arguments:
        msg
        h: initial state
        c: cipher
    """
    padded_msg = pkcs7_pad(msg)
    for i in range(0, len(padded_msg), 16):
        # H (probably) is not block-length, so pad it
        padded_h = pkcs7_pad(h)

        block = padded_msg[i:i+16]
        h = c(padded_h, block)

    return h


def generate_many_collisions(n: int, c: Callable[[bytes, bytes], bytes]) -> List[bytes]:
    """Generate 2^n collisions in the passed cipher `c`, using a randomized
    initial H.
    """
    h = os.urandom(2)
    blocks = []
    hashes = defaultdict(list)

    while True:
        # Check whether we've generated enough collisions
        # `blocks` includes the output H from the last pair of collisions, so
        # we'll actually have N + 1 H-values when we have N collisions.
        if len(blocks) >= n + 1:
            break

        # If we have two known collisions for this H, calculate the next H and
        # move along
        if len(hashes[h]) >= 2:
            h = merkle_damgard(hashes[h][0], h, c)
            blocks.append(h)
            continue

        # Otherwise, generate a random block and find it's H, using the output
        # H of the colliding message we've been building up to now
        msg = os.urandom(2)
        new_h = merkle_damgard(msg, h, c)
        if new_h in hashes:
            h = new_h

        hashes[h].append(msg)

    # Build the complete set of colliding messages from the blocks we have, for
    # example, if we have A,B -> H1 as our first colliding blocks, and
    # C,D -> H2 as our second colliding blocks, we would create a set of four
    # messages: [AC, AD, BC, BD]
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

    # Our cheap cipher truncates the hash to 2 bytes, our expensive cipher
    # truncates it to 4 bytes
    cheap_cipher = count_calls(partial(cipher, output_size=2))
    expensive_cipher = count_calls(partial(cipher, output_size=4))

    collision_found = False
    while not collision_found:
        # TODO: Add ability to generate 2^n+1 collisions from existing set of
        #       2^n?

        collisions = generate_many_collisions(16, cheap_cipher)
        print(f'Generated {len(collisions)} cheap collisions')
        
        # Check whether any of the cheap hash collisions also collide in the
        # expensive hash

        h = os.urandom(2)
        expensive_hashes = {}
        for collision in collisions:
            hsh = merkle_damgard(collision, h, expensive_cipher)

            if hsh in expensive_hashes:
                print('Collisions:')
                print(f'  {expensive_hashes[hsh].hex()}')
                print(f'  {collision.hex()}')
                collision_found = True
                break
            else:
                expensive_hashes[hsh] = collision

    print(f'Cheap cipher calls: {cheap_cipher.call_count}')
    print(f'Expensive cipher calls: {expensive_cipher.call_count}')
