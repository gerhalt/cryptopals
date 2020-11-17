#!/usr/bin/env python


import os
import sys
from base64 import b64encode, b64decode
from collections import deque
from random import choice, randint
from typing import Callable, Tuple

from cryptopals_15 import pkcs7_strip
from cryptopals_10 import cbc_decrypt, cbc_encrypt


BLOCK_SIZE = 16


POSSIBLE_INPUTS = [b64decode(s) for s in (
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

    # Plus a specially-formulated edge case to demonstrate the issue with a
    # series of valid padding bytes at the end of the block: the first block
    # has random garbage, followed by 0x06 five times, and then a garbage
    # character. If we're solving the last byte, and we corrupt a byte in the
    # previous block, resulting in an output byte of 0x06 in this block, the
    # padding oracle will return value padding, but we might naively assume
    # we've found the 0x01 case, which would be incorrect.
    b64encode(b'x' * 10 + b'\x06' * 5 + b'?' + b'j' * BLOCK_SIZE * 2),
    b64encode(b'x' * 15 + b'\x01' + b'j' * BLOCK_SIZE * 2)
)]


def randcrypt():
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


def padding_oracle_attack(ciphertext: bytes, iv: bytes,
                          padding_oracle: Callable[[bytes, bytes], bool]) -> bytes:
    """ Given an input ciphertext and known IV, uses provided oracle to
    discover original plaintext.
    """
    block_count = len(ciphertext) // BLOCK_SIZE

    plaintext = []
    for block_idx in range(0, block_count):
        # Byte indexes for the block we're discovering; we're actually exiting
        # the prior block (or the IV, if discovering the first block)
        block_start = block_idx * BLOCK_SIZE
        block_end = block_start + BLOCK_SIZE

        hacked_start = block_start - BLOCK_SIZE
        hacked_end = block_end - BLOCK_SIZE

        discovered = deque()

        # Byte position from end of the block
        for i in range(0, 16):
            target_idx = BLOCK_SIZE - i - 1
            desired_pad = i + 1

            # Reset the block base we're editing each time
            base_block = iv[:] if block_idx == 0 else ciphertext[hacked_start:hacked_end]
            for v in range(0, 256):

                # xor already-discovered elements with the desired padding
                # value
                block = list(base_block)
                block = block[:target_idx] + [v] + [desired_pad ^ k for k in discovered]
                block = bytes(block)

                # Set the IV to the hacked prior block, and the ciphertext to
                # the current block we've solving
                hacked_iv = block
                hacked_ciphertext = ciphertext[block_start:block_end]

                if has_valid_padding(hacked_ciphertext, hacked_iv):
                    # EDGE CASE: If we're on the last byte of the block, we
                    #     need to corrupt the second-to-last byte and re-check,
                    #     to avoid the case where there are X-1 padding bytes
                    #     with the correct value immediately preceeding the
                    #     last byte.
                    if target_idx == BLOCK_SIZE - 1:
                        # Corrupt the second to last byte to something different
                        new_value = original_value = hacked_iv[target_idx - 1]
                        while new_value == original_value: 
                            new_value = randint(0x00, 0xFF) 

                        # Small transformation so we can easily do a quick item
                        # assignment, then back again
                        hacked_iv = list(hacked_iv)
                        hacked_iv[target_idx - 1] = new_value
                        hacked_iv = bytes(hacked_iv)

                        if not has_valid_padding(hacked_ciphertext, hacked_iv):
                            # Keep looking, this was a false-positive that
                            # happened to make prior padding bytes become valid
                            continue

                    # xor with the padding value to get the pre-xor output
                    discovered.appendleft(v ^ desired_pad)
                    break
            else:
                raise Exception(f'Unable to determine byte at {block_idx}:{target_idx}')

        # Convert the discovered block to plaintext by XORing with the previous
        # block, or IV if converting the first ciphertext block
        prior_block = iv if block_idx == 0 else ciphertext[hacked_start:hacked_end]
        for c1, c2 in zip(prior_block, discovered):
            plaintext.append((c1 ^ c2).to_bytes(1, byteorder='little'))

    return pkcs7_strip(b''.join(plaintext))


if __name__ == '__main__':
    print('Challenge #17 - The CBC Padding Oracle')

    # Run this 100 times, due to random chance
    runs = 1000 
    for i in range(1, runs + 1):
        global KEY
        KEY = os.urandom(16)

        ciphertext, iv = randcrypt()
        plaintext = padding_oracle_attack(ciphertext, iv, has_valid_padding)

        # With no modifications, the padding should be valid
        assert has_valid_padding(ciphertext, iv)

        # Verify output plaintext against our initial set
        assert plaintext in POSSIBLE_INPUTS

        sys.stdout.write(f'\r{i} / {runs} ({i / runs * 100:.0f}%)')
        sys.stdout.flush()
