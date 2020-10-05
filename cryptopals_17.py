#!/usr/bin/env python


import os
import sys
from collections import deque
from random import choice
from typing import Callable, Tuple

from cryptopals_15 import pkcs7_strip
from cryptopals_10 import cbc_decrypt, cbc_encrypt


BLOCK_SIZE = 16
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

                # When determining the last byte of a block, there's an edge
                # case where, if our test value is the same as the original
                # ciphertext byte, the padding oracle will indicate it is valid
                # if we happen to be on the last block
                if target_idx == 15 and v == base_block[target_idx]:
                    continue

                # Convert to a list for easy concatenation
                block = list(base_block)

                # xor already-discovered elements with the desired padding
                # value
                block = block[:target_idx] + [v] + [desired_pad ^ k for k in discovered]
                block = bytes(block)

                # Run the IV and all blocks up through the next block through
                # the oracle

                # If the first block, modify the IV, else modify the ciphertext
                if block_idx == 0:
                    hacked_iv = block
                    hacked_ciphertext = ciphertext[:block_end]
                else:
                    hacked_iv = iv
                    hacked_ciphertext = list(ciphertext[:block_end])
                    hacked_ciphertext[hacked_start:hacked_end] = block
                    hacked_ciphertext = bytes(hacked_ciphertext)

                valid = has_valid_padding(hacked_ciphertext, hacked_iv)
                if valid:
                    # print(f'Valid byte ({v}) {bin(v)} at target_idx {target_idx} found')

                    # xor with the padding value to get the pre-xor output
                    discovered.appendleft(v ^ desired_pad)
                    break
            else:
                #print('Plaintext: ', b''.join(plaintext))
                #print(f'Range in ciphertext: {hacked_start}, {hacked_end} | {block_start}, {block_end}')
                #print(list(base_block))
                #print(list(block))
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
    for i in range(0, 100):
        sys.stdout.write('.')
        sys.stdout.flush()

        ciphertext, iv = randcrypt()
        plaintext = padding_oracle_attack(ciphertext, iv, has_valid_padding)

        # With no modifications, the padding should be valid
        assert has_valid_padding(ciphertext, iv)

        # Verify output plaintext against our initial set
        assert plaintext in POSSIBLE_INPUTS
