#!/usr/bin/env python

import os
import sys
from calendar import timegm
from datetime import datetime
from random import randint
from typing import Generator

from cryptopals_10 import xor
from cryptopals_21 import MersenneTwister


def twister_keystream(twister: MersenneTwister) -> Generator[int, int, None]:
    """Given a 32-bit Mersenne Twister instance, generates sequences of bytes
    composed of each output in the series, broken into quarters.
    """
    while True:
        n = twister.extract_number()
        for byte_idx in range(3, -1, -1):
            yield (n >> (8 * byte_idx)) & 0xFF


def twister_cipher(seed: int, msg: bytes) -> bytes:
    """Given a 16-bit `seed`, encrypts the given `msg` by xor-ing with bytes
    generated from a mersenne twister output series.
    """
    output = []

    mt = MersenneTwister(seed)
    keystream = twister_keystream(mt)
    for b in msg:
        output.append(b ^ next(keystream))

    return bytes(output)


def discover_seed(ciphertext: bytes, known_plaintext: bytes, seed_start: int, seed_end: int) -> int:
    """Given a `ciphertext`, a known plaintext chunk to look for in decrypted
    output, and a seed range to iterate over.
    """
    print('Discovering seed')
    discovered_seed = None
    for test_seed in range(seed_start, seed_end):
        if test_seed == seed_start or test_seed % 100 == 0:
            sys.stdout.write(f'\rTesting seed {test_seed} of {seed_start}..{seed_end}')

        test_out = twister_cipher(test_seed, ciphertext)
        if known in test_out:
            discovered_seed = test_seed
            print('\nDiscovered seed {discovered_seed}')
            break
    else:
        print('\nNo seed discovered!')

    return discovered_seed


def is_token_from_time_seeded_mt19937(token: bytes, known: bytes, window: int) -> bool:
    """Accepts a token and determines whether it was generated using MT19937
    output seeded with a relatively recent time. Looks for `known` in
    decrypted output. `window` is, in seconds, the duration to check both
    forwards and backwards in time.
    """
    now_epoch = timegm(datetime.utcnow().timetuple())

    seed = discover_seed(token, known, now_epoch - window, now_epoch + window)
    return seed is not None


if __name__ == '__main__':
    print('Challenge #24 - Create the MT19937 stream cipher and break it')

    # Verify our keystream produces the expected in-order bytes of the series
    mt = MersenneTwister(12345)
    tk = twister_keystream(mt)
    assert [next(tk) for i in range(0, 8)] == [0xED, 0xFB, 0x51, 0xE2, 0xE3, 0xE1, 0x2D, 0xE5]

    print('Generating random 16-bit seed and building plaintext')
    seed = randint(0, 0xFFFF)

    # Create a plaintext, composed of a known portion prefixed by a random
    # number of random bytes
    known = b'*' * 12
    plaintext = os.urandom(randint(10, 24)) + known
    ciphertext = twister_cipher(seed, plaintext)

    discovered_seed = discover_seed(ciphertext, known, 0x0, 0xFFFF)
    assert discovered_seed is not None, 'No seed discovered'
    assert seed == discovered_seed, f"Original seed {seed} doesn't match discovered seed {discovered_seed}" 

    # If we generate a simulated "password reset token" with some known data
    # in the plaintext, seeded with a recent epoch time
    time_seed = timegm(datetime.utcnow().timetuple()) - 10
    known = b'jashjushjish'
    token_plaintext = os.urandom(randint(24, 36)) + known
    good_pwt_token = twister_cipher(time_seed, token_plaintext)

    # and a simulated "password reset token" created completely randomly
    bad_pwt_token = os.urandom(48)

    print('Testing PWT generated with time-seeded MT19937')
    assert is_token_from_time_seeded_mt19937(good_pwt_token, known, 60)

    print('Testing PWT generated completely randomly')
    assert not is_token_from_time_seeded_mt19937(bad_pwt_token, known, 60)
