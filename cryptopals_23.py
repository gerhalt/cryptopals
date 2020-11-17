#!/usr/bin/env python

from cryptopals_21 import MersenneTwister as MT


def unxor_rshift(k: int, shift: int, shift_and: int = None):
    """Accepts the result of the following equation, along with some of the
    original equation parameters, and returns the original value `n`.

    k = n ^ ((n << shift) & shift_and) 

    """
    if shift_and is None:
        shift_and = 0xFFFFFFFF

    n = 0

    # From left-most bit to right, beginning at the end shifted away from
    for bit in range(31, -1, -1):
        # Shift the known bit into the right-most position
        known_bit = k >> bit

        # determine the corresponding xor bit
        xor_bit = ((n >> shift) & shift_and) >> bit

        # XOR, mask, shift, and OR onto N
        n |= ((known_bit ^ xor_bit) & 0b1) << bit 

    return n


def unxor_lshift(k: int, shift: int, shift_and: int = None):
    """Accepts the result of the following equation, along with some of the
    original equation parameters, and returns the original value `n`.

    k = n ^ ((n >> shift) & shift_and) 

    """
    if shift_and is None:
        shift_and = 0xFFFFFFFF

    n = 0 

    # From right-most bit position to left, starting from the end shifted away from
    for bit in range(0, 32):
        # shift the known bit into the right-most position
        known_bit = k >> bit

        # determine the corresponding xor bit
        xor_bit = ((n << shift) & shift_and) >> bit

        # XOR, mask, shift and OR onto N
        n |= ((known_bit ^ xor_bit) & 0b1) << bit

    return n


def untemper(n: int) -> int:
    """Given a number, applies the reverse of the MT19937 tempering operations
    to output the original state array value.
    """

    # From `MersenneTwister.extract_number`, in reverse order of application:
    # y ^= y >> self.L
    # y ^= (y << self.T) & self.C
    # y ^= (y << self.S) & self.B
    # y ^= (y >> self.U) & self.D
    n = unxor_rshift(n, MT.L)
    n = unxor_lshift(n, MT.T, MT.C)
    n = unxor_lshift(n, MT.S, MT.B)
    n = unxor_rshift(n, MT.U, MT.D)

    return n


if __name__ == '__main__':
    print('Challenge #23 - Clone a MT19937 RNG from its output')

    # Test un-shift-and-xor
    for shift in range(0, 32):
        original_y = 0xDEADBEEF
        xor_and = 0xDECAFBAD
        shifted_y = original_y ^ ((original_y << shift) & xor_and)
        assert unxor_lshift(shifted_y, shift, xor_and), original_y

    for shift in range(0, 32):
        original_y = 0xDEADBEEF
        xor_and = 0xDECAFBAD
        shifted_y = original_y ^ ((original_y >> shift) & xor_and)
        assert unxor_rshift(shifted_y, shift, xor_and), original_y

    # Given a series of known output, stopping right before the second twist
    mt = MT(1234)
    original_out = [mt.extract_number() for i in range(0, MT.N)]

    # When we create a new instance (with a different seed from our known series)
    spliced_mt = MT(999)
    spliced_mt.idx = 0

    # and iterate through each element in the known output, untempter it, and
    # stuff it into the state array of our new twister instance
    for i, o in enumerate(original_out):
        spliced_mt.mt[i] = untemper(o)

    # we should be able to create a duplicate series of outputs
    predicted_out = [spliced_mt.extract_number() for i in range(0, MT.N)]

    # and verify that it matches the original output
    for i, (a, b) in enumerate(zip(original_out, predicted_out)):
        assert a == b, f'Original output #{i} of {a} doesn\'t match predicted output {b}'
