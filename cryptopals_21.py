#!/usr/bin/env python


class MersenneTwister(object):
    """
    Implementation of MT19937, based on the psuedocode on
    https://en.wikipedia.org/wiki/Mersenne_Twister

    w: word size (in number of bits)
    n: degree of recurrence
    m: middle word, an offset used in the recurrence relation defining the series x, 1 ≤ m < n
    r: separation point of one word, or the number of bits of the lower bitmask, 0 ≤ r ≤ w - 1
    a: coefficients of the rational normal form twist matrix
    b, c: TGFSR(R) tempering bitmasks
    s, t: TGFSR(R) tempering bit shifts
    u, d, l: additional Mersenne Twister tempering bit shifts/masks
    """

    W, N, M, R = 32, 624, 397, 31 
    A = 0x9908B0DF
    U, D = 11, 0xFFFFFFFF
    S, B = 7,  0x9D2C5680
    T, C = 15, 0xEFC60000
    L = 18

    # Used for initial generation, but not part of the algorithm proper
    F = 1812433253

    def __init__(self, seed: int):
        self.mt = [0] * self.N
        self.idx = self.N + 1
        self.LOWER_MASK = (1 << self.R) - 1  # Binary number of r 1's
        self.UPPER_MASK = ((1 << self.W) - 1)

        self.seed(seed)

    def seed(self, seed: int):
        """Initializes the array.
        """
        self.idx = self.N
        self.mt[0] = seed
        for i in range(1, self.N):
            self.mt[i] = ((1 << self.W) - 1) & (self.F * (self.mt[i - 1] ^ (self.mt[i - 1] >> (self.W - 2))) + i)

    def extract_number(self):
        """Extract a tempered value based on `self.mt[index]` calling `twist`
        every `n` numbers.
        """
        if self.idx >= self.N:
            if self.idx > self.N:
                raise Exception('Generator was never seeded')
            self.twist()

        # Tempering transform
        y = self.mt[self.idx]
        y ^= (y >> self.U) & self.D
        y ^= (y << self.S) & self.B
        y ^= (y << self.T) & self.C
        y ^= y >> self.L

        self.idx += 1
        return ((1 << self.W) - 1) & y

    def twist(self):
        for i in range(0, self.N):
            x = (self.mt[i] & self.UPPER_MASK) + (self.mt[(i + 1) % self.N] & self.LOWER_MASK)
            x_a = x >> 1
            if x % 2 != 0:  # Lowest bit of `x` is 1
                x_a ^= self.A

            self.mt[i] = self.mt[(i + self.M) % self.N]

        self.idx = 0


if __name__ == '__main__':
    print('Challenge #21 - Implement the MT19937 Mersenne Twister RNG')

    mt = MersenneTwister(12345)
    print([mt.extract_number() for i in range(0, 10)])
