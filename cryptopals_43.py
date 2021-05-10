#!/usr/bin/env python
from random import randint

from Crypto.Util import number

from cryptopals_28 import sha1
from cryptopals_33 import modpow
from cryptopals_39 import moddiv, modinv


class DSA(object):

    H = sha1  # Hash function to use
    L = 2048  # Key length
    N = 224   # Modulus length
    DEFAULT_P = int("800000000000000089e1855218a0e7dac38136ffafa72eda7"
                    "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"
                    "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"
                    "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"
                    "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"
                    "1a584471bb1", 16)
    DEFAULT_Q = int("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
    DEFAULT_G = int("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"
                    "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"
                    "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"
                    "0f5b64c36b625a097f1651fe775323556fe00b3608c887892"
                    "878480e99041be601a62166ca6894bdd41a7054ec89f756ba"
                    "9fc95302291", 16)

    def __init__(self, p: int = None, q: int = None, g: int = None,
                 x: int = None, y: int = None):
        # q is an N-bit prime
        # p is an L-bit prime such that p-1 is a multiple of q
        # Choose an integer h randomly from {2...p-2}

        # q = h ** ((p - 1) / q) % g
        # If g = 1, try again with a different h, h = 2 is commonly used)
        # For now, hard-coded parameters
        self.p = p if p is not None else self.DEFAULT_P
        self.q = q if q is not None else self.DEFAULT_Q
        self.g = g if g is not None else self.DEFAULT_G

        # Compute the per-user keys
        self.x = x or randint(1, self.q - 1)
        self.y = y or modpow(self.g, self.x, self.p)
        print(f'Per-user keys:\n  X: {self.x}\n  Y: {self.y}')

    def sign(self, msg: bytes, k: int = None) -> bytes:
        """Sign a message `msg` with DSA and return the signature tuple `(r, s)`
        """
        r = s = 0
        while r == 0 or s == 0:
            k = k or randint(1, self.q - 1)

            r = modpow(self.g, k, self.p) % self.q
            hm = int.from_bytes(sha1(msg), 'big')
            s = (modinv(k, self.q) * (hm + self.x * r)) % self.q

        return r, s

    def verify(self, msg: bytes, r: int, s: int) -> bool:
        """Verify a signature `(r, s)` is for a given `msg`.
        """
        valid = 0 < r < self.q and 0 < s < self.q

        w = modinv(s, self.q)
        hm = int.from_bytes(sha1(msg), 'big')
        u1 = (hm * w) % self.q
        u2 = (r * w) % self.q
        v = ((modpow(self.g, u1, self.p) * modpow(self.y, u2, self.p)) % self.p) % self.q

        print(f'W: {w}')
        print(f'V: {v}')
        print(f'R: {r}')

        return valid and v == r


def dsa_recover_x(msg: bytes, k: int, q: int, r: int, s: int) -> int:
    hm = int.from_bytes(sha1(msg), 'big')
    return moddiv(s * k - hm, r, q)


if __name__ == '__main__':
    print('Challenge #43 - DSA key recovery from nonce')

    msg = b'Test message'

    dsa = DSA()
    r, s = dsa.sign(msg)

    print(f'R: {r}')
    print(f'S: {s}')

    assert dsa.verify(msg, r, s)

    msg = (b"For those that envy a MC it can be hazardous to your health\n"
           b"So be friendly, a matter of life and death, just like a etch-a-sketch\n")
    checksum = int.from_bytes(sha1(msg), 'big')
    assert checksum == 0xd2d0714f014a9784047eaeccf956520045c45265

    # Known public key
    y = int("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4"
            "abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004"
            "e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed"
            "1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b"
            "bb283e6633451e535c45513b2d33c99ea17", 16)

    # Known message signature
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940

    # Find k, known to be in {1...2**16}
    for test_k in range(1, 2 ** 16):
        # Generate r, check with known r
        test_r = modpow(dsa.g, test_k, dsa.p) % dsa.q
        if test_r == r:
            k = test_k
            break

    # Recover x
    x = dsa_recover_x(msg, k, dsa.q, r, s)
    print(f'Recovered X: {x}')

    dsa = DSA(x=x, y=y)
    r, s = dsa.sign(msg, k=k)

