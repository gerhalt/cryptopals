#!/usr/bin/env python

from hashlib import md5
from random import randint

TEST_P = 37
REAL_P = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

TEST_G = 5
REAL_G = 2


def modpow(base, exponent, mod):
    """Calculates the result of a modular exponentiation.
    """
    if mod == 1:
        return 0
    
    result = 1
    base = base % mod

    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % mod
        exponent = exponent >> 1
        base = (base * base) % mod

    return result


if __name__ == '__main__':
    print('Challenge #33 - Implement Diffie-Hellman')

    for p, g in ((TEST_P, TEST_G), (REAL_P, REAL_G)):
        a = randint(0, p)
        A = modpow(g, a, p)

        b = randint(0, p)
        B = modpow(g, b, p)

        s1 = modpow(B, a, p)
        s2 = modpow(B, a, p)
        assert s1 == s2

        # Convert session key to 
        h = md5(str(s1).encode('UTF-8')).digest()

        print(h)
